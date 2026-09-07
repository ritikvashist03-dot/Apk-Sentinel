package app.apksentinel.inspector.internal

import app.apksentinel.inspector.ArchiveFormat
import app.apksentinel.inspector.ArchiveInventory
import app.apksentinel.inspector.ArchiveLimit
import app.apksentinel.inspector.ArchiveLimitExceeded
import app.apksentinel.inspector.ArchiveMetadata
import app.apksentinel.inspector.ArchiveUnreadable
import app.apksentinel.inspector.ApkTechnicalEvidence
import app.apksentinel.inspector.FindingConfidence
import app.apksentinel.inspector.FindingSeverity
import app.apksentinel.inspector.HeuristicFinding
import app.apksentinel.inspector.HeuristicFindingCode
import app.apksentinel.inspector.HeuristicFindingsTruncated
import app.apksentinel.inspector.HeuristicScanTruncated
import app.apksentinel.inspector.InspectionFailure
import app.apksentinel.inspector.InspectionFailureCode
import app.apksentinel.inspector.InspectionLimits
import app.apksentinel.inspector.InspectionStage
import app.apksentinel.inspector.NativeLibraryInventory
import app.apksentinel.inspector.PathInventory
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.util.zip.ZipInputStream

internal data class ArchiveScanOutcome(
    val archive: ArchiveMetadata?,
    val inventory: ArchiveInventory?,
    val findings: List<HeuristicFinding>,
    val failures: List<InspectionFailure>,
    val stoppedForSafety: Boolean,
)

/**
 * Reads the archive sequentially. It never extracts an entry and stops the
 * underlying stream as soon as a hard resource limit is breached.
 */
internal class ArchiveScanner(
    private val heuristicScanner: HeuristicScanner = HeuristicScanner(),
) {
    fun inspect(
        input: File,
        limits: InspectionLimits,
        control: InspectionControl,
    ): ArchiveScanOutcome {
        val hasSignature = try {
            hasZipSignature(input)
        } catch (error: IOException) {
            return ArchiveScanOutcome(
                archive = null,
                inventory = null,
                findings = emptyList(),
                failures = listOf(
                    ArchiveUnreadable(
                        code = InspectionFailureCode.ZIP_OPEN_FAILED,
                    ),
                ),
                stoppedForSafety = false,
            )
        }
        if (!hasSignature) {
            return ArchiveScanOutcome(
                archive = null,
                inventory = null,
                findings = emptyList(),
                failures = listOf(
                    ArchiveUnreadable(
                        code = InspectionFailureCode.ZIP_SIGNATURE_MISSING,
                    ),
                ),
                stoppedForSafety = false,
            )
        }

        val state = ArchiveScanState(limits)
        try {
            ZipInputStream(BufferedInputStream(FileInputStream(input))).use { zip ->
                val buffer = ByteArray(32 * 1024)
                while (true) {
                    control.ensureActive()
                    val entry = zip.nextEntry ?: break
                    state.entryCount += 1
                    if (state.entryCount > limits.maxArchiveEntries) {
                        return state.stop(
                            ArchiveLimitExceeded(
                                limit = ArchiveLimit.ENTRY_COUNT,
                                observed = state.entryCount.toDouble(),
                                maximum = limits.maxArchiveEntries.toDouble(),
                            ),
                        )
                    }

                    val name = entry.name.orEmpty()
                    if (isUnsafeArchivePath(name)) {
                        state.pathTraversalEntryCount += 1
                        state.addFinding(
                            key = "unsafe-path:" + name,
                            finding = HeuristicFinding(
                                code = HeuristicFindingCode.UNSAFE_ARCHIVE_PATH,
                                severity = FindingSeverity.HIGH,
                                confidence = FindingConfidence.HIGH,
                                evidence = listOf(
                                    ApkTechnicalEvidence.ArchiveEntryPath(displayEntryName(name)),
                                ),
                            ),
                        )
                    }

                    if (name == ANDROID_MANIFEST_ENTRY) {
                        state.containsAndroidManifest = true
                    }
                    if (!entry.isDirectory) {
                        state.recordInventory(name)
                    }
                    heuristicScanner.findByEntryName(name).forEach { finding ->
                        state.addFinding(
                            key = "tracker-entry:" + finding.code.name,
                            finding = finding,
                        )
                    }

                    val initialDeclaredSize = entry.size
                    if (initialDeclaredSize >= 0L) {
                        state.recordKnownUncompressedBytes(initialDeclaredSize)?.let { limit ->
                            return state.stop(limit)
                        }
                    }

                    val candidate = isHeuristicCandidate(name)
                    val captureLimit = state.captureLimitForEntry(candidate)
                    val captured = if (candidate) ByteArrayOutputStream(captureLimit) else null
                    var entryBytes = 0L
                    var heuristicEntryTruncated = false

                    while (true) {
                        control.ensureActive()
                        val read = zip.read(buffer)
                        if (read < 0) {
                            break
                        }
                        if (read == 0) {
                            continue
                        }

                        entryBytes += read.toLong()
                        state.observedUncompressedBytes += read.toLong()
                        if (entryBytes > limits.maxEntryUncompressedBytes) {
                            return state.stop(
                                ArchiveLimitExceeded(
                                    limit = ArchiveLimit.ENTRY_UNCOMPRESSED_BYTES,
                                    observed = entryBytes.toDouble(),
                                    maximum = limits.maxEntryUncompressedBytes.toDouble(),
                                ),
                            )
                        }
                        if (state.observedUncompressedBytes > limits.maxTotalUncompressedBytes) {
                            return state.stop(
                                ArchiveLimitExceeded(
                                    limit = ArchiveLimit.TOTAL_UNCOMPRESSED_BYTES,
                                    observed = state.observedUncompressedBytes.toDouble(),
                                    maximum = limits.maxTotalUncompressedBytes.toDouble(),
                                ),
                            )
                        }

                        if (captured != null) {
                            val available = captureLimit - captured.size()
                            val copied = minOf(read, available.coerceAtLeast(0))
                            if (copied > 0) {
                                captured.write(buffer, 0, copied)
                            }
                            if (copied < read) {
                                heuristicEntryTruncated = true
                            }
                        }

                        if (state.observedUncompressedBytes >= state.nextProgressBytes) {
                            control.report(
                                stage = InspectionStage.INSPECT_ARCHIVE,
                                code = app.apksentinel.inspector.InspectionProgressCode.INSPECTING_ARCHIVE,
                                bytesProcessed = state.observedUncompressedBytes,
                                bytesLimit = limits.maxTotalUncompressedBytes,
                                entriesProcessed = state.entryCount,
                            )
                            state.nextProgressBytes =
                                state.observedUncompressedBytes + PROGRESS_INTERVAL_BYTES
                        }
                    }
                    zip.closeEntry()

                    if (initialDeclaredSize < 0L) {
                        val finalDeclaredSize = entry.size
                        if (finalDeclaredSize >= 0L) {
                            state.recordKnownUncompressedBytes(finalDeclaredSize)?.let { limit ->
                                return state.stop(limit)
                            }
                        } else {
                            state.entriesWithUnknownUncompressedSize += 1
                        }
                    }

                    val compressedSize = entry.compressedSize
                    if (compressedSize >= 0L) {
                        state.declaredCompressedBytes =
                            state.declaredCompressedBytes.saturatingAdd(compressedSize)
                        val ratio = entryBytes.toDouble() / compressedSize.coerceAtLeast(1L).toDouble()
                        state.maximumObservedCompressionRatio =
                            maxOf(state.maximumObservedCompressionRatio ?: 0.0, ratio)
                        if (ratio > limits.maxCompressionRatio) {
                            return state.stop(
                                ArchiveLimitExceeded(
                                    limit = ArchiveLimit.COMPRESSION_RATIO,
                                    observed = ratio,
                                    maximum = limits.maxCompressionRatio,
                                ),
                            )
                        }
                    } else {
                        state.entriesWithUnknownCompressedSize += 1
                    }

                    if (captured != null) {
                        state.scannedHeuristicBytes += captured.size().toLong()
                        heuristicScanner.scanEntryContent(
                            entryName = name,
                            content = captured.toByteArray(),
                            findingConsumer = { key, finding ->
                                state.addFinding(key, finding)
                            },
                        )
                        if (heuristicEntryTruncated) {
                            state.heuristicScanTruncated = true
                        }
                    }
                }
            }
        } catch (error: IOException) {
            state.failures += ArchiveUnreadable(
                code = InspectionFailureCode.ZIP_READ_FAILED,
            )
            return state.outcome(archiveComplete = false, stoppedForSafety = false)
        }

        return state.outcome(archiveComplete = true, stoppedForSafety = false)
    }
}

private class ArchiveScanState(
    private val limits: InspectionLimits,
) {
    val failures = mutableListOf<InspectionFailure>()
    private val findingCollector = FindingCollector(limits.maxHeuristicFindings)
    private val dexFiles = PathInventoryBuilder(limits.maxInventoryPathsPerKind)
    private val nativeLibraries = NativeLibraryInventoryBuilder(limits.maxInventoryPathsPerKind)
    private val assets = PathInventoryBuilder(limits.maxInventoryPathsPerKind)

    var entryCount = 0
    var declaredCompressedBytes = 0L
    var declaredUncompressedBytes = 0L
    var observedUncompressedBytes = 0L
    var entriesWithUnknownCompressedSize = 0
    var entriesWithUnknownUncompressedSize = 0
    var maximumObservedCompressionRatio: Double? = null
    var containsAndroidManifest = false
    var pathTraversalEntryCount = 0
    var scannedHeuristicBytes = 0L
    var heuristicScanTruncated = false
    var nextProgressBytes = PROGRESS_INTERVAL_BYTES

    fun recordInventory(name: String) {
        when {
            DEX_ENTRY_REGEX.matches(name) -> dexFiles.add(name)
            name.startsWith("lib/") && name.endsWith(".so") -> nativeLibraries.add(name)
            name.startsWith("assets/") -> assets.add(name)
        }
    }

    fun recordKnownUncompressedBytes(value: Long): ArchiveLimitExceeded? {
        if (value > limits.maxEntryUncompressedBytes) {
            return ArchiveLimitExceeded(
                limit = ArchiveLimit.ENTRY_UNCOMPRESSED_BYTES,
                observed = value.toDouble(),
                maximum = limits.maxEntryUncompressedBytes.toDouble(),
            )
        }
        declaredUncompressedBytes = declaredUncompressedBytes.saturatingAdd(value)
        return if (declaredUncompressedBytes > limits.maxTotalUncompressedBytes) {
            ArchiveLimitExceeded(
                limit = ArchiveLimit.TOTAL_UNCOMPRESSED_BYTES,
                observed = declaredUncompressedBytes.toDouble(),
                maximum = limits.maxTotalUncompressedBytes.toDouble(),
            )
        } else {
            null
        }
    }

    fun captureLimitForEntry(candidate: Boolean): Int {
        if (!candidate) {
            return 0
        }
        val remaining = (limits.maxTotalHeuristicBytes - scannedHeuristicBytes).coerceAtLeast(0L)
        return minOf(limits.maxHeuristicBytesPerEntry.toLong(), remaining).toInt()
    }

    fun addFinding(key: String, finding: HeuristicFinding) {
        findingCollector.add(key, finding)
    }

    fun stop(limit: ArchiveLimitExceeded): ArchiveScanOutcome {
        failures += limit
        return outcome(archiveComplete = false, stoppedForSafety = true)
    }

    fun outcome(
        archiveComplete: Boolean,
        stoppedForSafety: Boolean,
    ): ArchiveScanOutcome {
        if (heuristicScanTruncated &&
            failures.none { it is HeuristicScanTruncated }
        ) {
            failures += HeuristicScanTruncated(
                scannedBytes = scannedHeuristicBytes,
                maximumBytes = limits.maxTotalHeuristicBytes,
            )
        }
        if (findingCollector.isTruncated &&
            failures.none { it is HeuristicFindingsTruncated }
        ) {
            failures += HeuristicFindingsTruncated(
                retainedFindings = findingCollector.findings.size,
                maximumFindings = limits.maxHeuristicFindings,
            )
        }
        return ArchiveScanOutcome(
            archive = ArchiveMetadata(
                format = ArchiveFormat.ZIP,
                entryCount = entryCount,
                declaredCompressedBytes = declaredCompressedBytes,
                declaredUncompressedBytes = declaredUncompressedBytes,
                observedUncompressedBytes = observedUncompressedBytes,
                entriesWithUnknownCompressedSize = entriesWithUnknownCompressedSize,
                entriesWithUnknownUncompressedSize = entriesWithUnknownUncompressedSize,
                maximumObservedCompressionRatio = maximumObservedCompressionRatio,
                containsAndroidManifest = containsAndroidManifest,
                pathTraversalEntryCount = pathTraversalEntryCount,
                isComplete = archiveComplete,
            ),
            inventory = ArchiveInventory(
                dexFiles = dexFiles.build(),
                nativeLibraries = nativeLibraries.build(),
                assets = assets.build(),
            ),
            findings = findingCollector.findings,
            failures = failures.toList(),
            stoppedForSafety = stoppedForSafety,
        )
    }
}

private class FindingCollector(
    private val maximumFindings: Int,
) {
    private val seenKeys = linkedSetOf<String>()
    private val mutableFindings = mutableListOf<HeuristicFinding>()

    var isTruncated: Boolean = false
        private set

    val findings: List<HeuristicFinding>
        get() = mutableFindings.toList()

    fun add(key: String, finding: HeuristicFinding) {
        if (seenKeys.contains(key)) return
        if (mutableFindings.size >= maximumFindings) {
            // Do not retain attacker-controlled keys after the cap. The first
            // overflow is sufficient to make the partial result explicit.
            isTruncated = true
            return
        }
        seenKeys += key
        mutableFindings += finding
    }
}

private class PathInventoryBuilder(
    private val maximumSamples: Int,
) {
    private var count = 0
    private val samples = mutableListOf<String>()

    fun add(path: String) {
        count += 1
        if (samples.size < maximumSamples) {
            samples += path
        }
    }

    fun build(): PathInventory = PathInventory(
        count = count,
        samplePaths = samples.toList(),
        isTruncated = count > samples.size,
    )
}

private class NativeLibraryInventoryBuilder(
    private val maximumSamples: Int,
) {
    private var count = 0
    private val samples = mutableListOf<String>()
    private val abiCounts = linkedMapOf<String, Int>()

    fun add(path: String) {
        count += 1
        if (samples.size < maximumSamples) {
            samples += path
        }
        val abi = path.split('/').getOrNull(1).orEmpty().ifBlank { "unknown" }
        abiCounts[abi] = (abiCounts[abi] ?: 0) + 1
    }

    fun build(): NativeLibraryInventory = NativeLibraryInventory(
        count = count,
        samplePaths = samples.toList(),
        abiCounts = abiCounts.toMap(),
        isTruncated = count > samples.size,
    )
}

private fun hasZipSignature(file: File): Boolean {
    val header = ByteArray(4)
    val read = FileInputStream(file).use { input -> input.read(header) }
    if (read != header.size || header[0] != 'P'.code.toByte() || header[1] != 'K'.code.toByte()) {
        return false
    }
    return (header[2] == 3.toByte() && header[3] == 4.toByte()) ||
        (header[2] == 5.toByte() && header[3] == 6.toByte()) ||
        (header[2] == 7.toByte() && header[3] == 8.toByte())
}

private fun isUnsafeArchivePath(name: String): Boolean {
    if (name.indexOf('\u0000') >= 0) {
        return true
    }
    val normalized = name.replace('\\', '/')
    if (normalized.startsWith('/') || normalized.startsWith("//")) {
        return true
    }
    if (DRIVE_ABSOLUTE_PATH_REGEX.matches(normalized)) {
        return true
    }
    return normalized.split('/').any { segment -> segment == ".." }
}

private fun isHeuristicCandidate(name: String): Boolean =
    name == ANDROID_MANIFEST_ENTRY ||
        DEX_ENTRY_REGEX.matches(name) ||
        name.startsWith("assets/") ||
        name.startsWith("res/raw/")

private fun displayEntryName(name: String): String =
    name.replace('\u0000', '?').take(MAX_EVIDENCE_PATH_LENGTH)

private fun Long.saturatingAdd(value: Long): Long =
    if (this > Long.MAX_VALUE - value) Long.MAX_VALUE else this + value

private const val ANDROID_MANIFEST_ENTRY = "AndroidManifest.xml"
private const val PROGRESS_INTERVAL_BYTES = 512L * 1024L
private const val MAX_EVIDENCE_PATH_LENGTH = 512
private val DEX_ENTRY_REGEX = Regex("""classes(\d+)?\.dex""")
private val DRIVE_ABSOLUTE_PATH_REGEX = Regex("""^[A-Za-z]:.*""")
