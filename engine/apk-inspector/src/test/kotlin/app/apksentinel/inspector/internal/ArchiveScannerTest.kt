package app.apksentinel.inspector.internal

import app.apksentinel.inspector.ArchiveLimit
import app.apksentinel.inspector.ArchiveLimitExceeded
import app.apksentinel.inspector.ApkTechnicalEvidence
import app.apksentinel.inspector.FindingKind
import app.apksentinel.inspector.HeuristicFindingCode
import app.apksentinel.inspector.HeuristicFindingsTruncated
import app.apksentinel.inspector.InspectionCancellation
import app.apksentinel.inspector.InspectionLimits
import app.apksentinel.inspector.InspectionProgressListener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ArchiveScannerTest {
    @Test
    fun detectsPathTraversalWithoutExtractingTheEntry() {
        val archive = createZip(
            "../outside.txt" to "blocked".toByteArray(),
            "assets/inside.txt" to "safe".toByteArray(),
        )

        val outcome = scanner().inspect(archive, InspectionLimits(), control())

        assertNotNull(outcome.archive)
        assertTrue(outcome.archive!!.isComplete)
        assertEquals(1, outcome.archive!!.pathTraversalEntryCount)
        assertTrue(
            outcome.findings.any { finding ->
                finding.code == HeuristicFindingCode.UNSAFE_ARCHIVE_PATH &&
                    finding.evidence.filterIsInstance<ApkTechnicalEvidence.ArchiveEntryPath>()
                        .any { evidence -> evidence.value.contains("../outside.txt") }
            },
        )
        assertFalse(outcome.stoppedForSafety)
    }

    @Test
    fun stopsBeforeEnumeratingAnUnboundedNumberOfEntries() {
        val archive = createZip(
            "one.txt" to byteArrayOf(1),
            "two.txt" to byteArrayOf(2),
            "three.txt" to byteArrayOf(3),
        )
        val limits = InspectionLimits(maxArchiveEntries = 2)

        val outcome = scanner().inspect(archive, limits, control())

        assertTrue(outcome.stoppedForSafety)
        assertEquals(3, outcome.archive!!.entryCount)
        val failure = outcome.failures.filterIsInstance<ArchiveLimitExceeded>().single()
        assertEquals(ArchiveLimit.ENTRY_COUNT, failure.limit)
    }

    @Test
    fun stopsWhenAnEntryExpandsBeyondTheConfiguredPerEntryBudget() {
        val archive = createZip("assets/large.bin" to ByteArray(128) { 0x41 })
        val limits = InspectionLimits(
            maxEntryUncompressedBytes = 32,
            maxTotalUncompressedBytes = 1_024,
        )

        val outcome = scanner().inspect(archive, limits, control())

        assertTrue(outcome.stoppedForSafety)
        val failure = outcome.failures.filterIsInstance<ArchiveLimitExceeded>().single()
        assertEquals(ArchiveLimit.ENTRY_UNCOMPRESSED_BYTES, failure.limit)
        assertTrue(failure.observed > failure.maximum)
    }

    @Test
    fun stopsOnAnExcessiveCompressionRatio() {
        val archive = createZip("assets/repeated.txt" to ByteArray(16 * 1024) { 0x41 })
        val limits = InspectionLimits(
            maxEntryUncompressedBytes = 32 * 1024,
            maxTotalUncompressedBytes = 64 * 1024,
            maxCompressionRatio = 2.0,
        )

        val outcome = scanner().inspect(archive, limits, control())

        assertTrue(outcome.stoppedForSafety)
        val failure = outcome.failures.filterIsInstance<ArchiveLimitExceeded>().single()
        assertEquals(ArchiveLimit.COMPRESSION_RATIO, failure.limit)
        assertTrue(outcome.archive!!.maximumObservedCompressionRatio!! > 2.0)
    }

    @Test
    fun inventoriesDexNativeAssetsAndReportsLiteralHeuristics() {
        val dexLiteral = (
            "Lcom/facebook/appevents/AppEventsLogger; " +
                "https://telemetry.example.test/v1"
            ).toByteArray()
        val archive = createZip(
            "classes.dex" to dexLiteral,
            "lib/arm64-v8a/libexample.so" to byteArrayOf(0x7f),
            "assets/config.json" to "{}".toByteArray(),
        )

        val outcome = scanner().inspect(archive, InspectionLimits(), control())

        assertEquals(1, outcome.inventory!!.dexFiles.count)
        assertEquals(1, outcome.inventory!!.nativeLibraries.count)
        assertEquals(1, outcome.inventory!!.nativeLibraries.abiCounts["arm64-v8a"])
        assertEquals(1, outcome.inventory!!.assets.count)
        assertTrue(outcome.findings.any { it.kind == FindingKind.TRACKER_NAMESPACE })
        assertTrue(outcome.findings.any { it.kind == FindingKind.EMBEDDED_ENDPOINT })
        assertTrue(outcome.findings.any { it.code == HeuristicFindingCode.TRACKER_FACEBOOK })
        assertTrue(outcome.findings.any { it.code == HeuristicFindingCode.EMBEDDED_HTTP_ENDPOINT })
        assertTrue(
            outcome.findings
                .first { it.code == HeuristicFindingCode.EMBEDDED_HTTP_ENDPOINT }
                .evidence
                .any { it is ApkTechnicalEvidence.EndpointLiteral },
        )
    }

    @Test
    fun makesHeuristicFindingOutputTruncationAnExplicitPartialFailure() {
        val archive = createZip(
            "assets/one.txt" to "https://one.example.test/".toByteArray(),
            "assets/two.txt" to "https://two.example.test/".toByteArray(),
        )

        val outcome = scanner().inspect(
            archive,
            InspectionLimits(maxHeuristicFindings = 1),
            control(),
        )

        assertTrue(outcome.archive!!.isComplete)
        assertFalse(outcome.stoppedForSafety)
        assertEquals(1, outcome.findings.size)
        val failure = outcome.failures.filterIsInstance<HeuristicFindingsTruncated>().single()
        assertEquals(1, failure.retainedFindings)
        assertEquals(1, failure.maximumFindings)
    }

    private fun scanner(): ArchiveScanner = ArchiveScanner()

    private fun control(): InspectionControl = InspectionControl(
        cancellation = InspectionCancellation.None,
        progressListener = InspectionProgressListener { },
    )

    private fun createZip(vararg entries: Pair<String, ByteArray>): File {
        val file = File.createTempFile("apk-inspector-test-", ".zip")
        file.deleteOnExit()
        ZipOutputStream(FileOutputStream(file)).use { output ->
            entries.forEach { (name, bytes) ->
                output.putNextEntry(ZipEntry(name))
                output.write(bytes)
                output.closeEntry()
            }
        }
        return file
    }
}
