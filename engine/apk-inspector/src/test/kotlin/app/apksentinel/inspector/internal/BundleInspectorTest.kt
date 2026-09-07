package app.apksentinel.inspector.internal

import app.apksentinel.inspector.BundleApkRole
import app.apksentinel.inspector.BundleIdentityStatus
import app.apksentinel.inspector.BundleLimitationCode
import app.apksentinel.inspector.BundleApkEntry
import app.apksentinel.inspector.ArchiveFormat
import app.apksentinel.inspector.ArchiveMetadata
import app.apksentinel.inspector.AndroidSdkSummary
import app.apksentinel.inspector.InspectionCancellation
import app.apksentinel.inspector.InspectionLimits
import app.apksentinel.inspector.InspectionProgressListener
import app.apksentinel.inspector.ManifestSummary
import app.apksentinel.inspector.SignatureVerificationStatus
import app.apksentinel.inspector.SigningCertificateSummary
import app.apksentinel.inspector.SigningSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class BundleInspectorTest {
    @Test
    fun zipSlipIsReportedWithoutUsingTheEntryNameForExtraction() {
        val outer = createZip("../base.apk" to apkBytes())
        val cache = tempDirectory()

        val result = inspect(outer, cache)

        assertNotNull(result.bundle)
        assertTrue(result.bundle!!.limitations.contains(BundleLimitationCode.UNSAFE_PATH))
        assertFalse(File(cache.parentFile, "base.apk").exists())
        assertEquals(BundleApkRole.BASE, result.bundle!!.nestedApks.single().role)
    }

    @Test
    fun nestedApkCountCapMakesAValidPartialResult() {
        val outer = createZip(
            "base.apk" to apkBytes(),
            "split_config.arm64_v8a.apk" to apkBytes(),
        )
        val result = inspect(
            outer,
            tempDirectory(),
            InspectionLimits(maxBundleApkCount = 1),
        )

        assertNotNull(result.bundle)
        assertEquals(1, result.bundle!!.nestedApks.size)
        assertTrue(result.bundle!!.limitations.contains(BundleLimitationCode.NESTED_APK_LIMIT_REACHED))
        assertFalse(result.bundle!!.isComplete)
    }

    @Test
    fun duplicateBaseNeverSelectsAReadableSplitAsPrimary() {
        val outer = createZip(
            "base.apk" to apkBytes(),
            "base-master.apk" to apkBytes(),
        )

        val result = inspect(outer, tempDirectory())

        assertNotNull(result.bundle)
        assertNull(result.primary)
        assertTrue(result.bundle!!.limitations.contains(BundleLimitationCode.DUPLICATE_BASE))
        assertTrue(result.bundle!!.limitations.contains(BundleLimitationCode.IDENTITY_UNAVAILABLE))
    }

    @Test
    fun nestedExpansionCapIsReportedAsPartial() {
        val nested = createZip(
            "AndroidManifest.xml" to byteArrayOf(1, 2, 3),
            "assets/large.bin" to ByteArray(64) { 8 },
        ).readBytes()
        val outer = createZip("base.apk" to nested)
        val result = inspect(
            outer,
            tempDirectory(),
            InspectionLimits(
                maxBundleApkExpandedBytes = 16,
                maxBundleTotalExpandedBytes = 16,
                maxTotalUncompressedBytes = 1_024,
                maxEntryUncompressedBytes = 1_024,
            ),
        )

        assertNotNull(result.bundle)
        assertTrue(result.bundle!!.limitations.contains(BundleLimitationCode.NESTED_EXPANSION_LIMIT_REACHED))
        assertFalse(result.bundle!!.isComplete)
    }

    @Test
    fun extensionAloneDoesNotCreateBundleEvidence() {
        val outer = createZip("base.apk" to "not-an-apk".toByteArray())

        assertNull(inspect(outer, tempDirectory()).bundle)
    }

    @Test
    fun missingBaseIsTypedAndObbIsInventoryOnly() {
        val outer = createZip(
            "feature.apk" to apkBytes(),
            "Android/obb/com.example/main.obb" to ByteArray(1024) { 7 },
        )

        val bundle = inspect(outer, tempDirectory()).bundle

        assertNotNull(bundle)
        assertTrue(bundle!!.limitations.contains(BundleLimitationCode.MISSING_BASE))
        assertEquals(BundleIdentityStatus.UNAVAILABLE, bundle.identityStatus)
        assertEquals(1, bundle.obbFiles.size)
        assertEquals(1024L, bundle.obbFiles.single().byteCount)
        assertTrue(bundle.limitations.contains(BundleLimitationCode.BUNDLE_NOT_INSTALLABILITY_VERIFIED))
    }

    @Test
    fun xapkMetadataCanIdentifyANameThatDoesNotSayBase() {
        val metadata = """
            {"package_name":"com.example","version_code":7,"version_name":"1.0",
             "split_apks":[{"file":"com.example.apk","id":"base"}],
             "expansions":[{"file":"main.obb"}]}
        """.trimIndent().toByteArray()
        val outer = createZip(
            "manifest.json" to metadata,
            "com.example.apk" to apkBytes(),
            "main.obb" to byteArrayOf(1, 2, 3),
        )

        val bundle = inspect(outer, tempDirectory()).bundle

        assertNotNull(bundle)
        assertEquals(app.apksentinel.inspector.BundleFormat.XAPK, bundle!!.format)
        assertEquals(BundleApkRole.BASE, bundle.nestedApks.single().role)
        assertEquals(1, bundle.obbFiles.size)
        assertEquals("com.example", bundle.metadata?.packageName)
        assertTrue(bundle.metadata?.isTrusted == true)
    }

    @Test
    fun malformedXapkMetadataIsExplicitlyUntrusted() {
        val outer = createZip(
            "manifest.json" to "{\"package_name\":\"com.example\",}".toByteArray(),
            "base.apk" to apkBytes(),
        )

        val bundle = inspect(outer, tempDirectory()).bundle

        assertNotNull(bundle)
        assertTrue(bundle!!.limitations.contains(BundleLimitationCode.METADATA_UNTRUSTED))
        assertFalse(bundle.metadata?.isTrusted == true)
    }

    @Test
    fun identityAndSignerMismatchesAreTyped() {
        val base = entry("base.apk", BundleApkRole.BASE, "com.example", 7, "AA")
        val feature = entry("feature.apk", BundleApkRole.FEATURE, "com.other", 8, "BB")

        val limitations = bundleIdentityAndSignerLimitations(listOf(base, feature))

        assertTrue(limitations.contains(BundleLimitationCode.IDENTITY_MISMATCH))
        assertTrue(limitations.contains(BundleLimitationCode.SIGNER_MISMATCH))
        assertTrue(limitations.contains(BundleLimitationCode.IDENTITY_UNAVAILABLE))
    }

    private fun inspect(
        outer: File,
        cache: File,
        limits: InspectionLimits = InspectionLimits(),
    ): BundleInspectionOutcome = BundleInspector(
        cacheDirectory = cache,
        manifestInspector = null,
    ).inspect(outer, limits, control())

    private fun entry(
        path: String,
        role: BundleApkRole,
        packageName: String,
        versionCode: Long,
        signer: String,
    ): BundleApkEntry = BundleApkEntry(
        path = path,
        role = role,
        byteCount = 10,
        expandedBytes = 10,
        sha256 = signer,
        archive = ArchiveMetadata(
            format = ArchiveFormat.ZIP,
            entryCount = 1,
            declaredCompressedBytes = 1,
            declaredUncompressedBytes = 1,
            observedUncompressedBytes = 1,
            entriesWithUnknownCompressedSize = 0,
            entriesWithUnknownUncompressedSize = 0,
            maximumObservedCompressionRatio = 1.0,
            containsAndroidManifest = true,
            pathTraversalEntryCount = 0,
            isComplete = true,
        ),
        inventory = null,
        manifest = ManifestSummary(
            packageName = packageName,
            versionName = "1.0",
            versionCode = versionCode,
            sdk = AndroidSdkSummary(24, 35),
            permissions = emptyList(),
            permissionsTruncated = false,
            components = emptyList(),
            componentsTruncated = false,
            debugBuild = false,
        ),
        decodedManifest = null,
        signing = SigningSummary(
            status = SignatureVerificationStatus.VERIFIED,
            certificates = listOf(SigningCertificateSummary("s", "i", "1", signer)),
            verifiedSchemes = listOf("v2"),
            diagnostics = emptyList(),
        ),
    )

    private fun control(): InspectionControl = InspectionControl(
        cancellation = InspectionCancellation.None,
        progressListener = InspectionProgressListener { },
    )

    private fun apkBytes(): ByteArray {
        val file = createZip("AndroidManifest.xml" to byteArrayOf(1, 2, 3))
        return file.readBytes()
    }

    private fun createZip(vararg entries: Pair<String, ByteArray>): File {
        val file = File.createTempFile("apk-bundle-test-", ".zip")
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

    private fun tempDirectory(): File = File.createTempFile("apk-bundle-cache-", "").also {
        assertTrue(it.delete())
        assertTrue(it.mkdirs())
        it.deleteOnExit()
    }
}
