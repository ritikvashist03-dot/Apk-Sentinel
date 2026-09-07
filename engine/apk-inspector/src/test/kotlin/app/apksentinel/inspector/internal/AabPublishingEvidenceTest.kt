package app.apksentinel.inspector.internal

import app.apksentinel.inspector.BundleFormat
import app.apksentinel.inspector.BundleLimitationCode
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

class AabPublishingEvidenceTest {
    @Test
    fun appBundleIsTypedAsPublishingEvidenceAndNeverAsInstallableApk() {
        val aab = createZip(
            "BundleConfig.pb" to byteArrayOf(1, 2, 3),
            "base/manifest/AndroidManifest.xml" to byteArrayOf(4, 5),
            "base/dex/classes.dex" to ByteArray(8),
            "base/resources.pb" to ByteArray(13),
            "feature_camera/manifest/AndroidManifest.xml" to byteArrayOf(6),
            "BUNDLE-METADATA/com.android.tools.build.libraries.dependencies.pb" to ByteArray(3),
        )

        val result = BundleInspector(tempDirectory(), manifestInspector = null)
            .inspect(aab, InspectionLimits(), control())
        val bundle = result.bundle

        assertNotNull(bundle)
        assertEquals(BundleFormat.AAB, bundle!!.format)
        assertTrue(bundle.nestedApks.isEmpty())
        assertNotNull(bundle.publishingEvidence)
        assertEquals(2, bundle.publishingEvidence!!.modules.size)
        assertTrue(bundle.publishingEvidence!!.bundleConfigPresent)
        assertTrue(bundle.limitations.contains(BundleLimitationCode.AAB_PUBLISHING_BUNDLE_ONLY))
        assertFalse(bundle.limitations.contains(BundleLimitationCode.MISSING_BASE))
    }

    @Test
    fun appBundleEvidenceStopsAtConfiguredEntryBound() {
        val aab = createZip(
            "BundleConfig.pb" to byteArrayOf(1),
            "base/manifest/AndroidManifest.xml" to byteArrayOf(2),
            "base/resources.pb" to byteArrayOf(3),
        )
        val result = BundleInspector(tempDirectory(), manifestInspector = null)
            .inspect(aab, InspectionLimits(maxAabEvidenceEntries = 1), control())

        val bundle = requireNotNull(result.bundle)
        assertTrue(bundle.limitations.contains(BundleLimitationCode.AAB_EVIDENCE_BOUNDED))
        assertFalse(bundle.publishingEvidence!!.isComplete)
    }

    private fun control() = InspectionControl(
        cancellation = InspectionCancellation.None,
        progressListener = InspectionProgressListener { },
    )

    private fun createZip(vararg entries: Pair<String, ByteArray>): File {
        val file = File.createTempFile("apk-sentinel-aab-", ".aab")
        ZipOutputStream(FileOutputStream(file)).use { zip ->
            entries.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        file.deleteOnExit()
        return file
    }

    private fun tempDirectory(): File = File.createTempFile("apk-sentinel-aab-cache-", "").also {
        check(it.delete())
        check(it.mkdirs())
        it.deleteOnExit()
    }
}
