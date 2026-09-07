package app.apksentinel.mobile

import app.apksentinel.core.reporting.ReportSensitivity
import app.apksentinel.inspector.ComponentType
import app.apksentinel.inspector.IntentFilterDataEvidence
import app.apksentinel.inspector.IntentFilterEvidence
import app.apksentinel.inspector.IntentFilterPathEvidence
import app.apksentinel.inspector.IntentFilterPathKind
import app.apksentinel.inspector.ManifestComponent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkIntentFilterReportFieldsTest {
    private val rawAction = "android.intent.action.VIEW\\u202E"
    private val rawHost = "private.example"
    private val component = ManifestComponent(
        type = ComponentType.ACTIVITY,
        className = "example.Entry",
        exported = true,
        enabled = true,
        requiredPermission = null,
        intentFilters = listOf(
            IntentFilterEvidence(
                actions = listOf(rawAction),
                categories = listOf("android.intent.category.DEFAULT"),
                data = listOf(
                    IntentFilterDataEvidence(
                        scheme = "https",
                        host = rawHost,
                        paths = IntentFilterPathKind.entries.map { kind -> IntentFilterPathEvidence(kind, "/${kind.name.lowercase()}") },
                        pathsTruncated = true,
                        valuesTruncated = true,
                    ),
                ),
                actionsTruncated = true,
                categoriesTruncated = true,
                dataTruncated = true,
            ),
        ),
        intentFiltersTruncated = true,
    )

    @Test
    fun fullTechnicalReportKeepsStableCodesAndRawValues() {
        val fields = component.intentFilterReportFields(3, { it }, redacted = false)

        assertTrue(fields.any { it.key == "component_3_intent_filter_0_code" && it.value == "DECLARED_INTENT_FILTER" })
        assertTrue(fields.any { it.key == "component_3_intent_filter_0_data_0_code" && it.value == "DECLARED_INTENT_FILTER_DATA" })
        assertEquals(
            IntentFilterPathKind.entries.map { it.name }.toSet(),
            fields.filter { it.key.contains("_kind_code") }.map { it.value }.toSet(),
        )
        assertTrue(fields.any { it.value == rawAction && it.sensitivity == ReportSensitivity.TECHNICAL })
        assertTrue(fields.any { it.value == rawHost && it.sensitivity == ReportSensitivity.TECHNICAL })
    }

    @Test
    fun redactedReportOmitsEveryRawIntentValueAndRetainsOnlyCountsAndTruncation() {
        val fields = component.intentFilterReportFields(3, { it }, redacted = true)

        assertFalse(fields.any { it.value == rawAction || it.value == rawHost || it.key.contains("_kind_code") || it.key.endsWith("_code") })
        assertTrue(fields.isNotEmpty())
        assertTrue(fields.all { it.key.endsWith("_count") || it.key.endsWith("_truncated") })
        assertTrue(fields.all { it.sensitivity == ReportSensitivity.PUBLIC_SUMMARY })
    }
}
