package app.apksentinel.mobile

import app.apksentinel.engine.url.UrlInspection
import app.apksentinel.engine.url.UrlInspectionLimitation
import app.apksentinel.engine.url.UrlSafetyAnalyzer
import app.apksentinel.engine.url.UrlVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FraudReportDraftTest {
    @Test
    fun privateUrlPartsAreNeverIncludedInDraftPreview() {
        val inspection = UrlSafetyAnalyzer(emptySet()).inspect(
            "https://user:secret@example.com/account?token=keep-private#fragment",
        )

        val draft = FraudReportDraftBuilder.build(inspection)

        assertNotNull(draft)
        val url = draft!!.fields.first { it.kind == FraudReportFieldKind.URL }
        assertTrue(url.redacted)
        assertFalse(url.preview.contains("secret"))
        assertFalse(url.preview.contains("token"))
        assertFalse(url.preview.contains("fragment"))
        assertEquals(OfficialFraudPortal.host, draft.recipientHost)
    }

    @Test
    fun cleanLinkDoesNotCreateFraudDraft() {
        val inspection = UrlSafetyAnalyzer(emptySet()).inspect("https://example.com")

        assertEquals(UrlVerdict.NO_KNOWN_WARNING, inspection.verdict)
        assertEquals(null, FraudReportDraftBuilder.build(inspection))
    }

    @Test
    fun handoffSeparatesCancelledOpenedAndUnavailable() {
        assertEquals(FraudPortalHandoffOutcome.CANCELLED, fraudHandoffOutcome(false) { true })
        assertEquals(FraudPortalHandoffOutcome.OPENED, fraudHandoffOutcome(true) { true })
        assertEquals(FraudPortalHandoffOutcome.UNAVAILABLE, fraudHandoffOutcome(true) { false })
    }
}
