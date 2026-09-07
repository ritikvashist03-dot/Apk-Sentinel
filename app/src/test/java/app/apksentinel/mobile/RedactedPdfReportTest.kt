package app.apksentinel.mobile

import org.junit.Assert.assertTrue
import org.junit.Test

class RedactedPdfReportTest {
    @Test
    fun layoutWrapsAndCapsPages() {
        val report = RedactedPdfReport("Title", "Time", "Scope", "Redaction", List(300) { "A long human-readable finding that must be safely wrapped and bounded." }, "Limitations", emptyList())
        val pages = RedactedPdfLayout.pages(report)
        assertTrue(pages.size <= RedactedPdfLayout.MAX_PAGES)
        assertTrue(pages.all { it.size <= RedactedPdfLayout.MAX_LINES_PER_PAGE })
    }

    @Test
    fun retentionDeletesExpiredOrClockInvalidFiles() {
        assertTrue(RedactedPdfRetention.shouldDelete(1L, RedactedPdfCache.MAX_AGE_MILLIS + 1L))
        assertTrue(RedactedPdfRetention.shouldDelete(10L, 9L))
    }
}
