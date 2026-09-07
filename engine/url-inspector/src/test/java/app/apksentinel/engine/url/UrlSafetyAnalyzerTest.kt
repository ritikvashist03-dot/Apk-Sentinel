package app.apksentinel.engine.url

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlSafetyAnalyzerTest {
    @Test fun cleanHostIsNormalizedWithoutOpening() {
        val result = UrlSafetyAnalyzer().inspect("Example.COM/path")
        assertEquals(UrlVerdict.NO_KNOWN_WARNING, result.verdict)
        assertEquals("example.com", result.asciiHost)
        assertEquals("https://example.com/path", result.normalizedUrl)
    }

    @Test fun localThreatMatchBlocks() {
        val result = UrlSafetyAnalyzer(setOf("bad.example")).inspect("https://bad.example/login")
        assertEquals(UrlVerdict.BLOCKED_LOCAL_MATCH, result.verdict)
    }

    @Test fun shortenerAndSensitiveQueryRequireReview() {
        val result = UrlSafetyAnalyzer().inspect("https://bit.ly/x?token=secret")
        assertEquals(UrlVerdict.REVIEW, result.verdict)
        assertTrue(result.findings.any { it.kind == UrlFindingKind.SHORTENER })
        assertTrue(result.findings.any { it.kind == UrlFindingKind.SENSITIVE_QUERY })
        assertEquals(
            setOf(UrlFindingMessage.SHORTENER, UrlFindingMessage.SENSITIVE_QUERY),
            result.findings.map { it.message }.toSet(),
        )
        assertEquals(
            setOf(UrlFindingConfidence.HIGH, UrlFindingConfidence.MEDIUM),
            result.findings.map { it.confidence }.toSet(),
        )
    }

    @Test fun bidiControlIsRemovedAndReported() {
        val result = UrlSafetyAnalyzer().inspect("https://exa\u202Emple.com")
        assertTrue(result.findings.any { it.kind == UrlFindingKind.BIDI_CONTROL })
    }

    @Test fun nonWebSchemeIsRejected() {
        val result = UrlSafetyAnalyzer().inspect("javascript://example.com")
        assertEquals(UrlVerdict.INVALID, result.verdict)
        assertEquals(UrlFindingMessage.HTTP_HTTPS_ONLY, result.findings.single().message)
    }
}
