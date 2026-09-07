package app.apksentinel.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkSavedViewsTest {
    @Test fun parserAcceptsOnlyBoundedCategoricalTerms() {
        val parsed = NetworkFilterParser.parse("direction:out protocol:tcp app:known decision:blocked")
        assertTrue(parsed is NetworkFilterParseResult.Success)
        assertEquals("direction:out protocol:tcp app:known decision:blocked", (parsed as NetworkFilterParseResult.Success).canonicalExpression)
        assertEquals(NetworkFilterParseFailure.DUPLICATE_TERM, (NetworkFilterParser.parse("app:known app:unknown") as NetworkFilterParseResult.Failure).reason)
        assertEquals(NetworkFilterParseFailure.UNKNOWN_TERM, (NetworkFilterParser.parse("host:example.org") as NetworkFilterParseResult.Failure).reason)
        assertEquals(NetworkFilterParseFailure.TOO_LONG, (NetworkFilterParser.parse("a".repeat(121)) as NetworkFilterParseResult.Failure).reason)
    }
}
