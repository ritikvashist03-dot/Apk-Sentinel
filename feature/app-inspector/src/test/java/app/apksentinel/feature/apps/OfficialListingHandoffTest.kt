package app.apksentinel.feature.apps

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OfficialListingHandoffTest {

    @Test
    fun acceptsOrdinaryPackageNames() {
        assertTrue(OfficialListingHandoff.isHandoffEligible("com.example.app"))
        assertTrue(OfficialListingHandoff.isHandoffEligible("org.mozilla.firefox"))
        assertTrue(OfficialListingHandoff.isHandoffEligible("a.b_c.d9"))
    }

    @Test
    fun rejectsNamesThatWouldNotSurviveBecomingAUri() {
        // The value is interpolated into a URI, so anything that could change the query or
        // the scheme is refused outright rather than escaped.
        assertFalse(OfficialListingHandoff.isHandoffEligible("com.example.app&referrer=x"))
        assertFalse(OfficialListingHandoff.isHandoffEligible("com.example.app?id=other"))
        assertFalse(OfficialListingHandoff.isHandoffEligible("com.example app"))
        assertFalse(OfficialListingHandoff.isHandoffEligible("http://evil.example"))
        assertFalse(OfficialListingHandoff.isHandoffEligible("com.example.app#frag"))
        assertFalse(OfficialListingHandoff.isHandoffEligible("com..example"))
    }

    @Test
    fun rejectsShapesThatAreNotPackageNames() {
        assertFalse(OfficialListingHandoff.isHandoffEligible(""))
        assertFalse(OfficialListingHandoff.isHandoffEligible("   "))
        assertFalse(OfficialListingHandoff.isHandoffEligible("noseparator"))
        assertFalse(OfficialListingHandoff.isHandoffEligible("9com.example"))
        assertFalse(OfficialListingHandoff.isHandoffEligible("com.9example"))
        assertFalse(OfficialListingHandoff.isHandoffEligible("com.example." + "x".repeat(300)))
    }

    @Test
    fun anIneligibleNameProducesNoIntentAtAll() {
        assertTrue(OfficialListingHandoff.candidateIntents("com.example app").isEmpty())
    }
}
