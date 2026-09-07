package app.apksentinel.mobile

import app.apksentinel.core.security.SafeTextNormalizer
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SafeDisplayNameTest {
    @Test
    fun hostileSafNamesAreBidiAndControlFreeAndBounded() {
        val normalized = SafeTextNormalizer.normalizeDisplayText(
            "invoice\u202Egpj.exe\u0000" + "x".repeat(500),
            "Selected document",
            96,
        )
        assertTrue(normalized.codePointCount(0, normalized.length) <= 96)
        assertFalse(normalized.any { it.isISOControl() })
        assertFalse(normalized.contains('\u202E'))
    }

    @Test
    fun blankSafNameUsesSafeFallback() {
        assertTrue(
            SafeTextNormalizer.normalizeDisplayText("\u202E\n", "Selected attribution data", 96)
                .contains("Selected attribution data"),
        )
    }
}
