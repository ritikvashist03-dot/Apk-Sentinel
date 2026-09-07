package app.apksentinel.feature.apps

import android.content.Intent
import android.net.Uri

/**
 * Opens an installed app's official store listing so the user can compare it themselves.
 *
 * The "authentic-app verifier" outcome promises an official-link handoff, and there was no
 * store link anywhere in the app — only the separate fraud-report flow opened an external
 * URL. This closes that specific gap.
 *
 * It deliberately makes NO authenticity claim. Opening a listing does not prove the
 * installed package matches it; that is a judgement only the user can make by comparing
 * the publisher and name. The app never submits anything and never asserts a verdict.
 */
object OfficialListingHandoff {

    /**
     * Ordered candidates: the installed store app first, then the web listing. Callers try
     * them in order because a device may have no store app, and an unresolved intent must
     * degrade to something openable rather than throwing.
     */
    fun candidateIntents(packageName: String): List<Intent> {
        if (!isHandoffEligible(packageName)) return emptyList()
        return listOf(
            Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$packageName")),
            Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=$packageName")),
        )
    }

    /**
     * A package name is only handed off when it matches the Android package grammar.
     * The value reaches a URI, so anything with a scheme separator, query character or
     * whitespace is rejected rather than escaped — refusing an odd name costs the user one
     * button, while building a URI from it is a real injection surface.
     */
    fun isHandoffEligible(packageName: String): Boolean {
        val trimmed = packageName.trim()
        if (trimmed.length !in 3..255) return false
        if (!trimmed.contains('.')) return false
        return trimmed.split('.').all { segment ->
            segment.isNotEmpty() &&
                segment.first().isLetter() &&
                segment.all { it.isLetterOrDigit() || it == '_' }
        }
    }
}
