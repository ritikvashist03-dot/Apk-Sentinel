package app.apksentinel.mobile

import android.app.Activity
import android.app.LocaleManager
import android.content.Context
import android.content.ContextWrapper
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList
import java.util.Locale

/** The app language is a display preference, deliberately separate from erasable inspection data. */
internal enum class AppLanguage(val storageValue: String, val languageTag: String?) {
    SYSTEM_DEFAULT("system", null),
    ENGLISH("en", "en"),
    HINDI("hi", "hi");

    companion object {
        fun fromStorage(value: String?): AppLanguage = entries.firstOrNull { it.storageValue == value } ?: SYSTEM_DEFAULT
    }
}

/**
 * Applies a per-app resource configuration on API 26-32 and mirrors it to Android's per-app
 * language setting on API 33+. It never mutates the process-global configuration.
 */
internal object AppLocaleController {
    private const val PREFERENCES_NAME = "app_language"
    private const val SELECTION_KEY = "selection"

    fun explicitSelection(context: Context): AppLanguage? {
        val preferences = context.applicationContext
            .getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        if (!preferences.contains(SELECTION_KEY)) return null
        return AppLanguage.fromStorage(preferences.getString(SELECTION_KEY, null))
    }

    /** Returns only a persisted user choice; a fresh install has no selected radio option. */
    fun selected(context: Context): AppLanguage? = explicitSelection(context)

    fun hasExplicitSelection(context: Context): Boolean = context.applicationContext
        .getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        .contains(SELECTION_KEY)

    fun wrap(baseContext: Context): Context {
        val tag = selected(baseContext)?.languageTag ?: return baseContext
        val configuration = Configuration(baseContext.resources.configuration).apply {
            setLocales(LocaleList(Locale.forLanguageTag(tag)))
        }
        return baseContext.createConfigurationContext(configuration)
    }

    fun synchronizePlatformLocale(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            runCatching { synchronizeApi33Locale(context, selected(context)) }
        }
    }

    fun select(context: Context, selection: AppLanguage): Boolean {
        val activity = context.findActivity() ?: return false
        val previous = selected(activity)
        val saved = activity.applicationContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(SELECTION_KEY, selection.storageValue)
            .commit()
        if (!saved) return false
        synchronizePlatformLocale(activity)
        if (previous != selection) activity.recreate()
        return true
    }

    private tailrec fun Context.findActivity(): Activity? = when (this) {
        is Activity -> this
        is ContextWrapper -> baseContext.findActivity()
        else -> null
    }

    @androidx.annotation.RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun synchronizeApi33Locale(context: Context, selection: AppLanguage?) {
        val localeManager = context.getSystemService(LocaleManager::class.java)
        // A fresh install has no local preference. Leave a pre-existing
        // platform per-app locale untouched; an explicit SYSTEM_DEFAULT choice
        // still deliberately clears it.
        val requestedTags = platformLocaleLanguageTags(selection) ?: return
        val requestedLocales = LocaleList.forLanguageTags(requestedTags)
        if (localeManager.applicationLocales.toLanguageTags() != requestedLocales.toLanguageTags()) {
            localeManager.applicationLocales = requestedLocales
        }
    }
}

/** API-policy seam: null means do not write platform locales on a fresh install. */
internal fun platformLocaleLanguageTags(selection: AppLanguage?): String? = when {
    selection == null -> null
    selection == AppLanguage.SYSTEM_DEFAULT -> ""
    else -> selection.languageTag
}
