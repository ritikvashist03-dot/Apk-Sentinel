package app.apksentinel.mobile

/** One source of truth for onboarding's language radio state and action gate. */
internal data class OnboardingLanguageState(
    val selected: AppLanguage?,
) {
    val actionsEnabled: Boolean
        get() = selected != null

    fun isSelected(option: AppLanguage): Boolean = selected == option
}
