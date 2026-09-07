package app.apksentinel.mobile

import android.content.Context

/**
 * App-owned choices for optional notifications. This is deliberately a preferences and policy
 * layer only: it neither requests notification permission nor schedules or posts notifications.
 */
internal data class NotificationPreferences(
    val importantAlerts: Boolean = false,
    val interruptionReminder: Boolean = false,
    val monthlyCheckupReminder: Boolean = false,
    val weeklySummary: Boolean = false,
    val hideLockScreenDetails: Boolean = true,
    val quietHoursStartMinute: Int = 22 * 60,
    val quietHoursEndMinute: Int = 8 * 60,
)

internal data class DurableMonitoringEvidence(
    val firstObservedMillis: Long,
    val lastObservedMillis: Long,
    val durablyPersisted: Boolean,
)

internal enum class OptionalNotification { IMPORTANT_ALERT, INTERRUPTION_REMINDER, MONTHLY_CHECKUP, WEEKLY_SUMMARY }
internal enum class NotificationDecision { ALLOW, DISABLED, NOT_ELIGIBLE, QUIET_HOURS, ENGAGEMENT_COOLDOWN, INCIDENT_ALREADY_REMINDERED, CLOCK_UNAVAILABLE }

internal data class NotificationPolicyInput(
    val kind: OptionalNotification,
    val preferences: NotificationPreferences,
    val nowMillis: Long,
    val localMinuteOfDay: Int?,
    val evidence: DurableMonitoringEvidence? = null,
    val lastNonUrgentEngagementMillis: Long? = null,
    val lastMonthlyCheckupMillis: Long? = null,
    val incidentId: String? = null,
    val lastInterruptedIncidentId: String? = null,
)

/** Pure conservative policy; callers must persist cooldown receipts only after an actual delivery. */
internal object NotificationPolicy {
    const val QUIET_START_MINUTE = 22 * 60
    const val QUIET_END_MINUTE = 8 * 60
    const val NONURGENT_COOLDOWN_MILLIS = 7L * 24 * 60 * 60 * 1000
    const val MONTHLY_COOLDOWN_MILLIS = 30L * 24 * 60 * 60 * 1000
    const val WEEKLY_SUMMARY_ELIGIBILITY_MILLIS = 7L * 24 * 60 * 60 * 1000
    const val BYPASS_DO_NOT_DISTURB = false

    fun weeklySummaryEligible(evidence: DurableMonitoringEvidence?, nowMillis: Long): Boolean =
        evidence != null && evidence.durablyPersisted && nowMillis > 0L &&
            evidence.firstObservedMillis > 0L && evidence.lastObservedMillis >= evidence.firstObservedMillis &&
            nowMillis >= evidence.lastObservedMillis &&
            evidence.lastObservedMillis - evidence.firstObservedMillis >= WEEKLY_SUMMARY_ELIGIBILITY_MILLIS

    fun decide(input: NotificationPolicyInput): NotificationDecision {
        val localMinuteOfDay = input.localMinuteOfDay ?: return NotificationDecision.CLOCK_UNAVAILABLE
        if (input.nowMillis <= 0L || localMinuteOfDay !in 0 until 24 * 60 ||
            input.lastNonUrgentEngagementMillis?.let { it <= 0L || it > input.nowMillis } == true ||
            input.lastMonthlyCheckupMillis?.let { it <= 0L || it > input.nowMillis } == true
        ) return NotificationDecision.CLOCK_UNAVAILABLE
        if (!enabled(input.kind, input.preferences)) return NotificationDecision.DISABLED
        if (input.kind == OptionalNotification.WEEKLY_SUMMARY && !weeklySummaryEligible(input.evidence, input.nowMillis)) return NotificationDecision.NOT_ELIGIBLE
        if (input.kind == OptionalNotification.INTERRUPTION_REMINDER &&
            (input.incidentId.isNullOrBlank() || input.incidentId == input.lastInterruptedIncidentId)
        ) return NotificationDecision.INCIDENT_ALREADY_REMINDERED
        if (isQuietHour(localMinuteOfDay, input.preferences)) return NotificationDecision.QUIET_HOURS
        if (within(input.nowMillis, input.lastNonUrgentEngagementMillis, NONURGENT_COOLDOWN_MILLIS)) return NotificationDecision.ENGAGEMENT_COOLDOWN
        if (input.kind == OptionalNotification.MONTHLY_CHECKUP &&
            within(input.nowMillis, input.lastMonthlyCheckupMillis, MONTHLY_COOLDOWN_MILLIS)
        ) return NotificationDecision.ENGAGEMENT_COOLDOWN
        return NotificationDecision.ALLOW
    }

    private fun enabled(kind: OptionalNotification, preferences: NotificationPreferences): Boolean = when (kind) {
        OptionalNotification.IMPORTANT_ALERT -> preferences.importantAlerts
        OptionalNotification.INTERRUPTION_REMINDER -> preferences.interruptionReminder
        OptionalNotification.MONTHLY_CHECKUP -> preferences.monthlyCheckupReminder
        OptionalNotification.WEEKLY_SUMMARY -> preferences.weeklySummary
    }

    private fun within(now: Long, last: Long?, cooldown: Long): Boolean = last != null && last > 0L && last <= now && now - last < cooldown
    private fun isQuietHour(minute: Int, preferences: NotificationPreferences): Boolean {
        val start = preferences.quietHoursStartMinute
        val end = preferences.quietHoursEndMinute
        return if (start <= end) minute in start until end else minute >= start || minute < end
    }
}

internal class NotificationPreferencesStore(private val context: Context) {
    fun read(): NotificationPreferences = runCatching {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).let { prefs ->
            NotificationPreferences(
                importantAlerts = prefs.getBoolean(IMPORTANT, false),
                interruptionReminder = prefs.getBoolean(INTERRUPTION, false),
                monthlyCheckupReminder = prefs.getBoolean(MONTHLY, false),
                weeklySummary = prefs.getBoolean(WEEKLY, false),
                hideLockScreenDetails = prefs.getBoolean(HIDE_DETAILS, true),
            )
        }
    }.getOrDefault(NotificationPreferences())

    fun save(preferences: NotificationPreferences): Boolean = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit()
        .putBoolean(IMPORTANT, preferences.importantAlerts)
        .putBoolean(INTERRUPTION, preferences.interruptionReminder)
        .putBoolean(MONTHLY, preferences.monthlyCheckupReminder)
        .putBoolean(WEEKLY, preferences.weeklySummary)
        .putBoolean(HIDE_DETAILS, preferences.hideLockScreenDetails)
        .commit()

    fun erase(): Boolean = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit().clear().commit()

    companion object {
        internal const val PREFERENCES = "notification_preferences"
        private const val IMPORTANT = "important_alerts"
        private const val INTERRUPTION = "interruption_reminder"
        private const val MONTHLY = "monthly_checkup"
        private const val WEEKLY = "weekly_summary"
        private const val HIDE_DETAILS = "hide_lock_details"
    }
}
