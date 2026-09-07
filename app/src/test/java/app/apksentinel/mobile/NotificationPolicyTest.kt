package app.apksentinel.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationPolicyTest {
    private val week = NotificationPolicy.NONURGENT_COOLDOWN_MILLIS
    private fun input(kind: OptionalNotification, preferences: NotificationPreferences, now: Long = week + 1) =
        NotificationPolicyInput(kind, preferences, now, 12 * 60)

    @Test fun `optional defaults are off and details stay hidden`() {
        val defaults = NotificationPreferences()
        assertFalse(defaults.importantAlerts)
        assertFalse(defaults.interruptionReminder)
        assertFalse(defaults.monthlyCheckupReminder)
        assertFalse(defaults.weeklySummary)
        assertTrue(defaults.hideLockScreenDetails)
        assertFalse(NotificationPolicy.BYPASS_DO_NOT_DISTURB)
    }

    @Test fun `weekly summary needs seven days of durable evidence`() {
        val enabled = NotificationPreferences(weeklySummary = true)
        val now = week + 2
        assertFalse(NotificationPolicy.weeklySummaryEligible(DurableMonitoringEvidence(1, now, false), now))
        assertFalse(NotificationPolicy.weeklySummaryEligible(DurableMonitoringEvidence(1, week, true), week))
        assertTrue(NotificationPolicy.weeklySummaryEligible(DurableMonitoringEvidence(1, now, true), now))
        assertEquals(NotificationDecision.NOT_ELIGIBLE, NotificationPolicy.decide(input(OptionalNotification.WEEKLY_SUMMARY, enabled, now)))
    }

    @Test fun `quiet hours cooldown incident and unusable clock suppress delivery`() {
        val enabled = NotificationPreferences(importantAlerts = true, interruptionReminder = true)
        assertEquals(NotificationDecision.QUIET_HOURS, NotificationPolicy.decide(input(OptionalNotification.IMPORTANT_ALERT, enabled).copy(localMinuteOfDay = 23 * 60)))
        assertEquals(NotificationDecision.ENGAGEMENT_COOLDOWN, NotificationPolicy.decide(input(OptionalNotification.IMPORTANT_ALERT, enabled).copy(lastNonUrgentEngagementMillis = week)))
        assertEquals(NotificationDecision.INCIDENT_ALREADY_REMINDERED, NotificationPolicy.decide(input(OptionalNotification.INTERRUPTION_REMINDER, enabled).copy(incidentId = "i", lastInterruptedIncidentId = "i")))
        assertEquals(NotificationDecision.CLOCK_UNAVAILABLE, NotificationPolicy.decide(input(OptionalNotification.IMPORTANT_ALERT, enabled).copy(nowMillis = 0)))
        assertEquals(NotificationDecision.CLOCK_UNAVAILABLE, NotificationPolicy.decide(input(OptionalNotification.IMPORTANT_ALERT, enabled).copy(lastNonUrgentEngagementMillis = week + 2)))
    }
}
