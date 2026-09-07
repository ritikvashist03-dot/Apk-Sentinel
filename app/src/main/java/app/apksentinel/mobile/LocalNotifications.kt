package app.apksentinel.mobile

import android.Manifest
import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import java.util.Calendar

/** Local-only delivery. Receipts contain kinds, times and a bounded incident token; never findings. */
internal enum class NotificationRoute { HOME, DEVICE, NETWORK }
internal data class NotificationReceipt(val kind: OptionalNotification, val deliveredAtMillis: Long, val incidentToken: String? = null)

internal class NotificationReceiptStore(private val context: Context) {
    fun last(kind: OptionalNotification): NotificationReceipt? = runCatching {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val time = p.getLong("${kind.name}_time", 0L)
        if (time <= 0L) null else NotificationReceipt(kind, time, p.getString("${kind.name}_incident", null))
    }.getOrNull()
    fun record(receipt: NotificationReceipt): Boolean = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
        .putLong("${receipt.kind.name}_time", receipt.deliveredAtMillis)
        .putString("${receipt.kind.name}_incident", receipt.incidentToken?.take(64))
        .commit()
    fun erase(): Boolean = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()
    companion object { const val PREFS = "notification_delivery_receipts" }
}

/** Alarm scheduling is deliberately inexact; the app neither asks for nor uses exact-alarm access. */
internal object LocalNotificationScheduler {
    private const val ACTION_DELIVER = "app.apksentinel.mobile.DELIVER_OPTIONAL_NOTIFICATION"
    private const val EXTRA_KIND = "kind"
    private const val EXTRA_INCIDENT = "incident"
    private const val MONTHLY_REQUEST = 7201
    private const val WEEKLY_REQUEST = 7202

    fun reconcile(context: Context) {
        val prefs = NotificationPreferencesStore(context).read()
        if (prefs.monthlyCheckupReminder) scheduleMonthly(context) else cancel(context, OptionalNotification.MONTHLY_CHECKUP)
        val evidence = DurableMonitoringEvidenceStore(context).read()
        if (prefs.weeklySummary && NotificationPolicy.weeklySummaryEligible(evidence, System.currentTimeMillis())) scheduleWeekly(context) else cancel(context, OptionalNotification.WEEKLY_SUMMARY)
    }

    fun scheduleMonthly(context: Context) = schedule(context, OptionalNotification.MONTHLY_CHECKUP, System.currentTimeMillis() + NotificationPolicy.MONTHLY_COOLDOWN_MILLIS)
    fun scheduleWeekly(context: Context) = schedule(context, OptionalNotification.WEEKLY_SUMMARY, System.currentTimeMillis() + NotificationPolicy.NONURGENT_COOLDOWN_MILLIS)
    fun cancelAll(context: Context) { OptionalNotification.entries.forEach { cancel(context, it) } }
    fun cancel(context: Context, kind: OptionalNotification) { alarm(context)?.cancel(pendingIntent(context, kind, null)) }
    fun scheduleInterruption(context: Context, incidentId: String) = schedule(context, OptionalNotification.INTERRUPTION_REMINDER, System.currentTimeMillis() + 15 * 60_000L, incidentId)

    private fun schedule(context: Context, kind: OptionalNotification, trigger: Long, incident: String? = null) {
        val manager = alarm(context) ?: return
        // setAndAllowWhileIdle is inexact: delivery may be deferred by Android and never bypasses DND.
        manager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger, pendingIntent(context, kind, incident))
    }
    private fun alarm(context: Context) = context.getSystemService(AlarmManager::class.java)
    private fun pendingIntent(context: Context, kind: OptionalNotification, incident: String?): PendingIntent = PendingIntent.getBroadcast(
        context, if (kind == OptionalNotification.MONTHLY_CHECKUP) MONTHLY_REQUEST else if (kind == OptionalNotification.WEEKLY_SUMMARY) WEEKLY_REQUEST else 7300,
        Intent(context, OptionalNotificationReceiver::class.java).setAction(ACTION_DELIVER).putExtra(EXTRA_KIND, kind.name).putExtra(EXTRA_INCIDENT, incident?.take(64)),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )
    internal fun kind(intent: Intent): OptionalNotification? = intent.getStringExtra(EXTRA_KIND)?.let { runCatching { OptionalNotification.valueOf(it) }.getOrNull() }
    internal fun incident(intent: Intent): String? = intent.getStringExtra(EXTRA_INCIDENT)?.takeIf { it.length <= 64 }
}

internal class DurableMonitoringEvidenceStore(private val context: Context) {
    fun read(): DurableMonitoringEvidence? = runCatching {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        DurableMonitoringEvidence(p.getLong("first", 0L), p.getLong("last", 0L), p.getBoolean("durable", false)).takeIf { it.firstObservedMillis > 0L }
    }.getOrNull()
    fun erase(): Boolean = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()
    companion object { const val PREFS = "durable_monitoring_evidence" }
}

internal class OptionalNotificationReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val kind = LocalNotificationScheduler.kind(intent) ?: return
        LocalNotificationDelivery(context.applicationContext).deliver(kind, LocalNotificationScheduler.incident(intent))
    }
}

internal class OptionalNotificationRescheduleReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) { LocalNotificationScheduler.reconcile(context.applicationContext) }
}

internal class LocalNotificationDelivery(private val context: Context) {
    fun deliver(kind: OptionalNotification, incidentId: String? = null): NotificationDecision {
        val now = System.currentTimeMillis()
        val receipts = NotificationReceiptStore(context)
        val evidence = DurableMonitoringEvidenceStore(context).read()
        val lastNonUrgent = OptionalNotification.entries
            .mapNotNull { receipts.last(it)?.deliveredAtMillis }
            .maxOrNull()
        val decision = NotificationPolicy.decide(NotificationPolicyInput(kind, NotificationPreferencesStore(context).read(), now, localMinute(), evidence,
            lastNonUrgentEngagementMillis = lastNonUrgent,
            lastMonthlyCheckupMillis = receipts.last(OptionalNotification.MONTHLY_CHECKUP)?.deliveredAtMillis,
            incidentId = incidentId, lastInterruptedIncidentId = receipts.last(OptionalNotification.INTERRUPTION_REMINDER)?.incidentToken))
        if (decision != NotificationDecision.ALLOW) return decision
        // A denied system permission never triggers another prompt; keep only opted-in periodic work
        // alive so delivery can resume if the person later enables it in Android Settings.
        if (!notificationsAllowed()) {
            if (kind == OptionalNotification.MONTHLY_CHECKUP) LocalNotificationScheduler.scheduleMonthly(context)
            if (kind == OptionalNotification.WEEKLY_SUMMARY) LocalNotificationScheduler.scheduleWeekly(context)
            return NotificationDecision.NOT_ELIGIBLE
        }
        createChannels()
        val notification = Notification.Builder(context, channel(kind))
            .setSmallIcon(R.drawable.ic_nav_home).setContentTitle(title(kind)).setContentText(text(kind))
            .setVisibility(if (NotificationPreferencesStore(context).read().hideLockScreenDetails) Notification.VISIBILITY_PRIVATE else Notification.VISIBILITY_PUBLIC)
            .setContentIntent(openApp(kind)).setAutoCancel(true).build()
        runCatching { context.getSystemService(NotificationManager::class.java).notify(kind.ordinal + 8100, notification) }.getOrElse { return NotificationDecision.NOT_ELIGIBLE }
        if (!receipts.record(NotificationReceipt(kind, now, incidentId?.take(64)))) {
            context.getSystemService(NotificationManager::class.java).cancel(kind.ordinal + 8100)
            return NotificationDecision.NOT_ELIGIBLE
        }
        if (kind == OptionalNotification.MONTHLY_CHECKUP) LocalNotificationScheduler.scheduleMonthly(context)
        if (kind == OptionalNotification.WEEKLY_SUMMARY) LocalNotificationScheduler.scheduleWeekly(context)
        return NotificationDecision.ALLOW
    }
    fun erase(): Boolean {
        LocalNotificationScheduler.cancelAll(context)
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.cancelAll()
        if (Build.VERSION.SDK_INT >= 26) {
            manager.deleteNotificationChannel(CHANNEL_IMPORTANT)
            manager.deleteNotificationChannel(CHANNEL_REMINDERS)
            manager.deleteNotificationChannel(CHANNEL_SUMMARY)
        }
        val receiptsErased = NotificationReceiptStore(context).erase()
        val evidenceErased = DurableMonitoringEvidenceStore(context).erase()
        return receiptsErased && evidenceErased
    }
    private fun notificationsAllowed() = Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    private fun createChannels() { val m = context.getSystemService(NotificationManager::class.java); m.createNotificationChannel(NotificationChannel(CHANNEL_IMPORTANT, context.getString(R.string.notification_channel_important), NotificationManager.IMPORTANCE_DEFAULT).apply { lockscreenVisibility = Notification.VISIBILITY_PRIVATE }); m.createNotificationChannel(NotificationChannel(CHANNEL_REMINDERS, context.getString(R.string.notification_channel_reminders), NotificationManager.IMPORTANCE_LOW).apply { lockscreenVisibility = Notification.VISIBILITY_PRIVATE }); m.createNotificationChannel(NotificationChannel(CHANNEL_SUMMARY, context.getString(R.string.notification_channel_summary), NotificationManager.IMPORTANCE_LOW).apply { lockscreenVisibility = Notification.VISIBILITY_PRIVATE }) }
    private fun channel(k: OptionalNotification) = when (k) { OptionalNotification.IMPORTANT_ALERT -> CHANNEL_IMPORTANT; OptionalNotification.INTERRUPTION_REMINDER, OptionalNotification.MONTHLY_CHECKUP -> CHANNEL_REMINDERS; OptionalNotification.WEEKLY_SUMMARY -> CHANNEL_SUMMARY }
    private fun title(k: OptionalNotification) = context.getString(when (k) { OptionalNotification.IMPORTANT_ALERT -> R.string.notification_delivery_important_title; OptionalNotification.INTERRUPTION_REMINDER -> R.string.notification_delivery_interruption_title; OptionalNotification.MONTHLY_CHECKUP -> R.string.notification_delivery_monthly_title; OptionalNotification.WEEKLY_SUMMARY -> R.string.notification_delivery_weekly_title })
    private fun text(k: OptionalNotification) = context.getString(when (k) { OptionalNotification.IMPORTANT_ALERT -> R.string.notification_delivery_important_body; OptionalNotification.INTERRUPTION_REMINDER -> R.string.notification_delivery_interruption_body; OptionalNotification.MONTHLY_CHECKUP -> R.string.notification_delivery_monthly_body; OptionalNotification.WEEKLY_SUMMARY -> R.string.notification_delivery_weekly_body })
    private fun localMinute(): Int = Calendar.getInstance().let { it.get(Calendar.HOUR_OF_DAY) * 60 + it.get(Calendar.MINUTE) }
    private fun openApp(kind: OptionalNotification): PendingIntent = PendingIntent.getActivity(context, kind.ordinal + 7400, Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_NOTIFICATION_ROUTE, when (kind) { OptionalNotification.MONTHLY_CHECKUP -> NotificationRoute.DEVICE.name; OptionalNotification.INTERRUPTION_REMINDER, OptionalNotification.WEEKLY_SUMMARY -> NotificationRoute.NETWORK.name; else -> NotificationRoute.HOME.name }).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    companion object { const val CHANNEL_IMPORTANT = "optional_important"; const val CHANNEL_REMINDERS = "optional_reminders"; const val CHANNEL_SUMMARY = "optional_weekly" }
}
