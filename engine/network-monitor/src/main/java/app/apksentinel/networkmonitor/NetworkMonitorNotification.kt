package app.apksentinel.networkmonitor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

internal class NetworkMonitorNotification(
    private val context: Context,
) {
    fun createChannel() {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.network_monitor_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = context.getString(R.string.network_monitor_channel_description)
                setShowBadge(false)
            },
        )
    }

    fun preparing(): Notification = build(
        content = context.getString(R.string.network_monitor_notification_preparing),
        ongoing = true,
    )

    fun active(): Notification = build(
        content = context.getString(R.string.network_monitor_notification_active),
        ongoing = true,
    )

    fun stopping(): Notification = build(
        content = context.getString(R.string.network_monitor_notification_stopping),
        ongoing = false,
    )

    private fun build(content: String, ongoing: Boolean): Notification {
        val builder = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_network_monitor_notification)
            .setContentTitle(context.getString(R.string.network_monitor_notification_title))
            .setContentText(content)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(ongoing)
            .setOnlyAlertOnce(true)
            .addAction(
                Notification.Action.Builder(
                    null,
                    context.getString(R.string.network_monitor_stop_action),
                    PendingIntent.getService(
                        context,
                        STOP_REQUEST_CODE,
                        Intent(context, NetworkMonitorService::class.java).setAction(NetworkMonitorService.ACTION_STOP),
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                    ),
                ).build(),
            )

        context.packageManager.getLaunchIntentForPackage(context.packageName)?.let { launchIntent ->
            builder.setContentIntent(
                PendingIntent.getActivity(
                    context,
                    CONTENT_REQUEST_CODE,
                    launchIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                ),
            )
        }
        return builder.build()
    }

    internal companion object {
        const val CHANNEL_ID = "apk_sentinel_network_monitor"
        const val NOTIFICATION_ID = 4_201
        private const val STOP_REQUEST_CODE = 4_202
        private const val CONTENT_REQUEST_CODE = 4_203
    }
}
