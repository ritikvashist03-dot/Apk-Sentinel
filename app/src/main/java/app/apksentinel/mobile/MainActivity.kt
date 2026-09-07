package app.apksentinel.mobile

import android.os.Bundle
import android.content.Context
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import app.apksentinel.design.ApkSentinelTheme
import app.apksentinel.design.ProvideSentinelAccessibilityPreferences

class MainActivity : ComponentActivity() {
    private var notificationRoute by mutableStateOf<NotificationRoute?>(null)
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLocaleController.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AppLocaleController.synchronizePlatformLocale(this)
        NetworkHistoryComposition.initialize(applicationContext)
        FirewallPolicyComposition.initialize(applicationContext)
        ThreatNetworkProtectionComposition.initialize(applicationContext)
        RootCaptureComposition.initialize(applicationContext)
        OfflineAttributionComposition.initialize(applicationContext)
        RemoteStreamComposition.initialize(applicationContext)
        TlsInspectionComposition.initialize(applicationContext)
        notificationRoute = intent.notificationRoute()
        enableEdgeToEdge()
        setContent {
            val accessibility = remember { getSharedPreferences("accessibility_preferences", MODE_PRIVATE) }
            var highContrast by remember { mutableStateOf(accessibility.getBoolean("high_contrast", false)) }
            var reduceMotion by remember { mutableStateOf(accessibility.getBoolean("reduce_motion", false)) }
            ProvideSentinelAccessibilityPreferences(highContrast = highContrast, reduceMotion = reduceMotion) {
                ApkSentinelTheme {
                    SentinelShell(
                        highContrast = highContrast,
                        reduceMotion = reduceMotion,
                        onHighContrastChanged = { enabled ->
                            highContrast = enabled
                            accessibility.edit().putBoolean("high_contrast", enabled).apply()
                        },
                        onReduceMotionChanged = { enabled ->
                            reduceMotion = enabled
                            accessibility.edit().putBoolean("reduce_motion", enabled).apply()
                        },
                        notificationRoute = notificationRoute,
                        onNotificationRouteHandled = { notificationRoute = null },
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        notificationRoute = intent.notificationRoute()
    }

    override fun onStop() {
        // Rooted diagnostic capture is foreground-only and must not survive a background transition.
        RootCaptureComposition.stopForBackground()
        TlsInspectionComposition.stopForBackground()
        // A future protected receiver stream is foreground-owned and must stop
        // before the activity can be backgrounded.
        RemoteStreamComposition.stopForAppBackground()
        super.onStop()
    }

    override fun onDestroy() {
        if (isFinishing && !isChangingConfigurations) RootCaptureComposition.shutdown()
        super.onDestroy()
    }

    companion object { const val EXTRA_NOTIFICATION_ROUTE = "optional_notification_route" }
}

private fun android.content.Intent.notificationRoute(): NotificationRoute? =
    getStringExtra(MainActivity.EXTRA_NOTIFICATION_ROUTE)?.let { runCatching { NotificationRoute.valueOf(it) }.getOrNull() }
