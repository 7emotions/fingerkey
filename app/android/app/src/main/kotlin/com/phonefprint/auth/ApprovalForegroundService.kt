package com.phonefprint.auth

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import com.it_nomads.fluttersecurestorage.FlutterSecureStoragePlugin
import io.flutter.FlutterInjector
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.dart.DartExecutor

/**
 * Foreground service that keeps the daemon approval link alive when the app
 * is backgrounded. It hosts a HEADLESS Flutter engine (spawned from the same
 * [io.flutter.embedding.engine.FlutterEngineGroup] as the Activity's engine,
 * so both share one VM) and runs the named Dart entrypoint `mainBackground`,
 * which starts the [ConnectionManager] equivalent and owns every TLS socket.
 *
 * SINGLE OWNERSHIP: the process-wide [TcpTlsChannel] in [EngineHolder] is
 * attached to THIS engine, so this engine's Dart isolate is the only socket
 * owner. The Activity engine delegates all channel traffic to that instance
 * (see [TcpTlsChannelDelegate]) and receives pending events over the
 * cross-engine Dart bridge (lib/service_bridge.dart) — it never dials.
 *
 * This service MUST NOT run BiometricPrompt (it has no Activity): decisions
 * are signed by the UI engine and posted back through the bridge.
 */
class ApprovalForegroundService : Service() {

    companion object {
        private const val TAG = "ApprovalForegroundSvc"
        private const val CHANNEL_ID = "approval_link"
        private const val NOTIFICATION_ID = 1001

        /** Starts the service from a foreground context (idempotent). */
        fun start(context: Context) {
            val intent = Intent(context, ApprovalForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        // startForeground must run within ~5s of startForegroundService.
        startInForeground()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureEngine()
        // Keepalive (START_STICKY + boot restart) lands in a later task.
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        // Destroying the engine detaches the channel, which closes every
        // socket and shuts the executors down — the intended teardown path.
        EngineHolder.serviceEngine?.destroy()
        EngineHolder.serviceEngine = null
        super.onDestroy()
    }

    private fun startInForeground() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Approval link",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Keeps the approval link to your computers alive"
                setShowBadge(false)
                enableVibration(false)
            }
            nm.createNotificationChannel(channel)
        }

        // Android 13+ hides the notification until POST_NOTIFICATIONS is
        // granted, but the service still runs; that permission is surfaced
        // to the user by the UI, not here.
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                buildNotification(),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, buildNotification())
        }
    }

    private fun buildNotification(): Notification {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("FingerKey link active")
            .setContentText("Listening for approval requests")
            .setContentIntent(contentIntent)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setPriority(Notification.PRIORITY_LOW)
            .setOngoing(true)
            .build()
    }

    private fun ensureEngine() {
        if (EngineHolder.serviceEngine != null) return
        synchronized(EngineHolder) {
            if (EngineHolder.serviceEngine != null) return
            val entrypoint = DartExecutor.DartEntrypoint(
                FlutterInjector.instance().flutterLoader().findAppBundlePath(),
                "mainBackground",
            )
            val engine = EngineHolder.engineGroup(this)
                .createAndRunEngine(applicationContext, entrypoint)
            // Register only what the background isolate uses. Deliberately NOT
            // GeneratedPluginRegistrant: local_auth/mobile_scanner are
            // Activity-bound and never run headless (no biometric here).
            engine.plugins.add(FlutterSecureStoragePlugin())
            engine.plugins.add(EngineHolder.serviceChannel(this))
            EngineHolder.serviceEngine = engine
        }
    }
}
