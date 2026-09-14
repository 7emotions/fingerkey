package com.phonefprint.auth

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.os.Build
import android.provider.Settings
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler

/**
 * High-priority approval-request notifier, driven by the service engine's
 * background isolate (lib/service_bridge.dart) over MethodChannel
 * "com.phonefprint.auth/notify":
 *
 *   - showApproval({id, user, service, reason, command, sound}) -> "posted"
 *   - cancel({id}) -> null (dismisses the notification that showApproval posted)
 *
 * Pairs with [OverlayWindow]: when a pending request arrives while the UI
 * isolate is not attached (app backgrounded/killed), the service engine
 * posts this heads-up notification AND shows the overlay card. The `sound`
 * flag mirrors the persisted `soundEnabled` preference read by the Dart
 * side and picks between two high-importance channels — `approval` (default
 * sound) and `approval_silent` (muted) — because Android 8+ makes a
 * channel's sound immutable after first creation. The persistent
 * low-importance `approval_link` FGS channel is untouched.
 *
 * SINGLE OWNERSHIP: like [OverlayWindow], exactly one instance exists per
 * process, held by [EngineHolder] and attached to the headless engine of
 * [ApprovalForegroundService] — the service engine is its only owner.
 */
class ApprovalNotifier(context: Context? = null) :
    FlutterPlugin, MethodCallHandler {

    companion object {
        const val METHOD_CHANNEL = "com.phonefprint.auth/notify"

        /**
         * High-importance alert channels for incoming requests. Two channels
         * are needed because Android 8+ makes a channel's sound immutable
         * after first creation: `approval` carries the default notification
         * sound, `approval_silent` is silent. The per-post `sound` flag from
         * the Dart side picks the channel.
         */
        private const val CHANNEL_ID = "approval"
        private const val CHANNEL_ID_SILENT = "approval_silent"

        /** Base offset for per-request notification ids (the FGS uses 1001). */
        private const val NOTIFICATION_ID_BASE = 2000
    }

    private var applicationContext: Context? = context
    private var methodChannel: MethodChannel? = null

    // ---- FlutterPlugin --------------------------------------------------

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = binding.applicationContext
        methodChannel = MethodChannel(binding.binaryMessenger, METHOD_CHANNEL)
        methodChannel?.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel?.setMethodCallHandler(null)
        methodChannel = null
        applicationContext = null
    }

    // ---- MethodChannel.MethodCallHandler --------------------------------

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "showApproval" -> showApproval(call, result)
            "cancel" -> cancel(call, result)
            else -> result.notImplemented()
        }
    }

    private fun cancel(call: MethodCall, result: MethodChannel.Result) {
        val context = applicationContext
        if (context == null) {
            result.error("no_context", "Plugin not attached", null)
            return
        }
        val id = call.argument<String>("id") ?: ""
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        // Same id math as postApprovalNotification: a resolved/expired session
        // must cancel the exact notification its pending request posted.
        nm.cancel(NOTIFICATION_ID_BASE + (id.hashCode() and 0x7fffffff))
        result.success(null)
    }

    private fun showApproval(call: MethodCall, result: MethodChannel.Result) {
        val context = applicationContext
        if (context == null) {
            result.error("no_context", "Plugin not attached", null)
            return
        }
        val id = call.argument<String>("id") ?: ""
        val user = call.argument<String>("user") ?: ""
        val service = call.argument<String>("service") ?: ""
        val reason = call.argument<String>("reason") ?: ""
        val command = call.argument<String>("command") ?: ""
        val sound = call.argument<Boolean>("sound") ?: true
        postApprovalNotification(context, id, user, service, reason, command, sound)
        result.success("posted")
    }

    // ---- notification ----------------------------------------------------

    /**
     * Creates the two high-importance channels on Android 8+. Sound is
     * immutable after creation, so one channel carries the default sound and
     * the other is silent; the per-post `sound` flag picks between them. The
     * low-importance `approval_link` FGS channel is untouched.
     */
    private fun ensureChannels(nm: NotificationManager) {
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Approval requests",
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "Incoming sudo/pkexec approval requests"
                setSound(
                    Settings.System.DEFAULT_NOTIFICATION_URI,
                    Notification.AUDIO_ATTRIBUTES_DEFAULT,
                )
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID_SILENT,
                "Approval requests (silent)",
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "Incoming sudo/pkexec approval requests without sound"
                setSound(null, null)
            },
        )
    }

    private fun postApprovalNotification(
        context: Context,
        id: String,
        user: String,
        service: String,
        reason: String,
        command: String,
        sound: Boolean,
    ) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        // Android 8+ ignores channel sound changes after the channel exists,
        // so the sound decision is made by choosing between two pre-created
        // channels instead of mutating one.
        val channelId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ensureChannels(nm)
            if (sound) CHANNEL_ID else CHANNEL_ID_SILENT
        } else {
            CHANNEL_ID
        }

        val title = when {
            user.isNotBlank() && service.isNotBlank() ->
                "Approve sudo/pkexec for $user on $service?"
            user.isNotBlank() -> "Approve sudo/pkexec for $user?"
            else -> "Approve sudo/pkexec?"
        }
        val text = when {
            reason.isNotBlank() -> "Reason: $reason"
            command.isNotBlank() -> "Command: $command"
            else -> "Open FingerKey to review and approve"
        }

        val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
        val contentIntent = PendingIntent.getActivity(
            context,
            0,
            launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(context, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(context)
        }
        builder
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(contentIntent)
            .setCategory(Notification.CATEGORY_ALARM)
            .setAutoCancel(true)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            @Suppress("DEPRECATION")
            builder.setPriority(Notification.PRIORITY_HIGH)
            if (sound) {
                @Suppress("DEPRECATION")
                builder.setDefaults(Notification.DEFAULT_SOUND)
            }
        }
        // One notification per session id; a re-post replaces the old one.
        nm.notify(NOTIFICATION_ID_BASE + (id.hashCode() and 0x7fffffff), builder.build())
    }
}
