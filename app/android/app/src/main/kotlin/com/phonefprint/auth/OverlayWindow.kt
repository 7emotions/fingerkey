package com.phonefprint.auth

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import java.util.concurrent.CopyOnWriteArraySet

/**
 * Native approval overlay — the "华强北 AirPods 弹窗" of FingerKey. Shows an
 * approval card ABOVE every other app via `WindowManager.addView` with
 * `TYPE_APPLICATION_OVERLAY`, so a sudo/pkexec request is visible even when
 * this app is backgrounded.
 *
 * MethodChannel "com.phonefprint.auth/overlay":
 *   - show({id, user, service, reason, command, expiresAt}) -> "shown"
 *     (or "permission_required" when SYSTEM_ALERT_WINDOW access is missing;
 *     the user is routed to the Settings grant page once instead of crashing)
 *   - hide()
 *
 * EventChannel "com.phonefprint.auth/overlay_events":
 *   - {type: decision, id, decision: "approve"|"deny"} on a button press
 *   - {type: expired, id} when the countdown runs out
 *
 * SINGLE OWNERSHIP: exactly one instance exists per process, held by
 * [EngineHolder] and attached to the headless engine of
 * [ApprovalForegroundService] — the service engine is its only owner, like
 * [TcpTlsChannel].
 *
 * The APPROVE/DENY buttons deliberately do NOT start an Activity or call
 * BiometricPrompt here; they post a decision event to the Dart listener.
 * TODO(task 12): route the "approve" decision to the biometric flow (a
 * BiometricPrompt in the main Activity or a PendingIntent back to it).
 */
class OverlayWindow(context: Context? = null) :
    FlutterPlugin, MethodCallHandler, EventChannel.StreamHandler {

    companion object {
        const val METHOD_CHANNEL = "com.phonefprint.auth/overlay"
        const val EVENT_CHANNEL = "com.phonefprint.auth/overlay_events"

        /** Fallback expiry when the caller omits expiresAt (60s, like the daemon). */
        private const val DEFAULT_TTL_MS = 60_000L
    }

    private var applicationContext: Context? = context
    private var methodChannel: MethodChannel? = null
    private var eventChannel: EventChannel? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    /** Sink of this engine's own Dart subscription (at most one per channel). */
    @Volatile
    private var engineSink: EventChannel.EventSink? = null

    /** Sinks of any delegating engines (mirrors [TcpTlsChannel]). */
    private val delegateSinks = CopyOnWriteArraySet<EventChannel.EventSink>()

    // Overlay state. One request at a time; a new show() replaces the old one.
    private var rootView: View? = null
    private var countdownText: TextView? = null
    private var sessionId: String? = null
    private var expiresAtMs: Long = 0L

    /** True once the Settings grant page was opened; reset when granted. */
    private var permissionPrompted = false

    private val countdownTick = object : Runnable {
        override fun run() {
            val remaining = ((expiresAtMs - System.currentTimeMillis()) / 1000)
                .coerceAtLeast(0)
            countdownText?.text = if (remaining > 0) "Expires in ${remaining}s" else "Expired"
            if (remaining <= 0) {
                expire()
            } else {
                mainHandler.postDelayed(this, 500)
            }
        }
    }

    // ---- FlutterPlugin --------------------------------------------------

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = binding.applicationContext
        methodChannel = MethodChannel(binding.binaryMessenger, METHOD_CHANNEL)
        methodChannel?.setMethodCallHandler(this)
        eventChannel = EventChannel(binding.binaryMessenger, EVENT_CHANNEL)
        eventChannel?.setStreamHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        // The owning service engine is going down; drop the window with it.
        removeView()
        methodChannel?.setMethodCallHandler(null)
        methodChannel = null
        eventChannel?.setStreamHandler(null)
        eventChannel = null
        applicationContext = null
    }

    // ---- MethodChannel.MethodCallHandler --------------------------------

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "show" -> show(call, result)
            "hide" -> {
                removeView()
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    // ---- EventChannel.StreamHandler -------------------------------------

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        engineSink = events
    }

    override fun onCancel(arguments: Any?) {
        engineSink = null
    }

    /** Adds a sink mirroring this channel's events to another engine. */
    fun addEventSink(sink: EventChannel.EventSink) {
        delegateSinks.add(sink)
    }

    /** Removes a previously added mirroring sink. */
    fun removeEventSink(sink: EventChannel.EventSink) {
        delegateSinks.remove(sink)
    }

    // ---- show / hide -----------------------------------------------------

    private fun show(call: MethodCall, result: MethodChannel.Result) {
        val context = applicationContext
        if (context == null) {
            result.error("no_context", "Plugin not attached", null)
            return
        }
        mainHandler.post {
            if (!Settings.canDrawOverlays(context)) {
                // Special-access permission (SYSTEM_ALERT_WINDOW): there is no
                // runtime dialog. Route the user to the grant page once and
                // report back instead of crashing on addView.
                promptOverlayPermissionOnce(context)
                result.success("permission_required")
                return@post
            }
            permissionPrompted = false // granted again; a future revocation may re-prompt
            val id = call.argument<String>("id") ?: ""
            val user = call.argument<String>("user") ?: ""
            val service = call.argument<String>("service") ?: ""
            val reason = call.argument<String>("reason") ?: ""
            val command = call.argument<String>("command") ?: ""
            val expiresAt = call.argument<Number>("expiresAt")?.toLong()
                ?: (System.currentTimeMillis() + DEFAULT_TTL_MS)
            showOverlay(context, id, user, service, reason, command, expiresAt)
            result.success("shown")
        }
    }

    private fun showOverlay(
        context: Context,
        id: String,
        user: String,
        service: String,
        reason: String,
        command: String,
        expiresAt: Long,
    ) {
        // One request at a time: a newer request replaces the old window.
        removeView()
        val view = buildCard(context, id, user, service, reason, command)
        sessionId = id
        expiresAtMs = expiresAt
        rootView = view
        try {
            val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            windowManager.addView(view, windowParams())
        } catch (e: Exception) {
            // e.g. permission revoked between the check and addView.
            rootView = null
            sessionId = null
            postEvent(mapOf("type" to "expired", "id" to id))
            return
        }
        mainHandler.post(countdownTick)
    }

    private fun hideOverlay() {
        removeView()
    }

    private fun removeView() {
        mainHandler.removeCallbacks(countdownTick)
        val context = applicationContext ?: return
        val view = rootView ?: return
        rootView = null
        countdownText = null
        sessionId = null
        try {
            val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            windowManager.removeView(view)
        } catch (_: IllegalArgumentException) {
            // Not attached (e.g. already removed); nothing to do.
        }
    }

    private fun expire() {
        val id = sessionId ?: return
        removeView()
        postEvent(mapOf("type" to "expired", "id" to id))
    }

    private fun onDecision(id: String, decision: String) {
        // TODO(task 12): route "approve" to the biometric flow (BiometricPrompt
        // in the main Activity, or a PendingIntent back to it). Until then the
        // decision is posted to the Dart listener, which owns the routing.
        hideOverlay()
        postEvent(mapOf("type" to "decision", "id" to id, "decision" to decision))
    }

    private fun promptOverlayPermissionOnce(context: Context) {
        if (permissionPrompted) return
        permissionPrompted = true
        val intent = Intent(
            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
            Uri.parse("package:${context.packageName}"),
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            context.startActivity(intent)
        } catch (_: Exception) {
            // No activity can handle the grant page; show() already returned
            // "permission_required" so the caller can fall back.
        }
    }

    // ---- view building (programmatic, no layout XML) --------------------

    private fun windowParams(): WindowManager.LayoutParams {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }
        return WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            // Not focusable (don't steal keys/IME from the app below) and not
            // touch-modal (touches outside the card still reach the app below).
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.CENTER
        }
    }

    private fun buildCard(
        context: Context,
        id: String,
        user: String,
        service: String,
        reason: String,
        command: String,
    ): View {
        val dp = context.resources.displayMetrics.density
        fun dpf(value: Float): Int = (value * dp).toInt()

        val title = when {
            user.isNotBlank() && service.isNotBlank() ->
                "Approve sudo/pkexec for $user on $service?"
            user.isNotBlank() -> "Approve sudo/pkexec for $user?"
            else -> "Approve sudo/pkexec?"
        }

        val card = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                cornerRadius = 24f * dp
                setColor(Color.parseColor("#1E1E2E"))
            }
            setPadding(dpf(24f), dpf(20f), dpf(24f), dpf(20f))
        }

        card.addView(TextView(context).apply {
            text = title
            setTextColor(Color.WHITE)
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
        })

        if (reason.isNotBlank()) {
            card.addView(row(context, "REASON", reason))
        }
        if (command.isNotBlank()) {
            card.addView(row(context, "COMMAND", command))
        }

        countdownText = TextView(context).apply {
            setTextColor(Color.parseColor("#FAB387"))
            textSize = 14f
            text = "Expires in —s"
        }
        card.addView(countdownText)

        card.addView(
            LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, dpf(12f), 0, 0)
                addView(
                    decisionButton(context, "DENY", Color.parseColor("#D64545")),
                    LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                        marginEnd = dpf(8f)
                    },
                )
                addView(
                    decisionButton(context, "APPROVE", Color.parseColor("#3A9D5D")),
                    LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                        marginStart = dpf(8f)
                    },
                )
            },
        )
        return card
    }

    /** Two-line label/value row; the label is muted, the value is white. */
    private fun row(context: Context, label: String, value: String): View {
        val dp = context.resources.displayMetrics.density
        fun dpf(value: Float): Int = (value * dp).toInt()
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dpf(10f), 0, 0)
            addView(TextView(context).apply {
                text = label
                setTextColor(Color.parseColor("#A6ADC8"))
                textSize = 11f
                typeface = Typeface.DEFAULT_BOLD
            })
            addView(TextView(context).apply {
                text = value
                setTextColor(Color.parseColor("#CDD6F4"))
                textSize = 14f
            })
        }
    }

    private fun decisionButton(context: Context, label: String, color: Int): Button =
        Button(context).apply {
            text = label
            setTextColor(Color.WHITE)
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            background = GradientDrawable().apply {
                cornerRadius = 999f
                setColor(color)
            }
            setOnClickListener {
                val id = sessionId ?: return@setOnClickListener
                onDecision(id, label.lowercase())
            }
        }

    // ---- events ----------------------------------------------------------

    private fun postEvent(event: Map<String, Any?>) {
        val sinks = delegateSinks.toList() + listOfNotNull(engineSink)
        if (sinks.isEmpty()) return
        mainHandler.post {
            for (sink in sinks) {
                try {
                    sink.success(event)
                } catch (_: RuntimeException) {
                    // A sink from a destroyed engine may throw on use; drop it.
                }
            }
        }
    }
}
