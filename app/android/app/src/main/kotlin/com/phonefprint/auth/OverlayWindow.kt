package com.phonefprint.auth

import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.ClipDrawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.LayerDrawable
import android.graphics.drawable.RippleDrawable
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import java.util.concurrent.CopyOnWriteArraySet
import kotlin.math.min

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
 *   - hideForId({id}) — removes the card only when it shows this session
 *
 * EventChannel "com.phonefprint.auth/overlay_events":
 *   - {type: decision, id, decision: "deny", source} on DENY (task 12: the
 *     service isolate signs the deny and posts it through the signed-decision
 *     path — no biometric, no Activity)
 *   - {type: expired, id} when the countdown runs out
 *
 * APPROVE never posts a decision event: it launches [MainActivity] with
 * FLAG_ACTIVITY_NEW_TASK carrying the pending session payload (see
 * [OverlayLaunchBridge]); the Activity's approval screen runs the biometric
 * prompt ONCE and posts the SIGNED decision through the UI bridge. This
 * window never calls BiometricPrompt — it has no Activity context.
 *
 * SINGLE OWNERSHIP: exactly one instance exists per process, held by
 * [EngineHolder] and attached to the headless engine of
 * [ApprovalForegroundService] — the service engine is its only owner, like
 * [TcpTlsChannel].
 */
class OverlayWindow(context: Context? = null) :
    FlutterPlugin, MethodCallHandler, EventChannel.StreamHandler {

    companion object {
        const val METHOD_CHANNEL = "com.phonefprint.auth/overlay"
        const val EVENT_CHANNEL = "com.phonefprint.auth/overlay_events"

        /** Fallback expiry when the caller omits expiresAt (60s, like the daemon). */
        private const val DEFAULT_TTL_MS = 60_000L

        // Warm fallback palette: the literal values buildColorScheme()
        // (app/lib/app_theme.dart, amber seed 0xFFFFB000, dark) resolves to.
        // The Dart side asserts these stay in sync (test/app_theme_test.dart);
        // at runtime the service isolate sends the live palette in the show()
        // payload and these are overridden, so the overlay follows the app
        // theme instead of drifting to a stale copy.
        private const val FALLBACK_CARD = "#241F17"
        private const val FALLBACK_BORDER = "#4F4539"
        private const val FALLBACK_TONAL = "#2F2921"
        private const val FALLBACK_TRACK = "#3A342B"
        private const val FALLBACK_ACCENT = "#F2BE6E"
        private const val FALLBACK_ACCENT_SOFT_ALPHA = 0x26
        private const val FALLBACK_ON_ACCENT = "#432C00"
        private const val FALLBACK_TEXT = "#EDE1D4"
        private const val FALLBACK_MUTED = "#D2C4B4"
        private const val FALLBACK_LABEL = "#9B8F80"
        private const val FALLBACK_DENY_STROKE = "#9B8F80"
    }

    private var applicationContext: Context? = context
    private var methodChannel: MethodChannel? = null
    private var eventChannel: EventChannel? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    // Overlay palette: warm fallbacks below, overridden from the "palette"
    // map of the show() payload at runtime (task 18), so the card always
    // matches the scheme the app is actually running.
    private var cardColor = Color.parseColor(FALLBACK_CARD)
    private var borderColor = Color.parseColor(FALLBACK_BORDER)
    private var tonalColor = Color.parseColor(FALLBACK_TONAL)
    private var trackColor = Color.parseColor(FALLBACK_TRACK)
    private var accentColor = Color.parseColor(FALLBACK_ACCENT)
    private var accentSoftColor = Color.parseColor(FALLBACK_ACCENT).let {
        Color.argb(FALLBACK_ACCENT_SOFT_ALPHA, Color.red(it), Color.green(it), Color.blue(it))
    }
    private var onAccentColor = Color.parseColor(FALLBACK_ON_ACCENT)
    private var textColor = Color.parseColor(FALLBACK_TEXT)
    private var mutedColor = Color.parseColor(FALLBACK_MUTED)
    private var labelColor = Color.parseColor(FALLBACK_LABEL)
    private var denyStrokeColor = Color.parseColor(FALLBACK_DENY_STROKE)

    /** Sink of this engine's own Dart subscription (at most one per channel). */
    @Volatile
    private var engineSink: EventChannel.EventSink? = null

    /** Sinks of any delegating engines (mirrors [TcpTlsChannel]). */
    private val delegateSinks = CopyOnWriteArraySet<EventChannel.EventSink>()

    // Overlay state. One request at a time; a new show() replaces the old one.
    private var rootView: View? = null
    private var countdownText: TextView? = null
    private var countdownBar: ProgressBar? = null
    private var countdownMaxSec: Int = 0
    private var sessionId: String? = null
    private var expiresAtMs: Long = 0L

    /** Full session payload of the shown request (the show() arguments), kept
     * so APPROVE can hand it to the main Activity (task 12). */
    private var pendingRequest: Map<*, *>? = null

    /** True once the Settings grant page was opened; reset when granted. */
    private var permissionPrompted = false

    private val countdownTick = object : Runnable {
        override fun run() {
            val remaining = ((expiresAtMs - System.currentTimeMillis()) / 1000)
                .coerceAtLeast(0)
            countdownText?.text = if (remaining > 0) "Expires in ${remaining}s" else "Expired"
            countdownBar?.progress = remaining.toInt().coerceIn(0, countdownMaxSec)
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
            "hideForId" -> hideForId(call, result)
            else -> result.notImplemented()
        }
    }

    /**
     * Removes the view ONLY when the currently shown card belongs to [id];
     * a no-op otherwise, so a stale session's dismissal cannot tear down the
     * card of a newer one.
     */
    private fun hideForId(call: MethodCall, result: MethodChannel.Result) {
        val id = call.argument<String>("id")
        if (id == null || sessionId != id) {
            result.success(null)
            return
        }
        removeView()
        result.success(null)
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
            applyPalette(call.argument<Map<*, *>>("palette"))
            val id = call.argument<String>("id") ?: ""
            val user = call.argument<String>("user") ?: ""
            val service = call.argument<String>("service") ?: ""
            val reason = call.argument<String>("reason") ?: ""
            val command = call.argument<String>("command") ?: ""
            val expiresAt = call.argument<Number>("expiresAt")?.toLong()
                ?: (System.currentTimeMillis() + DEFAULT_TTL_MS)
            val request = call.arguments as? Map<*, *>
            showOverlay(context, id, user, service, reason, command, expiresAt, request)
            result.success("shown")
        }
    }

    /**
     * Overrides the palette from the show() payload's "palette" map (hex
     * strings without `#`, plus a decimal "accentSoftAlpha"). Absent or
     * malformed entries keep the warm fallback for that slot, so a stale
     * client can never break the card.
     */
    private fun applyPalette(palette: Map<*, *>?) {
        if (palette == null) return
        fun hex(key: String): Int? {
            val value = palette[key] as? String ?: return null
            return runCatching { Color.parseColor("#$value") }.getOrNull()
        }
        hex("card")?.let { cardColor = it }
        hex("cardHigh")?.let { tonalColor = it }
        hex("border")?.let { borderColor = it }
        hex("track")?.let { trackColor = it }
        hex("onAccent")?.let { onAccentColor = it }
        hex("text")?.let { textColor = it }
        hex("muted")?.let { mutedColor = it }
        hex("label")?.let { labelColor = it }
        hex("denyStroke")?.let { denyStrokeColor = it }
        val accent = hex("accent")
        if (accent != null) accentColor = accent
        val softAlpha = palette["accentSoftAlpha"]?.let { raw ->
            when (raw) {
                is String -> raw.toIntOrNull()
                is Number -> raw.toInt()
                else -> null
            }
        }
        if (softAlpha != null && accent != null) {
            accentSoftColor = Color.argb(
                softAlpha.coerceIn(0, 255),
                Color.red(accent),
                Color.green(accent),
                Color.blue(accent),
            )
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
        request: Map<*, *>?,
    ) {
        // One request at a time: a newer request replaces the old window.
        removeView()
        countdownMaxSec = ((expiresAt - System.currentTimeMillis()) / 1000)
            .coerceAtLeast(1)
            .toInt()
        val sourceName = (request?.get("sourceName") as? String).orEmpty()
        val view = buildCard(context, id, user, service, reason, command, sourceName)
        sessionId = id
        expiresAtMs = expiresAt
        pendingRequest = request
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
        countdownBar = null
        sessionId = null
        pendingRequest = null
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
        val request = pendingRequest
        if (decision == "approve") {
            // Biometric MUST run in the main Activity (task 12): launch it
            // with the full session payload and hand over the request. The
            // overlay hides once the launch is accepted so the Activity's
            // own card (bridge snapshot replay) owns it and prompts ONCE.
            // No decision event is posted: the Activity posts the SIGNED
            // decision through the UI bridge.
            if (launchApprovalActivity(request)) hideOverlay()
            return
        }
        // DENY needs no biometric and no Activity: the service isolate signs
        // the deny decision and posts it through the single signed-decision
        // path, then the daemon answers with the usual decision-result.
        hideOverlay()
        postEvent(
            mapOf(
                "type" to "decision",
                "id" to id,
                "decision" to decision,
                "source" to request?.get("source"),
            ),
        )
    }

    /**
     * Launches the main Activity with FLAG_ACTIVITY_NEW_TASK carrying the
     * pending session payload (id/user/service/tty/reason/command/source,
     * task 12). Returns false when the launch was rejected (e.g. background
     * activity start restrictions), so the caller keeps the overlay visible.
     */
    private fun launchApprovalActivity(request: Map<*, *>?): Boolean {
        val context = applicationContext ?: return false
        fun str(key: String): String = (request?.get(key) as? String).orEmpty()
        fun num(key: String): Long = (request?.get(key) as? Number)?.toLong() ?: 0L
        val intent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(OverlayLaunchBridge.EXTRA_ID, str("id"))
            .putExtra(OverlayLaunchBridge.EXTRA_NONCE, str("nonce"))
            .putExtra(OverlayLaunchBridge.EXTRA_USER, str("user"))
            .putExtra(OverlayLaunchBridge.EXTRA_SERVICE, str("service"))
            .putExtra(OverlayLaunchBridge.EXTRA_TTY, str("tty"))
            .putExtra(OverlayLaunchBridge.EXTRA_REASON, str("reason"))
            .putExtra(OverlayLaunchBridge.EXTRA_COMMAND, str("command"))
            .putExtra(OverlayLaunchBridge.EXTRA_SOURCE, str("source"))
            .putExtra(OverlayLaunchBridge.EXTRA_SOURCE_NAME, str("sourceName"))
            .putExtra(OverlayLaunchBridge.EXTRA_EXPIRES_AT, num("expiresAt"))
        return try {
            context.startActivity(intent)
            true
        } catch (e: Exception) {
            false
        }
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
        sourceName: String,
    ): View {
        val dp = context.resources.displayMetrics.density
        fun dpf(value: Float): Int = (value * dp).toInt()

        val headline = if (user.isNotBlank()) {
            "Approve sudo/pkexec for $user"
        } else {
            "Approve sudo/pkexec"
        }

        val card = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                cornerRadius = 28f * dp
                setColor(cardColor)
                setStroke(dpf(1f), borderColor)
            }
            // The rounded background provides the outline, so this elevation
            // casts a real shadow over the app below.
            elevation = 16f * dp
            setPadding(dpf(22f), dpf(20f), dpf(22f), dpf(20f))
            // Card, not sheet: cap the width so it doesn't stretch
            // edge-to-edge on tablets, with a margin on phones.
            val screenWidth = context.resources.displayMetrics.widthPixels
            minimumWidth = min(screenWidth - dpf(48f), dpf(420f))
        }

        // Header: tonal fingerprint chip + title + originating computer.
        card.addView(
            LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(
                    FrameLayout(context).apply {
                        background = GradientDrawable().apply {
                            shape = GradientDrawable.OVAL
                            setColor(accentSoftColor)
                        }
                        addView(
                            ImageView(context).apply {
                                setImageResource(R.drawable.ic_fingerprint)
                                imageTintList = ColorStateList.valueOf(accentColor)
                            },
                            FrameLayout.LayoutParams(dpf(24f), dpf(24f), Gravity.CENTER),
                        )
                    },
                    LinearLayout.LayoutParams(dpf(42f), dpf(42f)),
                )
                addView(
                    LinearLayout(context).apply {
                        orientation = LinearLayout.VERTICAL
                        addView(TextView(context).apply {
                            text = "Approve this request"
                            setTextColor(textColor)
                            textSize = 16f
                            typeface = Typeface.DEFAULT_BOLD
                        })
                        addView(TextView(context).apply {
                            text = sourceName.ifBlank { "(unknown computer)" }
                            setTextColor(mutedColor)
                            textSize = 12f
                        })
                    },
                    LinearLayout.LayoutParams(
                        0,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        1f,
                    ).apply { marginStart = dpf(12f) },
                )
            },
        )

        // The ask itself, prominent; the service is de-emphasised below it.
        card.addView(
            TextView(context).apply {
                text = headline
                setTextColor(textColor)
                textSize = 15f
                typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dpf(16f) },
        )
        if (service.isNotBlank()) {
            card.addView(
                TextView(context).apply {
                    text = "on $service"
                    setTextColor(labelColor)
                    textSize = 13f
                },
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = dpf(2f) },
            )
        }

        if (reason.isNotBlank()) {
            card.addView(fieldBlock(context, "REASON", reason, monospace = false))
        }
        if (command.isNotBlank()) {
            card.addView(fieldBlock(context, "COMMAND", command, monospace = true))
        }

        // Countdown: a slim draining bar plus the seconds text. The tick
        // updates both; the text string is unchanged.
        val track = GradientDrawable().apply {
            cornerRadius = 999f
            setColor(trackColor)
        }
        val fill = GradientDrawable().apply {
            cornerRadius = 999f
            setColor(accentColor)
        }
        val barLayers = LayerDrawable(
            arrayOf(track, ClipDrawable(fill, Gravity.START, ClipDrawable.HORIZONTAL)),
        ).apply {
            setId(0, android.R.id.background)
            setId(1, android.R.id.progress)
        }
        countdownBar = ProgressBar(
            context,
            null,
            android.R.attr.progressBarStyleHorizontal,
        ).apply {
            isIndeterminate = false
            progressDrawable = barLayers
            max = countdownMaxSec
            progress = countdownMaxSec
        }
        countdownText = TextView(context).apply {
            setTextColor(accentColor)
            textSize = 12f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            text = "Expires in —s"
        }
        card.addView(
            LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(
                    countdownBar,
                    LinearLayout.LayoutParams(0, dpf(4f), 1f),
                )
                addView(
                    countdownText,
                    LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    ).apply { marginStart = dpf(10f) },
                )
            },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dpf(18f) },
        )

        card.addView(
            LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                addView(
                    decisionButton(context, "DENY", filled = false),
                    LinearLayout.LayoutParams(0, dpf(48f), 1f).apply {
                        marginEnd = dpf(6f)
                    },
                )
                addView(
                    decisionButton(context, "APPROVE", filled = true),
                    LinearLayout.LayoutParams(0, dpf(48f), 1f).apply {
                        marginStart = dpf(6f)
                    },
                )
            },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dpf(18f) },
        )
        return card
    }

    /** Tonal labeled block: small letterspaced label above a readable value. */
    private fun fieldBlock(
        context: Context,
        label: String,
        value: String,
        monospace: Boolean,
    ): View {
        val dp = context.resources.displayMetrics.density
        fun dpf(value: Float): Int = (value * dp).toInt()
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                cornerRadius = 14f * dp
                setColor(tonalColor)
            }
            setPadding(dpf(12f), dpf(10f), dpf(12f), dpf(10f))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dpf(10f) }
            addView(TextView(context).apply {
                text = label
                setTextColor(labelColor)
                textSize = 11f
                typeface = Typeface.DEFAULT_BOLD
                letterSpacing = 0.08f
            })
            addView(TextView(context).apply {
                text = value
                setTextColor(textColor)
                textSize = 14f
                if (monospace) typeface = Typeface.MONOSPACE
                setPadding(0, dpf(4f), 0, 0)
            })
        }
    }

    /** APPROVE is the filled amber primary; DENY is the outlined secondary. */
    private fun decisionButton(context: Context, label: String, filled: Boolean): Button {
        val dp = context.resources.displayMetrics.density
        fun dpf(value: Float): Int = (value * dp).toInt()
        val shape = GradientDrawable().apply {
            cornerRadius = 16f * dp
            if (filled) {
                setColor(accentColor)
            } else {
                setColor(Color.TRANSPARENT)
                setStroke(dpf(1f), denyStrokeColor)
            }
        }
        val mask = GradientDrawable().apply {
            cornerRadius = 16f * dp
            setColor(Color.WHITE)
        }
        val rippleColor = if (filled) {
            Color.argb(0x33, 0x00, 0x00, 0x00)
        } else {
            Color.argb(0x26, 0xFF, 0xFF, 0xFF)
        }
        return Button(context).apply {
            text = label
            isAllCaps = false
            setTextColor(if (filled) onAccentColor else textColor)
            textSize = 14f
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
            letterSpacing = 0.02f
            background = RippleDrawable(ColorStateList.valueOf(rippleColor), shape, mask)
            if (filled) {
                setCompoundDrawablesWithIntrinsicBounds(R.drawable.ic_fingerprint, 0, 0, 0)
                compoundDrawableTintList = ColorStateList.valueOf(onAccentColor)
                compoundDrawablePadding = dpf(8f)
            }
            setOnClickListener {
                val id = sessionId ?: return@setOnClickListener
                onDecision(id, label.lowercase())
            }
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
