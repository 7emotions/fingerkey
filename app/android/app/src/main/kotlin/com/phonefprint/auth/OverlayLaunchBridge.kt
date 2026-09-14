package com.phonefprint.auth

import android.content.Intent
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel

/**
 * UI-side listener for overlay-APPROVE taps (task 12). The native overlay only
 * exists while the app is backgrounded (see [OverlayWindow]); when the user
 * taps APPROVE there, [OverlayWindow] launches [MainActivity] with
 * FLAG_ACTIVITY_NEW_TASK and the pending session payload in the Intent extras.
 * This plugin turns that Intent into an event on EventChannel
 * "com.phonefprint.auth/launch_events" so the Dart approval screen can match
 * the card that the bridge snapshot replay delivers and run the biometric
 * approve flow ONCE — no decision is ever made from the service or overlay.
 *
 * The payload survives Activity/engine recreation in a process-wide companion
 * holder: [ingest] stores it from [MainActivity]'s onCreate/onNewIntent, and
 * [onListen] replays it to a fresh engine's first listener, so a cold start
 * never loses the tap. Approval requests are keyed by session id on the Dart
 * side, so a replayed payload is idempotent.
 *
 * Unlike [EngineHolder]'s singletons this plugin is NOT owned by the service
 * engine: it is registered on the Activity's engine (one fresh instance per
 * engine, mirroring [TcpTlsChannelDelegate]), while the payload itself is
 * process-static because Activity instances are recreated.
 */
class OverlayLaunchBridge : FlutterPlugin, EventChannel.StreamHandler {

    companion object {
        const val EVENT_CHANNEL = "com.phonefprint.auth/launch_events"

        // Intent extras, filled by OverlayWindow from the pending session.
        const val EXTRA_ID = "com.phonefprint.auth.extra.id"
        const val EXTRA_NONCE = "com.phonefprint.auth.extra.nonce"
        const val EXTRA_USER = "com.phonefprint.auth.extra.user"
        const val EXTRA_SERVICE = "com.phonefprint.auth.extra.service"
        const val EXTRA_TTY = "com.phonefprint.auth.extra.tty"
        const val EXTRA_REASON = "com.phonefprint.auth.extra.reason"
        const val EXTRA_COMMAND = "com.phonefprint.auth.extra.command"
        const val EXTRA_SOURCE = "com.phonefprint.auth.extra.source"
        const val EXTRA_SOURCE_NAME = "com.phonefprint.auth.extra.source_name"
        const val EXTRA_EXPIRES_AT = "com.phonefprint.auth.extra.expires_at"

        /** Process-wide pending approve payload, replayed to the next UI engine. */
        @Volatile
        private var pendingApprove: Map<String, Any?>? = null

        /** The live UI-engine listener, set while the approval screen subscribes. */
        @Volatile
        private var sink: EventChannel.EventSink? = null

        /**
         * Stores the approve payload carried by an Activity [intent] (called
         * from [MainActivity]'s onCreate/onNewIntent). When the UI engine is
         * already listening (singleTop warm path) the payload is emitted
         * directly and not stored; otherwise it waits for the next [onListen].
         */
        fun ingest(intent: Intent?) {
            val payload = payloadFrom(intent) ?: return
            val events = sink
            if (events != null) {
                events.success(payload)
            } else {
                synchronized(this) { pendingApprove = payload }
            }
        }

        /** Extracts the approve payload from a launch [intent], if any. */
        fun payloadFrom(intent: Intent?): Map<String, Any?>? {
            val extras = intent?.extras ?: return null
            val id = extras.getString(EXTRA_ID) ?: return null
            return mapOf(
                "id" to id,
                "nonce" to extras.getString(EXTRA_NONCE),
                "user" to extras.getString(EXTRA_USER),
                "service" to extras.getString(EXTRA_SERVICE),
                "tty" to extras.getString(EXTRA_TTY),
                "reason" to extras.getString(EXTRA_REASON),
                "command" to extras.getString(EXTRA_COMMAND),
                "source" to extras.getString(EXTRA_SOURCE),
                "sourceName" to extras.getString(EXTRA_SOURCE_NAME),
                "expiresAt" to extras.getLong(EXTRA_EXPIRES_AT),
            )
        }
    }

    private var eventChannel: EventChannel? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        eventChannel = EventChannel(binding.binaryMessenger, EVENT_CHANNEL)
        eventChannel?.setStreamHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        eventChannel?.setStreamHandler(null)
        eventChannel = null
        sink = null
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        sink = events
        // A cold start (fresh engine after the overlay launch) replays the
        // stored payload to the first listener, then forgets it.
        synchronized(this) {
            val payload = pendingApprove
            if (payload != null && events != null) events.success(payload)
            pendingApprove = null
        }
    }

    override fun onCancel(arguments: Any?) {
        sink = null
    }
}
