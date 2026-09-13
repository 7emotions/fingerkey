package com.phonefprint.auth

import android.content.Context
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel

/**
 * Native-readable "roster configured" marker that gates the boot receiver
 * (task 13).
 *
 * MECHANISM: the roster lives in FlutterSecureStorage (encrypted), which a
 * BroadcastReceiver cannot read. The Dart [com.phonefprint.auth.KeyStore]
 * therefore mirrors "is the roster non-empty" into this plain
 * SharedPreferences flag on every roster write (`_syncConfiguredFlag` in
 * lib/key_store.dart, fired from add/remove/reset). [BootReceiver] reads the
 * flag natively and only starts the service when the app has at least one
 * paired computer, so an empty/unconfigured install never spawns a
 * foreground service at boot.
 *
 * The channel is registered on BOTH engines because roster writes happen in
 * both: pairing and reset in the UI engine, forget and mDNS lastAddr refresh
 * in the service engine. A write dropped before the channel is attached
 * self-corrects on the next roster write; a stale-true flag is harmless
 * (the service's Dart `_bootstrap` retries instead of crashing).
 */
object KeepalivePrefs {
    private const val PREFS = "keepalive"
    private const val KEY_CONFIGURED = "roster_configured"

    const val CHANNEL = "com.phonefprint.auth/keepalive"

    /** True when the roster holds at least one paired computer. */
    fun isConfigured(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_CONFIGURED, false)

    private fun setConfigured(context: Context, configured: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_CONFIGURED, configured)
            .apply()
    }

    fun register(messenger: BinaryMessenger, context: Context) {
        MethodChannel(messenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "setRosterConfigured" -> {
                    setConfigured(context, call.argument<Boolean>("configured") ?: false)
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }
}
