package com.phonefprint.auth

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Boot receiver: brings the approval link back after a reboot.
 *
 * ROSTER GUARD (task 13): the service only restarts when the roster is
 * non-empty. The roster lives in FlutterSecureStorage, which native code
 * cannot read from a receiver, so the Dart KeyStore mirrors its emptiness
 * into a plain SharedPreferences flag ([KeepalivePrefs]) on every roster
 * write; this receiver reads that flag. An empty/unconfigured install
 * therefore never spawns the foreground service at boot.
 *
 * Android 12+ note: BOOT_COMPLETED does not grant the background
 * foreground-service-start exemption, so `startForegroundService` throws
 * `ForegroundServiceStartNotAllowedException` there. It is caught and logged
 * — the service comes back the moment the user next opens the app
 * (MainActivity.onCreate), and on Android <12 it restarts right here.
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!KeepalivePrefs.isConfigured(context)) {
            Log.i(TAG, "Roster empty; not starting the approval service")
            return
        }
        try {
            ApprovalForegroundService.start(context)
        } catch (e: Exception) {
            // Never crash a boot receiver; see the Android 12+ note above.
            Log.w(TAG, "Boot start blocked: ${e.message}")
        }
    }
}
