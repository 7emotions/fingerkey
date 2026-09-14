package com.phonefprint.auth

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * Battery-optimization plumbing for the settings screen (task 13).
 *
 * `isIgnoringBatteryOptimizations` reflects whether the app already holds
 * the exemption; `requestIgnoreBatteryOptimizations` opens the SYSTEM
 * dialog (`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`). The dialog is only
 * ever fired from an explicit user tap in Settings — never automatically —
 * and the settings entry hides itself once the exemption is granted.
 */
class PowerChannel private constructor(private val appContext: Context) :
    MethodChannel.MethodCallHandler {

    companion object {
        const val CHANNEL = "com.phonefprint.auth/power"

        fun register(messenger: BinaryMessenger, context: Context) {
            MethodChannel(messenger, CHANNEL)
                .setMethodCallHandler(PowerChannel(context.applicationContext))
        }
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isIgnoringBatteryOptimizations" -> result.success(isIgnoring())
            "requestIgnoreBatteryOptimizations" -> {
                requestIgnore()
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun isIgnoring(): Boolean {
        val pm = appContext.getSystemService(Context.POWER_SERVICE) as PowerManager
        return pm.isIgnoringBatteryOptimizations(appContext.packageName)
    }

    private fun requestIgnore() {
        val intent = Intent(
            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
            Uri.parse("package:${appContext.packageName}"),
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        appContext.startActivity(intent)
    }
}
