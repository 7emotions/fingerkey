package com.phonefprint.auth

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Placeholder boot receiver that restarts the approval service after a reboot.
 *
 * The real implementation lands in later tasks; this stub only exists so
 * the manifest compiles.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        // TODO(next tasks): start ApprovalForegroundService.
    }
}
