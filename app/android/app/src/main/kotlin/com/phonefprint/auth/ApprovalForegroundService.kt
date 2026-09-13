package com.phonefprint.auth

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * Placeholder foreground service for the background approval popup.
 *
 * The manifest declares this service with foregroundServiceType="specialUse".
 * The real implementation (overlay window, notification, approve/deny path)
 * lands in later tasks; this stub only exists so the manifest compiles.
 */
class ApprovalForegroundService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
}
