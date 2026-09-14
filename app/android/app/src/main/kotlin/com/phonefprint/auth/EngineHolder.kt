package com.phonefprint.auth

import android.content.Context
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.FlutterEngineGroup

/**
 * Process-wide holders shared between the Activity's engine and the headless
 * engine of [ApprovalForegroundService]. Both engines run in the same process
 * and share one [FlutterEngineGroup], so they share one VM.
 *
 * SINGLE OWNERSHIP: exactly one [TcpTlsChannel] instance exists per process
 * and it owns every daemon socket. It is attached to the service's headless
 * engine; the Activity engine reaches it only through
 * [TcpTlsChannelDelegate]. Keeping the instance here (rather than inside the
 * service) lets the delegate dial even before the headless engine is up.
 */
object EngineHolder {
    @Volatile
    private var group: FlutterEngineGroup? = null

    @Volatile
    private var channel: TcpTlsChannel? = null

    @Volatile
    private var overlay: OverlayWindow? = null

    @Volatile
    private var notifier: ApprovalNotifier? = null

    @Volatile
    var serviceEngine: FlutterEngine? = null

    fun engineGroup(context: Context): FlutterEngineGroup =
        group ?: synchronized(this) {
            group ?: FlutterEngineGroup(context.applicationContext).also { group = it }
        }

    fun serviceChannel(context: Context): TcpTlsChannel =
        channel ?: synchronized(this) {
            channel ?: TcpTlsChannel(context.applicationContext).also { channel = it }
        }

    fun overlayChannel(context: Context): OverlayWindow =
        overlay ?: synchronized(this) {
            overlay ?: OverlayWindow(context.applicationContext).also { overlay = it }
        }

    fun notifier(context: Context): ApprovalNotifier =
        notifier ?: synchronized(this) {
            notifier ?: ApprovalNotifier(context.applicationContext).also { notifier = it }
        }
}
