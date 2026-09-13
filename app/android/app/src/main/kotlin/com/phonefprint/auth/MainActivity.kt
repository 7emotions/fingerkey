package com.phonefprint.auth

import android.content.Context
import android.os.Bundle
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.dart.DartExecutor
import io.flutter.plugins.GeneratedPluginRegistrant

/**
 * UI host for the approval flow. SINGLE OWNERSHIP: this engine owns no
 * daemon socket. The persistent links live in the headless engine of
 * [ApprovalForegroundService] (started in [onCreate]); this engine:
 *  - shares the process [io.flutter.embedding.engine.FlutterEngineGroup]
 *    (one VM) via [provideFlutterEngine],
 *  - delegates pairing-time channel traffic to the service's single
 *    [TcpTlsChannel] through [TcpTlsChannelDelegate],
 *  - renders the service's pending stream via the cross-engine Dart bridge
 *    (lib/service_bridge.dart), never dialing for approvals.
 */
class MainActivity : FlutterFragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keep the approval link alive whenever the app is in use.
        ApprovalForegroundService.start(this)
    }

    override fun provideFlutterEngine(context: Context): FlutterEngine? =
        // Spawn from the shared group so this engine and the service's
        // headless engine run in one VM (same isolate group).
        EngineHolder.engineGroup(context)
            .createAndRunEngine(context, DartExecutor.DartEntrypoint.createDefault())

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // provideFlutterEngine takes over the automatic plugin registration.
        GeneratedPluginRegistrant.registerWith(flutterEngine)
        // Delegate every TLS channel call to the service-owned instance.
        flutterEngine.plugins.add(
            TcpTlsChannelDelegate { EngineHolder.serviceChannel(applicationContext) },
        )
    }
}
