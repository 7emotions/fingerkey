package com.phonefprint.auth

import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine

class MainActivity : FlutterFragmentActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // Registers the native Bluetooth SPP MethodChannel and EventChannel.
        flutterEngine.plugins.add(BtSppChannel())
    }
}
