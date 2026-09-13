package com.phonefprint.auth

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * Non-owning channel forwarder for the Activity's engine. It registers the
 * same TLS channel names on the Activity's binary messenger but owns nothing:
 * every method call is delegated to the process-wide [TcpTlsChannel] held by
 * [EngineHolder] (attached to the foreground service's headless engine), and
 * the event stream is a mirror sink of that single channel.
 *
 * Because this plugin never touches the owner's sockets or executors, the
 * Activity engine's teardown ([onDetachedFromEngine]) cannot kill the
 * service's connections — the single-ownership invariant.
 */
class TcpTlsChannelDelegate(
    private val ownerLookup: () -> TcpTlsChannel?,
) : FlutterPlugin, MethodChannel.MethodCallHandler, EventChannel.StreamHandler {

    private var methodChannel: MethodChannel? = null
    private var eventChannel: EventChannel? = null
    private var registeredSink: EventChannel.EventSink? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel = MethodChannel(binding.binaryMessenger, TcpTlsChannel.METHOD_CHANNEL)
        methodChannel?.setMethodCallHandler(this)
        eventChannel = EventChannel(binding.binaryMessenger, TcpTlsChannel.EVENT_CHANNEL)
        eventChannel?.setStreamHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        registeredSink?.let { ownerLookup()?.removeEventSink(it) }
        registeredSink = null
        methodChannel?.setMethodCallHandler(null)
        methodChannel = null
        eventChannel?.setStreamHandler(null)
        eventChannel = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        val owner = ownerLookup()
        if (owner == null) {
            result.error("service_not_ready", "Background link service is not running", null)
            return
        }
        owner.onMethodCall(call, result)
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        registeredSink = events
        if (events != null) ownerLookup()?.addEventSink(events)
    }

    override fun onCancel(arguments: Any?) {
        registeredSink?.let { ownerLookup()?.removeEventSink(it) }
        registeredSink = null
    }
}
