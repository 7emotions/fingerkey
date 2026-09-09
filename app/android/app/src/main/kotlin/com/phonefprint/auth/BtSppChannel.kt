package com.phonefprint.auth

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Base64
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.PluginRegistry
import java.io.IOException
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Native Android Bluetooth Classic SPP client exposed to Flutter.
 *
 * MethodChannel "com.phonefprint.auth/bt":
 *   - checkEnabled       -> bool (BluetoothAdapter is enabled)
 *   - requestPermissions -> bool (runtime BT permissions granted)
 *   - startDiscovery     -> bool (started); streams {name, address} over the event channel
 *   - bond(address)      -> bool (createBond() accepted)
 *   - connect(address)   -> dials the SPP server; streams status/data events
 *   - send(base64)       -> bool (enqueued on the write queue)
 *   - disconnect         -> closes the socket
 *
 * EventChannel "com.phonefprint.auth/bt_events" streams maps:
 *   - {status: connected, address}
 *   - {status: data, data: base64}
 *   - {status: error, message}
 *   - {status: disconnected, address}
 *   - {name, address} during discovery
 */
class BtSppChannel : FlutterPlugin, MethodCallHandler, EventChannel.StreamHandler,
    ActivityAware, PluginRegistry.RequestPermissionsResultListener {

    companion object {
        const val METHOD_CHANNEL = "com.phonefprint.auth/bt"
        const val EVENT_CHANNEL = "com.phonefprint.auth/bt_events"

        /** Serial Port Profile UUID — must match the daemon's SPP server. */
        val SPP_UUID: UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")

        /** How long bond() waits for BOND_BONDED before giving up. */
        private const val BOND_TIMEOUT_MS = 30_000L

        private const val PERMISSION_REQUEST_CODE = 0x2FA
    }

    // Socket lifecycle runs on background executors, never on the main thread.
    private val socketExecutor = Executors.newSingleThreadExecutor()
    private val writeExecutor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private var methodChannel: MethodChannel? = null
    private var eventChannel: EventChannel? = null

    @Volatile
    private var eventSink: EventChannel.EventSink? = null

    @Volatile
    private var activity: Activity? = null

    // Pending runtime-permission result, resolved by onRequestPermissionsResult.
    private var pendingPermissionResult: MethodChannel.Result? = null

    private var discoveryReceiver: BroadcastReceiver? = null

    @Volatile
    private var socket: BluetoothSocket? = null
    private val connected = AtomicBoolean(false)
    private val writeQueue = LinkedBlockingQueue<ByteArray>()

    // ---- FlutterPlugin --------------------------------------------------

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel = MethodChannel(binding.binaryMessenger, METHOD_CHANNEL)
        methodChannel?.setMethodCallHandler(this)

        eventChannel = EventChannel(binding.binaryMessenger, EVENT_CHANNEL)
        eventChannel?.setStreamHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        tearDown()
        methodChannel?.setMethodCallHandler(null)
        methodChannel = null
        eventChannel?.setStreamHandler(null)
        eventChannel = null
    }

    // ---- ActivityAware --------------------------------------------------

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addRequestPermissionsResultListener(this)
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addRequestPermissionsResultListener(this)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ): Boolean {
        if (requestCode != PERMISSION_REQUEST_CODE) return false
        val result = pendingPermissionResult
        pendingPermissionResult = null
        val granted = grantResults.isNotEmpty() &&
            grantResults.all { it == PackageManager.PERMISSION_GRANTED }
        result?.success(granted)
        return true
    }

    // ---- MethodChannel.MethodCallHandler --------------------------------

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "checkEnabled" -> result.success(isAdapterEnabled())
            "requestPermissions" -> requestPermissions(result)
            "startDiscovery" -> startDiscovery(result)
            "bond" -> bond(call, result)
            "connect" -> connect(call, result)
            "send" -> send(call, result)
            "disconnect" -> {
                disconnect()
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    // ---- EventChannel.StreamHandler -------------------------------------

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
        unregisterDiscoveryReceiver()
    }

    // ---- Method implementations -----------------------------------------

    private fun isAdapterEnabled(): Boolean {
        val adapter = BluetoothAdapter.getDefaultAdapter() ?: return false
        return try {
            adapter.isEnabled
        } catch (e: SecurityException) {
            false
        }
    }

    private fun requestPermissions(result: MethodChannel.Result) {
        val host = activity ?: run {
            result.success(false)
            return
        }
        val needed = requiredPermissions()
        if (needed.isEmpty() || hasPermissions(host, needed)) {
            result.success(true)
            return
        }
        pendingPermissionResult = result
        host.requestPermissions(needed, PERMISSION_REQUEST_CODE)
    }

    private fun requiredPermissions(): Array<String> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_SCAN)
    } else {
        arrayOf(Manifest.permission.BLUETOOTH)
    }

    private fun hasPermissions(context: Context, permissions: Array<String>): Boolean =
        permissions.all {
            context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        }

    private fun startDiscovery(result: MethodChannel.Result) {
        val adapter = BluetoothAdapter.getDefaultAdapter()
        if (adapter == null) {
            result.error("no_adapter", "Bluetooth is not available on this device", null)
            return
        }
        val context = activity?.applicationContext ?: run {
            result.error("no_activity", "Activity is not attached", null)
            return
        }
        try {
            registerDiscoveryReceiver(context)
            if (adapter.isDiscovering) adapter.cancelDiscovery()
            result.success(adapter.startDiscovery())
        } catch (e: SecurityException) {
            result.error("permission_denied", e.message, null)
        }
    }

    private fun registerDiscoveryReceiver(context: Context) {
        if (discoveryReceiver != null) return
        val filter = IntentFilter(BluetoothDevice.ACTION_FOUND)
        discoveryReceiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                if (intent.action != BluetoothDevice.ACTION_FOUND) return
                val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                } ?: return
                val name = try {
                    device.name ?: ""
                } catch (e: SecurityException) {
                    ""
                }
                eventSink?.success(
                    mapOf("name" to name, "address" to (device.address ?: ""))
                )
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(discoveryReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(discoveryReceiver, filter)
        }
    }

    private fun unregisterDiscoveryReceiver() {
        val receiver = discoveryReceiver ?: return
        discoveryReceiver = null
        val context = activity?.applicationContext ?: return
        try {
            context.unregisterReceiver(receiver)
        } catch (e: IllegalArgumentException) {
            // Already unregistered.
        }
    }

    private fun bond(call: MethodCall, result: MethodChannel.Result) {
        val address = call.argument<String>("address")
        if (address.isNullOrBlank()) {
            result.error("bad_args", "address is required", null)
            return
        }
        val device = remoteDevice(address)
        if (device == null) {
            result.error("bad_address", "Invalid Bluetooth address: $address", null)
            return
        }
        val context = activity?.applicationContext ?: run {
            result.error("no_activity", "Activity is not attached", null)
            return
        }
        val started = try {
            device.createBond()
        } catch (e: SecurityException) {
            result.error("permission_denied", e.message, null)
            return
        }
        if (!started) {
            result.success(false)
            return
        }

        // createBond() only initiates pairing and returns immediately. Hold
        // the result until the bond reaches BOND_BONDED (an already-bonded
        // device broadcasts BOND_BONDED right away) or the timeout fires, so
        // the Dart side connects after the link is already encrypted.
        val settled = AtomicBoolean(false)
        var timeout: Runnable? = null
        var receiver: BroadcastReceiver? = null

        fun settle(success: Boolean) {
            if (!settled.compareAndSet(false, true)) return
            timeout?.let { mainHandler.removeCallbacks(it) }
            receiver?.let {
                try {
                    context.unregisterReceiver(it)
                } catch (e: IllegalArgumentException) {
                    // Already unregistered.
                }
            }
            mainHandler.post { result.success(success) }
        }

        receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                if (intent.action != BluetoothDevice.ACTION_BOND_STATE_CHANGED) return
                val changed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                } ?: return
                if (changed.address != device.address) return
                when (intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.BOND_NONE)) {
                    BluetoothDevice.BOND_BONDED -> settle(true)
                    BluetoothDevice.BOND_NONE -> settle(false)
                }
            }
        }
        val filter = IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(receiver, filter)
        }
        timeout = Runnable { settle(false) }
        mainHandler.postDelayed(timeout, BOND_TIMEOUT_MS)
    }

    private fun connect(call: MethodCall, result: MethodChannel.Result) {
        val address = call.argument<String>("address")
        if (address.isNullOrBlank()) {
            result.error("bad_args", "address is required", null)
            return
        }
        if (connected.get()) {
            result.error("already_connected", "A socket connection is already active", null)
            return
        }
        socketExecutor.execute {
            var btSocket: BluetoothSocket? = null
            try {
                val device = remoteDevice(address)
                    ?: throw IllegalArgumentException("Invalid Bluetooth address: $address")
                btSocket = device.createRfcommSocketToServiceRecord(SPP_UUID)
                socket = btSocket
                btSocket.connect()
                connected.set(true)
                postEvent(mapOf("status" to "connected", "address" to address))
                startWriter()
                mainHandler.post { result.success(true) }
                readLoop(btSocket, address)
            } catch (e: SecurityException) {
                mainHandler.post {
                    result.error("permission_denied", e.message, null)
                }
            } catch (e: Exception) {
                mainHandler.post {
                    result.error("connect_failed", e.message, null)
                }
            } finally {
                connected.set(false)
                try {
                    btSocket?.close()
                } catch (_: IOException) {
                }
                if (socket === btSocket) socket = null
                writeQueue.clear()
                postEvent(mapOf("status" to "disconnected", "address" to address))
            }
        }
    }

    private fun readLoop(btSocket: BluetoothSocket, address: String) {
        val buffer = ByteArray(4096)
        while (connected.get()) {
            val n = try {
                btSocket.inputStream.read(buffer)
            } catch (e: IOException) {
                break
            }
            if (n <= 0) break
            val data = buffer.copyOf(n)
            postEvent(
                mapOf(
                    "status" to "data",
                    "data" to Base64.encodeToString(data, Base64.NO_WRAP)
                )
            )
        }
    }

    /** Drains the write queue into the socket output stream. */
    private fun startWriter() {
        writeExecutor.execute {
            while (connected.get()) {
                val payload = try {
                    writeQueue.poll(500, TimeUnit.MILLISECONDS)
                } catch (e: InterruptedException) {
                    break
                } ?: continue
                try {
                    socket?.let { active ->
                        active.outputStream.write(payload)
                        active.outputStream.flush()
                    } ?: break
                } catch (e: IOException) {
                    postEvent(mapOf("status" to "error", "message" to (e.message ?: "write failed")))
                    disconnect()
                    break
                }
            }
        }
    }

    private fun send(call: MethodCall, result: MethodChannel.Result) {
        val encoded = call.argument<String>("data")
        if (encoded == null) {
            result.error("bad_args", "data is required", null)
            return
        }
        val payload = try {
            Base64.decode(encoded, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            result.error("bad_data", "data is not valid base64", null)
            return
        }
        if (!connected.get()) {
            result.error("not_connected", "No active socket connection", null)
            return
        }
        writeQueue.offer(payload)
        result.success(true)
    }

    private fun disconnect() {
        connected.set(false)
        val active = socket
        socket = null
        try {
            active?.close()
        } catch (_: IOException) {
        }
    }

    private fun tearDown() {
        disconnect()
        unregisterDiscoveryReceiver()
        socketExecutor.shutdownNow()
        writeExecutor.shutdownNow()
    }

    // ---- Helpers --------------------------------------------------------

    private fun remoteDevice(address: String): BluetoothDevice? {
        val adapter = BluetoothAdapter.getDefaultAdapter() ?: return null
        return try {
            adapter.getRemoteDevice(address)
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun postEvent(event: Map<String, Any?>) {
        val sink = eventSink ?: return
        mainHandler.post { sink.success(event) }
    }
}
