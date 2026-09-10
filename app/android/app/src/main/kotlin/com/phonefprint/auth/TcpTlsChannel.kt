package com.phonefprint.auth

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import android.util.Base64
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import java.io.IOException
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Native Android LAN TCP+TLS client exposed to Flutter. Replaces the old
 * Classic SPP transport: the daemon now listens TLS on :4443 and publishes
 * `_phonefprint._tcp` over mDNS; the phone pins the LEAF certificate's
 * SHA-256 (lowercase hex) instead of bonding.
 *
 * MethodChannel "com.phonefprint.auth/tcp":
 *   - connect({host, port, fp}) -> int connectionId (throws fingerprint_mismatch)
 *   - send({id, data(base64)}) -> bool
 *   - disconnect({id})
 *   - browse() -> [{name, host, port, fp}] via NsdManager
 *
 * EventChannel "com.phonefprint.auth/tcp_events" streams maps, all carrying
 * the connection id:
 *   - {id, status: connected}
 *   - {id, status: data, data: base64}
 *   - {id, status: error, message}
 *   - {id, status: disconnected}
 *
 * Every connection gets its own id so the app can keep one live socket per
 * roster computer ("connect all").
 */
class TcpTlsChannel : FlutterPlugin, MethodCallHandler, EventChannel.StreamHandler {

    companion object {
        const val METHOD_CHANNEL = "com.phonefprint.auth/tcp"
        const val EVENT_CHANNEL = "com.phonefprint.auth/tcp_events"
        const val SERVICE_TYPE = "_phonefprint._tcp"

        /** How long a TCP connect() may block before failing. */
        private const val CONNECT_TIMEOUT_MS = 5_000

        /** How long [browse] collects resolved services before returning. */
        private const val BROWSE_TIMEOUT_MS = 4_000L

        private const val HANDSHAKE_SO_TIMEOUT_MS = 10_000
        private val nextId = AtomicInteger(0)
    }

    private var applicationContext: Context? = null
    private var methodChannel: MethodChannel? = null
    private var eventChannel: EventChannel? = null

    @Volatile
    private var eventSink: EventChannel.EventSink? = null

    private val connections = ConcurrentHashMap<Int, Connection>()
    private val readExecutor = Executors.newCachedThreadPool()
    private val writeExecutor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private class Connection(val id: Int) {
        @Volatile
        var socket: SSLSocket? = null
        val connected = AtomicBoolean(false)
        val writeQueue = LinkedBlockingQueue<ByteArray>()
    }

    // ---- FlutterPlugin --------------------------------------------------

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = binding.applicationContext
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
        applicationContext = null
    }

    // ---- MethodChannel.MethodCallHandler --------------------------------

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "connect" -> connect(call, result)
            "send" -> send(call, result)
            "disconnect" -> {
                disconnect(call)
                result.success(null)
            }
            "browse" -> browse(result)
            else -> result.notImplemented()
        }
    }

    // ---- EventChannel.StreamHandler -------------------------------------

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    // ---- connect ---------------------------------------------------------

    private fun connect(call: MethodCall, result: MethodChannel.Result) {
        val host = call.argument<String>("host")
        val port = call.argument<Int>("port")
        val fp = call.argument<String>("fp")
        if (host.isNullOrBlank() || port == null || fp.isNullOrBlank()) {
            result.error("bad_args", "host, port and fp are required", null)
            return
        }
        val id = nextId.incrementAndGet()
        val conn = Connection(id)
        connections[id] = conn
        readExecutor.execute {
            try {
                val socket = openTlsSocket(host, port, fp)
                conn.socket = socket
                conn.connected.set(true)
                postEvent(mapOf("id" to id, "status" to "connected"))
                startWriter(conn, socket)
                mainHandler.post { result.success(id) }
                readLoop(conn, socket)
            } catch (e: Exception) {
                val code =
                    if (isFingerprintMismatch(e)) "fingerprint_mismatch"
                    else "connect_failed"
                mainHandler.post { result.error(code, e.message, null) }
            } finally {
                conn.connected.set(false)
                connections.remove(id)
                try {
                    conn.socket?.close()
                } catch (_: IOException) {
                }
                conn.writeQueue.clear()
                postEvent(mapOf("id" to id, "status" to "disconnected"))
            }
        }
    }

    private fun openTlsSocket(host: String, port: Int, fp: String): SSLSocket {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(PinningTrustManager(fp)), SecureRandom())
        val socket = sslContext.socketFactory.createSocket() as SSLSocket
        // Disable endpoint hostname verification: the leaf-certificate pin is
        // the identity check (the cert is self-signed, so a hostname check
        // could never pass anyway).
        val params = socket.sslParameters
        params.endpointIdentificationAlgorithm = ""
        socket.sslParameters = params
        socket.soTimeout = HANDSHAKE_SO_TIMEOUT_MS
        socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        socket.startHandshake()
        socket.soTimeout = 0 // blocking reads for the frame loop
        return socket
    }

    private fun readLoop(conn: Connection, socket: SSLSocket) {
        val buffer = ByteArray(16384)
        while (conn.connected.get()) {
            val n = try {
                socket.inputStream.read(buffer)
            } catch (e: IOException) {
                break
            }
            if (n <= 0) break
            postEvent(
                mapOf(
                    "id" to conn.id,
                    "status" to "data",
                    "data" to Base64.encodeToString(buffer.copyOf(n), Base64.NO_WRAP)
                )
            )
        }
        conn.connected.set(false)
        try {
            socket.close()
        } catch (_: IOException) {
        }
    }

    private fun startWriter(conn: Connection, socket: SSLSocket) {
        writeExecutor.execute {
            while (conn.connected.get()) {
                val payload = try {
                    conn.writeQueue.poll(500, TimeUnit.MILLISECONDS)
                } catch (e: InterruptedException) {
                    break
                } ?: continue
                try {
                    socket.outputStream.write(payload)
                    socket.outputStream.flush()
                } catch (e: IOException) {
                    postEvent(
                        mapOf(
                            "id" to conn.id,
                            "status" to "error",
                            "message" to (e.message ?: "write failed")
                        )
                    )
                    conn.connected.set(false)
                    try {
                        socket.close()
                    } catch (_: IOException) {
                    }
                    break
                }
            }
        }
    }

    private fun send(call: MethodCall, result: MethodChannel.Result) {
        val id = call.argument<Int>("id")
        val encoded = call.argument<String>("data")
        if (id == null || encoded == null) {
            result.error("bad_args", "id and data are required", null)
            return
        }
        val payload = try {
            Base64.decode(encoded, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            result.error("bad_data", "data is not valid base64", null)
            return
        }
        val conn = connections[id]
        if (conn == null || !conn.connected.get()) {
            result.error("not_connected", "No active connection $id", null)
            return
        }
        conn.writeQueue.offer(payload)
        result.success(true)
    }

    private fun disconnect(call: MethodCall) {
        val id = call.argument<Int>("id") ?: return
        val conn = connections[id] ?: return
        conn.connected.set(false)
        try {
            conn.socket?.close()
        } catch (_: IOException) {
        }
    }

    // ---- browse (mDNS / NSD) --------------------------------------------

    private fun browse(result: MethodChannel.Result) {
        val context = applicationContext ?: run {
            result.error("no_context", "Plugin not attached", null)
            return
        }
        val nsd = context.getSystemService(Context.NSD_SERVICE) as NsdManager
        val resolved = ConcurrentHashMap<String, Map<String, Any?>>()
        val finished = AtomicBoolean(false)

        fun finish(value: Any?) {
            if (finished.compareAndSet(false, true)) {
                mainHandler.post { result.success(value) }
            }
        }

        val resolveListener = object : NsdManager.ResolveListener {
            override fun onServiceResolved(info: NsdServiceInfo) {
                val fp = info.attributes?.get("fp")?.toString(Charsets.UTF_8) ?: ""
                resolved[info.serviceName] = mapOf(
                    "name" to (info.serviceName ?: ""),
                    "host" to (info.host?.hostAddress ?: ""),
                    "port" to info.port,
                    "fp" to fp
                )
            }

            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                // Skip; only resolved services with a pinned fingerprint count.
            }
        }

        val discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                nsd.resolveService(serviceInfo, resolveListener)
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                resolved.remove(serviceInfo.serviceName)
            }

            override fun onDiscoveryStarted(serviceType: String) {}

            override fun onDiscoveryStopped(serviceType: String) {}

            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                nsd.stopServiceDiscovery(this)
                finish(emptyList<Map<String, Any?>>())
            }

            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
        }

        nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)

        mainHandler.postDelayed({
            try {
                nsd.stopServiceDiscovery(discoveryListener)
            } catch (_: IllegalArgumentException) {
                // Already stopped.
            }
            finish(resolved.values.toList())
        }, BROWSE_TIMEOUT_MS)
    }

    // ---- teardown / helpers ---------------------------------------------

    private fun tearDown() {
        for (conn in connections.values) {
            conn.connected.set(false)
            try {
                conn.socket?.close()
            } catch (_: IOException) {
            }
        }
        connections.clear()
        readExecutor.shutdownNow()
        writeExecutor.shutdownNow()
    }

    private fun postEvent(event: Map<String, Any?>) {
        val sink = eventSink ?: return
        mainHandler.post { sink.success(event) }
    }

    private fun isFingerprintMismatch(t: Throwable): Boolean {
        var cur: Throwable? = t
        while (cur != null) {
            if (cur.message?.contains("fingerprint_mismatch") == true) return true
            cur = cur.cause
        }
        return false
    }

    /**
     * Trust manager that pins the LEAF certificate's SHA-256 (lowercase hex)
     * to the expected fingerprint. Hostname verification is disabled at the
     * socket level, so this pin is the sole server-identity check.
     */
    private class PinningTrustManager(private val expectedFp: String) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            throw CertificateException("client certificates are not accepted")
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            if (chain.isEmpty()) throw CertificateException("empty certificate chain")
            val actual = sha256Hex(chain[0].encoded)
            if (actual != expectedFp.lowercase()) {
                throw CertificateException("fingerprint_mismatch: $actual != ${expectedFp.lowercase()}")
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
}

private fun sha256Hex(bytes: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
