package io.github.styayur.wutnet

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import io.github.styayur.wutnet.protocol.Protocol
import io.github.styayur.wutnet.protocol.ProtocolFailure
import io.github.styayur.wutnet.protocol.Response
import io.github.styayur.wutnet.protocol.State
import io.github.styayur.wutnet.protocol.Transport
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URI

data class WifiNetwork(val network: Network, val validated: Boolean, val captive: Boolean)

class NetworkAccess(private val manager: ConnectivityManager) {
    fun resolve(preferred: Network? = null, requirePreferred: Boolean = false,
                observed: List<Network> = emptyList()): WifiNetwork? {
        fun describe(network: Network): WifiNetwork? {
            val caps = manager.getNetworkCapabilities(network) ?: return null
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
            return WifiNetwork(network, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL))
        }
        if (requirePreferred) return preferred?.let(::describe)
        preferred?.let(::describe)?.let { return it }
        // Cellular default routes never replace a Wi-Fi candidate. Ambiguous Wi-Fi fails closed.
        // Foreground callbacks enumerate Wi-Fi even when the default is cellular.
        // Avoid deprecated allNetworks; initial status refreshes as callbacks arrive.
        val wifi = (observed + listOfNotNull(manager.activeNetwork)).distinct().mapNotNull(::describe)
        val captive = wifi.filter { it.captive }
        if (captive.size == 1) return captive.single()
        manager.activeNetwork?.let(::describe)?.let { return it }
        return wifi.singleOrNull()
    }
}

/** Per-operation cookie jar, per-request network binding, explicit proxy bypass, no global binding. */
class NetworkHttp(private val wifi: WifiNetwork, private val manager: ConnectivityManager) : Transport {
    private val cookies = CookieManager(null, CookiePolicy.ACCEPT_ORIGINAL_SERVER)
    override fun validated(): Boolean = manager.getNetworkCapabilities(wifi.network)
        ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true

    override fun request(uri: URI, headers: Map<String, String>, body: ByteArray?): Response {
        if (!Protocol.allowedRequest(uri)) throw ProtocolFailure(State.UntrustedPortal)
        if (Thread.currentThread().isInterrupted) throw InterruptedException()
        // Never retry on the default network if this Wi-Fi is lost.
        val caps = manager.getNetworkCapabilities(wifi.network)
        if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) throw ProtocolFailure(State.NoNetwork)
        val connection = wifi.network.openConnection(uri.toURL(), Proxy.NO_PROXY) as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 5000; connection.readTimeout = 5000
            connection.useCaches = false
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("User-Agent", "WUTNet/0.1 Android")
            for ((name, value) in headers) connection.setRequestProperty(name, value)
            // Discovery and Internet probes neither receive nor send the local portal cookies.
            val portal = uri.host == Protocol.HOST
            if (portal) for ((name, values) in cookies.get(uri, emptyMap())) {
                connection.setRequestProperty(name, values.joinToString("; "))
            }
            if (body != null) {
                require(portal && uri.path.endsWith("/account/login"))
                connection.requestMethod = "POST"; connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
                connection.setFixedLengthStreamingMode(body.size)
                if (Thread.currentThread().isInterrupted) throw InterruptedException()
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            if (portal) {
                val responseHeaders = connection.headerFields.entries.filter { it.key != null }
                    .associate { it.key!! to it.value }
                cookies.put(uri, responseHeaders)
            }
            if (status in 300..399) return Response(status, location = connection.getHeaderField("Location"))
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val result = stream?.use {
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                while (true) {
                    if (Thread.currentThread().isInterrupted) throw InterruptedException()
                    val count = it.read(buffer)
                    if (count == -1) break
                    if (output.size() + count > 1_048_576) throw ProtocolFailure(State.PortalUnavailable)
                    output.write(buffer, 0, count)
                }
                output.toString("UTF-8")
            } ?: ""
            return Response(status, result)
        } finally { connection.disconnect() }
    }
}
