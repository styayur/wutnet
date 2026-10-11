package io.github.styayur.wutnet

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import io.github.styayur.wutnet.protocol.NetworkTrust
import io.github.styayur.wutnet.protocol.Protocol
import io.github.styayur.wutnet.protocol.ProtocolFailure
import io.github.styayur.wutnet.protocol.State
import java.net.Inet4Address

/** Registrations are local to this installation; no SSID/Profile name is read. */
class PhysicalNetworkTrust(context: Context, private val manager: ConnectivityManager,
                           private val network: Network) : NetworkTrust {
    private val preferences = context.getSharedPreferences("trusted-networks-v1", Context.MODE_PRIVATE)
    private fun physical(): Pair<String, String>? {
        val caps = manager.getNetworkCapabilities(network) ?: return null
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
        val links = manager.getLinkProperties(network) ?: return null
        val address = links.linkAddresses.filter { it.address is Inet4Address }.singleOrNull() ?: return null
        val gateway = links.routes.filter { it.isDefaultRoute && it.gateway is Inet4Address }
            .mapNotNull { it.gateway?.hostAddress }.distinct().singleOrNull() ?: return null
        val host = address.address.hostAddress ?: return null
        val fingerprint = Protocol.physicalFingerprint(host, address.prefixLength, gateway) ?: return null
        return fingerprint to host
    }
    override fun fingerprint(): String? = physical()?.first
    override fun matchesUserIp(userIp: String?): Boolean {
        val current = physical() ?: return false
        return userIp.isNullOrBlank() || userIp == current.second
    }
    override fun contains(fingerprint: String): Boolean =
        preferences.getStringSet("networks", emptySet())!!.contains(fingerprint)
    override fun register(fingerprint: String) {
        if (fingerprint() != fingerprint) throw ProtocolFailure(State.NoNetwork)
        val entries = preferences.getStringSet("networks", emptySet())!!.toMutableSet()
        entries.add(fingerprint)
        if (!preferences.edit().putStringSet("networks", entries).commit())
            throw ProtocolFailure(State.NetworkTrustRequired)
    }
    companion object {
        fun clear(context: Context) {
            if (!context.getSharedPreferences("trusted-networks-v1", Context.MODE_PRIVATE).edit().clear().commit())
                throw IllegalStateException("Could not clear network registrations")
        }
    }
}
