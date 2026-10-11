package io.github.styayur.wutnet.protocol

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder

enum class State {
    Online, CaptivePortal, WhutOffline, Authenticating, Authenticated, NoNetwork,
    UntrustedPortal, AuthFailed, CsrfFailed, PortalUnavailable, TransportError,
    CredentialRequired, NetworkTrustRequired
}

class ProtocolFailure(val state: State) : Exception(state.name)

object Protocol {
    const val HOST = "172.30.21.100"
    const val PORTAL_PATH = "/tpl/whut/login.html"
    val probe = URI("http://neverssl.com/")
    val internetProbe = URI("https://connectivitycheck.gstatic.com/generate_204")
    val internetIdentityProbe = URI("http://www.msftconnecttest.com/connecttest.txt")
    val discoveryProbes = listOf(URI("http://www.msftconnecttest.com/redirect"), internetIdentityProbe, probe)
    private fun reject(): Nothing = throw ProtocolFailure(State.UntrustedPortal)

    fun uri(value: String): URI = try { URI(value) } catch (_: Exception) { reject() }

    private fun trustedOrigin(uri: URI): Boolean =
        uri.scheme == "http" && uri.host == HOST && uri.port in listOf(-1, 80) &&
            uri.rawUserInfo == null && uri.rawFragment == null

    fun trustedPortal(uri: URI): Boolean = trustedOrigin(uri) && uri.rawPath == PORTAL_PATH

    fun requirePortal(uri: URI): URI = uri.also { if (!trustedPortal(it)) reject() }

    fun trustedBootstrap(uri: URI): Boolean = trustedOrigin(uri) &&
        uri.rawPath.matches(Regex("/api/r/[0-9]{1,10}"))

    fun query(uri: URI, name: String): String? {
        val matches = (uri.rawQuery ?: "").split('&').map { it.split('=', limit = 2) }
            .filter { decode(it[0]) == name }
        if (matches.size > 1) reject()
        return matches.singleOrNull()?.let {
            if (it.size != 2) reject()
            decode(it[1]).also { value ->
                if (value.length > 1024 || value.any { c -> c.isISOControl() }) reject()
            }
        }
    }

    fun bootstrapPortal(uri: URI): URI {
        if (!trustedBootstrap(uri)) reject()
        val values = linkedMapOf("nasId" to uri.rawPath.substringAfterLast('/'))
        for (key in listOf("userip", "acip", "acname", "wlanacname")) {
            query(uri, key)?.let { value ->
                if (key in listOf("userip", "acip") && value.isNotEmpty() && ipv4(value) == null) reject()
                values[key] = value
                if (key == "userip") values["ip"] = value
            }
        }
        return URI("http://$HOST$PORTAL_PATH?" + values.entries.joinToString("&") {
            it.key + "=" + URLEncoder.encode(it.value, "UTF-8")
        })
    }

    // Parse numeric IPv4 without DNS or permissive abbreviated address formats.
    fun ipv4(value: String): List<Int>? {
        val parts = value.split('.')
        if (parts.size != 4 || parts.any { !it.matches(Regex("[0-9]{1,3}")) }) return null
        val numbers = parts.map { it.toInt() }
        return numbers.takeIf { it.all { n -> n in 0..255 } }
    }

    fun physicalFingerprint(host: String, bits: Int, gateway: String): String? {
        val octets = ipv4(host) ?: return null
        if (ipv4(gateway) == null || bits !in 1..32 || octets[0] in listOf(0, 127) || octets[0] >= 224 ||
            (octets[0] == 169 && octets[1] == 254) || (octets[0] == 198 && octets[1] in 18..19)) return null
        val prefix = octets.mapIndexed { index, value ->
            val remaining = (bits - index * 8).coerceIn(0, 8)
            value and (255 shl (8 - remaining) and 255)
        }.joinToString(".")
        return "$prefix/$bits|$gateway|$HOST|wifi"
    }

    fun nasId(portal: URI): String {
        requirePortal(portal)
        val matches = (portal.rawQuery ?: "").split('&').map { it.split('=', limit = 2) }
            .filter { decode(it[0]) == "nasId" }
        if (matches.size != 1 || matches[0].size != 2) reject()
        return decode(matches[0][1]).also {
            if (it.isBlank() || it.length > 256 || it.any { c -> c.isISOControl() }) reject()
        }
    }

    private fun decode(value: String): String = try {
        URLDecoder.decode(value, "UTF-8")
    } catch (_: IllegalArgumentException) { reject() }

    fun safeApiBase(value: String): Boolean = value.length in 1..256 &&
        value.startsWith('/') && !value.contains("..") && !value.contains("//") &&
        value.matches(Regex("/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*/?"))

    fun apiBase(config: String): String {
        // Fail closed on missing/ambiguous structure; never fall back to an unverified API.
        // Tokenise strings/comments first: a commented test URL must not become active.
        val active = Regex("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|/\\*[\\s\\S]*?\\*/|//[^\\r\\n]*")
            .replace(config) { if (it.value.startsWith('/')) " " else it.value }
        val paths = Regex("\\bhost_url\\s*=\\s*(['\"])([^'\"\\r\\n]+)\\1")
            .findAll(active).map { it.groupValues[2].trim() }.distinct().toList()
        if (paths.size != 1) throw ProtocolFailure(State.PortalUnavailable)
        val path = paths.single()
        if (!safeApiBase(path)) reject()
        return path.trimEnd('/')
    }

    fun endpoint(base: String, suffix: String): URI {
        if (!safeApiBase(base)) reject()
        return URI("http://$HOST${base.trimEnd('/')}$suffix")
    }

    fun allowedRequest(uri: URI): Boolean {
        if (uri in discoveryProbes || uri == internetProbe) return true
        return trustedOrigin(uri) && (uri.rawPath == PORTAL_PATH ||
            uri.rawPath == "/tpl/whut/static/js/config.js" || safeApiBase(uri.rawPath))
    }

    fun csrf(body: String): String {
        val token = json(body, State.CsrfFailed)["csrf_token"] as? String
            ?: throw ProtocolFailure(State.CsrfFailed)
        if (token.isBlank() || token.length > 4096 || token.any { it.isISOControl() })
            throw ProtocolFailure(State.CsrfFailed)
        return token
    }

    fun statusCode(body: String): Int = code(body, State.PortalUnavailable)
    fun loginCode(body: String): Int = code(body, State.AuthFailed)

    private fun code(body: String, failure: State): Int {
        val number = json(body, failure)["code"] as? JsonNumber ?: throw ProtocolFailure(failure)
        return number.value.toIntOrNull() ?: throw ProtocolFailure(failure)
    }

    private fun json(body: String, failure: State): Map<String, Any?> = try {
        JsonObjectReader(body).read()
    } catch (_: IllegalArgumentException) { throw ProtocolFailure(failure) }

    fun loginBody(user: String, password: CharArray, nasId: String): ByteArray {
        // URL encoding requires immutable Strings; they cannot be reliably wiped on ART.
        // Keep them scoped to this request and wipe the mutable POST bytes immediately after.
        val fields = linkedMapOf("username" to user, "password" to String(password),
            "swtichip" to "", "nasId" to nasId, "userIpv4" to "", "userMac" to "",
            "captcha" to "", "captchaId" to "")
        return fields.entries.joinToString("&") {
            URLEncoder.encode(it.key, "UTF-8") + "=" + URLEncoder.encode(it.value, "UTF-8")
        }.toByteArray(Charsets.UTF_8)
    }
}
