package io.github.styayur.wutnet.protocol

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder

enum class State {
    Online, CaptivePortal, WhutOffline, Authenticating, Authenticated, NoNetwork,
    UntrustedPortal, AuthFailed, CsrfFailed, PortalUnavailable, TransportError,
    CredentialRequired
}

class ProtocolFailure(val state: State) : Exception(state.name)

object Protocol {
    const val HOST = "172.30.21.100"
    const val PORTAL_PATH = "/tpl/whut/login.html"
    val probe = URI("http://neverssl.com/")
    val internetProbe = URI("https://connectivitycheck.gstatic.com/generate_204")
    val internetIdentityProbe = URI("http://www.msftconnecttest.com/connecttest.txt")
    private fun reject(): Nothing = throw ProtocolFailure(State.UntrustedPortal)

    fun uri(value: String): URI = try { URI(value) } catch (_: Exception) { reject() }

    private fun trustedOrigin(uri: URI): Boolean =
        uri.scheme == "http" && uri.host == HOST && uri.port in listOf(-1, 80) &&
            uri.rawUserInfo == null && uri.rawFragment == null

    fun trustedPortal(uri: URI): Boolean = trustedOrigin(uri) && uri.rawPath == PORTAL_PATH

    fun requirePortal(uri: URI): URI = uri.also { if (!trustedPortal(it)) reject() }

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
        val matches = Regex("\\bhost_url\\s*=\\s*(['\"])([^'\"\\r\\n]+)\\1").findAll(config).toList()
        if (matches.size != 1) throw ProtocolFailure(State.PortalUnavailable)
        val path = matches.single().groupValues[2].trim()
        if (!safeApiBase(path)) reject()
        return path.trimEnd('/')
    }

    fun endpoint(base: String, suffix: String): URI {
        if (!safeApiBase(base)) reject()
        return URI("http://$HOST${base.trimEnd('/')}$suffix")
    }

    fun allowedRequest(uri: URI): Boolean {
        if (uri == probe || uri == internetProbe ||
            uri == internetIdentityProbe) return true
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
