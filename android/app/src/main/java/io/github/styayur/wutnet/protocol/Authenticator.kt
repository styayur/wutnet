package io.github.styayur.wutnet.protocol

import java.net.URI

data class Response(val status: Int, val body: String = "", val location: String? = null)
interface Transport {
    fun request(uri: URI, headers: Map<String, String> = emptyMap(), body: ByteArray? = null): Response
    fun validated(): Boolean
}
class Credential(val username: String, val password: CharArray) {
    override fun toString(): String = "Credential(redacted)"
}
fun interface Credentials { fun load(): Credential }
interface NetworkTrust {
    fun fingerprint(): String?
    fun matchesUserIp(userIp: String?): Boolean
    fun contains(fingerprint: String): Boolean
    fun register(fingerprint: String)
}
data class Diagnostics(
    val portalDetected: Boolean = false, val portalTrusted: Boolean = false,
    val nasId: String? = null, val apiBase: String? = null, val csrf: String = "NOT CHECKED",
    val account: String = "NOT CHECKED", val internet: String = "NOT CHECKED",
    val networkFingerprint: String? = null
)
data class Snapshot(val state: State, val diagnostics: Diagnostics = Diagnostics())

/** One finite attempt; pure Kotlin so ordering and credential boundaries are JVM-testable. */
class Authenticator(private val transport: Transport, private val credentials: Credentials,
                    private val trust: NetworkTrust,
                    private val emit: (Snapshot) -> Unit = {}) {
    private var diagnostics = Diagnostics()
    private fun state(state: State): Snapshot = Snapshot(state, diagnostics).also(emit)
    private fun checkCancelled() { if (Thread.currentThread().isInterrupted) throw InterruptedException() }
    private fun request(uri: URI, headers: Map<String, String> = emptyMap(), body: ByteArray? = null): Response {
        checkCancelled()
        if (!Protocol.allowedRequest(uri)) throw ProtocolFailure(State.UntrustedPortal)
        return transport.request(uri, headers, body)
    }
    private fun ok(uri: URI, headers: Map<String, String> = emptyMap(), body: ByteArray? = null,
                   failure: State = State.PortalUnavailable): String {
        val response = request(uri, headers, body)
        // Redirects from portal endpoints are never followed, especially for POSTs.
        if (response.status in 300..399) throw ProtocolFailure(State.UntrustedPortal)
        if (response.status != 200) throw ProtocolFailure(failure)
        return response.body
    }
    private fun internet(): Boolean {
        if (transport.validated()) {
            diagnostics = diagnostics.copy(internet = "OK (Wi-Fi VALIDATED)")
            return true
        }
        val https = try { request(Protocol.internetProbe).status == 204 } catch (e: Exception) {
            if (e is InterruptedException) throw e
            false
        }
        if (https) {
            diagnostics = diagnostics.copy(internet = "OK (Wi-Fi HTTPS 204)")
            return true
        }
        // Google's endpoint may be filtered on campus; reuse Windows' exact NCSI body
        // fingerprint as a bounded, credential-free fallback. HTTP 200 alone is insufficient.
        val identity = try {
            val response = request(Protocol.internetIdentityProbe)
            response.status == 200 && response.body.trim() == "Microsoft Connect Test"
        } catch (e: Exception) {
            if (e is InterruptedException) throw e
            false
        }
        diagnostics = diagnostics.copy(internet = if (identity) "OK (Wi-Fi NCSI identity probe)" else "FAILED")
        return identity
    }
    private fun redirect(base: URI, location: String): URI {
        val hint = Protocol.uri(location)
        if (hint.rawPath.split('/').any { it == "." || it == ".." })
            throw ProtocolFailure(State.UntrustedPortal)
        return base.resolve(hint)
    }
    private fun discover(): URI {
        var foreign = false
        for (probe in Protocol.discoveryProbes) {
            val response = try { request(probe) } catch (e: Exception) {
                if (e is InterruptedException) throw e
                continue
            }
            if (response.status !in 300..399 || response.location == null) continue
            val target = redirect(probe, response.location)
            if (Protocol.trustedPortal(target) || Protocol.trustedBootstrap(target)) return target
            if (target.host == Protocol.HOST) throw ProtocolFailure(State.PortalUnavailable)
            foreign = true // Never follow a foreign redirect or send it cookies.
        }
        throw ProtocolFailure(if (foreign) State.UntrustedPortal else State.PortalUnavailable)
    }
    fun run(login: Boolean, portalHint: String? = null, captive: Boolean = false,
            approvedFingerprint: String? = null): Snapshot {
        try {
            checkCancelled()
            if (!captive && transport.validated()) {
                diagnostics = diagnostics.copy(internet = "OK (Wi-Fi VALIDATED)")
                return state(State.Online)
            }
            state(if (captive) State.CaptivePortal else State.WhutOffline)
            if (!captive && internet()) return state(State.Online)
            val entry = if (!portalHint.isNullOrBlank()) {
                // System-supplied URLs are hints, never a trust exemption.
                Protocol.uri(portalHint).also {
                    if (!Protocol.trustedPortal(it) && !Protocol.trustedBootstrap(it))
                        throw ProtocolFailure(State.UntrustedPortal)
                }
            } else discover()
            val portal = if (Protocol.trustedBootstrap(entry)) {
                val canonical = Protocol.bootstrapPortal(entry)
                val response = request(entry) // Same Transport and cookie jar for the whole session.
                if (response.status in 300..399) {
                    val next = redirect(entry, response.location ?: throw ProtocolFailure(State.PortalUnavailable))
                    if (!Protocol.trustedPortal(next) && !Protocol.trustedBootstrap(next))
                        throw ProtocolFailure(State.UntrustedPortal)
                } else if (response.status !in 200..299) throw ProtocolFailure(State.PortalUnavailable)
                canonical
            } else Protocol.requirePortal(entry)
            diagnostics = diagnostics.copy(portalDetected = true, portalTrusted = true)
            val nasId = Protocol.nasId(portal)
            diagnostics = diagnostics.copy(nasId = nasId)
            ok(portal)
            val apiBase = Protocol.apiBase(ok(URI("http://${Protocol.HOST}/tpl/whut/static/js/config.js")))
            diagnostics = diagnostics.copy(apiBase = apiBase)
            val csrf = try {
                Protocol.csrf(ok(Protocol.endpoint(apiBase, "/csrf-token"),
                    mapOf("Referer" to portal.toASCIIString()), failure = State.CsrfFailed))
            } catch (e: ProtocolFailure) {
                diagnostics = diagnostics.copy(csrf = "FAILED"); throw e
            }
            diagnostics = diagnostics.copy(csrf = "OK")
            val headers = mapOf("Accept" to "application/json, */*", "Referer" to portal.toASCIIString(),
                "X-Requested-With" to "XMLHttpRequest", "X-Csrf-Token" to csrf)
            val statusUri = Protocol.endpoint(apiBase, "/account/status?token=null")
            var code = Protocol.statusCode(ok(statusUri, headers))
            diagnostics = diagnostics.copy(account = if (code == 0) "ONLINE" else "OFFLINE (code $code)")
            if (code == 0) {
                return state(if (internet()) State.Authenticated else State.TransportError)
            }
            state(State.WhutOffline)
            if (!login) return state(State.WhutOffline)
            // Fingerprints (portal + config + CSRF + status) all passed before decryption.
            checkCancelled()
            val fingerprint = trust.fingerprint() ?: throw ProtocolFailure(State.NoNetwork)
            val userIp = Protocol.query(portal, "userip") ?: Protocol.query(portal, "ip")
            if (!trust.matchesUserIp(userIp)) throw ProtocolFailure(State.UntrustedPortal)
            diagnostics = diagnostics.copy(networkFingerprint = fingerprint)
            if (!trust.contains(fingerprint)) {
                if (approvedFingerprint != fingerprint) return state(State.NetworkTrustRequired)
                trust.register(fingerprint)
            }
            if (trust.fingerprint() != fingerprint || !trust.contains(fingerprint))
                throw ProtocolFailure(State.NetworkTrustRequired)
            val credential = credentials.load()
            state(State.Authenticating)
            val body = try { Protocol.loginBody(credential.username, credential.password, nasId) }
                finally { credential.password.fill('\u0000') }
            val loginResponse = try {
                if (trust.fingerprint() != fingerprint || !trust.matchesUserIp(userIp))
                    throw ProtocolFailure(State.NoNetwork)
                ok(Protocol.endpoint(apiBase, "/account/login"),
                    headers + ("Origin" to "http://${Protocol.HOST}"), body, State.AuthFailed)
            } finally { body.fill(0) }
            code = Protocol.loginCode(loginResponse)
            if (code != 0) throw ProtocolFailure(State.AuthFailed)
            code = Protocol.statusCode(ok(statusUri, headers))
            diagnostics = diagnostics.copy(account = if (code == 0) "ONLINE" else "OFFLINE (code $code)")
            if (code != 0) throw ProtocolFailure(State.AuthFailed)
            return state(if (internet()) State.Authenticated else State.TransportError)
        } catch (e: ProtocolFailure) {
            if (e.state == State.UntrustedPortal) diagnostics = diagnostics.copy(portalTrusted = false)
            return state(e.state)
        } catch (e: InterruptedException) { throw e
        } catch (_: Exception) { return state(State.TransportError) }
    }
}
