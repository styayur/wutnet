package io.github.styayur.wutnet.protocol

import java.net.URI
import org.junit.Assert.*
import org.junit.Test

class AuthenticatorTest {
    private class Trust(var key: String = "network-one", var userIpMatches: Boolean = true) : NetworkTrust {
        val entries = mutableSetOf("network-one")
        override fun fingerprint(): String = key
        override fun matchesUserIp(userIp: String?) = userIpMatches
        override fun contains(fingerprint: String) = fingerprint in entries
        override fun register(fingerprint: String) { entries.add(fingerprint) }
    }
    private fun Authenticator(transport: Transport, credentials: Credentials,
                              emit: (Snapshot) -> Unit = {}): Authenticator =
        Authenticator(transport, credentials, Trust(), emit)

    private class Fake : Transport {
        var validated = false
        var redirect = "http://172.30.21.100/tpl/whut/login.html?nasId=synthetic"
        var config = "var host_url='/api';"
        var csrf = "{\"csrf_token\":\"synthetic\"}"
        var login = "{\"code\":0}"
        var finalOnline = true
        var internet = true
        var identityBody = "<html>captive</html>"
        var postCount = 0
        var statusCount = 0
        var postedBytes: ByteArray? = null
        var bootstrapLocation = "/tpl/whut/login.html?nasId=59"
        val paths = mutableListOf<String>()
        override fun validated() = validated
        override fun request(uri: URI, headers: Map<String, String>, body: ByteArray?): Response {
            paths.add(uri.path)
            return when {
                uri == Protocol.probe || uri == Protocol.discoveryProbes.first() -> Response(302, location = redirect)
                uri == Protocol.internetProbe -> Response(if (internet) 204 else 200)
                uri == Protocol.internetIdentityProbe -> Response(200, identityBody)
                uri.path.endsWith("login.html") -> Response(200, "<html>synthetic</html>")
                uri.path.endsWith("config.js") -> Response(200, config)
                uri.path.startsWith("/api/r/") -> Response(302, location = bootstrapLocation)
                uri.path.endsWith("csrf-token") -> Response(200, csrf)
                uri.path.endsWith("account/status") -> {
                    assertEquals("synthetic", headers["X-Csrf-Token"])
                    statusCount++
                    Response(200, if (postCount > 0 && finalOnline) "{\"code\":0}" else "{\"code\":1}")
                }
                uri.path.endsWith("account/login") -> {
                    assertNotNull(body); postedBytes = body; postCount++; Response(200, login)
                }
                else -> error("Unexpected endpoint")
            }
        }
    }
    @Test fun fullTransitionRequiresThreeIndependentChecks() {
        val fake = Fake(); val states = mutableListOf<State>(); val password = "synthetic".toCharArray()
        val result = Authenticator(fake, Credentials { Credential("synthetic", password) }) { states.add(it.state) }
            .run(login = true, captive = true)
        assertEquals(State.Authenticated, result.state)
        assertEquals(listOf(State.CaptivePortal, State.WhutOffline, State.Authenticating, State.Authenticated), states)
        assertEquals(2, fake.statusCount); assertEquals(1, fake.postCount)
        assertTrue(password.all { it == '\u0000' }); assertTrue(fake.postedBytes!!.all { it == 0.toByte() })
    }
    @Test fun untrustedRedirectNeverLoadsCredential() {
        val fake = Fake().apply { redirect = "http://evil.example/?next=172.30.21.100" }
        val result = Authenticator(fake, Credentials { error("Must not load credential") }).run(true, captive = true)
        assertEquals(State.UntrustedPortal, result.state); assertEquals(0, fake.postCount)
    }
    @Test fun unsafeConfigNeverLoadsCredential() {
        val fake = Fake().apply { config = "host_url='//evil.example/api'" }
        assertEquals(State.UntrustedPortal,
            Authenticator(fake, Credentials { error("Must not decrypt") }).run(true, captive = true).state)
    }
    @Test fun csrfFailureNeverLoadsCredential() {
        val fake = Fake().apply { csrf = "{}" }
        val result = Authenticator(fake, Credentials { error("Must not decrypt") }).run(true, captive = true)
        assertEquals(State.CsrfFailed, result.state); assertEquals("FAILED", result.diagnostics.csrf)
    }
    @Test fun diagnoseNeverLoadsCredential() {
        val fake = Fake()
        assertEquals(State.WhutOffline,
            Authenticator(fake, Credentials { error("Must not decrypt") }).run(false, captive = true).state)
        assertEquals(0, fake.postCount)
    }
    @Test fun validatedWifiAvoidsLogin() {
        val fake = Fake().apply { validated = true }
        assertEquals(State.Online, Authenticator(fake, Credentials { error("No decrypt") }).run(true).state)
        assertTrue(fake.paths.isEmpty())
    }
    @Test fun loginAcceptedButStatusOfflineFails() {
        val fake = Fake().apply { finalOnline = false }
        assertEquals(State.AuthFailed, Authenticator(fake, creds()).run(true, captive = true).state)
    }
    @Test fun statusOnlineButHttp200ProbeFails() {
        val fake = Fake().apply { internet = false }
        assertEquals(State.TransportError, Authenticator(fake, creds()).run(true, captive = true).state)
    }
    @Test fun filteredHttpsCanUseExactNcsiFingerprint() {
        val fake = Fake().apply { internet = false; identityBody = "Microsoft Connect Test" }
        val result = Authenticator(fake, creds()).run(true, captive = true)
        assertEquals(State.Authenticated, result.state)
        assertEquals("OK (Wi-Fi NCSI identity probe)", result.diagnostics.internet)
    }
    @Test fun verificationCodeFailsWithoutEchoingServerMessage() {
        val fake = Fake().apply { login = "{\"code\":2,\"msg\":\"synthetic-private-value\"}" }
        val result = Authenticator(fake, creds()).run(true, captive = true)
        assertEquals(State.AuthFailed, result.state)
        assertFalse(result.toString().contains("synthetic-private-value"))
    }
    @Test fun missingCredentialFailsClosed() {
        val result = Authenticator(Fake(), Credentials { throw ProtocolFailure(State.CredentialRequired) })
            .run(true, captive = true)
        assertEquals(State.CredentialRequired, result.state)
    }
    @Test fun untrustedSystemHintNeverMakesRequest() {
        val fake = Fake()
        assertEquals(State.UntrustedPortal, Authenticator(fake, creds())
            .run(true, "http://172.30.21.101/tpl/whut/login.html?nasId=x", true).state)
        assertTrue(fake.paths.isEmpty())
    }
    @Test fun credentialToStringRedactsBothFields() {
        val credential = Credential("private-user", "private-password".toCharArray())
        assertEquals("Credential(redacted)", credential.toString())
    }
    @Test fun cancellationBeforeAttemptNeverDecryptsOrRequests() {
        val fake = Fake()
        Thread.currentThread().interrupt()
        try {
            Authenticator(fake, Credentials { error("No decrypt") }).run(true, captive = true)
            fail("Expected cancellation")
        } catch (_: InterruptedException) {
            assertTrue(fake.paths.isEmpty())
        } finally { Thread.interrupted() }
    }
    @Test fun postRedirectIsRejectedAndBodyWiped() {
        val fake = Fake()
        val redirecting = object : Transport {
            override fun validated() = false
            override fun request(uri: URI, headers: Map<String, String>, body: ByteArray?): Response {
                val result = fake.request(uri, headers, body)
                return if (body != null) Response(302, location = "http://evil.example/") else result
            }
        }
        assertEquals(State.UntrustedPortal, Authenticator(redirecting, creds()).run(true, captive = true).state)
        assertTrue(fake.postedBytes!!.all { it == 0.toByte() })
        assertFalse(fake.paths.contains("/evil"))
    }
    @Test fun bootstrapIsReplayedBeforePortalAndCredential() {
        val fake = Fake().apply {
            redirect = "http://172.30.21.100/api/r/731?userip=10.90.24.17&acname=SYNTHETIC"
            config = "//var host_url='http://invalid.example/api'\nvar host_url='/api';"
        }
        val result = Authenticator(fake, creds()).run(true, captive = true)
        assertEquals(State.Authenticated, result.state)
        assertEquals("731", result.diagnostics.nasId)
        assertTrue(fake.paths.indexOf("/api/r/731") < fake.paths.indexOf(Protocol.PORTAL_PATH))
    }
    @Test fun foreignBootstrapRedirectNeverDecrypts() {
        val fake = Fake().apply {
            redirect = "http://172.30.21.100/api/r/59"
            bootstrapLocation = "http://evil.example/"
        }
        assertEquals(State.UntrustedPortal, Authenticator(fake, Credentials { error("No decrypt") })
            .run(true, captive = true).state)
        assertEquals(0, fake.postCount)
    }
    @Test fun probesContinueAfterTimeoutAndForeignRedirect() {
        val fake = Fake()
        val transport = object : Transport {
            override fun validated() = false
            override fun request(uri: URI, headers: Map<String, String>, body: ByteArray?): Response = when (uri) {
                Protocol.discoveryProbes[0] -> throw java.net.SocketTimeoutException()
                Protocol.discoveryProbes[1] -> Response(302, location = "http://evil.example/")
                else -> fake.request(uri, headers, body)
            }
        }
        assertEquals(State.Authenticated, Authenticator(transport, creds()).run(true, captive = true).state)
    }
    @Test fun unknownNetworkRequiresExplicitApprovalAndPreservesOtherEntries() {
        val trust = Trust("network-two")
        val fake = Fake()
        val result = Authenticator(fake, Credentials { error("No decrypt") }, trust).run(true, captive = true)
        assertEquals(State.NetworkTrustRequired, result.state)
        assertEquals(setOf("network-one"), trust.entries)
        assertEquals(0, fake.postCount)
        assertEquals(State.Authenticated, Authenticator(fake, creds(), trust)
            .run(true, captive = true, approvedFingerprint = "network-two").state)
        assertEquals(setOf("network-one", "network-two"), trust.entries)
        trust.key = "network-one"
        assertEquals(State.Authenticated, Authenticator(Fake(), creds(), trust).run(true, captive = true).state)
    }
    @Test fun staleApprovalCannotRegisterAnotherNetwork() {
        val trust = Trust("network-three")
        assertEquals(State.NetworkTrustRequired, Authenticator(Fake(), Credentials { error("No decrypt") }, trust)
            .run(true, captive = true, approvedFingerprint = "network-two").state)
        assertEquals(setOf("network-one"), trust.entries)
    }
    @Test fun failedProtocolCannotEnrollEvenWithApproval() {
        val trust = Trust("network-two")
        val fake = Fake().apply { csrf = "{}" }
        assertEquals(State.CsrfFailed, Authenticator(fake, Credentials { error("No decrypt") }, trust)
            .run(true, captive = true, approvedFingerprint = "network-two").state)
        assertEquals(setOf("network-one"), trust.entries)
    }
    @Test fun mismatchedBootstrapPhysicalAddressFailsClosed() {
        val trust = Trust(userIpMatches = false)
        assertEquals(State.UntrustedPortal, Authenticator(Fake(), Credentials { error("No decrypt") }, trust)
            .run(true, captive = true).state)
    }
    @Test fun networkChangeAfterDecryptPreventsPostAndWipesPassword() {
        val trust = Trust(); val fake = Fake(); val password = "synthetic".toCharArray()
        val result = Authenticator(fake, Credentials {
            trust.key = "network-two"; Credential("synthetic", password)
        }, trust).run(true, captive = true)
        assertEquals(State.NoNetwork, result.state)
        assertEquals(0, fake.postCount)
        assertTrue(password.all { it == '\u0000' })
    }
    private fun creds() = Credentials { Credential("synthetic", "synthetic".toCharArray()) }
}
