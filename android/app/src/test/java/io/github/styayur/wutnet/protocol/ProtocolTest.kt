package io.github.styayur.wutnet.protocol

import java.net.URI
import org.junit.Assert.*
import org.junit.Test

class ProtocolTest {
    private val portal = "http://172.30.21.100/tpl/whut/login.html?nasId=synthetic%2Btest"
    private fun rejects(block: () -> Unit) {
        try { block(); fail("Expected a safe rejection") } catch (_: ProtocolFailure) { }
    }
    @Test fun validPortalAndExplicitPort() {
        assertTrue(Protocol.trustedPortal(URI(portal)))
        assertTrue(Protocol.trustedPortal(URI(portal.replace(".100/", ".100:80/"))))
    }
    @Test fun maliciousPortalHosts() {
        listOf("http://172.30.21.100.evil.example/", "http://172.30.21.101/",
            "http://evil.example/?next=172.30.21.100", "http://user:pass@172.30.21.100/tpl/whut/login.html",
            "http://172.30.21.100:8080/tpl/whut/login.html", "https://172.30.21.100/tpl/whut/login.html")
            .forEach { assertFalse(it, Protocol.trustedPortal(URI(it))) }
    }
    @Test fun exactPathOnly() {
        listOf("/tpl/whut/login.html/", "/tpl/whut/../whut/login.html", "/tpl/whut/login%2ehtml",
            "/tpl/whut/Login.html", "/tpl/whut/login.html#fragment")
            .forEach { assertFalse(Protocol.trustedPortal(URI("http://172.30.21.100$it"))) }
    }
    @Test fun nasIdDecoding() {
        assertEquals("synthetic+test", Protocol.nasId(URI(portal)))
        assertEquals("a b", Protocol.nasId(URI(portal.substringBefore('?') + "?nasId=a+b")))
    }
    @Test fun nasIdMissingDuplicateAndControlRejected() {
        listOf("", "?nasId=", "?nasId=a&nasId=b", "?nasId=%0a")
            .forEach { rejects { Protocol.nasId(URI(portal.substringBefore('?') + it)) } }
    }
    @Test fun maliciousApiBases() {
        listOf("/api/../evil", "http://evil.example/api", "//evil.example/api", "/api%2f..%2fevil",
            "/api\\evil", "/api?next=x", "/", "/api#x", "api")
            .forEach { assertFalse(it, Protocol.safeApiBase(it)) }
    }
    @Test fun configParsing() {
        assertEquals("/api", Protocol.apiBase("var host_url = '/api/';"))
        assertEquals("/v2/api", Protocol.apiBase("window.host_url = \"/v2/api\";"))
        rejects { Protocol.apiBase("host_url='//evil.example/api'") }
        rejects { Protocol.apiBase("host_url='/api'; host_url='/other'") }
        rejects { Protocol.apiBase("const unrelated = '/api'") }
    }
    @Test fun numericResponseCodes() {
        assertEquals(0, Protocol.loginCode("{\"code\":0,\"msg\":\"ok\"}"))
        assertEquals(2, Protocol.loginCode("{\"code\":2}"))
        assertEquals(1, Protocol.statusCode("{\"code\":1,\"extra\":[true,null,{\"x\":2}]}"))
        assertEquals(0, Protocol.statusCode("{\"code\":0}"))
    }
    @Test fun malformedResponsesNeverMeanSuccess() {
        listOf("{}", "{\"code\":\"0\"}", "{\"code\":false}", "{\"code\":0.0}",
            "{\"code\":0,\"code\":1}", "{\"nested\":{\"code\":0}}", "{\"code\":0}junk",
            "{\"code\":00}", "<html>OK</html>").forEach { body ->
            rejects { Protocol.loginCode(body) }; rejects { Protocol.statusCode(body) }
        }
    }
    @Test fun csrfStrictness() {
        assertEquals("synthetic", Protocol.csrf("{\"csrf_token\":\"synthetic\"}"))
        listOf("{}", "{\"csrf_token\":\"\"}", "{\"csrf_token\":\"x\\ny\"}")
            .forEach { rejects { Protocol.csrf(it) } }
    }
    @Test fun loginFieldSpellingAndEncoding() {
        val chars = "a&b=+".toCharArray()
        val body = Protocol.loginBody("test user", chars, "a+b").toString(Charsets.UTF_8)
        assertTrue(body.contains("password=a%26b%3D%2B"))
        assertTrue(body.contains("username=test+user"))
        assertTrue(body.contains("swtichip=")); assertTrue(body.contains("nasId=a%2Bb"))
        assertEquals(8, body.split('&').size)
    }
    @Test fun requestPolicy() {
        assertTrue(Protocol.allowedRequest(Protocol.probe))
        assertTrue(Protocol.allowedRequest(Protocol.internetProbe))
        assertFalse(Protocol.allowedRequest(URI("http://evil.example/api")))
        assertFalse(Protocol.allowedRequest(URI("http://neverssl.com/evil")))
    }
}
