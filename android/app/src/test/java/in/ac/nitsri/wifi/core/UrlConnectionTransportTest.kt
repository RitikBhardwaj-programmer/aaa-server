package `in`.ac.nitsri.wifi.core

import com.sun.net.httpserver.HttpServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.InetSocketAddress

/** The real HttpURLConnection transport against a fake portal (the JDK's built-in HTTP server). */
class UrlConnectionTransportTest {

    private class Seen(val method: String, val path: String, val headers: Map<String, String?>, val body: String)

    private lateinit var server: HttpServer
    private val seen = mutableListOf<Seen>()
    private var status = 200
    private var reply = "{}"
    private lateinit var base: String

    @Before
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { ex ->
            seen += Seen(
                ex.requestMethod,
                ex.requestURI.toString(),
                listOf("Authorization", "Content-Type", "Accept", "Cookie").associateWith { ex.requestHeaders.getFirst(it) },
                ex.requestBody.readBytes().toString(Charsets.UTF_8),
            )
            val bytes = reply.toByteArray()
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.responseHeaders.add("Cache-Control", "no-store")
            if (status == 204) {
                ex.sendResponseHeaders(204, -1)
            } else {
                ex.sendResponseHeaders(status, bytes.size.toLong())
                ex.responseBody.use { it.write(bytes) }
            }
            ex.close()
        }
        server.start()
        base = "http://127.0.0.1:${server.address.port}"
    }

    @After
    fun stop() = server.stop(0)

    private val client by lazy { ApiClient(base, UrlConnectionTransport(), TokenHolder()) }

    @Test
    fun fullLoginThenAuthorizedCall() {
        reply = Contract.TOKEN
        client.login("student042", "pw")
        reply = Contract.DEVICES
        val d = client.devices()

        assertEquals(2, d.online)
        val (login, devices) = seen
        assertEquals("POST", login.method)
        assertEquals("/api/v1/auth/token", login.path)
        assertEquals("application/json", login.headers["Content-Type"])
        assertNull(login.headers["Authorization"])
        assertEquals("student042", org.json.JSONObject(login.body).getString("uid"))
        assertEquals("GET", devices.method)
        assertEquals("/api/v1/devices", devices.path)
        assertEquals("Bearer eyJ1aWQiOi.test-token", devices.headers["Authorization"])
        assertNull("no cookies", devices.headers["Cookie"])
        assertEquals("application/json", devices.headers["Accept"])
    }

    @Test
    fun errorBodyIsReadFromErrorStream() {
        status = 401
        reply = Contract.error("login_failed", "Login failed. Check your ID and password, then try again.")
        val r = UrlConnectionTransport().execute(HttpRequest("POST", "$base/api/v1/auth/token", mapOf("Content-Type" to "application/json"), "{}"))
        assertEquals(401, r.status)
        assertTrue(r.body.contains("login_failed"))
    }

    @Test
    fun rateLimitThroughRealConnection() {
        reply = Contract.TOKEN
        client.login("student042", "pw")
        status = 429
        reply = Contract.error("rate_limited", "Too many calls.")
        try {
            client.alerts()
            throw AssertionError("no exception")
        } catch (e: ApiException) {
            assertTrue(e.rateLimited)
            assertEquals("Too many calls.", e.message)
            assertTrue(client.tokens.loggedIn)
        }
    }

    @Test
    fun noContent() {
        reply = Contract.TOKEN
        client.login("student042", "pw")
        status = 204
        reply = ""
        client.changePassword("old", "new password that is long")
        assertEquals("POST", seen.last().method)
        assertFalse(client.tokens.loggedIn)
    }

    @Test
    fun serverDown() {
        server.stop(0)
        try {
            client.login("a", "b")
            throw AssertionError("no exception")
        } catch (e: ApiException) {
            assertEquals(ApiException.NETWORK, e.code)
        }
    }
}
