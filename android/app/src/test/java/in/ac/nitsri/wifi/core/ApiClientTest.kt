package `in`.ac.nitsri.wifi.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ApiClientTest {

    private var now = 1_000_000L
    private val tokens = TokenHolder { now }
    private val http = FakeTransport()
    private val client = ApiClient("http://127.0.0.1:8081/", http, tokens)

    private fun loggedIn(): ApiClient {
        http.answer(200, Contract.TOKEN)
        client.login("student042", "correct horse battery")
        return client
    }

    private fun expectError(block: () -> Unit): ApiException {
        try {
            block()
        } catch (e: ApiException) {
            return e
        }
        fail("no ApiException")
        throw AssertionError()
    }

    // ---- login and token -------------------------------------------------------------------------

    @Test
    fun loginSendsJsonAndKeepsTokenInMemory() {
        http.answer(200, Contract.TOKEN)
        val user = client.login(" student042 ", "correct horse battery")

        assertEquals(User("student042", true, 3), user)
        assertEquals(user, tokens.user)
        assertTrue(tokens.loggedIn)
        val r = http.last
        assertEquals("POST", r.method)
        assertEquals("http://127.0.0.1:8081/api/v1/auth/token", r.url)
        assertEquals("application/json", r.headers["Content-Type"])
        assertNull("no token on the token endpoint", r.headers["Authorization"])
        val body = JSONObject(r.body!!)
        assertEquals(" student042 ", body.getString("uid")) // the server trims
        assertEquals("correct horse battery", body.getString("password"))
    }

    @Test
    fun tokenIsSentAsBearerHeader() {
        loggedIn()
        http.answer(200, Contract.ME)
        client.me()
        assertEquals("Bearer eyJ1aWQiOi.test-token", http.last.headers["Authorization"])
        assertEquals("GET", http.last.method)
        assertNull("GET sends no body", http.last.body)
        assertNull(http.last.headers["Content-Type"])
    }

    @Test
    fun tokenIsNotReachableFromOutside() {
        // The only public view of the token is "logged in or not"; no getter, no toString leak.
        val publicMembers = TokenHolder::class.java.methods.map { it.name }
        assertFalse(publicMembers.any { it.equals("getToken", ignoreCase = true) })
        loggedIn()
        assertFalse(tokens.toString().contains("test-token"))
        assertFalse(http.last.toString().contains("test-token"))
        assertFalse(http.last.toString().contains("correct horse"))
    }

    @Test
    fun loginFailedIsNotASessionEnd() {
        http.answer(401, Contract.error("login_failed", "Login failed. Check your ID and password, then try again."))
        val e = expectError { client.login("student042", "wrong") }
        assertEquals(401, e.status)
        assertEquals("login_failed", e.code)
        assertEquals("Login failed. Check your ID and password, then try again.", e.message)
        assertFalse(e.sessionEnded)
        assertFalse(tokens.loggedIn)
    }

    @Test
    fun loginRateLimitedShowsServerMessage() {
        http.answer(429, Contract.error("rate_limited", "Too many attempts. Wait 15 minutes and try again."))
        val e = expectError { client.login("student042", "x") }
        assertTrue(e.rateLimited)
        assertEquals("Too many attempts. Wait 15 minutes and try again.", e.message)
    }

    @Test
    fun loginBusyAndInvalidInput() {
        http.answer(503, Contract.error("busy", "Too many logins in progress."))
        assertEquals("busy", expectError { client.login("a", "b") }.code)
        http.answer(400, Contract.error("invalid_input", "Send uid and password as strings."))
        assertEquals("invalid_input", expectError { client.login("a", "b") }.code)
    }

    @Test
    fun noCallWithoutToken() {
        val e = expectError { client.devices() }
        assertTrue(e.sessionEnded)
        assertTrue("no request was sent", http.requests.isEmpty())
    }

    @Test
    fun expiredTokenIsForgottenByTheClock() {
        loggedIn()
        now += 899_000
        assertTrue(tokens.loggedIn)
        now += 1_000
        assertFalse(tokens.loggedIn)
        assertNull(tokens.user)
        assertTrue(expectError { client.me() }.sessionEnded)
        assertEquals(1, http.requests.size)
    }

    @Test
    fun tokenLifetimeIsCappedAt30Minutes() {
        http.answer(200, Contract.TOKEN.replace("900", "86400"))
        client.login("student042", "pw")
        now += 30 * 60 * 1000L
        assertFalse(tokens.loggedIn)
    }

    @Test
    fun unauthorizedForgetsTokenAndEndsSession() {
        loggedIn()
        http.answer(401, Contract.error("unauthorized", "Log in again."))
        val e = expectError { client.devices() }
        assertTrue(e.sessionEnded)
        assertEquals("Log in again.", e.message)
        assertFalse(tokens.loggedIn)
        assertTrue(expectError { client.alerts() }.sessionEnded)
        assertEquals("the second call is not sent", 2, http.requests.size)
    }

    @Test
    fun unauthorizedWithoutJsonBody() {
        loggedIn()
        http.answer(401, "")
        val e = expectError { client.me() }
        assertTrue(e.sessionEnded)
        assertEquals(ApiException.MSG_SESSION_ENDED, e.message)
    }

    @Test
    fun rateLimitedKeepsTokenAndShowsMessage() {
        loggedIn()
        http.answer(429, Contract.error("rate_limited", "Too many calls. Wait a minute."))
        val e = expectError { client.devices() }
        assertTrue(e.rateLimited)
        assertFalse(e.sessionEnded)
        assertEquals("Too many calls. Wait a minute.", e.message)
        assertTrue(tokens.loggedIn)
    }

    @Test
    fun rateLimitedWithoutJsonBody() {
        loggedIn()
        http.answer(429, "<html>slow down</html>")
        val e = expectError { client.devices() }
        assertTrue(e.rateLimited)
        assertEquals("http_429", e.code)
    }

    @Test
    fun networkFailure() {
        http.unreachable()
        val e = expectError { client.login("a", "b") }
        assertEquals(ApiException.NETWORK, e.code)
        assertEquals(0, e.status)
    }

    @Test
    fun unreadableSuccessBody() {
        loggedIn()
        http.answer(200, "not json")
        assertEquals(ApiException.BAD_RESPONSE, expectError { client.devices() }.code)
        http.answer(200, """{"online": "two"}""")
        assertEquals(ApiException.BAD_RESPONSE, expectError { client.devices() }.code)
    }

    @Test
    fun everyContractErrorCodeIsPassedThrough() {
        loggedIn()
        val errors = listOf(
            400 to "invalid_input", 400 to "password_refused", 403 to "wrong_password", 404 to "not_found",
            405 to "method_not_allowed", 409 to "conflict", 409 to "disconnect_in_progress", 413 to "too_large",
            415 to "unsupported_media_type", 500 to "server_error", 503 to "unavailable", 503 to "busy",
        )
        for ((status, code) in errors) {
            http.answer(status, Contract.error(code, "Message for $code."))
            val e = expectError { client.me() }
            assertEquals(status, e.status)
            assertEquals(code, e.code)
            assertEquals("Message for $code.", e.message)
            assertFalse(e.sessionEnded)
        }
        assertTrue(tokens.loggedIn)
    }

    @Test
    fun unknownErrorBody() {
        loggedIn()
        http.answer(502, "Bad Gateway")
        val e = expectError { client.me() }
        assertEquals("http_502", e.code)
        assertEquals("The portal is not available. Try again later.", e.message)
    }

    // ---- endpoints -------------------------------------------------------------------------------

    @Test
    fun me() {
        loggedIn()
        http.answer(200, """{"uid": "staff1", "student": false, "device_limit": null}""")
        assertEquals(User("staff1", false, null), client.me())
        assertEquals("http://127.0.0.1:8081/api/v1/me", http.last.url)
    }

    @Test
    fun devices() {
        loggedIn()
        http.answer(200, Contract.DEVICES)
        val d = client.devices()
        assertEquals("http://127.0.0.1:8081/api/v1/devices", http.last.url)
        assertEquals(2, d.online)
        assertEquals(3, d.deviceLimit)
        assertEquals(300, d.reauthInterval)
        val slot = d.slots.single()
        assertEquals("DE-AD-BE-EF-00-02", slot.mac)
        assertEquals("2026-10-26T11:40:00+05:30", slot.joined)
        assertFalse(slot.overLimit)
        assertEquals(
            DeviceSession("AP-615", "10.10.0.20", "2026-10-26T11:40:00+05:30", "2026-10-26T11:50:00+05:30", 2048, 4096),
            slot.session,
        )
        assertEquals(KnownDevice("DE-AD-BE-EF-00-01", "2026-10-20T09:00:00+05:30", "2026-10-26T11:00:00+05:30", true), d.known.single())
        assertEquals(LimitEvent("2026-10-26T10:00:00+05:30", "DE-AD-BE-EF-00-03", 3, 3, "soft"), d.limitEvents.single())
    }

    @Test
    fun devicesWithNullsAndUnknownFields() {
        loggedIn()
        http.answer(
            200,
            """{"online": 0, "device_limit": null, "reauth_interval": 300, "future_field": [1],
                "slots": [{"mac": "AA-BB-CC-DD-EE-FF", "joined": null, "over_limit": true, "session": null}],
                "known": [], "limit_events": []}""",
        )
        val d = client.devices()
        assertNull(d.deviceLimit)
        assertNull(d.slots.single().session)
        assertTrue(d.slots.single().overLimit)
    }

    @Test
    fun disconnect() {
        loggedIn()
        http.answer(200, Contract.DISCONNECT)
        val r = client.disconnect("DE-AD-BE-EF-00-01")
        assertEquals("http://127.0.0.1:8081/api/v1/devices/disconnect", http.last.url)
        assertEquals("POST", http.last.method)
        assertEquals("application/json", http.last.headers["Content-Type"])
        assertEquals("DE-AD-BE-EF-00-01", JSONObject(http.last.body!!).getString("mac"))
        assertEquals(DisconnectResult("DE-AD-BE-EF-00-01", listOf(NasResult("10.89.0.1", "ACK"))), r)
    }

    @Test
    fun disconnectErrors() {
        loggedIn()
        http.answer(404, Contract.error("not_found", "No live session of yours has that MAC."))
        assertEquals("not_found", expectError { client.disconnect("DE-AD-BE-EF-00-01") }.code)
        http.answer(409, Contract.error("disconnect_in_progress", "A disconnect is already running."))
        assertEquals("disconnect_in_progress", expectError { client.disconnect("DE-AD-BE-EF-00-01") }.code)
    }

    @Test
    fun badMacIsRefusedWithoutACall() {
        loggedIn()
        val calls = http.requests.size
        assertEquals("invalid_input", expectError { client.disconnect("DE AD/../x") }.code)
        assertEquals("invalid_input", expectError { client.review("../password", ApiClient.VERDICT_ME) }.code)
        assertEquals(calls, http.requests.size)
    }

    @Test
    fun changePasswordEndsToken() {
        loggedIn()
        http.answer(204)
        client.changePassword("old password 123", "a much longer new password")
        assertEquals("http://127.0.0.1:8081/api/v1/password", http.last.url)
        val body = JSONObject(http.last.body!!)
        assertEquals("old password 123", body.getString("old"))
        assertEquals("a much longer new password", body.getString("new"))
        assertFalse("all tokens end after a password change", tokens.loggedIn)
    }

    @Test
    fun changePasswordErrorsKeepToken() {
        loggedIn()
        http.answer(403, Contract.error("wrong_password", "The current password is wrong."))
        val e = expectError { client.changePassword("bad", "a much longer new password") }
        assertEquals("wrong_password", e.code)
        assertFalse(e.sessionEnded)
        assertTrue(tokens.loggedIn)
        http.answer(400, Contract.error("invalid_input", "That password is too common. Choose another one."))
        assertEquals("That password is too common. Choose another one.", expectError { client.changePassword("a", "b") }.message)
        http.answer(400, Contract.error("password_refused", "The directory refused the new password."))
        assertEquals("password_refused", expectError { client.changePassword("a", "b") }.code)
        http.answer(429, Contract.error("rate_limited", "Too many wrong attempts. Wait 15 minutes and try again."))
        assertTrue(expectError { client.changePassword("a", "b") }.rateLimited)
    }

    @Test
    fun activity() {
        loggedIn()
        http.answer(200, Contract.ACTIVITY)
        val a = client.activity(7)
        assertEquals("http://127.0.0.1:8081/api/v1/activity?days=7", http.last.url)
        assertEquals(7, a.days)
        assertEquals(SignIn("2026-10-26T18:25:07+05:30", "accept", "AP-615", "DE-AD-BE-EF-00-01", true), a.signins[0])
        assertNull(a.signins[1].accessPoint)
        assertEquals("reject", a.signins[1].result)
    }

    @Test
    fun activityDaysAreChecked() {
        loggedIn()
        assertEquals("invalid_input", expectError { client.activity(0) }.code)
        assertEquals("invalid_input", expectError { client.activity(31) }.code)
        assertEquals(1, http.requests.size)
    }

    @Test
    fun alerts() {
        loggedIn()
        http.answer(200, Contract.ALERTS)
        val a = client.alerts()
        assertEquals("http://127.0.0.1:8081/api/v1/alerts", http.last.url)
        assertEquals(2, a.count)
        assertEquals(Alert("DE-AD-BE-EF-00-01", "2026-10-26T18:25:07+05:30", "2026-10-26T18:30:00+05:30", true, false), a.alerts[0])
        assertTrue(a.alerts[1].privateMac)
    }

    @Test
    fun reviewMe() {
        loggedIn()
        http.answer(200, Contract.REVIEW_ME)
        val r = client.review("DE-AD-BE-EF-00-01", ApiClient.VERDICT_ME)
        assertEquals("http://127.0.0.1:8081/api/v1/alerts/DE-AD-BE-EF-00-01", http.last.url)
        assertEquals("me", JSONObject(http.last.body!!).getString("verdict"))
        assertEquals(Review("DE-AD-BE-EF-00-01", "me", null, null), r)
    }

    @Test
    fun reviewNotMeLeadsToPassword() {
        loggedIn()
        http.answer(200, Contract.REVIEW_NOT_ME)
        val r = client.review("DE-AD-BE-EF-00-01", ApiClient.VERDICT_NOT_ME)
        assertEquals("not_me", JSONObject(http.last.body!!).getString("verdict"))
        assertEquals(listOf(NasResult("10.89.0.1", "ACK")), r.disconnect)
        assertEquals(ApiClient.NEXT_PASSWORD, r.next)
    }

    @Test
    fun reviewNotMeOffline() {
        loggedIn()
        http.answer(200, """{"mac": "DE-AD-BE-EF-00-01", "verdict": "not_me", "disconnect": [], "next": "password"}""")
        assertEquals(emptyList<NasResult>(), client.review("DE-AD-BE-EF-00-01", ApiClient.VERDICT_NOT_ME).disconnect)
    }

    @Test
    fun androidProfile() {
        loggedIn()
        val pem = resource("test-ca.pem")
        http.answer(200, Contract.profile(pem))
        val p = client.androidProfile()
        assertEquals("http://127.0.0.1:8081/api/v1/profiles/android", http.last.url)
        assertEquals(
            AndroidProfile("NITS-Lab", "TTLS", "PAP", "student042", "anonymous", "radius.nitsrinagar.lab", "DNS:radius.nitsrinagar.lab", pem),
            p,
        )
    }

    @Test
    fun androidProfileUnavailable() {
        loggedIn()
        http.answer(503, Contract.error("unavailable", "The CA file cannot be read."))
        assertEquals("unavailable", expectError { client.androidProfile() }.code)
    }

    @Test
    fun logoutForgetsToken() {
        loggedIn()
        client.logout()
        assertFalse(tokens.loggedIn)
        assertNull(tokens.user)
    }

    // ---- S6: EAP-TLS profile and device certificates ---------------------------------------------

    @Test
    fun androidProfileMethods() {
        loggedIn()
        val pem = resource("test-ca.pem")
        http.answer(200, Contract.profile(pem))
        client.androidProfile(ApiClient.METHOD_TTLS)
        assertEquals("http://127.0.0.1:8081/api/v1/profiles/android", http.last.url)   // the S3 request, unchanged
        http.answer(200, Contract.tlsProfile(pem))
        val p = client.androidProfile(ApiClient.METHOD_TLS)
        assertEquals("http://127.0.0.1:8081/api/v1/profiles/android?method=tls", http.last.url)
        assertEquals(AndroidProfile("NITS-Lab", "TLS", null, "student042", null, "radius.nitsrinagar.lab", "DNS:radius.nitsrinagar.lab", pem), p)
        try {
            client.androidProfile("peap")
            fail("peap accepted")
        } catch (e: IllegalArgumentException) {
        }
    }

    @Test
    fun issueCertSendsCsrAndLabel() {
        loggedIn()
        http.answer(201, """{"serial": "4f1c0e", "label": "Pixel 8", "issued_at": "2026-10-27T10:00:00+05:30",
            "not_after": "2027-10-27T10:00:00+05:30", "cert_pem": "C", "chain_pem": "D"}""")
        val c = client.issueCert("-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----\n", "Pixel 8")
        assertEquals("POST", http.last.method)
        assertEquals("http://127.0.0.1:8081/api/v1/certs", http.last.url)
        assertEquals("application/json", http.last.headers["Content-Type"])
        assertEquals("Pixel 8", JSONObject(http.last.body!!).getString("label"))
        assertEquals(IssuedCert("4f1c0e", "Pixel 8", "2026-10-27T10:00:00+05:30", "2027-10-27T10:00:00+05:30", "C", "D"), c)
    }

    @Test
    fun issueCertErrors() {
        loggedIn()
        http.answer(409, Contract.error("cert_limit", "You have 3 active certificates."))
        val limit = expectError { client.issueCert("csr", "Pixel 8") }
        assertTrue(limit.certLimit)
        assertFalse(limit.sessionEnded)
        http.answer(400, Contract.error("bad_csr", "Not a valid CSR."))
        val bad = expectError { client.issueCert("csr", "Pixel 8") }
        assertEquals("bad_csr", bad.code)
        assertFalse(bad.certLimit)
    }

    @Test
    fun certList() {
        loggedIn()
        http.answer(200, Contract.CERTS)
        val list = client.certs()
        assertEquals("http://127.0.0.1:8081/api/v1/certs", http.last.url)
        assertEquals("GET", http.last.method)
        assertEquals(3, list.limit)
        assertEquals(
            DeviceCert("4f1c0e", "Pixel 8", "2026-10-27T10:00:00+05:30", "2027-10-27T10:00:00+05:30", null, null, "app", true),
            list.certs[0],
        )
        assertEquals("not_me", list.certs[1].revokeReason)
        assertFalse(list.certs[1].active)
    }

    @Test
    fun revokeCertIsADelete() {
        loggedIn()
        http.answer(200, Contract.REVOKE)
        val r = client.revokeCert("4f1c0e")
        assertEquals("DELETE", http.last.method)
        assertEquals("http://127.0.0.1:8081/api/v1/certs/4f1c0e", http.last.url)
        assertNull(http.last.body)
        assertNull(http.last.headers["Content-Type"])
        assertEquals(RevokeResult("4f1c0e", "2026-10-27T11:00:00+05:30", listOf(NasResult("10.89.0.1", "ACK"))), r)
    }

    @Test
    fun revokeCertChecksTheSerialBeforeACall() {
        loggedIn()
        val before = http.requests.size
        for (bad in listOf("", "4F1C0E", "../me", "4f1c0e?x=1", "a".repeat(65))) {
            assertEquals("invalid_input", expectError { client.revokeCert(bad) }.code)
        }
        assertEquals(before, http.requests.size)
        http.answer(404, Contract.error("not_found", "No such certificate."))
        assertEquals("not_found", expectError { client.revokeCert("abcdef") }.code)
    }

    @Test
    fun reviewNotMeWithRevokedCertificates() {
        loggedIn()
        http.answer(200, Contract.REVIEW_NOT_ME_REVOKED)
        val r = client.review("DE-AD-BE-EF-00-01", ApiClient.VERDICT_NOT_ME)
        assertEquals(listOf("4f1c0e", "a0b1c2"), r.revoked)
        assertEquals(emptyList<String>(), r.revokeFailed)
        // Older portals (no fields) and "me" (null): both null
        http.answer(200, Contract.REVIEW_NOT_ME)
        assertNull(client.review("DE-AD-BE-EF-00-01", ApiClient.VERDICT_NOT_ME).revoked)
    }
}
