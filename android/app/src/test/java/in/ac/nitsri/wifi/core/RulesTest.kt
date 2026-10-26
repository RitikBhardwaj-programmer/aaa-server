package `in`.ac.nitsri.wifi.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class RulesTest {

    @Test
    fun baseUrls() {
        assertNull(BaseUrlPolicy.problem("http://127.0.0.1:8081", allowLoopbackCleartext = true))
        assertNull(BaseUrlPolicy.problem("https://portal.example.ac.in", allowLoopbackCleartext = false))
        assertNull(BaseUrlPolicy.problem("https://127.0.0.1:8443/", allowLoopbackCleartext = false))
        // Release builds: https only
        assertNotNull(BaseUrlPolicy.problem("http://127.0.0.1:8081", allowLoopbackCleartext = false))
        // Debug builds: cleartext only to 127.0.0.1
        assertNotNull(BaseUrlPolicy.problem("http://localhost:8081", allowLoopbackCleartext = true))
        assertNotNull(BaseUrlPolicy.problem("http://10.0.2.2:8081", allowLoopbackCleartext = true))
        assertNotNull(BaseUrlPolicy.problem("http://127.0.0.1.evil.test", allowLoopbackCleartext = true))
        assertNotNull(BaseUrlPolicy.problem("", allowLoopbackCleartext = false))
        assertNotNull(BaseUrlPolicy.problem("ftp://portal", allowLoopbackCleartext = false))
        assertNotNull(BaseUrlPolicy.problem("https://user@portal.example", allowLoopbackCleartext = false))
    }

    @Test
    fun passwordRulesUseServerMessages() {
        val good = "a long enough passphrase"
        assertNull(PasswordRules.problem("student042", good, good))
        assertEquals("The new password and the confirmation are not the same.", PasswordRules.problem("student042", good, good + "x"))
        assertEquals("The new password must have at least 15 characters.", PasswordRules.problem("u", "short", "short"))
        val long = "x".repeat(129)
        assertEquals("The new password must have at most 128 characters.", PasswordRules.problem("u", long, long))
        val withUid = "my Student042 password!"
        assertEquals("The new password must not contain your user ID.", PasswordRules.problem("student042", withUid, withUid))
    }

    @Test
    fun passwordLengthCountsCodePoints() {
        // 15 emoji are 30 UTF-16 units but 15 characters for the server
        val emoji = "😀".repeat(15)
        assertNull(PasswordRules.problem("u", emoji, emoji))
        val fourteen = "😀".repeat(14)
        assertNotNull(PasswordRules.problem("u", fourteen, fourteen))
    }

    @Test
    fun formats() {
        assertEquals("26 Oct 11:40", Formats.time("2026-10-26T11:40:00+05:30"))
        assertEquals("-", Formats.time(null))
        assertEquals("garbage", Formats.time("garbage"))
        assertEquals("512 B", Formats.bytes(512))
        assertEquals("2.0 KB", Formats.bytes(2048))
        assertEquals("1.5 MB", Formats.bytes(1536L * 1024))
        assertEquals("2 of 3 online", Formats.onlineCount(2, 3))
        assertEquals("2 online", Formats.onlineCount(2, null))
        assertEquals("1 new device signed in", Formats.alertBanner(1))
        assertEquals("2 new devices signed in", Formats.alertBanner(2))
        assertEquals("10.89.0.1: disconnected.", Formats.disconnectResults(listOf(NasResult("10.89.0.1", "ACK")), 300))
        assertEquals(
            "10.89.0.1: no answer.\nThe device is dropped at the next re-check, within 300 seconds.",
            Formats.disconnectResults(listOf(NasResult("10.89.0.1", "none")), 300),
        )
        assertEquals("The device is not online.", Formats.disconnectResults(emptyList(), 300))
    }
}
