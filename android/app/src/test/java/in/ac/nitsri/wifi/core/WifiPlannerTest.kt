package `in`.ac.nitsri.wifi.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Date

class WifiPlannerTest {

    private val caPem = resource("test-ca.pem")
    private val profile = AndroidProfile(
        ssid = "NITS-Lab",
        eap = "TTLS",
        phase2 = "PAP",
        identity = "student042",
        anonymousIdentity = "anonymous",
        domainSuffixMatch = "radius.nitsrinagar.lab",
        altSubjectMatch = "DNS:radius.nitsrinagar.lab",
        caPem = caPem,
    )

    private fun refused(p: AndroidProfile, now: Date = Date()): String {
        try {
            WifiPlanner.plan(p, now)
        } catch (e: WifiPlanException) {
            return e.message!!
        }
        fail("plan was accepted")
        throw AssertionError()
    }

    @Test
    fun contractProfileMapsToPlan() {
        val plan = WifiPlanner.plan(profile)
        assertEquals("NITS-Lab", plan.ssid)
        assertEquals("student042", plan.identity)
        assertEquals("anonymous", plan.anonymousIdentity)
        assertEquals("radius.nitsrinagar.lab", plan.domainSuffixMatch)
        assertEquals("DNS:radius.nitsrinagar.lab", plan.altSubjectMatch)
        assertTrue(plan.caCertificate.subjectX500Principal.name.contains("Unit Test CA"))
    }

    @Test
    fun parsedFromTheContractJson() {
        val o = org.json.JSONObject(Contract.profile(caPem))
        val plan = WifiPlanner.plan(Parse.androidProfile(o))
        assertEquals("DNS:radius.nitsrinagar.lab", plan.altSubjectMatch)
    }

    @Test
    fun missingAltSubjectMatchFallsBackToDnsDomain() {
        assertEquals("DNS:radius.nitsrinagar.lab", WifiPlanner.plan(profile.copy(altSubjectMatch = null)).altSubjectMatch)
    }

    @Test
    fun onlyTtlsPap() {
        assertTrue(refused(profile.copy(eap = "TLS", phase2 = null, anonymousIdentity = null)).contains("EAP-TTLS only"))
        assertTrue(refused(profile.copy(phase2 = "MSCHAPV2")).contains("PAP"))
    }

    @Test
    fun requiredFields() {
        refused(profile.copy(ssid = ""))
        refused(profile.copy(ssid = "x".repeat(33)))
        refused(profile.copy(identity = " "))
        refused(profile.copy(anonymousIdentity = null))
        refused(profile.copy(domainSuffixMatch = ""))
        refused(profile.copy(domainSuffixMatch = "*.nitsrinagar.lab"))
        refused(profile.copy(domainSuffixMatch = "lab"))
        refused(profile.copy(altSubjectMatch = "radius.nitsrinagar.lab"))
        refused(profile.copy(altSubjectMatch = "DNS:"))
    }

    @Test
    fun caMustBeReadable() {
        assertTrue(refused(profile.copy(caPem = "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")).contains("cannot be read"))
        assertTrue(refused(profile.copy(caPem = "")).contains("cannot be read"))
    }

    @Test
    fun caMustBeACa() {
        assertTrue(refused(profile.copy(caPem = resource("test-leaf.pem"))).contains("not a CA"))
    }

    @Test
    fun caMustBeValidNow() {
        val notAfter = WifiPlanner.caCertificate(caPem).notAfter
        val notBefore = WifiPlanner.caCertificate(caPem).notBefore
        assertTrue(refused(profile, Date(notAfter.time + 1000)).contains("expired"))
        assertTrue(refused(profile, Date(notBefore.time - 86_400_000)).contains("not valid yet"))
    }

    // ---- result messages ------------------------------------------------------------------------

    @Test
    fun addNetworksResults() {
        assertTrue(SetupMessages.addNetworks("NITS-Lab", true, listOf(AddNetworkOutcome.SUCCESS)).saved)
        assertTrue(SetupMessages.addNetworks("NITS-Lab", true, null).saved)
        val exists = SetupMessages.addNetworks("NITS-Lab", true, listOf(AddNetworkOutcome.ALREADY_EXISTS))
        assertTrue(exists.saved)
        assertTrue(exists.message.contains("already saved"))
        assertFalse(SetupMessages.addNetworks("NITS-Lab", true, listOf(AddNetworkOutcome.FAILED)).saved)
        val cancelled = SetupMessages.addNetworks("NITS-Lab", false, null)
        assertFalse(cancelled.saved)
        assertTrue(cancelled.message.contains("not saved"))
    }

    @Test
    fun suggestionResults() {
        val ok = SetupMessages.suggestion("NITS-Lab", SuggestionStatus.SUCCESS)
        assertTrue(ok.saved)
        assertTrue("Android 10 approval notification is explained", ok.message.contains("Allow"))
        assertTrue(SetupMessages.suggestion("NITS-Lab", SuggestionStatus.DUPLICATE).saved)
        for (s in listOf(SuggestionStatus.APP_DISALLOWED, SuggestionStatus.EXCEEDS_MAX, SuggestionStatus.INVALID, SuggestionStatus.INTERNAL)) {
            assertFalse(SetupMessages.suggestion("NITS-Lab", s).saved)
        }
    }
}
