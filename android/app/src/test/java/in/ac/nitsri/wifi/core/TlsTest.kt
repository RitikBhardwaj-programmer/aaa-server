package `in`.ac.nitsri.wifi.core

import org.bouncycastle.asn1.ASN1String
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.interfaces.ECPublicKey
import java.util.Date

/** EAP-TLS: key and CSR, the TLS plan, the certificate checks and the enrollment flow (core/Tls.kt). */
class TlsTest {

    private val pki = TestPki()
    private val caPem = TestPki.pem(pki.root)
    private val tlsProfile = AndroidProfile(
        ssid = "NITS-Lab",
        eap = "TLS",
        phase2 = null,
        identity = "student042",
        anonymousIdentity = null,
        domainSuffixMatch = "radius.nitsrinagar.lab",
        altSubjectMatch = "DNS:radius.nitsrinagar.lab",
        caPem = caPem,
    )

    private val http = FakeTransport()
    private val client = ApiClient("http://127.0.0.1:8081", http, TokenHolder()).also {
        http.answer(200, Contract.TOKEN)
        it.login("student042", "correct horse battery")
        http.requests.clear()
    }

    private fun refused(block: () -> Unit): String {
        try {
            block()
        } catch (e: WifiPlanException) {
            return e.message!!
        }
        fail("accepted")
        throw AssertionError()
    }

    // ---- key pair and CSR ----------------------------------------------------------------------

    @Test
    fun keyIsEcP256InSoftware() {
        val keys = DeviceKeys.generate()
        assertEquals("EC", keys.private.algorithm)
        assertEquals(256, (keys.public as ECPublicKey).params.order.bitLength())
        // A software key: its PKCS#8 bytes exist, which setClientKeyEntry needs (an AndroidKeyStore key has none)
        assertEquals("PKCS#8", keys.private.format)
        assertTrue(keys.private.encoded.isNotEmpty())
    }

    @Test
    fun csrIsSignedByTheKeyAndNamesTheUid() {
        val keys = DeviceKeys.generate()
        val pem = Csr.pem(keys, "student042")
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----\n"))
        assertTrue(pem.endsWith("\n-----END CERTIFICATE REQUEST-----\n"))
        assertTrue(pem.lines().all { it.length <= 64 })
        val csr = TestPki.csr(pem)
        assertTrue(csr.isSignatureValid(JcaContentVerifierProviderBuilder().build(keys.public)))
        assertEquals("student042", (csr.subject.getRDNs(BCStyle.CN).single().first.value as ASN1String).string)
        assertTrue(TestPki.csrKey(pem).encoded.contentEquals(keys.public.encoded))
        assertFalse("never the private key", pem.contains("PRIVATE"))
    }

    @Test
    fun csrSubjectCannotBeChangedByTheUid() {
        val csr = TestPki.csr(Csr.pem(DeviceKeys.generate(), "a,O=evil+CN=b"))
        assertEquals(1, csr.subject.rdNs.size)
        assertEquals("a,O=evil+CN=b", (csr.subject.getRDNs(BCStyle.CN).single().first.value as ASN1String).string)
    }

    // ---- TLS plan --------------------------------------------------------------------------------

    @Test
    fun contractTlsProfileMapsToPlan() {
        val plan = WifiPlanner.planTls(Parse.androidProfile(JSONObject(Contract.tlsProfile(caPem))))
        assertEquals(TlsPlan("NITS-Lab", "student042", "radius.nitsrinagar.lab", "DNS:radius.nitsrinagar.lab", pki.root), plan)
    }

    @Test
    fun tlsPlanRefusesOtherMethodsAndBadValues() {
        assertTrue(refused { WifiPlanner.planTls(tlsProfile.copy(eap = "TTLS", phase2 = "PAP")) }.contains("instead of EAP-TLS"))
        assertTrue(refused { WifiPlanner.planTls(tlsProfile.copy(phase2 = "PAP")) }.contains("inner method"))
        assertTrue(refused { WifiPlanner.planTls(tlsProfile.copy(domainSuffixMatch = "bad name")) }.contains("server name"))
        assertTrue(refused { WifiPlanner.planTls(tlsProfile.copy(identity = " ")) }.contains("user ID"))
        assertTrue(refused { WifiPlanner.planTls(tlsProfile.copy(caPem = TestPki.pem(pki.device(DeviceKeys.generate().public)))) }
            .contains("not a CA"))
        // The TTLS planner still refuses a TLS profile: TTLS stays as it was
        assertTrue(refused { WifiPlanner.plan(tlsProfile) }.contains("EAP-TTLS only"))
    }

    // ---- certificate checks ----------------------------------------------------------------------

    private fun issued(json: String) = Parse.issuedCert(JSONObject(json))

    @Test
    fun credentialHasTheKeyTheDeviceCertAndTheDeviceCa() {
        val keys = DeviceKeys.generate()
        val leaf = pki.device(keys.public)
        val c = TlsCertificates.credential(keys, issued(pki.issued(leaf)))
        assertEquals(listOf(leaf, pki.deviceCa), c.chain)       // the root stays out: the server has it
        assertEquals(keys.private, c.privateKey)
        assertEquals(leaf.serialNumber.toString(16), c.serial)
        assertFalse(c.toString().contains(keys.private.toString()))
    }

    @Test
    fun certificateForAnotherKeyIsRefused() {
        val leaf = pki.device(DeviceKeys.generate().public)
        assertTrue(refused { TlsCertificates.credential(DeviceKeys.generate(), issued(pki.issued(leaf))) }.contains("another key"))
    }

    @Test
    fun caExpiredOrServerOnlyCertificatesAreRefused() {
        val keys = DeviceKeys.generate()
        val ca = pki.cert("CN=student042", keys.public, org.bouncycastle.asn1.x500.X500Name(pki.deviceCa.subjectX500Principal.name),
            pki.deviceCaKeys, ca = true)
        assertTrue(refused { TlsCertificates.credential(keys, issued(pki.issued(ca))) }.contains("CA certificate"))
        val serverOnly = pki.device(keys.public, clientAuth = false)
        assertTrue(refused { TlsCertificates.credential(keys, issued(pki.issued(serverOnly))) }.contains("cannot sign in"))
        val expired = pki.device(keys.public, to = Date(System.currentTimeMillis() - 86_400_000))
        assertTrue(refused { TlsCertificates.credential(keys, issued(pki.issued(expired))) }.contains("expired"))
        val junk = JSONObject(pki.issued(pki.device(keys.public))).put("cert_pem", "junk").toString()
        assertTrue(refused { TlsCertificates.credential(keys, issued(junk)) }.contains("cannot be read"))
    }

    @Test
    fun chainThatDidNotSignTheCertificateIsRefused() {
        val keys = DeviceKeys.generate()
        val other = TestPki()
        val leaf = other.device(keys.public)                        // signed by another Device CA of the same name
        val json = JSONObject(pki.issued(leaf)).toString()
        assertTrue(refused { TlsCertificates.credential(keys, issued(json)) }.contains("does not match"))
    }

    // ---- enrollment flow -------------------------------------------------------------------------

    private fun signCsr(clientAuth: Boolean = true, otherKey: Boolean = false) = http.respond { r ->
        val csrPem = JSONObject(r.body!!).getString("csr_pem")
        val key = if (otherKey) DeviceKeys.generate().public else TestPki.csrKey(csrPem)
        HttpResponse(201, pki.issued(pki.device(key, clientAuth = clientAuth)))
    }

    @Test
    fun enrollAsksForTheTlsProfileThenSendsTheCsr() {
        http.answer(200, Contract.tlsProfile(caPem))
        signCsr()
        val r = TlsEnrollment(client).enroll("samsung SM-S911B") as EnrollResult.Ready

        assertEquals("http://127.0.0.1:8081/api/v1/profiles/android?method=tls", http.requests[0].url)
        val post = http.requests[1]
        assertEquals("POST", post.method)
        assertEquals("http://127.0.0.1:8081/api/v1/certs", post.url)
        val body = JSONObject(post.body!!)
        assertEquals(setOf("csr_pem", "label"), body.keySet())
        assertEquals("samsung SM-S911B", body.getString("label"))
        assertTrue(TestPki.csrKey(body.getString("csr_pem")).encoded.contentEquals(r.credential.chain[0].publicKey.encoded))
        assertFalse("the private key never leaves the phone", post.body!!.contains("PRIVATE"))
        assertEquals("student042", r.plan.identity)
        assertEquals(2, r.credential.chain.size)
        assertEquals(2, http.requests.size)
    }

    @Test
    fun certLimitIsAnApiErrorWithAClearMessage() {
        http.answer(200, Contract.tlsProfile(caPem))
        http.answer(409, Contract.error("cert_limit", "You have 3 active certificates."))
        try {
            TlsEnrollment(client).enroll("Pixel 8")
            fail("no ApiException")
        } catch (e: ApiException) {
            assertTrue(e.certLimit)
            assertTrue(CertMessages.issueError(e).contains("Revoke the certificate of a device"))
        }
    }

    @Test
    fun badProfileIssuesNoCertificate() {
        http.answer(200, Contract.profile(caPem))                    // a TTLS answer to ?method=tls
        val r = TlsEnrollment(client).enroll("Pixel 8")
        assertTrue((r as EnrollResult.Refused).message.contains("instead of EAP-TLS"))
        assertEquals(1, http.requests.size)
    }

    @Test
    fun unusableCertificateIsRevokedAtOnce() {
        http.answer(200, Contract.tlsProfile(caPem))
        signCsr(otherKey = true)
        http.answer(200, Contract.REVOKE)
        val r = TlsEnrollment(client).enroll("Pixel 8")
        assertTrue((r as EnrollResult.Refused).message.contains("another key"))
        val delete = http.requests[2]
        assertEquals("DELETE", delete.method)
        assertTrue(delete.url.startsWith("http://127.0.0.1:8081/api/v1/certs/"))
        assertNull(delete.body)
    }

    @Test
    fun aFailedRevokeOfAnUnusableCertificateStillRefuses() {
        http.answer(200, Contract.tlsProfile(caPem))
        signCsr(clientAuth = false)
        http.answer(503, Contract.error("unavailable", "Try again later."))
        assertTrue(TlsEnrollment(client).enroll("Pixel 8") is EnrollResult.Refused)
    }

    // ---- labels and messages ---------------------------------------------------------------------

    @Test
    fun labels() {
        assertEquals("samsung SM-S911B", CertLabels.of("samsung", "SM-S911B"))
        assertEquals("Google Pixel 8", CertLabels.of("Google", "Pixel 8"))
        assertEquals("OnePlus 12", CertLabels.of("OnePlus", "OnePlus 12"))      // no maker twice
        assertEquals(CertLabels.FALLBACK, CertLabels.of(null, " \n"))
        assertEquals(40, CertLabels.clean("x".repeat(80)).length)
        assertEquals("a b", CertLabels.clean("a\u0000\t\n b"))
        val emoji = "📱".repeat(41)
        assertEquals(40, CertLabels.clean(emoji).codePointCount(0, CertLabels.clean(emoji).length))
    }

    @Test
    fun messages() {
        val list = Parse.certList(JSONObject(Contract.CERTS))
        assertEquals("1 of 3 active", CertMessages.count(list))
        assertEquals("Pixel 8", CertMessages.title(list.certs[0]))
        assertEquals("MacBook · revoked (Not me)", CertMessages.title(list.certs[1]))
        assertTrue(CertMessages.detail(list.certs[1]).contains("from the web portal"))
        assertTrue(CertMessages.detail(list.certs[1]).contains("Revoked 20 Oct 09:00"))
        assertTrue(CertMessages.issueError(ApiException(400, "bad_csr", "x")).contains("Update the app"))
        assertTrue(CertMessages.issueError(ApiException(404, "not_found", "x")).contains("does not give device certificates"))
        assertEquals("Try later.", CertMessages.issueError(ApiException(503, "unavailable", "Try later.")))
        val revoked = CertMessages.revoked(Parse.revoke(JSONObject(Contract.REVOKE)))
        assertTrue(revoked.contains("4f1c0e is revoked") && revoked.contains("10.89.0.1: disconnected."))
        val review = Parse.review(JSONObject(Contract.REVIEW_NOT_ME_REVOKED))
        assertEquals("2 device certificates of this device are revoked.", CertMessages.afterNotMe(review))
        assertEquals("", CertMessages.afterNotMe(Parse.review(JSONObject(Contract.REVIEW_NOT_ME))))
        assertTrue(CertMessages.afterNotMe(review.copy(revoked = emptyList(), revokeFailed = listOf("*"))).contains("could not be revoked"))
    }
}
