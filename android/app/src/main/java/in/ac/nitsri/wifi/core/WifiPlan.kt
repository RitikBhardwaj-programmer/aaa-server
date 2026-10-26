package `in`.ac.nitsri.wifi.core

import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Everything that goes into the `WifiEnterpriseConfig`, checked, except the password: the user
 * types that on the phone (the API never sends one). wifi/WifiInstaller.kt applies the plan:
 *
 * | plan field          | WifiEnterpriseConfig                     |
 * |---------------------|------------------------------------------|
 * | (always)            | setEapMethod(Eap.TTLS)                   |
 * | (always)            | setPhase2Method(Phase2.PAP)              |
 * | identity            | setIdentity                              |
 * | anonymousIdentity   | setAnonymousIdentity                     |
 * | caCertificate       | setCaCertificate                         |
 * | domainSuffixMatch   | setDomainSuffixMatch                     |
 * | altSubjectMatch     | setAltSubjectMatch                       |
 */
data class WifiPlan(
    val ssid: String,
    val identity: String,
    val anonymousIdentity: String,
    val domainSuffixMatch: String,
    val altSubjectMatch: String,
    val caCertificate: X509Certificate,
)

class WifiPlanException(message: String) : Exception(message)

object WifiPlanner {

    private val HOST = Regex("(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")

    /** Checks the `GET /profiles/android` answer (docs/api/v1.md section 5) and makes the plan. */
    fun plan(p: AndroidProfile, now: Date = Date()): WifiPlan {
        if (p.eap != "TTLS") fail("This app sets up EAP-TTLS only, but the portal offered ${p.eap}. Update the app.")
        if (p.phase2 != "PAP") fail("This app sets up EAP-TTLS with PAP only, but the portal offered ${p.phase2}. Update the app.")
        val ssidBytes = p.ssid.toByteArray(Charsets.UTF_8).size
        if (p.ssid.isBlank() || ssidBytes > 32) fail("The portal sent a network name that is not valid.")
        if (p.identity.isBlank()) fail("The portal sent no user ID for the network.")
        val anonymous = p.anonymousIdentity
        if (anonymous.isNullOrBlank()) fail("The portal sent no anonymous identity for the network.")
        val domain = p.domainSuffixMatch
        if (!HOST.matches(domain)) fail("The portal sent a server name that is not valid.")
        // Older portals might send only the domain; the brief's rule is "DNS:" + domain.
        val alt = p.altSubjectMatch ?: "DNS:$domain"
        if (!alt.split(';').all { it.startsWith("DNS:") && HOST.matches(it.removePrefix("DNS:")) }) {
            fail("The portal sent a server name check that is not valid.")
        }
        return WifiPlan(p.ssid, p.identity, anonymous, domain, alt, caCertificate(p.caPem, now))
    }

    /** The first certificate of [pem]. It must be a CA certificate that is valid at [now]. */
    fun caCertificate(pem: String, now: Date = Date()): X509Certificate {
        val cert = try {
            CertificateFactory.getInstance("X.509")
                .generateCertificates(ByteArrayInputStream(pem.toByteArray(Charsets.US_ASCII)))
                .firstOrNull() as? X509Certificate
        } catch (e: CertificateException) {
            null
        } ?: fail("The portal sent a CA certificate that cannot be read.")
        if (cert.basicConstraints < 0) fail("The portal sent a certificate that is not a CA certificate.")
        try {
            cert.checkValidity(now)
        } catch (e: CertificateExpiredException) {
            fail("The lab CA certificate has expired. Tell the lab administrator.")
        } catch (e: CertificateNotYetValidException) {
            fail("The lab CA certificate is not valid yet. Check the date and time of the phone.")
        }
        return cert
    }

    private fun fail(message: String): Nothing = throw WifiPlanException(message)
}

/** Android 11+: the per-network result of `Settings.ACTION_WIFI_ADD_NETWORKS`. */
enum class AddNetworkOutcome { SUCCESS, ALREADY_EXISTS, FAILED }

/** Android 10: the status of `WifiManager.addNetworkSuggestions`. */
enum class SuggestionStatus { SUCCESS, DUPLICATE, APP_DISALLOWED, EXCEEDS_MAX, INVALID, INTERNAL }

class SetupResult(val saved: Boolean, val message: String)

/** The text that the Wi-Fi screen shows after a setup attempt. */
object SetupMessages {

    /**
     * [resultOk] is `resultCode == RESULT_OK`. [outcomes] is `EXTRA_WIFI_NETWORK_RESULT_LIST`
     * (one entry per network; null when Settings sent none).
     */
    fun addNetworks(ssid: String, resultOk: Boolean, outcomes: List<AddNetworkOutcome>?): SetupResult {
        if (!resultOk) return SetupResult(false, "$ssid was not saved. Tap Set up Wi-Fi to try again.")
        return when (outcomes?.firstOrNull()) {
            null, AddNetworkOutcome.SUCCESS ->
                SetupResult(true, "$ssid is saved. The phone connects when the network is in range.")
            AddNetworkOutcome.ALREADY_EXISTS ->
                SetupResult(true, "$ssid was already saved with these settings.")
            AddNetworkOutcome.FAILED ->
                SetupResult(false, "Android could not save $ssid. Remove the old $ssid network in Settings > Wi-Fi, then try again.")
        }
    }

    fun suggestion(ssid: String, status: SuggestionStatus): SetupResult = when (status) {
        SuggestionStatus.SUCCESS, SuggestionStatus.DUPLICATE -> SetupResult(
            true,
            "$ssid is suggested to Android. Look for the notification \"Allow suggested Wi-Fi networks?\" " +
                "and tap Allow. Then the phone connects when $ssid is in range.",
        )
        SuggestionStatus.APP_DISALLOWED -> SetupResult(
            false,
            "You turned off Wi-Fi suggestions for this app. Turn them on in Settings > Apps > NITS Wi-Fi " +
                "(Wi-Fi control or Special app access), then try again.",
        )
        SuggestionStatus.EXCEEDS_MAX -> SetupResult(false, "Android has too many suggested networks. Try again later.")
        SuggestionStatus.INVALID -> SetupResult(false, "Android refused the network settings. Update the app.")
        SuggestionStatus.INTERNAL -> SetupResult(false, "Android could not add $ssid. Try again.")
    }
}
