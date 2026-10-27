package `in`.ac.nitsri.wifi.core

import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.ByteArrayInputStream
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date

/**
 * EAP-TLS with a device certificate (docs/api/v1.md sections 6 and 7).
 *
 * The key pair is made on the phone, in memory, by the platform's software provider: it is NOT an
 * AndroidKeyStore key. `WifiEnterpriseConfig.setClientKeyEntry*` sends the key to the Wi-Fi
 * service as PKCS#8 bytes (`PrivateKey.getEncoded()`, see AOSP `ParcelUtil.writePrivateKey`), and
 * an AndroidKeyStore key is not exportable (`getEncoded()` is null). The only API that takes a
 * key by reference, `setClientKeyPairAlias` (API 31), needs a KeyChain key that a device policy
 * owner granted to Wi-Fi (`DevicePolicyManager.grantKeyPairToWifiAuth`), which this app is not.
 *
 * So the app keeps the private key only in memory, in local variables, from [DeviceKeys.generate]
 * until Android has saved the network; it never writes it to a file, preferences, a Bundle, a log
 * or a backup (allowBackup is false). Android then keeps the key in its own Wi-Fi key store and
 * deletes it with the network.
 */
object DeviceKeys {
    /** A new EC P-256 key pair (software, in memory). */
    fun generate(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }
}

/** PKCS#10 certificate requests. The server ignores the subject (it puts CN = uid) but it is the uid here too. */
object Csr {
    private const val SIGNATURE = "SHA256withECDSA"

    fun pem(keys: KeyPair, uid: String): String {
        val subject = X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, uid).build()
        val signer = JcaContentSignerBuilder(SIGNATURE).build(keys.private)
        val der = JcaPKCS10CertificationRequestBuilder(subject, keys.public).build(signer).encoded
        val body = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)
        return "-----BEGIN CERTIFICATE REQUEST-----\n$body\n-----END CERTIFICATE REQUEST-----\n"
    }
}

/** The client key and certificate chain (device certificate first, then the Device CA). */
class TlsCredential(val privateKey: PrivateKey, val chain: List<X509Certificate>, val serial: String) {
    // Never the key in a log or a crash report
    override fun toString() = "TlsCredential(serial=$serial)"
}

/** The result of [TlsEnrollment.enroll]: ready to save, or refused with a message for the user. */
sealed interface EnrollResult {
    class Ready(val plan: TlsPlan, val credential: TlsCredential) : EnrollResult

    data class Refused(val message: String) : EnrollResult
}

/**
 * The EAP-TLS setup steps that need the network: `GET /profiles/android?method=tls`, a new key
 * pair and CSR, `POST /certs`, and the checks of the new certificate. Blocks: run it off the main
 * thread. API errors are thrown as [ApiException] (`409 cert_limit` included, see [CertMessages]).
 */
class TlsEnrollment(
    private val api: ApiClient,
    private val newKeys: () -> KeyPair = DeviceKeys::generate,
    private val clock: () -> Date = ::Date,
) {
    fun enroll(label: String): EnrollResult {
        val plan = try {
            WifiPlanner.planTls(api.androidProfile(ApiClient.METHOD_TLS), clock())
        } catch (e: WifiPlanException) {
            return EnrollResult.Refused(e.message.orEmpty())        // no certificate was issued
        }
        val keys = newKeys()
        val issued = api.issueCert(Csr.pem(keys, plan.identity), CertLabels.clean(label))
        return try {
            EnrollResult.Ready(plan, TlsCertificates.credential(keys, issued, clock()))
        } catch (e: WifiPlanException) {
            // A certificate that this phone cannot use must not take one of the 3 places
            try {
                api.revokeCert(issued.serial)
            } catch (ignored: ApiException) {
            }
            EnrollResult.Refused(e.message.orEmpty())
        }
    }
}

/** Checks of the `POST /certs` answer. */
object TlsCertificates {
    private const val CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

    /**
     * The device certificate must be for [keys] (same public key), not a CA, valid at [now], and
     * allowed for client authentication. The chain is the CA certificates of `chain_pem` that are
     * not self-signed (the Device CA): Android gets the device certificate and the Device CA; the
     * server has the root.
     */
    fun credential(keys: KeyPair, issued: IssuedCert, now: Date = Date()): TlsCredential {
        val leaf = parse(issued.certPem).firstOrNull() ?: fail("The portal sent a certificate that cannot be read.")
        if (!leaf.publicKey.encoded.contentEquals(keys.public.encoded)) {
            fail("The portal sent a certificate for another key. Try again.")
        }
        if (leaf.basicConstraints >= 0) fail("The portal sent a CA certificate as the device certificate.")
        val usages = try {
            leaf.extendedKeyUsage
        } catch (e: CertificateException) {
            null
        }
        if (usages != null && CLIENT_AUTH !in usages) fail("The portal sent a certificate that cannot sign in to Wi-Fi.")
        try {
            leaf.checkValidity(now)
        } catch (e: CertificateExpiredException) {
            fail("The new certificate has already expired. Check the date and time of the phone.")
        } catch (e: CertificateNotYetValidException) {
            fail("The new certificate is not valid yet. Check the date and time of the phone.")
        }
        val intermediates = issued.chainPem?.let(::parse).orEmpty()
            .filter { it.basicConstraints >= 0 && it.subjectX500Principal != it.issuerX500Principal }
        val issuer = intermediates.firstOrNull { it.subjectX500Principal == leaf.issuerX500Principal }
        if (issuer != null) {
            try {
                leaf.verify(issuer.publicKey)
            } catch (e: GeneralSecurityException) {
                fail("The portal sent a certificate chain that does not match.")
            }
        }
        return TlsCredential(keys.private, listOf(leaf) + intermediates, issued.serial)
    }

    private fun parse(pem: String): List<X509Certificate> = try {
        CertificateFactory.getInstance("X.509")
            .generateCertificates(ByteArrayInputStream(pem.toByteArray(Charsets.US_ASCII)))
            .filterIsInstance<X509Certificate>()
    } catch (e: CertificateException) {
        fail("The portal sent a certificate that cannot be read.")
    }

    private fun fail(message: String): Nothing = throw WifiPlanException(message)
}

/** The `label` of `POST /certs`: 1 to 40 characters (docs/api/v1.md section 6). */
object CertLabels {
    const val MAX = 40
    const val FALLBACK = "Android phone"

    /** "samsung" + "SM-S911B" -> "samsung SM-S911B"; the model alone when it already names the maker. */
    fun of(manufacturer: String?, model: String?): String {
        val maker = manufacturer.orEmpty().trim()
        val name = model.orEmpty().trim()
        val label = if (maker.isEmpty() || name.startsWith(maker, ignoreCase = true)) name else "$maker $name"
        return clean(label)
    }

    /** Printable characters only, single spaces, at most [MAX] code points; [FALLBACK] when empty. */
    fun clean(label: String): String {
        val text = label.filter { !it.isISOControl() }.split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ")
        if (text.isEmpty()) return FALLBACK
        val cps = text.codePoints().limit(MAX.toLong()).toArray()
        return String(cps, 0, cps.size).trim()
    }
}

/** Texts for the certificate parts of the Wi-Fi screen. */
object CertMessages {

    /** The message for a failed `POST /certs` (or the profile call before it). */
    fun issueError(e: ApiException): String = when {
        e.certLimit -> "You already have 3 active device certificates, the most you can have. " +
            "Revoke the certificate of a device that you no longer use (below), then try again."
        e.code == "bad_csr" -> "The portal refused the certificate request of this app. Update the app."
        e.status == 404 -> "This portal does not give device certificates yet. Use the password setup."
        else -> e.message.orEmpty()
    }

    fun title(c: DeviceCert): String = if (c.active) c.label else "${c.label} · ${revokedText(c)}"

    fun detail(c: DeviceCert): String {
        val dates = "Issued ${Formats.time(c.issuedAt)} · valid until ${Formats.time(c.notAfter)}"
        val via = when (c.via) {
            "app" -> " · from this app"
            "web" -> " · from the web portal"
            else -> ""
        }
        val revoked = if (c.revokedAt != null) "\nRevoked ${Formats.time(c.revokedAt)}" else ""
        return "$dates$via\nSerial ${c.serial}$revoked"
    }

    fun count(list: CertList): String {
        val active = list.certs.count { it.active }
        return if (list.limit == null) "$active active" else "$active of ${list.limit} active"
    }

    fun revoked(r: RevokeResult, reauthInterval: Int? = null): String {
        val base = "The certificate ${r.serial} is revoked. A device that uses it cannot sign in again."
        return if (r.disconnect.isEmpty()) base else base + "\n" + Formats.disconnectResults(r.disconnect, reauthInterval)
    }

    /** After "Not me": which certificates of the device were revoked, or "" when none. */
    fun afterNotMe(r: Review): String {
        val lines = mutableListOf<String>()
        val n = r.revoked?.size ?: 0
        if (n == 1) lines += "1 device certificate of this device is revoked."
        if (n > 1) lines += "$n device certificates of this device are revoked."
        if (!r.revokeFailed.isNullOrEmpty()) {
            lines += "A device certificate could not be revoked. Revoke it under Set up Wi-Fi > Device certificates."
        }
        return lines.joinToString("\n")
    }

    /** The setup was not saved, so the app revoked the new certificate (its key is gone). */
    fun unusedRevoked(serial: String) =
        "The new certificate $serial was revoked, so that it does not count against your 3 devices."

    private fun revokedText(c: DeviceCert) = when (c.revokeReason) {
        "user" -> "revoked by you"
        "not_me" -> "revoked (Not me)"
        "admin" -> "revoked by the administrator"
        null -> if (c.revokedAt == null) "expired" else "revoked"
        else -> "revoked"
    }
}
