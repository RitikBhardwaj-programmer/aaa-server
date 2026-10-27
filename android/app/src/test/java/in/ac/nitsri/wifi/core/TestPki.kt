package `in`.ac.nitsri.wifi.core

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import java.math.BigInteger
import java.security.KeyPair
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

/** A throwaway root CA and Device CA that sign CSRs as pki.py would (CN = uid, clientAuth). */
class TestPki {
    val rootKeys: KeyPair = DeviceKeys.generate()
    val root: X509Certificate = cert("CN=Unit Test Root CA", rootKeys.public, X500Name("CN=Unit Test Root CA"), rootKeys, ca = true)
    val deviceCaKeys: KeyPair = DeviceKeys.generate()
    val deviceCa: X509Certificate = cert("CN=Unit Test Device CA", deviceCaKeys.public, X500Name(root.subjectX500Principal.name), rootKeys, ca = true)
    private var serial = 0x4f1c0eL

    fun cert(
        subject: String,
        key: PublicKey,
        issuer: X500Name,
        signer: KeyPair,
        ca: Boolean = false,
        clientAuth: Boolean = true,
        from: Date = Date(System.currentTimeMillis() - 60_000),
        to: Date = Date(System.currentTimeMillis() + 365L * 86_400_000),
    ): X509Certificate {
        val b = JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(serial++), from, to, X500Name(subject), key)
            .addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
        if (!ca) {
            val purpose = if (clientAuth) KeyPurposeId.id_kp_clientAuth else KeyPurposeId.id_kp_serverAuth
            b.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(purpose))
        }
        return JcaX509CertificateConverter().getCertificate(b.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private)))
    }

    /** A device certificate for [key], issued by the Device CA. */
    fun device(key: PublicKey, uid: String = "student042", clientAuth: Boolean = true, to: Date? = null) =
        if (to == null) cert("CN=$uid", key, X500Name(deviceCa.subjectX500Principal.name), deviceCaKeys, clientAuth = clientAuth)
        else cert("CN=$uid", key, X500Name(deviceCa.subjectX500Principal.name), deviceCaKeys, clientAuth = clientAuth,
            from = Date(to.time - 86_400_000), to = to)

    /** The `POST /certs` answer for [cert]. */
    fun issued(cert: X509Certificate, label: String = "Pixel 8") = org.json.JSONObject()
        .put("serial", cert.serialNumber.toString(16))
        .put("label", label)
        .put("issued_at", "2026-10-27T10:00:00+05:30")
        .put("not_after", "2027-10-27T10:00:00+05:30")
        .put("cert_pem", pem(cert))
        .put("chain_pem", pem(deviceCa) + pem(root))
        .toString()

    companion object {
        fun pem(c: X509Certificate) =
            "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(c.encoded) +
                "\n-----END CERTIFICATE-----\n"

        fun csr(pem: String): PKCS10CertificationRequest {
            val body = pem.removePrefix("-----BEGIN CERTIFICATE REQUEST-----").substringBefore("-----END CERTIFICATE REQUEST-----")
            return PKCS10CertificationRequest(Base64.getMimeDecoder().decode(body))
        }

        fun csrKey(pem: String): PublicKey = JcaPKCS10CertificationRequest(csr(pem)).publicKey
    }
}
