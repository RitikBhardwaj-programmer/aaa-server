package `in`.ac.nitsri.wifi.core

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

// Response shapes of docs/api/v1.md. Unknown fields are ignored (section "Clients must ignore
// fields that they do not know"). Times stay ISO 8601 strings; Formats turns them into text.

data class User(val uid: String, val student: Boolean, val deviceLimit: Int?)

data class DeviceSession(
    val accessPoint: String?,
    val ip: String?,
    val started: String?,
    val updated: String?,
    val bytesUp: Long?,
    val bytesDown: Long?,
)

data class Slot(val mac: String, val joined: String?, val overLimit: Boolean, val session: DeviceSession?)

data class KnownDevice(val mac: String, val firstSeen: String?, val lastSeen: String?, val online: Boolean)

data class LimitEvent(val time: String?, val mac: String, val liveDevices: Int?, val deviceLimit: Int?, val mode: String)

data class Devices(
    val online: Int,
    val deviceLimit: Int?,
    val reauthInterval: Int?,
    val slots: List<Slot>,
    val known: List<KnownDevice>,
    val limitEvents: List<LimitEvent>,
)

/** One NAS answer to a Disconnect-Request: `result` is "ACK", "NAK" or "none". */
data class NasResult(val nas: String, val result: String)

data class DisconnectResult(val mac: String, val results: List<NasResult>)

data class SignIn(val time: String?, val result: String, val accessPoint: String?, val mac: String?, val privateMac: Boolean)

data class SignInActivity(val days: Int, val signins: List<SignIn>)

data class Alert(val mac: String, val firstSeen: String?, val lastSeen: String?, val online: Boolean, val privateMac: Boolean)

data class Alerts(val count: Int, val alerts: List<Alert>)

/**
 * The answer to `POST /alerts/{mac}`. [revoked] and [revokeFailed] (docs/api/v1.md section 7) are
 * the serials of the device's certificates that "Not me" revoked or could not revoke; null for
 * "This was me" and on a portal without certificates.
 */
data class Review(
    val mac: String,
    val verdict: String,
    val disconnect: List<NasResult>?,
    val next: String?,
    val revoked: List<String>? = null,
    val revokeFailed: List<String>? = null,
)

data class AndroidProfile(
    val ssid: String,
    val eap: String,
    val phase2: String?,
    val identity: String,
    val anonymousIdentity: String?,
    val domainSuffixMatch: String,
    val altSubjectMatch: String?,
    val caPem: String,
)

/** One device certificate of `GET /certs` (docs/api/v1.md section 6). */
data class DeviceCert(
    val serial: String,
    val label: String,
    val issuedAt: String?,
    val notAfter: String?,
    val revokedAt: String?,
    val revokeReason: String?,
    val via: String?,
    val active: Boolean,
)

data class CertList(val limit: Int?, val certs: List<DeviceCert>)

/** The answer to `POST /certs`: the new certificate and its chain (Device CA, then root CA). */
data class IssuedCert(
    val serial: String,
    val label: String,
    val issuedAt: String?,
    val notAfter: String?,
    val certPem: String,
    val chainPem: String?,
)

data class RevokeResult(val serial: String, val revokedAt: String?, val disconnect: List<NasResult>)

/** JSON to models. Throws [JSONException] when a required field is missing or has the wrong type. */
internal object Parse {

    fun user(o: JSONObject) = User(o.str("uid"), o.getBoolean("student"), o.intOrNull("device_limit"))

    fun devices(o: JSONObject) = Devices(
        online = o.getInt("online"),
        deviceLimit = o.intOrNull("device_limit"),
        reauthInterval = o.intOrNull("reauth_interval"),
        slots = o.list("slots") { s ->
            Slot(
                mac = s.str("mac"),
                joined = s.strOrNull("joined"),
                overLimit = s.optBoolean("over_limit", false),
                session = s.objOrNull("session")?.let {
                    DeviceSession(
                        accessPoint = it.strOrNull("access_point"),
                        ip = it.strOrNull("ip"),
                        started = it.strOrNull("started"),
                        updated = it.strOrNull("updated"),
                        bytesUp = it.longOrNull("bytes_up"),
                        bytesDown = it.longOrNull("bytes_down"),
                    )
                },
            )
        },
        known = o.list("known") { KnownDevice(it.str("mac"), it.strOrNull("first_seen"), it.strOrNull("last_seen"), it.optBoolean("online", false)) },
        limitEvents = o.list("limit_events") {
            LimitEvent(it.strOrNull("time"), it.str("mac"), it.intOrNull("live_devices"), it.intOrNull("device_limit"), it.str("mode"))
        },
    )

    fun disconnect(o: JSONObject) = DisconnectResult(o.str("mac"), nasResults(o.getJSONArray("results")))

    fun activity(o: JSONObject) = SignInActivity(
        days = o.getInt("days"),
        signins = o.list("signins") {
            SignIn(it.strOrNull("time"), it.str("result"), it.strOrNull("access_point"), it.strOrNull("mac"), it.optBoolean("private_mac", false))
        },
    )

    fun alerts(o: JSONObject) = Alerts(
        count = o.getInt("count"),
        alerts = o.list("alerts") {
            Alert(it.str("mac"), it.strOrNull("first_seen"), it.strOrNull("last_seen"), it.optBoolean("online", false), it.optBoolean("private_mac", false))
        },
    )

    fun review(o: JSONObject) = Review(
        mac = o.str("mac"),
        verdict = o.str("verdict"),
        disconnect = if (o.isNull("disconnect")) null else nasResults(o.getJSONArray("disconnect")),
        next = o.strOrNull("next"),
        revoked = o.strListOrNull("revoked"),
        revokeFailed = o.strListOrNull("revoke_failed"),
    )

    fun certList(o: JSONObject) = CertList(
        limit = o.intOrNull("limit"),
        certs = o.list("certs") {
            DeviceCert(
                serial = it.str("serial"),
                label = it.str("label"),
                issuedAt = it.strOrNull("issued_at"),
                notAfter = it.strOrNull("not_after"),
                revokedAt = it.strOrNull("revoked_at"),
                revokeReason = it.strOrNull("revoke_reason"),
                via = it.strOrNull("via"),
                active = it.getBoolean("active"),
            )
        },
    )

    fun issuedCert(o: JSONObject) = IssuedCert(
        serial = o.str("serial"),
        label = o.str("label"),
        issuedAt = o.strOrNull("issued_at"),
        notAfter = o.strOrNull("not_after"),
        certPem = o.str("cert_pem"),
        chainPem = o.strOrNull("chain_pem"),
    )

    fun revoke(o: JSONObject) = RevokeResult(
        serial = o.str("serial"),
        revokedAt = o.strOrNull("revoked_at"),
        disconnect = if (o.isNull("disconnect")) emptyList() else nasResults(o.getJSONArray("disconnect")),
    )

    fun androidProfile(o: JSONObject) = AndroidProfile(
        ssid = o.str("ssid"),
        eap = o.str("eap"),
        phase2 = o.strOrNull("phase2"),
        identity = o.str("identity"),
        anonymousIdentity = o.strOrNull("anonymous_identity"),
        domainSuffixMatch = o.str("domain_suffix_match"),
        altSubjectMatch = o.strOrNull("alt_subject_match"),
        caPem = o.str("ca_pem"),
    )

    private fun nasResults(a: JSONArray) = (0 until a.length()).map {
        val r = a.getJSONObject(it)
        NasResult(r.str("nas"), r.str("result"))
    }

    // org.json's optString gives the text "null" for a JSON null, so these helpers check isNull first.

    private fun JSONObject.str(key: String): String {
        if (isNull(key)) throw JSONException("$key is missing")
        return get(key) as? String ?: throw JSONException("$key is not a string")
    }

    private fun JSONObject.strOrNull(key: String): String? =
        if (isNull(key)) null else get(key) as? String ?: throw JSONException("$key is not a string")

    /** Absent (older portals) or null: null. Present: a list of strings. */
    private fun JSONObject.strListOrNull(key: String): List<String>? {
        if (isNull(key)) return null
        val a = getJSONArray(key)
        return (0 until a.length()).map { a.get(it) as? String ?: throw JSONException("$key holds a non-string") }
    }

    private fun JSONObject.intOrNull(key: String): Int? = if (isNull(key)) null else getInt(key)

    private fun JSONObject.longOrNull(key: String): Long? = if (isNull(key)) null else getLong(key)

    private fun JSONObject.objOrNull(key: String): JSONObject? = if (isNull(key)) null else getJSONObject(key)

    private fun <T> JSONObject.list(key: String, item: (JSONObject) -> T): List<T> {
        if (isNull(key)) return emptyList()
        val a = getJSONArray(key)
        return (0 until a.length()).map { item(a.getJSONObject(it)) }
    }
}
