package `in`.ac.nitsri.wifi.core

import java.io.IOException

/** Records each request and answers from a queue. A queued null throws IOException (no network). */
class FakeTransport : HttpTransport {
    val requests = mutableListOf<HttpRequest>()
    private val answers = ArrayDeque<HttpResponse?>()

    fun answer(status: Int, body: String = "") = apply { answers.addLast(HttpResponse(status, body)) }

    fun unreachable() = apply { answers.addLast(null) }

    override fun execute(request: HttpRequest): HttpResponse {
        requests += request
        check(answers.isNotEmpty()) { "unexpected request $request" }
        return answers.removeFirst() ?: throw IOException("connection refused")
    }

    val last: HttpRequest get() = requests.last()
}

/** Response bodies copied from docs/api/v1.md. */
object Contract {
    const val TOKEN = """{
      "access_token": "eyJ1aWQiOi.test-token",
      "token_type": "Bearer",
      "expires_in": 900,
      "user": {"uid": "student042", "student": true, "device_limit": 3}
    }"""

    const val ME = """{"uid": "student042", "student": true, "device_limit": 3}"""

    const val DEVICES = """{
      "online": 2,
      "device_limit": 3,
      "reauth_interval": 300,
      "slots": [
        {
          "mac": "DE-AD-BE-EF-00-02",
          "joined": "2026-10-26T11:40:00+05:30",
          "over_limit": false,
          "session": {
            "access_point": "AP-615",
            "ip": "10.10.0.20",
            "started": "2026-10-26T11:40:00+05:30",
            "updated": "2026-10-26T11:50:00+05:30",
            "bytes_up": 2048,
            "bytes_down": 4096
          }
        }
      ],
      "known": [
        {"mac": "DE-AD-BE-EF-00-01", "first_seen": "2026-10-20T09:00:00+05:30", "last_seen": "2026-10-26T11:00:00+05:30", "online": true}
      ],
      "limit_events": [
        {"time": "2026-10-26T10:00:00+05:30", "mac": "DE-AD-BE-EF-00-03", "live_devices": 3, "device_limit": 3, "mode": "soft"}
      ]
    }"""

    const val DISCONNECT = """{"mac": "DE-AD-BE-EF-00-01", "results": [{"nas": "10.89.0.1", "result": "ACK"}]}"""

    const val ACTIVITY = """{
      "days": 7,
      "signins": [
        {"time": "2026-10-26T18:25:07+05:30", "result": "accept", "access_point": "AP-615", "mac": "DE-AD-BE-EF-00-01", "private_mac": true},
        {"time": "2026-10-26T18:20:00+05:30", "result": "reject", "access_point": null, "mac": "DE-AD-BE-EF-00-01", "private_mac": true}
      ]
    }"""

    const val ALERTS = """{
      "count": 2,
      "alerts": [
        {"mac": "DE-AD-BE-EF-00-01", "first_seen": "2026-10-26T18:25:07+05:30", "last_seen": "2026-10-26T18:30:00+05:30", "online": true, "private_mac": false},
        {"mac": "DA-AD-BE-EF-00-09", "first_seen": "2026-10-25T08:00:00+05:30", "last_seen": "2026-10-25T09:00:00+05:30", "online": false, "private_mac": true}
      ]
    }"""

    const val REVIEW_ME = """{"mac": "DE-AD-BE-EF-00-01", "verdict": "me", "disconnect": null, "next": null}"""

    const val REVIEW_NOT_ME = """{"mac": "DE-AD-BE-EF-00-01", "verdict": "not_me", "disconnect": [{"nas": "10.89.0.1", "result": "ACK"}], "next": "password"}"""

    fun profile(caPem: String) = org.json.JSONObject()
        .put("ssid", "NITS-Lab")
        .put("eap", "TTLS")
        .put("phase2", "PAP")
        .put("identity", "student042")
        .put("anonymous_identity", "anonymous")
        .put("domain_suffix_match", "radius.nitsrinagar.lab")
        .put("alt_subject_match", "DNS:radius.nitsrinagar.lab")
        .put("ca_pem", caPem)
        .toString()

    fun error(code: String, message: String) = """{"error": {"code": "$code", "message": "$message"}}"""
}

fun resource(name: String): String =
    requireNotNull(Contract::class.java.classLoader!!.getResource(name)) { name }.readText()
