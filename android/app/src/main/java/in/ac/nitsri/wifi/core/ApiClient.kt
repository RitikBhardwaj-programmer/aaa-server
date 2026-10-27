package `in`.ac.nitsri.wifi.core

import org.json.JSONException
import org.json.JSONObject
import java.io.IOException

/**
 * Client for the portal API (docs/api/v1.md). Every call blocks: run it off the main thread.
 * Every failure is an [ApiException]. A `401` on a call with a token forgets the token, so the
 * caller sends the user back to Login ([ApiException.sessionEnded]).
 *
 * The password is only passed through: it is never kept in a field.
 */
class ApiClient(
    baseUrl: String,
    private val transport: HttpTransport,
    val tokens: TokenHolder,
) {
    private val api = baseUrl.trimEnd('/') + "/api/v1"

    /** `POST /auth/token`. Keeps the token in [tokens] and returns the user. */
    fun login(uid: String, password: String): User {
        val body = JSONObject().put("uid", uid).put("password", password)
        val o = parse(call("POST", "/auth/token", body, auth = false))
        return try {
            val user = Parse.user(o.getJSONObject("user"))
            tokens.set(o.getString("access_token"), o.getLong("expires_in"), user)
            user
        } catch (e: JSONException) {
            throw badResponse(200)
        }
    }

    fun me(): User = get("/me", Parse::user)

    fun devices(): Devices = get("/devices", Parse::devices)

    fun disconnect(mac: String): DisconnectResult {
        requireMac(mac)
        return read(call("POST", "/devices/disconnect", JSONObject().put("mac", mac)), Parse::disconnect)
    }

    /**
     * `POST /password`. On success (`204`) the server ends this token and every other token of the
     * user, so the client forgets it too: the user logs in again with the new password.
     */
    fun changePassword(old: String, new: String) {
        val r = call("POST", "/password", JSONObject().put("old", old).put("new", new))
        tokens.clear()
        if (r.status != 204) throw badResponse(r.status)
    }

    fun activity(days: Int = 7): SignInActivity {
        if (days !in 1..30) throw ApiException(400, "invalid_input", "Days must be 1 to 30.")
        return get("/activity?days=$days", Parse::activity)
    }

    fun alerts(): Alerts = get("/alerts", Parse::alerts)

    /** `POST /alerts/{mac}` with [VERDICT_ME] or [VERDICT_NOT_ME]. */
    fun review(mac: String, verdict: String): Review {
        requireMac(mac)
        require(verdict == VERDICT_ME || verdict == VERDICT_NOT_ME)
        // The MAC alphabet [0-9A-Za-z:.-] is safe in a path segment as it is
        return read(call("POST", "/alerts/$mac", JSONObject().put("verdict", verdict)), Parse::review)
    }

    fun androidProfile(): AndroidProfile = get("/profiles/android", Parse::androidProfile)

    fun logout() = tokens.clear()

    // ---- plumbing --------------------------------------------------------------------------------

    private fun <T> get(path: String, parser: (JSONObject) -> T): T = read(call("GET", path, null), parser)

    private fun <T> read(r: HttpResponse, parser: (JSONObject) -> T): T = try {
        parser(parse(r))
    } catch (e: JSONException) {
        throw badResponse(r.status)
    }

    private fun call(method: String, path: String, body: JSONObject?, auth: Boolean = true): HttpResponse {
        val headers = linkedMapOf("Accept" to "application/json")
        if (body != null) headers["Content-Type"] = "application/json"
        if (auth) {
            val token = tokens.current() ?: throw ApiException(401, ApiException.NO_TOKEN, ApiException.MSG_SESSION_ENDED)
            headers["Authorization"] = "Bearer $token"
        }
        val response = try {
            transport.execute(HttpRequest(method, api + path, headers, body?.toString()))
        } catch (e: IOException) {
            throw ApiException(0, ApiException.NETWORK, ApiException.MSG_NETWORK)
        }
        if (response.status in 200..299) return response
        if (response.status == 401 && auth) tokens.clear()
        throw error(response)
    }

    private fun parse(r: HttpResponse): JSONObject = try {
        JSONObject(r.body)
    } catch (e: JSONException) {
        throw badResponse(r.status)
    }

    /** The `{"error": {"code", "message"}}` body, or a generic error when the body is not that. */
    private fun error(r: HttpResponse): ApiException {
        try {
            val e = JSONObject(r.body).getJSONObject("error")
            val code = e.getString("code")
            val message = e.getString("message")
            if (code.isNotBlank() && message.isNotBlank()) return ApiException(r.status, code, message)
        } catch (ignored: JSONException) {
        }
        val message = when (r.status) {
            401 -> ApiException.MSG_SESSION_ENDED
            429 -> "Too many attempts. Wait, then try again."
            in 500..599 -> "The portal is not available. Try again later."
            else -> "The portal refused the request (HTTP ${r.status})."
        }
        return ApiException(r.status, "http_${r.status}", message)
    }

    private fun badResponse(status: Int) = ApiException(status, ApiException.BAD_RESPONSE, ApiException.MSG_BAD_RESPONSE)

    private fun requireMac(mac: String) {
        if (!MAC.matches(mac)) throw ApiException(400, "invalid_input", "That is not a valid device address.")
    }

    companion object {
        const val VERDICT_ME = "me"
        const val VERDICT_NOT_ME = "not_me"
        const val NEXT_PASSWORD = "password"

        /** The MAC form that the server accepts (docs/api/v1.md section 1.1). */
        val MAC = Regex("[0-9A-Za-z:.-]{1,40}")
    }
}
