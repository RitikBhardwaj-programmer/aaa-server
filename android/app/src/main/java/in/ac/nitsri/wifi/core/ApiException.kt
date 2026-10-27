package `in`.ac.nitsri.wifi.core

/**
 * A failed API call. [code] is the stable code from `{"error": {"code", "message"}}`
 * (docs/api/v1.md section 1.4), or one of the client codes below. [message] is safe to show.
 */
class ApiException(val status: Int, val code: String, message: String) : Exception(message) {

    /** The token is missing, expired or no longer valid: the app goes back to Login. */
    val sessionEnded: Boolean get() = status == 401 && code != LOGIN_FAILED

    val rateLimited: Boolean get() = status == 429

    companion object {
        const val LOGIN_FAILED = "login_failed"

        // Client codes (never sent by the server)
        const val NETWORK = "network"
        const val BAD_RESPONSE = "bad_response"
        const val NO_TOKEN = "unauthorized"

        const val MSG_NETWORK = "Cannot reach the portal. Check the connection and try again."
        const val MSG_BAD_RESPONSE = "The portal sent an answer that this app cannot read."
        const val MSG_SESSION_ENDED = "Your session has ended. Log in again."
    }
}
