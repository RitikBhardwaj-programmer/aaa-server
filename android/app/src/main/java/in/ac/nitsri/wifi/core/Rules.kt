package `in`.ac.nitsri.wifi.core

import java.net.URI
import java.net.URISyntaxException
import java.util.Locale

/**
 * Which portal addresses a build may use. Release: https only. Debug: also plain http to
 * 127.0.0.1 (the `adb reverse tcp:8081 tcp:8081` lab setup). The network security config enforces
 * the same rule for the whole app; this check gives a clear message instead of a failed call.
 */
object BaseUrlPolicy {

    /** Null when [url] is allowed, else the reason. */
    fun problem(url: String, allowLoopbackCleartext: Boolean): String? {
        if (url.isBlank()) return "This build has no portal address. Build it with -PportalReleaseBaseUrl=https://…"
        val uri = try {
            URI(url)
        } catch (e: URISyntaxException) {
            return "The portal address of this build is not valid."
        }
        if (uri.host.isNullOrEmpty() || uri.userInfo != null || uri.query != null || uri.fragment != null) {
            return "The portal address of this build is not valid."
        }
        return when (uri.scheme?.lowercase(Locale.ROOT)) {
            "https" -> null
            "http" -> if (allowLoopbackCleartext && uri.host == "127.0.0.1") null
            else "The portal address must use https."
            else -> "The portal address must use https."
        }
    }
}

/**
 * The password rules of `app.check_new_password` (portal/app.py), with the same messages, so the
 * user sees a mistake before a call. The server checks again, and only the server has the
 * blocklist: its `400 invalid_input` message is shown as it is.
 */
object PasswordRules {
    const val MIN_LENGTH = 15
    const val MAX_LENGTH = 128

    /** Null when the new password passes the local rules, else the message. */
    fun problem(uid: String, new: String, confirm: String): String? {
        // Python's len() counts code points, not UTF-16 units
        val length = new.codePointCount(0, new.length)
        return when {
            new != confirm -> "The new password and the confirmation are not the same."
            length < MIN_LENGTH -> "The new password must have at least $MIN_LENGTH characters."
            length > MAX_LENGTH -> "The new password must have at most $MAX_LENGTH characters."
            uid.isNotEmpty() && new.lowercase(Locale.ROOT).contains(uid.lowercase(Locale.ROOT)) ->
                "The new password must not contain your user ID."
            else -> null
        }
    }
}
