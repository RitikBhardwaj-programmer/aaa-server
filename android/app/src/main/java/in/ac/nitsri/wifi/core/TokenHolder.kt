package `in`.ac.nitsri.wifi.core

/**
 * The access token, in memory only (docs/api/v1.md section 1.2). It is never written to disk,
 * preferences, a Bundle or a log, and it is never handed out: only [ApiClient] reads it. When the
 * process ends, the token is gone and the user logs in again.
 */
class TokenHolder(private val clock: () -> Long = System::currentTimeMillis) {

    private var token: String? = null
    private var expiresAtMs = 0L

    /** The logged-in user, or null. */
    @get:Synchronized
    var user: User? = null
        private set

    @Synchronized
    fun set(token: String, expiresInSeconds: Long, user: User) {
        // The server never lets a token live longer than 30 minutes; do not trust a larger value.
        val seconds = expiresInSeconds.coerceIn(0, MAX_LIFETIME_SECONDS)
        this.token = token
        this.expiresAtMs = clock() + seconds * 1000
        this.user = user
    }

    /** The token while it is still valid by the clock; null (and forgotten) once it has expired. */
    @Synchronized
    internal fun current(): String? {
        if (token != null && clock() >= expiresAtMs) clear()
        return token
    }

    val loggedIn: Boolean get() = current() != null

    /** Log out: there is no logout endpoint, the client forgets the token. */
    @Synchronized
    fun clear() {
        token = null
        expiresAtMs = 0
        user = null
    }

    companion object {
        const val MAX_LIFETIME_SECONDS = 30L * 60
    }
}
