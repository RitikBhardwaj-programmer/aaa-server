package `in`.ac.nitsri.wifi

import android.app.Application
import android.content.Context
import `in`.ac.nitsri.wifi.core.ApiClient
import `in`.ac.nitsri.wifi.core.BaseUrlPolicy
import `in`.ac.nitsri.wifi.core.TokenHolder
import `in`.ac.nitsri.wifi.core.UrlConnectionTransport

/** Holds the one API client. The token lives in [tokens], in this process's memory only. */
class WifiApp : Application() {

    val tokens = TokenHolder()

    val api: ApiClient by lazy { ApiClient(BuildConfig.PORTAL_BASE_URL, UrlConnectionTransport(), tokens) }

    /** Null when this build's portal address is allowed (https, or http://127.0.0.1 in debug). */
    val baseUrlProblem: String?
        get() = BaseUrlPolicy.problem(BuildConfig.PORTAL_BASE_URL, BuildConfig.ALLOW_LOOPBACK_CLEARTEXT)
}

val Context.wifiApp: WifiApp get() = applicationContext as WifiApp
