package `in`.ac.nitsri.wifi.ui

import android.os.Build
import android.view.View
import `in`.ac.nitsri.wifi.R
import `in`.ac.nitsri.wifi.core.SetupResult
import `in`.ac.nitsri.wifi.core.WifiPlanException
import `in`.ac.nitsri.wifi.core.WifiPlanner
import `in`.ac.nitsri.wifi.databinding.ScreenWifiBinding
import `in`.ac.nitsri.wifi.wifi.WifiInstaller

/** Fetches `GET /profiles/android`, checks it, and saves the network with the typed password. */
class WifiScreen(
    private val host: HomeActivity,
    private val b: ScreenWifiBinding,
    private val installer: WifiInstaller,
) {
    init {
        b.howto.setText(if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) R.string.wifi_android11 else R.string.wifi_android10)
        b.setup.setOnClickListener { setUp() }
    }

    private fun setUp() {
        val password = b.password.text?.toString().orEmpty()
        if (password.isEmpty()) {
            b.passwordLayout.error = host.getString(R.string.wifi_password)
            return
        }
        b.passwordLayout.error = null
        // Typed once: the field is cleared now, the text goes only into the WifiEnterpriseConfig.
        b.password.text?.clear()
        b.status.status(null)
        host.callApi(
            busy = { busy ->
                b.progress.visibility = if (busy) View.VISIBLE else View.GONE
                b.setup.isEnabled = !busy
            },
            onError = { b.status.status(it.message, Status.ERROR) },
            call = { it.androidProfile() },
            onResult = { profile ->
                try {
                    val plan = WifiPlanner.plan(profile)
                    b.settings.text = host.getString(R.string.wifi_settings, plan.ssid, plan.identity, plan.domainSuffixMatch)
                    b.settings.visibility = View.VISIBLE
                    installer.install(plan, password)
                } catch (e: WifiPlanException) {
                    b.status.status(e.message, Status.ERROR)
                }
            },
        )
    }

    fun showResult(result: SetupResult) {
        b.status.status(result.message, if (result.saved) Status.OK else Status.ERROR)
    }
}
