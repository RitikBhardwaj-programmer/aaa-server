package `in`.ac.nitsri.wifi.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import `in`.ac.nitsri.wifi.R
import `in`.ac.nitsri.wifi.core.Alerts
import `in`.ac.nitsri.wifi.databinding.ActivityHomeBinding
import `in`.ac.nitsri.wifi.wifi.WifiInstaller
import `in`.ac.nitsri.wifi.wifiApp

/** The three tabs: My devices, Sign-in activity (with the new-device alerts), Set up Wi-Fi. */
class HomeActivity : SessionActivity() {

    private lateinit var b: ActivityHomeBinding
    private lateinit var devices: DevicesScreen
    private lateinit var activityScreen: ActivityScreen
    private lateinit var wifi: WifiScreen
    private var tab = R.id.nav_devices

    // Registered before the activity starts, as the Activity Result API needs
    private val installer = WifiInstaller(this) { result, serial -> wifi.showResult(result, serial) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityHomeBinding.inflate(layoutInflater)
        setContentView(b.root)
        fitSystemBars(b.root, b.toolbar)

        b.toolbar.subtitle = wifiApp.tokens.user?.let { getString(R.string.logged_in_as, it.uid) }
        b.toolbar.inflateMenu(R.menu.home)
        b.toolbar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.menu_change_password -> openChangePassword()
                R.id.menu_log_out -> {
                    api.logout()
                    toLogin(null)
                }
            }
            true
        }

        devices = DevicesScreen(this, b.devices)
        activityScreen = ActivityScreen(this, b.activity)
        wifi = WifiScreen(this, b.wifi, installer)
        savedInstanceState?.let {
            tab = it.getInt(STATE_TAB, tab)
            installer.restore(it)
            wifi.restore(it)
        }

        b.nav.setOnItemSelectedListener { item ->
            show(item.itemId)
            true
        }
        b.nav.selectedItemId = tab
        show(tab)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        // Only the tab, the network name, the setup method and a certificate serial: never the
        // token, a password or a key
        outState.putInt(STATE_TAB, tab)
        installer.save(outState)
        wifi.save(outState)
    }

    override fun onResume() {
        super.onResume()
        if (!wifiApp.tokens.loggedIn) return
        if (tab == R.id.nav_activity) activityScreen.load() else refreshAlertBadge()
    }

    private fun show(id: Int) {
        tab = id
        b.devices.root.visibility = if (id == R.id.nav_devices) View.VISIBLE else View.GONE
        b.activity.root.visibility = if (id == R.id.nav_activity) View.VISIBLE else View.GONE
        b.wifi.root.visibility = if (id == R.id.nav_wifi) View.VISIBLE else View.GONE
        when (id) {
            R.id.nav_devices -> devices.loadOnce()
            R.id.nav_activity -> activityScreen.loadOnce()
        }
    }

    fun openActivityTab() {
        b.nav.selectedItemId = R.id.nav_activity
    }

    fun openChangePassword() {
        startActivity(Intent(this, ChangePasswordActivity::class.java))
    }

    fun showAlertBadge(alerts: Alerts) {
        if (alerts.count > 0) {
            b.nav.getOrCreateBadge(R.id.nav_activity).apply {
                number = alerts.count
                isVisible = true
            }
        } else {
            b.nav.removeBadge(R.id.nav_activity)
        }
        devices.showAlertHint(alerts.count)
    }

    private fun refreshAlertBadge() {
        callApi(onError = {}, call = { it.alerts() }, onResult = ::showAlertBadge)
    }

    companion object {
        private const val STATE_TAB = "tab"
    }
}
