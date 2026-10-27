package `in`.ac.nitsri.wifi.ui

import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import `in`.ac.nitsri.wifi.R
import `in`.ac.nitsri.wifi.core.ApiException
import `in`.ac.nitsri.wifi.core.CertLabels
import `in`.ac.nitsri.wifi.core.CertList
import `in`.ac.nitsri.wifi.core.CertMessages
import `in`.ac.nitsri.wifi.core.DeviceCert
import `in`.ac.nitsri.wifi.core.EnrollResult
import `in`.ac.nitsri.wifi.core.SetupResult
import `in`.ac.nitsri.wifi.core.TlsEnrollment
import `in`.ac.nitsri.wifi.core.WifiPlanException
import `in`.ac.nitsri.wifi.core.WifiPlanner
import `in`.ac.nitsri.wifi.databinding.ItemCertBinding
import `in`.ac.nitsri.wifi.databinding.ScreenWifiBinding
import `in`.ac.nitsri.wifi.wifi.WifiInstaller

/**
 * Set up Wi-Fi. Password (EAP-TTLS, the default): fetches `GET /profiles/android`, checks it, and
 * saves the network with the typed password. Device certificate (EAP-TLS, when the user picks it):
 * makes a key and a CSR on the phone, gets the certificate from `POST /certs` and saves the network
 * with it (core/Tls.kt). It also lists the user's certificates (`GET /certs`) with Revoke.
 */
class WifiScreen(
    private val host: HomeActivity,
    private val b: ScreenWifiBinding,
    private val installer: WifiInstaller,
) {
    private var certsLoaded = false

    private val tls: Boolean get() = b.method.checkedButtonId == R.id.methodTls

    init {
        b.howto.setText(if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) R.string.wifi_android11 else R.string.wifi_android10)
        b.setup.setOnClickListener { if (tls) setUpTls() else setUp() }
        b.method.addOnButtonCheckedListener { _, _, isChecked -> if (isChecked) showMethod() }
        b.certRefresh.setOnClickListener {
            b.certStatus.status(null)
            loadCerts()
        }
        showMethod()
    }

    fun save(out: Bundle) = out.putBoolean(STATE_TLS, tls)        // the choice only

    fun restore(state: Bundle) {
        if (state.getBoolean(STATE_TLS)) b.method.check(R.id.methodTls)
    }

    private fun showMethod() {
        b.intro.setText(if (tls) R.string.wifi_intro_tls else R.string.wifi_intro)
        b.setup.setText(if (tls) R.string.wifi_button_tls else R.string.wifi_button)
        b.passwordLayout.visibility = if (tls) View.GONE else View.VISIBLE
        b.certSection.visibility = if (tls) View.VISIBLE else View.GONE
        b.settings.visibility = View.GONE
        b.status.status(null)
        if (tls && !certsLoaded) loadCerts()
    }

    private fun busy(busy: Boolean) {
        b.progress.visibility = if (busy) View.VISIBLE else View.GONE
        b.setup.isEnabled = !busy
        b.methodTtls.isEnabled = !busy        // the group's own isEnabled does not reach its buttons
        b.methodTls.isEnabled = !busy
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
            busy = ::busy,
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

    private fun setUpTls() {
        b.status.status(null)
        val label = CertLabels.of(Build.MANUFACTURER, Build.MODEL)
        host.callApi(
            busy = ::busy,
            onError = { e ->
                b.status.status(CertMessages.issueError(e), Status.ERROR)
                if (e.certLimit) loadCerts()
            },
            // The key pair lives only in this call and in the result handed to the installer
            call = { api -> TlsEnrollment(api).enroll(label) },
            onResult = { r ->
                when (r) {
                    is EnrollResult.Refused -> b.status.status(r.message, Status.ERROR)
                    is EnrollResult.Ready -> {
                        b.settings.text = host.getString(R.string.wifi_settings_tls, r.plan.ssid, r.plan.identity, r.plan.domainSuffixMatch)
                        b.settings.visibility = View.VISIBLE
                        installer.installTls(r.plan, r.credential)
                    }
                }
            },
        )
    }

    /** From the installer. [serial] is the new certificate of an EAP-TLS setup, else null. */
    fun showResult(result: SetupResult, serial: String?) {
        b.status.status(result.message, if (result.saved) Status.OK else Status.ERROR)
        if (serial == null) return
        if (result.saved) {
            loadCerts()
            return
        }
        // Not saved: the key is gone, so the certificate can never be used. Free its place.
        host.callApi(
            onError = { b.certStatus.status(it.message, Status.ERROR) },
            call = { it.revokeCert(serial) },
            onResult = {
                b.status.status(result.message + "\n" + CertMessages.unusedRevoked(serial), Status.ERROR)
                loadCerts()
            },
        )
    }

    private fun loadCerts() {
        certsLoaded = true
        host.callApi(
            busy = { b.certRefresh.isEnabled = !it },
            onError = { b.certStatus.status(CertMessages.issueError(it), Status.ERROR) },
            call = { it.certs() },
            onResult = ::showCerts,
        )
    }

    private fun showCerts(list: CertList) {
        b.certCount.text = CertMessages.count(list)
        b.certList.removeAllViews()
        if (list.certs.isEmpty()) addLine(b.certList, host.getString(R.string.certs_none), "")
        list.certs.forEach(::addCert)
    }

    private fun addCert(c: DeviceCert) {
        val card = ItemCertBinding.inflate(LayoutInflater.from(host), b.certList, false)
        card.title.text = CertMessages.title(c)
        card.detail.text = CertMessages.detail(c)
        card.revoke.visibility = if (c.active) View.VISIBLE else View.GONE
        card.revoke.contentDescription = host.getString(R.string.certs_revoke_desc, c.label)
        card.revoke.setOnClickListener {
            MaterialAlertDialogBuilder(host)
                .setTitle(R.string.certs_revoke_title)
                .setMessage(host.getString(R.string.certs_revoke_text, c.label))
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.certs_revoke) { _, _ -> revoke(c.serial) }
                .show()
        }
        b.certList.addView(card.root)
    }

    private fun revoke(serial: String) {
        host.callApi(
            busy = { b.certRefresh.isEnabled = !it },
            onError = { e: ApiException -> b.certStatus.status(e.message, Status.ERROR) },
            call = { it.revokeCert(serial) },
            onResult = { r ->
                b.certStatus.status(CertMessages.revoked(r), Status.OK)
                loadCerts()
            },
        )
    }

    companion object {
        private const val STATE_TLS = "wifi_method_tls"
    }
}
