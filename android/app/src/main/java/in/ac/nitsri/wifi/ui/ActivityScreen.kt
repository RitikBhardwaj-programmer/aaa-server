package `in`.ac.nitsri.wifi.ui

import android.view.LayoutInflater
import android.view.View
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import `in`.ac.nitsri.wifi.R
import `in`.ac.nitsri.wifi.core.Alert
import `in`.ac.nitsri.wifi.core.Alerts
import `in`.ac.nitsri.wifi.core.ApiClient
import `in`.ac.nitsri.wifi.core.CertMessages
import `in`.ac.nitsri.wifi.core.Formats
import `in`.ac.nitsri.wifi.core.SignInActivity
import `in`.ac.nitsri.wifi.databinding.ItemAlertBinding
import `in`.ac.nitsri.wifi.databinding.ScreenActivityBinding

/** The new-device banner ("This was me" / "Not me") and the sign-ins of the last 7 days. */
class ActivityScreen(private val host: HomeActivity, private val b: ScreenActivityBinding) {

    private var loaded = false

    init {
        b.refresh.setOnClickListener {
            b.status.status(null)
            load()
        }
    }

    fun loadOnce() {
        if (!loaded) load()
    }

    fun load() {
        loaded = true
        host.callApi(
            busy = { b.refresh.isEnabled = !it },
            onError = { b.status.status(it.message, Status.ERROR) },
            call = { api -> api.alerts() to api.activity(DAYS) },
            onResult = { (alerts, activity) ->
                showAlerts(alerts)
                showSignIns(activity)
                host.showAlertBadge(alerts)
            },
        )
    }

    private fun showAlerts(a: Alerts) {
        b.alertList.removeAllViews()
        b.alerts.visibility = if (a.alerts.isEmpty()) View.GONE else View.VISIBLE
        b.alertsTitle.text = Formats.alertBanner(a.count)
        a.alerts.forEach(::addAlert)
    }

    private fun addAlert(alert: Alert) {
        val row = ItemAlertBinding.inflate(LayoutInflater.from(host), b.alertList, false)
        row.mac.text = macLabel(alert.mac, alert.privateMac, alert.online)
        row.detail.text = host.getString(R.string.alert_detail, Formats.time(alert.firstSeen), Formats.time(alert.lastSeen))
        row.me.contentDescription = host.getString(R.string.alert_me_desc, alert.mac)
        row.notMe.contentDescription = host.getString(R.string.alert_not_me_desc, alert.mac)
        row.me.setOnClickListener { review(alert.mac, ApiClient.VERDICT_ME) }
        row.notMe.setOnClickListener {
            MaterialAlertDialogBuilder(host)
                .setTitle(R.string.alert_not_me_title)
                .setMessage(host.getString(R.string.alert_not_me_text, alert.mac))
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.alert_not_me) { _, _ -> review(alert.mac, ApiClient.VERDICT_NOT_ME) }
                .show()
        }
        b.alertList.addView(row.root)
    }

    private fun review(mac: String, verdict: String) {
        host.callApi(
            onError = { b.status.status(it.message, Status.ERROR) },
            call = { it.review(mac, verdict) },
            onResult = { r ->
                if (r.verdict == ApiClient.VERDICT_ME) {
                    b.status.status(host.getString(R.string.alert_reviewed, mac), Status.OK)
                } else {
                    val revoked = CertMessages.afterNotMe(r)
                    val text = Formats.disconnectResults(r.disconnect.orEmpty(), null)
                    b.status.status(if (revoked.isEmpty()) text else "$text\n$revoked", Status.INFO)
                }
                load()
                if (r.next == ApiClient.NEXT_PASSWORD) host.openChangePassword()
            },
        )
    }

    private fun showSignIns(a: SignInActivity) {
        b.signins.removeAllViews()
        if (a.signins.isEmpty()) addLine(b.signins, host.getString(R.string.activity_none), "")
        a.signins.forEach {
            val result = host.getString(if (it.result == "accept") R.string.activity_accept else R.string.activity_reject)
            addLine(
                b.signins,
                "$result · ${Formats.time(it.time)}",
                host.getString(
                    R.string.activity_detail,
                    macLabel(it.mac ?: "-", it.privateMac, false),
                    it.accessPoint ?: host.getString(R.string.unknown_ap),
                ),
            )
        }
    }

    private fun macLabel(mac: String, privateMac: Boolean, online: Boolean): String {
        var label = mac
        if (privateMac) label += " (${host.getString(R.string.private_address)})"
        if (online) label += " · ${host.getString(R.string.devices_online)}"
        return label
    }

    companion object {
        const val DAYS = 7
    }
}
