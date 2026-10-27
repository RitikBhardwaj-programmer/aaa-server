package `in`.ac.nitsri.wifi.ui

import android.view.LayoutInflater
import android.view.View
import android.widget.LinearLayout
import androidx.core.content.ContextCompat
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import `in`.ac.nitsri.wifi.R
import `in`.ac.nitsri.wifi.core.Devices
import `in`.ac.nitsri.wifi.core.Formats
import `in`.ac.nitsri.wifi.core.Slot
import `in`.ac.nitsri.wifi.databinding.ItemSlotBinding
import `in`.ac.nitsri.wifi.databinding.ScreenDevicesBinding

/** "N of 3 online", the device slots with Disconnect, the devices seen and the limit events. */
class DevicesScreen(private val host: HomeActivity, private val b: ScreenDevicesBinding) {

    private var loaded = false
    private var reauthInterval: Int? = null

    init {
        b.refresh.setOnClickListener {
            b.status.status(null)
            load()
        }
        b.alertHint.setOnClickListener { host.openActivityTab() }
    }

    fun loadOnce() {
        if (!loaded) load()
    }

    fun load() {
        loaded = true
        host.callApi(
            busy = { b.refresh.isEnabled = !it },
            onError = { b.status.status(it.message, Status.ERROR) },
            call = { api -> api.devices() to api.alerts() },
            onResult = { (devices, alerts) ->
                show(devices)
                host.showAlertBadge(alerts)
            },
        )
    }

    fun showAlertHint(count: Int) {
        b.alertHint.visibility = if (count > 0) View.VISIBLE else View.GONE
        b.alertHint.text = host.getString(R.string.devices_alert_hint, Formats.alertBanner(count))
    }

    private fun show(d: Devices) {
        reauthInterval = d.reauthInterval
        b.count.text = Formats.onlineCount(d.online, d.deviceLimit)
        showMeter(d.online, d.deviceLimit)

        b.slots.removeAllViews()
        if (d.slots.isEmpty()) addLine(b.slots, host.getString(R.string.devices_none_online), "")
        d.slots.forEach(::addSlot)

        b.known.removeAllViews()
        if (d.known.isEmpty()) addLine(b.known, host.getString(R.string.devices_none_known), "")
        d.known.forEach {
            val title = if (it.online) "${it.mac} · ${host.getString(R.string.devices_online)}" else it.mac
            addLine(b.known, title, host.getString(R.string.devices_known_detail, Formats.time(it.firstSeen), Formats.time(it.lastSeen)))
        }

        b.events.removeAllViews()
        b.eventsHeader.visibility = if (d.limitEvents.isEmpty()) View.GONE else View.VISIBLE
        d.limitEvents.forEach {
            val mode = host.getString(if (it.mode == "enforce") R.string.mode_enforce else R.string.mode_soft)
            addLine(
                b.events,
                it.mac,
                host.getString(R.string.devices_event_detail, Formats.time(it.time), "${it.liveDevices ?: "-"}", "${it.deviceLimit ?: "-"}", mode),
            )
        }
    }

    /** One box per allowed device: ink when used, chinar when over the limit, rule when free. */
    private fun showMeter(online: Int, limit: Int?) {
        b.meter.removeAllViews()
        val boxes = maxOf(limit ?: online, online)
        b.meter.visibility = if (boxes == 0) View.GONE else View.VISIBLE
        val gap = (4 * host.resources.displayMetrics.density).toInt()
        for (i in 0 until boxes) {
            val color = when {
                limit != null && i >= limit -> R.color.chinar
                i < online -> R.color.ink
                else -> R.color.rule
            }
            b.meter.addView(
                View(host).apply { setBackgroundColor(ContextCompat.getColor(host, color)) },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, 1f).apply { marginEnd = gap },
            )
        }
    }

    private fun addSlot(slot: Slot) {
        val card = ItemSlotBinding.inflate(LayoutInflater.from(host), b.slots, false)
        card.mac.text = slot.mac
        card.overLimit.visibility = if (slot.overLimit) View.VISIBLE else View.GONE
        val s = slot.session
        card.detail.text = if (s == null) Formats.time(slot.joined) else host.getString(
            R.string.devices_slot_detail,
            s.accessPoint ?: host.getString(R.string.unknown_ap),
            s.ip ?: "-",
            Formats.time(s.started),
            Formats.bytes(s.bytesUp),
            Formats.bytes(s.bytesDown),
        )
        card.disconnect.contentDescription = host.getString(R.string.devices_disconnect_desc, slot.mac)
        card.disconnect.setOnClickListener { confirmDisconnect(slot.mac) }
        b.slots.addView(card.root)
    }

    private fun confirmDisconnect(mac: String) {
        MaterialAlertDialogBuilder(host)
            .setTitle(R.string.devices_disconnect_title)
            .setMessage(host.getString(R.string.devices_disconnect_text, mac))
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.devices_disconnect) { _, _ -> disconnect(mac) }
            .show()
    }

    private fun disconnect(mac: String) {
        host.callApi(
            onError = { b.status.status(it.message, Status.ERROR) },
            call = { it.disconnect(mac) },
            onResult = { r ->
                val allAck = r.results.isNotEmpty() && r.results.all { it.result == "ACK" }
                b.status.status(Formats.disconnectResults(r.results, reauthInterval), if (allAck) Status.OK else Status.INFO)
                load()
            },
        )
    }
}
