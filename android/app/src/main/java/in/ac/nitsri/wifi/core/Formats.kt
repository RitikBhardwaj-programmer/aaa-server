package `in`.ac.nitsri.wifi.core

import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.Locale

/** Text for the screens. Times are shown in the offset that the server sent (the lab's time zone). */
object Formats {

    private val TIME = DateTimeFormatter.ofPattern("d MMM HH:mm", Locale.ENGLISH)

    fun time(iso: String?): String {
        if (iso == null) return "-"
        return try {
            OffsetDateTime.parse(iso).format(TIME)
        } catch (e: DateTimeParseException) {
            iso
        }
    }

    fun bytes(n: Long?): String {
        if (n == null) return "-"
        if (n < 1024) return "$n B"
        val units = listOf("KB", "MB", "GB", "TB")
        var value = n / 1024.0
        var i = 0
        while (value >= 1024 && i < units.size - 1) {
            value /= 1024
            i++
        }
        return String.format(Locale.ENGLISH, "%.1f %s", value, units[i])
    }

    /** "2 of 3 online", or "2 online" when the user has no device limit. */
    fun onlineCount(online: Int, limit: Int?): String =
        if (limit == null) "$online online" else "$online of $limit online"

    /** "1 new device signed in" / "2 new devices signed in". */
    fun alertBanner(count: Int): String =
        if (count == 1) "1 new device signed in" else "$count new devices signed in"

    /** One line per NAS, for the answer to Disconnect or "Not me". */
    fun disconnectResults(results: List<NasResult>, reauthInterval: Int?): String {
        if (results.isEmpty()) return "The device is not online."
        val lines = results.map {
            when (it.result) {
                "ACK" -> "${it.nas}: disconnected."
                "NAK" -> "${it.nas}: refused the disconnect."
                else -> "${it.nas}: no answer."
            }
        }
        val dropped = results.all { it.result == "ACK" }
        val tail = when {
            dropped -> ""
            reauthInterval != null -> "\nThe device is dropped at the next re-check, within $reauthInterval seconds."
            else -> "\nThe device is dropped at the next re-check."
        }
        return lines.joinToString("\n") + tail
    }
}
