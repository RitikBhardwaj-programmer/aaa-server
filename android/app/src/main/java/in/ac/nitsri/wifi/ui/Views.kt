package `in`.ac.nitsri.wifi.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import `in`.ac.nitsri.wifi.R
import `in`.ac.nitsri.wifi.databinding.ItemLineBinding

/** A two-line row (title, detail) added to [parent]. */
internal fun addLine(parent: ViewGroup, title: CharSequence, detail: CharSequence): ItemLineBinding {
    val row = ItemLineBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    row.title.text = title
    row.detail.text = detail
    parent.addView(row.root)
    return row
}

/** Shows [text] in a status line: chinar for errors, willow for success, ink otherwise. */
internal fun TextView.status(text: CharSequence?, kind: Status = Status.INFO) {
    if (text.isNullOrEmpty()) {
        visibility = android.view.View.GONE
        return
    }
    this.text = text
    setTextColor(
        ContextCompat.getColor(
            context,
            when (kind) {
                Status.ERROR -> R.color.chinar
                Status.OK -> R.color.willow
                Status.INFO -> R.color.ink
            },
        ),
    )
    visibility = android.view.View.VISIBLE
}

internal enum class Status { INFO, OK, ERROR }
