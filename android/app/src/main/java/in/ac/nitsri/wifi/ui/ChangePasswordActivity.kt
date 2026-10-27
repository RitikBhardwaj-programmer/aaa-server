package `in`.ac.nitsri.wifi.ui

import android.os.Bundle
import android.view.View
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import `in`.ac.nitsri.wifi.R
import `in`.ac.nitsri.wifi.core.PasswordRules
import `in`.ac.nitsri.wifi.databinding.ActivityChangePasswordBinding
import `in`.ac.nitsri.wifi.wifiApp

/**
 * `POST /password`. The rules and messages are the server's (core/Rules.kt); the server checks
 * again and has the blocklist. Success ends every token, so the user logs in again.
 */
class ChangePasswordActivity : SessionActivity() {

    private lateinit var b: ActivityChangePasswordBinding

    // After a change the token has ended, but the success dialog must stay until the user taps OK.
    private var changed = false

    override val needsSession: Boolean get() = !changed

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityChangePasswordBinding.inflate(layoutInflater)
        setContentView(b.root)
        fitSystemBars(b.root, b.toolbar)
        b.toolbar.setNavigationOnClickListener { finish() }
        b.change.setOnClickListener { change() }
    }

    private fun change() {
        val uid = wifiApp.tokens.user?.uid.orEmpty()
        val old = b.old.text?.toString().orEmpty()
        val new = b.newPassword.text?.toString().orEmpty()
        val confirm = b.confirm.text?.toString().orEmpty()
        PasswordRules.problem(uid, new, confirm)?.let {
            showMessage(it)
            return
        }
        hideKeyboard(b.root)
        callApi(
            busy = { busy ->
                b.progress.visibility = if (busy) View.VISIBLE else View.GONE
                b.change.isEnabled = !busy
            },
            onError = { showMessage(it.message.orEmpty()) },
            call = { it.changePassword(old, new) },
            onResult = {
                changed = true
                b.old.text?.clear()
                b.newPassword.text?.clear()
                b.confirm.text?.clear()
                MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.password_done_title)
                    .setMessage(R.string.password_done_text)
                    .setCancelable(false)
                    .setPositiveButton(R.string.ok) { _, _ -> toLogin(getString(R.string.password_done_text)) }
                    .show()
            },
        )
    }

    private fun showMessage(text: String) {
        b.message.text = text
        b.message.visibility = View.VISIBLE
    }
}
