package `in`.ac.nitsri.wifi.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import `in`.ac.nitsri.wifi.BuildConfig
import `in`.ac.nitsri.wifi.R
import `in`.ac.nitsri.wifi.databinding.ActivityLoginBinding
import `in`.ac.nitsri.wifi.wifiApp

class LoginActivity : SessionActivity() {

    override val needsSession = false

    private lateinit var b: ActivityLoginBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (wifiApp.tokens.loggedIn) {
            toHome()
            return
        }
        b = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(b.root)
        fitSystemBars(b.root, b.band)

        b.portal.text = getString(R.string.login_portal, BuildConfig.PORTAL_BASE_URL.ifEmpty { "-" })
        intent.getStringExtra(EXTRA_MESSAGE)?.let(::showMessage)
        wifiApp.baseUrlProblem?.let {
            showMessage(it)
            b.login.isEnabled = false
        }

        b.login.setOnClickListener { login() }
        b.password.setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_DONE) login()
            action == EditorInfo.IME_ACTION_DONE
        }
    }

    private fun login() {
        val uid = b.uid.text?.toString().orEmpty()
        val password = b.password.text?.toString().orEmpty()
        if (uid.isBlank() || password.isEmpty()) {
            showMessage(getString(R.string.login_needed))
            return
        }
        hideKeyboard(b.root)
        // The password is not kept: it leaves the field now and goes only into the one request.
        b.password.text?.clear()
        callApi(
            busy = { busy ->
                b.progress.visibility = if (busy) View.VISIBLE else View.GONE
                b.login.isEnabled = !busy
            },
            onError = { showMessage(it.message.orEmpty()) },
            call = { it.login(uid, password) },
            onResult = { toHome() },
        )
    }

    private fun showMessage(text: String) {
        b.message.text = text
        b.message.visibility = View.VISIBLE
    }

    private fun toHome() {
        startActivity(Intent(this, HomeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        finish()
    }

    companion object {
        const val EXTRA_MESSAGE = "message"
    }
}
