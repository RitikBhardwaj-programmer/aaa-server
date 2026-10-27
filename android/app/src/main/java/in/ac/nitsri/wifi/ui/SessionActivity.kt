package `in`.ac.nitsri.wifi.ui

import android.content.Context
import android.content.Intent
import android.view.View
import android.view.inputmethod.InputMethodManager
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import `in`.ac.nitsri.wifi.core.ApiClient
import `in`.ac.nitsri.wifi.core.ApiException
import `in`.ac.nitsri.wifi.wifiApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Base of the screens: runs API calls off the main thread, and sends the user back to Login when
 * the session ends (a `401`, or the token expired, or the process was restarted).
 */
abstract class SessionActivity : AppCompatActivity() {

    protected val scope = MainScope()

    protected open val needsSession = true

    protected val api: ApiClient get() = wifiApp.api

    override fun onResume() {
        super.onResume()
        if (needsSession && !wifiApp.tokens.loggedIn) toLogin(ApiException.MSG_SESSION_ENDED)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    /**
     * Runs [call] on the IO dispatcher. [busy] is told when it starts and ends. A session end goes
     * to Login; every other [ApiException] goes to [onError] (a `429` has the server's message).
     */
    fun <T> callApi(
        busy: (Boolean) -> Unit = {},
        onError: (ApiException) -> Unit,
        call: (ApiClient) -> T,
        onResult: (T) -> Unit,
    ) {
        scope.launch {
            busy(true)
            val result = try {
                Result.success(withContext(Dispatchers.IO) { call(api) })
            } catch (e: ApiException) {
                Result.failure(e)
            }
            busy(false)
            result.fold(onResult) { e ->
                val error = e as ApiException
                if (error.sessionEnded) toLogin(error.message) else onError(error)
            }
        }
    }

    fun toLogin(message: String?) {
        wifiApp.tokens.clear()
        startActivity(
            Intent(this, LoginActivity::class.java)
                .putExtra(LoginActivity.EXTRA_MESSAGE, message)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        finish()
    }

    protected fun hideKeyboard(view: View) {
        (getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).hideSoftInputFromWindow(view.windowToken, 0)
    }

    /**
     * Edge-to-edge (enforced from targetSdk 35): [topBar] draws behind the status bar, the root keeps
     * its content above the navigation bar and the keyboard.
     */
    protected fun fitSystemBars(root: View, topBar: View) {
        val topBarPadding = topBar.paddingTop
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            v.updatePadding(left = bars.left, right = bars.right, bottom = maxOf(bars.bottom, ime.bottom))
            topBar.updatePadding(top = topBarPadding + bars.top)
            WindowInsetsCompat.CONSUMED
        }
    }
}
