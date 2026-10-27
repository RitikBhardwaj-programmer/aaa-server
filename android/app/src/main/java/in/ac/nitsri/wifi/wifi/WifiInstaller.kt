package `in`.ac.nitsri.wifi.wifi

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiEnterpriseConfig
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import `in`.ac.nitsri.wifi.core.AddNetworkOutcome
import `in`.ac.nitsri.wifi.core.SetupMessages
import `in`.ac.nitsri.wifi.core.SetupResult
import `in`.ac.nitsri.wifi.core.SuggestionStatus
import `in`.ac.nitsri.wifi.core.WifiPlan

/**
 * Saves the NITS-Lab network from a checked [WifiPlan] and the password that the user typed.
 *
 * - Android 11+ (API 30): `Settings.ACTION_WIFI_ADD_NETWORKS`. The user taps Save; the network
 *   becomes a normal saved network (it stays when the app is removed).
 * - Android 10 (API 29): `WifiManager.addNetworkSuggestions`. Android asks with a notification
 *   ("Allow suggested Wi-Fi networks?"). A suggestion goes away when the app is removed.
 *
 * Create it before the activity starts (the Activity Result API needs that).
 */
class WifiInstaller(
    private val activity: ComponentActivity,
    private val onResult: (SetupResult) -> Unit,
) {
    private var pendingSsid: String? = null

    private val addNetworks = activity.registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val ssid = pendingSsid ?: DEFAULT_SSID
        pendingSsid = null
        val outcomes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            r.data?.getIntegerArrayListExtra(Settings.EXTRA_WIFI_NETWORK_RESULT_LIST)?.map(::outcome)
        } else {
            null
        }
        onResult(SetupMessages.addNetworks(ssid, r.resultCode == android.app.Activity.RESULT_OK, outcomes))
    }

    fun save(out: Bundle) = out.putString(STATE_SSID, pendingSsid)

    fun restore(state: Bundle) {
        pendingSsid = state.getString(STATE_SSID)
    }

    /** Builds the configuration and hands it to Android. The caller clears the password field. */
    fun install(plan: WifiPlan, password: String) {
        val suggestion = try {
            suggestion(plan, password)
        } catch (e: IllegalArgumentException) {
            // Android refuses an enterprise network without server validation; the plan has it,
            // so this means the platform did not accept a value.
            onResult(SetupResult(false, "Android refused the network settings. Update the app."))
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val intent = Intent(Settings.ACTION_WIFI_ADD_NETWORKS)
                .putParcelableArrayListExtra(Settings.EXTRA_WIFI_NETWORK_LIST, arrayListOf(suggestion))
            try {
                pendingSsid = plan.ssid
                addNetworks.launch(intent)
                return
            } catch (e: ActivityNotFoundException) {
                pendingSsid = null
                // Some builds have no such screen: fall back to a suggestion.
            }
        }
        onResult(suggest(plan.ssid, suggestion))
    }

    private fun suggest(ssid: String, suggestion: WifiNetworkSuggestion): SetupResult {
        val wifi = activity.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        // Remove an older suggestion first, so a new password replaces the old one.
        wifi.removeNetworkSuggestions(listOf(suggestion))
        val status = when (wifi.addNetworkSuggestions(listOf(suggestion))) {
            WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS -> SuggestionStatus.SUCCESS
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE -> SuggestionStatus.DUPLICATE
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED -> SuggestionStatus.APP_DISALLOWED
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP -> SuggestionStatus.EXCEEDS_MAX
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID -> SuggestionStatus.INVALID
            else -> SuggestionStatus.INTERNAL
        }
        return SetupMessages.suggestion(ssid, status)
    }

    companion object {
        private const val STATE_SSID = "wifi_pending_ssid"
        private const val DEFAULT_SSID = "The network"

        /** EAP-TTLS, inner PAP, the lab CA and the server name check (see core/WifiPlan.kt). */
        fun enterpriseConfig(plan: WifiPlan, password: String) = WifiEnterpriseConfig().apply {
            setEapMethod(WifiEnterpriseConfig.Eap.TTLS)
            setPhase2Method(WifiEnterpriseConfig.Phase2.PAP)
            setIdentity(plan.identity)
            setAnonymousIdentity(plan.anonymousIdentity)
            setPassword(password)
            setCaCertificate(plan.caCertificate)
            setDomainSuffixMatch(plan.domainSuffixMatch)
            setAltSubjectMatch(plan.altSubjectMatch)
        }

        fun suggestion(plan: WifiPlan, password: String): WifiNetworkSuggestion {
            val builder = WifiNetworkSuggestion.Builder()
                .setSsid(plan.ssid)
                .setWpa2EnterpriseConfig(enterpriseConfig(plan, password))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) persistentMac(builder)
            return builder.build()
        }

        /**
         * One fixed (per-network) random MAC, so this phone stays one of the 3 devices. Android may
         * still use a new MAC after "Forget network", and One UI lets the user change the MAC type.
         */
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        private fun persistentMac(builder: WifiNetworkSuggestion.Builder) {
            builder.setMacRandomizationSetting(WifiNetworkSuggestion.RANDOMIZATION_PERSISTENT)
        }

        @RequiresApi(Build.VERSION_CODES.R)
        private fun outcome(code: Int) = when (code) {
            Settings.ADD_WIFI_RESULT_SUCCESS -> AddNetworkOutcome.SUCCESS
            Settings.ADD_WIFI_RESULT_ALREADY_EXISTS -> AddNetworkOutcome.ALREADY_EXISTS
            else -> AddNetworkOutcome.FAILED
        }
    }
}
