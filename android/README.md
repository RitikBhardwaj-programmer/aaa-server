# NITS Wi-Fi: the Android app

One app for everything on Android (stage S4 of `docs/plans/onboarding-and-eap-tls.md`):
log in, see "N of 3 online" and disconnect a device, review sign-ins and new-device alerts
("This was me" / "Not me"), change the password, and set up the `NITS-Lab` network
(WPA2-Enterprise, EAP-TTLS/PAP, the lab CA, server name `radius.nitsrinagar.lab`).

The app is a client of the portal JSON API, `docs/api/v1.md`. It has no server code of its own.

| | |
|---|---|
| Application ID | `in.ac.nitsri.wifi` |
| minSdk / targetSdk | 29 (Android 10) / 37 |
| Toolchain | AGP 9.4.0 (built-in Kotlin), Gradle 9.6.0 (wrapper), JDK 17 |
| Libraries | androidx.core-ktx, androidx.appcompat, material, kotlinx-coroutines-android; junit and org.json (unit tests only) |
| HTTP | `HttpURLConnection` / `HttpsURLConnection` and `org.json` from the platform |
| Permissions | `INTERNET`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE` |

## Security rules the app follows

- **Token in memory only.** `core/TokenHolder.kt` keeps the access token in a field of the
  process. It is never written to preferences, files, a `Bundle` or a log, and nothing outside
  `ApiClient` can read it. When the process ends, the user logs in again (there is no refresh token).
- **Password never stored.** The login and Wi-Fi password fields are cleared as soon as the
  text is read. The Wi-Fi password goes only into `WifiEnterpriseConfig.setPassword`; Android
  keeps it with the saved network.
- **401** on any call with a token: the token is forgotten and the app opens Login with the
  message. **429**: the server's message is shown, the session stays.
- **Transport.** Debug builds talk to `http://127.0.0.1:8081` (adb reverse). The debug network
  security config allows plain http to `127.0.0.1` only; everything else is https. Release builds
  allow https only, and the build refuses a non-https address.
- **No logs.** The app has no `Log` calls. `HttpRequest.toString()` leaves the headers out.
- No backup (`allowBackup=false`, data extraction rules exclude everything).

## Build

You need JDK 17+ and the Android SDK (platform 37, build tools 36). Android Studio has both.

```sh
cd android
./gradlew lint testDebugUnitTest assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

A release build needs the public https address of the portal (there is none yet, see README 5b):

```sh
./gradlew assembleRelease -PportalReleaseBaseUrl=https://portal.example
```

CI (`.github/workflows/android.yml`) runs the same three tasks and uploads the debug APK as the
artifact `nits-wifi-debug-apk`.

## Install on the phone and reach the lab portal

The portal listens on `127.0.0.1:8081` of the lab laptop only. `adb reverse` makes the phone's
`127.0.0.1:8081` go over USB to the laptop, so the portal never goes on the LAN.

1. On the phone: Settings > About phone > Software information > tap Build number 7 times;
   then Settings > Developer options > USB debugging on.
2. Connect USB, accept the "Allow USB debugging?" prompt.
3. On the laptop (the lab running, `docker compose up -d`):

```sh
adb devices                          # the phone is listed as "device"
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb reverse tcp:8081 tcp:8081        # again after every USB reconnect or adb restart
adb reverse --list                   # shows: tcp:8081 tcp:8081
```

The app shows the portal address under the login button (`Portal: http://127.0.0.1:8081`).
If login says "Cannot reach the portal", run `adb reverse` again.

## How Wi-Fi setup works

`GET /api/v1/profiles/android` gives `ssid`, `eap`, `phase2`, `identity`, `anonymous_identity`,
`domain_suffix_match`, `alt_subject_match` and `ca_pem`. `core/WifiPlan.kt` checks them (TTLS
and PAP only, a CA certificate that is valid now, a real host name) and
`wifi/WifiInstaller.kt` builds the `WifiEnterpriseConfig`:

| Setting | Value |
|---|---|
| `setEapMethod` / `setPhase2Method` | `TTLS` / `PAP` |
| `setIdentity` | `identity` (the uid) |
| `setAnonymousIdentity` | `anonymous_identity` (`anonymous`) |
| `setPassword` | typed by the user on the Set up Wi-Fi screen, then the field is cleared |
| `setCaCertificate` | `ca_pem` (the lab root CA) |
| `setDomainSuffixMatch` | `domain_suffix_match` (`radius.nitsrinagar.lab`) |
| `setAltSubjectMatch` | `alt_subject_match` (`DNS:radius.nitsrinagar.lab`) |

- **Android 11+ (API 30+):** `Settings.ACTION_WIFI_ADD_NETWORKS` with one
  `WifiNetworkSuggestion`. Android shows "Save this network?". The result code and
  `EXTRA_WIFI_NETWORK_RESULT_LIST` (success / already exists / failed) become the message on the
  screen. The network becomes a normal saved network. If the phone has no such screen, the app
  falls back to a suggestion.
- **Android 10 (API 29):** `WifiManager.addNetworkSuggestions`. Android shows a notification
  "Allow suggested Wi-Fi networks?"; the user must tap Allow. A suggestion is removed when the
  app is uninstalled.
- **Fixed MAC (Android 13+, API 33):** `setMacRandomizationSetting(RANDOMIZATION_PERSISTENT)`:
  one random MAC per network that stays the same, so the phone keeps one of the 3 device slots.
  What Samsung (One UI) may do anyway:
  - One UI has its own per-network "MAC address type" (Randomized MAC / Phone MAC) under
    Settings > Wi-Fi > NITS-Lab > View more. The user can change it; the app cannot lock it.
  - Whether the setting from the suggestion is copied when Settings saves the network through
    `ACTION_WIFI_ADD_NETWORKS` is up to the OEM build. Check it on the S23 (test 6 below).
  - "Forget network", a factory reset or a "Reset network settings" makes a new random MAC: the
    phone then shows as a new device (and a new-device alert).
  - Android 10 to 12 cannot ask for this; the system default (persistent randomized per network)
    applies.
- After a password change, set up Wi-Fi again: the saved network still has the old password.

## Unit tests (JVM, no device)

`./gradlew testDebugUnitTest` runs `app/src/test`:

- `ApiClientTest`: every response of the contract (S0 to S3) parsed from the JSON in
  `docs/api/v1.md`, every error code, 401 (token forgotten, back to Login; `login_failed` is not
  a session end), 429 (message kept, session kept), network failure, unreadable bodies, the token
  never leaving `TokenHolder`, the 30-minute cap, MAC and `days` checks before a call.
- `UrlConnectionTransportTest`: the real `HttpURLConnection` transport against a fake portal (the
  JDK's `com.sun.net.httpserver`): headers, JSON body, 204, error bodies, 429, server down.
- `WifiPlannerTest`: the profile to `WifiEnterpriseConfig` mapping layer: TTLS/PAP only,
  required fields, `DNS:` alt subject match, CA parsing (not a CA, expired, not yet valid), and
  the setup result messages. The test CA in `src/test/resources` is a throwaway, not the lab CA.
- `RulesTest`: base URL policy (https only; debug cleartext to 127.0.0.1 only), the password
  rules with the server's messages (code points, like Python `len`), and the formats.

The Android calls (`WifiEnterpriseConfig`, `WifiNetworkSuggestion`, Settings intent) cannot run
on the JVM; they are covered by the manual test below.

## Manual test script (Samsung Galaxy S23, Android 14/15)

Start: lab running, a student test account (for example `student042`) with no devices online,
the app installed, `adb reverse tcp:8081 tcp:8081` done. Write the results in the experiment log.

1. **Login.** Wrong password → "Login failed. Check your ID and password, then try again."
   Right password → My devices. Six wrong passwords in a row → the 429 message is shown.
2. **Token in memory only.** Log in, then `adb shell am force-stop in.ac.nitsri.wifi` and open
   the app → Login (no saved session). `adb shell run-as in.ac.nitsri.wifi ls -R` shows no file
   with a token.
3. **Set up Wi-Fi.** Set up Wi-Fi tab → type the password → Set up Wi-Fi → "Save this network?"
   → Save → "NITS-Lab is saved". Settings > Wi-Fi > NITS-Lab: EAP method TTLS, phase 2 PAP,
   CA certificate set, domain `radius.nitsrinagar.lab`, identity `student042`, anonymous identity
   `anonymous`. The phone connects (`radiusd -X`: Access-Accept, outer identity `anonymous`).
4. **Cancel.** Remove NITS-Lab, Set up Wi-Fi → Cancel on the Settings screen → "NITS-Lab was not
   saved." Again with Save, then a third time → "already saved" or "saved".
5. **Server name check.** With a RADIUS certificate for another name (or a fake AP), the phone
   must refuse to connect.
6. **MAC.** Settings > Wi-Fi > NITS-Lab > View more > MAC address type: note the value and the
   MAC. Turn Wi-Fi off and on, reconnect: same MAC. The portal shows the same device, the count
   stays the same.
7. **My devices.** "1 of 3 online", the slot with AP, IP, data. Disconnect → confirm → "disconnected"
   (ACK from the AP) or the re-check message; the phone drops off, then joins again.
8. **New-device alert.** Join from a new device (or after "Forget network" on the S23) → the
   Activity badge and the banner "1 new device signed in". "This was me" → the alert goes away.
   With another new device: "Not me" → confirm → Disconnect result, then Change password opens.
9. **Change password.** A 10-character password → "The new password must have at least 15
   characters." A wrong current password → the 403 message. A good one → "Password changed" →
   Login. Log in with the new password; set up Wi-Fi again with it; the phone connects.
10. **Session end.** Change the password on the web portal while the app is open, then Refresh in
    the app → Login with the session message.
11. **Accessibility.** TalkBack on: every button says what it does ("Disconnect DE-AD-…",
    "DE-AD-… was not me"), headings are read as headings, errors are announced.
