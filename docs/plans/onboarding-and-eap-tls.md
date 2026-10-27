# Plan: one-tap Wi-Fi onboarding, sign-in alerts and an all-in-one Android app

## Context
Today every student downloads `ca.pem` and types EAP-TTLS settings by hand (README §7). This is slow and error-prone. A wrong setting such as "Do not validate" also exposes passwords to fake APs. The user wants the self-service portal to:
1. show the number of connected devices;
2. change the password;
3. show Google-style "new device signed in" alerts;
4. install the certificate and Wi-Fi profile automatically and connect.

Decisions made with the user (2026-10-26):
- **Credentials: both, staged.** Phase 1 installs EAP-TTLS/PAP profiles. Phase 2 adds per-device EAP-TLS certificates.
- **Android: a small native app.**
- **Alerts: in the portal only**, with no email.
- **First access: any internet for now.**
- **Build in cloud sessions.**

**What already exists** (measured, `portal/app.py`):
- `/devices` with "N of 3 online" slots, devices seen (`user_devices.first_seen`), and Disconnect over RFC 5176;
- `/password` (RFC 3062, NT-hash delete, blocklist);
- login, CSRF, rate limits and a strict CSP.

**What is missing:** sign-in history, alerts, profile downloads, an API and an app.

**Answer to "can the app do everything?"** Yes, on Android. The portal gets one versioned JSON API (`/api/v1`). The Android app is a full client of that API: login, devices, disconnect, sign-in activity and alerts, password change, and Wi-Fi setup. The web portal uses the same core functions. The app cannot cover iOS, macOS, Windows or Linux: an iOS app needs a paid Apple developer account. Those platforms get one-click downloads from the web portal (`/setup`). So there is one backend and two front ends (web for all devices, app for Android), and no separate onboarding app.

**Research basis:** eduroam CAT, geteduroam, letswifi-portal, ClearPass Onboard, SecureW2. Sources are in the research summary, and the key facts are repeated here:
- Android 11+ blocks web pages from installing a CA, but an app can embed the CA in a `WifiEnterpriseConfig`.
- Apple `.mobileconfig` supports TTLS + PAP, the CA anchor and `TLSTrustedServerNames`.
- Windows uses a WLAN profile XML + `netsh`.

## Architecture
```
            ┌──────────── web browser (all OS) ── /setup downloads (.mobileconfig, Windows ps1+xml, nmcli, ONC)
 student ───┤
            └──────────── Android app (Kotlin) ── /api/v1 (Bearer token) + WifiNetworkSuggestion / ACTION_WIFI_ADD_NETWORKS
                                   │
                    Flask portal: core functions (login, devices, disconnect, password, activity, profiles, pki)
                         │                    │                         │
                    LDAP (cn=portal)    PostgreSQL (role portal:   radclient → AP :3799 (Disconnect)
                                        SELECT + fn portal_signins + own tables)
```

## Stages (each a cloud session that opens a PR to `feature/merged-aaa-core`)
Order: **S0 → (S1 ∥ S2 ∥ S3 ∥ S4) → (S5 ∥ S6) → S7**. Each stage owns its files, and only S0 touches the shared ones.

**S0: Foundation and API contract** (serial; everything depends on it)
- In `portal/app.py`, move the route logic into `login_core`, `device_overview`, `disconnect_core` and `password_core`. Web behaviour does not change. Feature blueprints are registered at the end of the file.
- New `portal/apiauth.py`:
  - `POST /api/v1/auth/token` returns a Bearer token signed with itsdangerous (salt `api-v1`, carries uid/dn/version/iat/exp). It lives 15 min, with a 30 min absolute limit.
  - `GET /api/v1/me`.
  - `account_state()` runs again on every call, so a password change or a disabled account ends all tokens.
  - `/api` accepts the header only (a cookie is refused), is exempt from CSRF, requires a JSON content type, and has no CORS.
  - It uses the same limiters as the web portal.
- Hooks: `{% block head %}` and endpoint-gated nav links in `base.html`; an `_alerts.html` include in `devices.html`.
- Other files: `Dockerfile` copies `*.py`; compose env `WIFI_SSID`, `API_TOKEN_MINUTES`, `PROFILE_SIGNING`; `portal-test` runs `unittest discover`.
- New `docs/api/v1.md` holds the full contract for all stages, including the error shape `{"error":{"code","message"}}`.
- New `portal/tests/unit/` (mocks, no live services).
- New `.github/workflows/portal.yml` (unit tests + pyflakes).
- Reserve migration numbers 004, 005 and 006 now.

**S1: Devices and password API** (`portal/api.py`)
- `GET /api/v1/devices`
- `POST /api/v1/devices/disconnect {mac}` returns ACK/NAK per NAS.
- `POST /api/v1/password {old,new}` returns 204 and ends all tokens.

**S2: Sign-in activity and new-device alerts** (`portal/activity.py`, `activity.html`, `_alerts.html`, `activity.css`)
- Migration `004-portal-signins.sql`: a `SECURITY DEFINER` function `portal_signins(user, days≤30, limit≤100)`.
  - It returns only time, result, AP and MAC from `radpostauth`, and never Class.
  - Settings: `search_path` pinned; EXECUTE granted to `portal` only.
- Migration `005-device-reviews.sql`: `device_reviews(username, mac, verdict me|not_me, reviewed_at)`. The `portal` role gets INSERT and UPDATE on the verdict columns only.
- An alert is a `user_devices` row from the last 30 days with no review. Several are bundled into one banner ("2 new devices signed in").
- **"This was me"** marks the device as reviewed. **"Not me"** disconnects the device, records the verdict, and opens the password page.
- MACs with the locally-administered bit set get a "private address" label.
- API: `GET /api/v1/activity`, `GET /api/v1/alerts`, `POST /api/v1/alerts/{mac} {verdict}`.

**S3: TTLS/PAP profile generators** (`portal/profiles.py`: pure functions, no Flask; `portal/downloads.py`, `setup.html`)
- The page detects the OS and offers:
  - **Apple:** a CMS-signed `.mobileconfig` with root CA + `com.apple.wifi.managed`: `AcceptEAPTypes [21]`, `TTLSInnerAuthentication PAP`, `OuterIdentity anonymous`, `TLSTrustedServerNames [radius.nitsrinagar.lab]`, CA anchor. The username is filled in, and the device prompts for the password.
  - **Windows:** a `.ps1` that runs `certutil -user -addstore Root` and `netsh wlan add profile`, plus the WLAN XML (TTLS, ServerNames, TrustedRootCAHash).
  - **Linux:** an `nmcli` script (`ttls`/`pap`, `domain-suffix-match`, CA embedded, password not stored).
  - **ChromeOS:** an ONC file.
- `GET /api/v1/profiles/android` gives the app its settings (SSID, EAP, phase 2, anonymous identity, domain, CA PEM, identity).
- No password is ever stored or put in a file.
- The CA is the real one, CN "NIT Srinagar Lab CA" from `certs/`. Tests make a throwaway CA, because `certs/` is gitignored.

**S4: Android app** (`android/`: Kotlin, minSdk 29; `.github/workflows/android.yml`)
- Screens: Login · Devices (Disconnect) · Activity and alerts (This was me / Not me) · Change password · Set up Wi-Fi.
- Wi-Fi setup builds a `WifiEnterpriseConfig`: TTLS/PAP, `setCaCertificate`, `setDomainSuffixMatch` + `setAltSubjectMatch`, anonymous identity.
  - Android 11+ uses `ACTION_WIFI_ADD_NETWORKS`. Android 10 uses `addNetworkSuggestions`.
  - The MAC is set to persistent where the API allows it, so the 3-device count stays stable.
- The token is kept in memory only, and the password is never stored. The base URL is a build config value. Lab testing uses `adb reverse tcp:8081 tcp:8081`, so the portal stays on 127.0.0.1.
- Tests: JVM unit tests of the API client against a fake server.

**S5: EAP-TLS server side** (Wave B)
- `certs/make-certs.sh`: a **Device CA** intermediate. The root key stays offline.
- Migration `006-device-certs.sql`: `device_certs(serial, username, label, pubkey_sha256, issued_at, not_after, revoked_at, revoke_reason, via)`.
- `portal/pki.py`:
  - a per-user advisory lock stops more than 3 active certificates from being issued at once;
  - certificates use CN = uid, clientAuth, 1-year validity.
- `POST /api/v1/certs {csr_pem,label}` (Android: the key is generated on the phone). `GET /api/v1/certs`. `DELETE /api/v1/certs/{serial}` revokes the certificate and sends a Disconnect.
- Web `/certs`, plus a one-time PKCS#12 download with a passphrase shown on screen, for Apple, Windows and Linux.
- FreeRADIUS:
  - `mods-available/eap` gets a `tls-device` config;
  - a new `sites-available/check-eap-tls` checks the serial is not revoked, then runs LDAP + `campus_authorize`.
  - Revocation is a table lookup, with no CRL or OCSP service.

**S6: EAP-TLS clients**
- TLS variants of the profiles: a pkcs12 payload, Windows TLS, nmcli TLS.
- The Android app generates the key and CSR and calls `setClientKeyEntry`.
- "Not me" also revokes the certificate.

**S7: Documentation**
- README §5b/§7, `docs/aaa-lab-guide.html`.
- New ADR `docs/decisions/0003-device-onboarding-and-eap-tls.md`.
- `docs/plans/next-steps.md`.

## Running it in cloud sessions
1. **Before any session starts:** push `feature/merged-aaa-core` (commit `82ee017`) to `origin` (github.com/RitikBhardwaj-programmer/aaa-server). Approving this plan approves that push.
2. Each session is created with `repository: RitikBhardwaj-programmer/aaa-server`. Cloud sessions start from the **default branch (main)**, so every brief says: check out `feature/merged-aaa-core`, branch `feature/onboarding-sN-<slug>` from it, and open the PR against `feature/merged-aaa-core`.
3. S0 runs alone and acts as the canary. After its PR is merged, S1–S4 start in parallel, then S5 ∥ S6, then S7.
4. Each brief says how the session checks its own work, and includes: *"If something you need is missing (a file, a secret, access, a tool), say exactly what and stop. Never mock, substitute or guess."*

## Verification
| Check | Where |
|---|---|
| Unit tests (mocks) and pyflakes for every stage; plist round-trip and `openssl cms -verify` for `.mobileconfig`; JSON/ONC schema, `bash -n` nmcli; Gradle `lint testDebugUnitTest assembleDebug` (or GitHub Actions if no SDK) | cloud session, per PR |
| Existing suites must stay green: `scripts/test.ps1` (8 password-store + 33 portal + 60 e2e) plus the new live tests (API auth, grants: portal still cannot read `radpostauth` directly, function returns own rows only) | locally after each merge |
| S2 on real hardware: the S23 joins from a new MAC → banner appears; "Not me" → Disconnect ACK from the Aruba, then password page | local, Aruba + S23 |
| S3: Windows `.ps1` on this laptop connects to NITS-Lab; `.mobileconfig` on an iPhone/Mac if one is available (otherwise mark it unverified) | local |
| S4: the app on the S23 via `adb reverse` adds NITS-Lab, connects, shows devices and alerts, and disconnects | local |
| S5/S6: `radiusd -XC`, `eapol_test` EAP-TLS accept, revoked serial → reject, 4th certificate → 409; S23 connects with its certificate, and revoke drops it | local |
| Independent security review (opus) of S0 (tokens), S2 (SQL function) and S5 (PKI, RADIUS) before merge | subagent |
Each real-device test gets an experiment note (`lab-experiment-log`).

## New dependencies (approving the plan approves these)
- **Python:** `cryptography`, pinned with `cffi` and `pycparser`. Needed for CMS signing (S3) and the CA and PKCS#12 (S5).
- **Android:** AGP, Kotlin, `androidx.core-ktx`, `androidx.appcompat`, `material`, `kotlinx-coroutines-android`, `junit`. Bouncy Castle (CSR) only in S6.
- **GitHub Actions workflows** for the portal and the Android app.
- **Not now:** `segno` (QR code, backlog), `signxml`/`lxml`, and `gunicorn` (needed before the portal goes on the LAN).

## Risks and open items
- **Windows `TrustedRootCAHash`:** SHA-1 vs SHA-256 is uncertain; test on the laptop. It is also unclear whether a CurrentUser root store is enough.
- **Apple profiles show "Not Verified"** when signed by the lab CA; add on-screen guidance.
- **Android OEM builds** may refuse `ACTION_WIFI_ADD_NETWORKS` for enterprise networks; check on the S23. Check the `.lab` domain-suffix match too.
- **Aruba re-check gap** (open item from 2026-10-26) and PMK caching: after "Not me" or a revoke, rely on Disconnect, and test the PMK cache settings on the AP-615.
- **Device CA key inside the portal container:** later move it to a signing sidecar or HSM.
- **"Any internet" first access** needs the portal on public HTTPS, so the README 5b checklist must be done first. The lab uses `adb reverse` and localhost.

## Backlog ("things we can add", ranked)
1. Device nicknames.
2. "Private MAC" label + "Remove device".
3. AP names in sign-in history.
4. Connection-test page (last accept or reject + reason for this MAC).
5. Refresh tokens for the app.
6. QR code that opens `/setup` on a phone.
7. Certificate and profile expiry reminders.
8. Signed Windows provisioning XML (`ms-settings:wifi-provisioning`).
9. Onboarding SSID with a walled garden.
10. MPSK for consoles: uncertain on Aruba Instant without ClearPass.

From the S2 security review (PR #5, 2026-10-27; no Blocker or High; L1 fixed in the PR):
- **M1** Reject rows can flood a user's sign-in history. Rejects are logged under the outer `User-Name`, which anyone can set, so fake "Refused" rows can push real logins past the 100-row cap of `portal_signins`. Fix: separate caps for accepts and rejects, or group rejects (count, first and last time); log outer-only rejects under a marker name.
- **M2** Role `portal` can SELECT all of `radacct` (every user's AP and Class), so "users see only their own rows" holds in the app, not in the database. Not new in S2. Fix: say so in the DPDP notes now; later replace the `radacct` grant with per-user SECURITY DEFINER functions.
- **L3** No rate limit on the "This was me" verdict. Fix: reuse an existing limiter.
- **L4** An alert can never be dismissed when its `user_devices.callingstationid` fails `MAC_RE`. Fix: validate MACs when the row is written (trigger), or review by a server-side key.
- **L5** The banner opens a second unpooled database connection on every `/devices` render and, with alerts, runs `live_sessions` twice. Fix: reuse the page's connection and live sessions, or add a pool.

## Routing card
| Phase | Agent | Model | Effort | Why |
|---|---|---|---|---|
| S0 foundation + token auth, S5 PKI/RADIUS | cloud session | opus | high | Auth and PKI fail quietly; the contract shapes every later stage |
| S1, S2, S3, S6, S7 builds | cloud sessions (parallel per wave) | sonnet | medium | Clear plan, tests catch failures loudly |
| S4 Android app | cloud session | sonnet | high | New codebase; Android API edge cases |
| Security review of S0/S2/S5 PRs | subagent | opus | high | Independent eyes on tokens, SQL definer, certificates |
| Merge + local real-device verification | this session | opus | medium | Needs the lab, Aruba and S23 |
Codex handoffs: optional read-only second-opinion review of the S5 PKI PR (`codex exec -s read-only`), only if you want it.
Antigravity handoffs: none.
Switch needed: none. The cloud sessions are started with the card's model and effort.
