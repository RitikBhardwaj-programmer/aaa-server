# Next steps: merged AAA design after Stages 1–3

Date: 2026-10-11. Branch: `feature/merged-aaa-core` (cut from `feature/instant-disable`).

## Goal
Finish the merged AAA design from `reports/IIT Delhi AAA plan review.md` on the lab. Passwords are checked only by an LDAP bind (decision 0002).

History: on 2026-10-11 the teacher said Kerberos could come later, so the lab was made Kerberos-ready (decision 0001). On 2026-10-25 the teacher decided to remove Kerberos; the krb5 stub and `PASSWORD_BACKEND` were removed (decision 0002).

## Done
Phase D: log lookup. `scripts/who-had-ip.ps1 -Ip -At` runs `who_had_ip()` (migration 003, index on `FramedIPAddress, AcctStartTime`) in a read-only session; 10 new end-to-end tests; DHCP/NAT import format documented in README section 5 only.

Phase C: self-service portal (Flask, LDAP bind login, RFC 3062 password change that also deletes the NT hash, my devices, disconnect), reviewed by an opus security review; 2 high, 2 medium and the actionable low findings fixed, promotion items listed in README 5b. 8 + 33 portal + 49 end-to-end tests pass with ALLOW_PEAP=yes and =no.

Phase A: committed 5a0a4a3 after the Codex review (5 findings fixed). Phase B: secure defaults done (TTLS default, ALLOW_PEAP gate, {ARGON2}, stored-uid accounting, self password change, decision record 0001, later 0002); 8 password-store checks + 49 end-to-end tests pass with ALLOW_PEAP=yes and =no.

Stages 1–3: PostgreSQL accounting (partitions, buffered-sql spool, server receive time), 3-device limit (soft/enforce), stale-session reaper, user_devices, per-device reject rate limit, Disconnect via PostgreSQL. 46/46 tests in both modes after the phase A review fixes; logins survive a database outage.

## Phases

| Phase | Work | Files | Done when |
|---|---|---|---|
| A. Review + commit | Independent review of the Stages 1–3 diff; fix findings; commit | whole diff | Findings fixed, 44/44 tests, one commit |
| B. Secure defaults | B1 EAP-TTLS/PAP as default EAP type; PEAP behind `ALLOW_PEAP` (on until the S23 moves) · B2 `{ARGON2}` password hashes in OpenLDAP; `add-user.sh` stops writing `sambaNTPassword` when PEAP is off · B3 LDAP bind as the only password check (`password_check` in the inner tunnel) · B4 uid rule `[A-Za-z0-9._-]`; accounting uses the stored uid · B5 decision records | `radius/raddb/mods-available/eap`, `sites-available/inner-tunnel`, `ldap/Dockerfile`, `ldap/entrypoint.sh`, `ldap/add-user.sh`, `.env.example`, `docs/decisions/0001-ldap-now-kerberos-later.md`, `docs/decisions/0002-ldap-only.md`, tests | Tests: TTLS default works; PEAP refused when `ALLOW_PEAP=no`; new users have `{ARGON2}` and no NT hash; bind still works |
| C. Self-service portal (Stage 4) | Login by LDAP bind; password change by LDAP Password Modify; "my devices" from `user_devices` + live sessions; "disconnect this device" (says when the AP ignores Disconnect); CSRF protection, login rate limit, localhost-only in the lab | new `portal/` service, compose | Portal tests pass; security review clean |
| D. Log lookup (Stage 5) | `who-had-ip <IP> <time>` → user, MAC, session, from `radacct`; index on (FramedIPAddress, AcctStartTime); DHCP/NAT import format documented only | `scripts/`, schema migration, README | A test session is traced to the user with one command |
| E. Real-device tests (later, user present) | Move the S23 to TTLS/PAP, then `ALLOW_PEAP=no`; review experiments 3–5 (Class/User-Name echo, PostgreSQL device limit with 4 devices, interim updates at 600 s) | `docs/experiments/` | One experiment note each |
| F. Guide update | `docs/aaa-lab-guide.html`: SQLite → PostgreSQL, device limit, rate limit | `docs/aaa-lab-guide.html` | Guide matches README |

Order: A → B → C and D (independent) → F. E waits for the user.

## Risks
- B1/B2: the S23 is set up for PEAP. Turning PEAP off before it moves to TTLS/PAP breaks its login. Existing users keep `{SSHA}` until their next password change (a hash cannot be converted without the password).
- C: a web page that accepts passwords. Needs the security review before anyone outside the lab PC uses it.
- Docker Desktop exposes RADIUS on the hostel LAN while it runs.

## Routing card
| Phase | Agent | Model | Effort | Why |
|---|---|---|---|---|
| A review | Codex `exec -s read-only` + own diff read | n/a | — | Independent eyes on SQL/unlang; uses the ChatGPT quota |
| B provisions | this session | opus | high | Auth design; mistakes fail quietly |
| C build | new session from this plan | sonnet | medium | Clear plan; test failures are loud |
| C security review | subagent | opus | high | Password-handling web page |
| D build | new session | sonnet | medium | Small, well specified |
| F guide | Codex `exec -s workspace-write` | n/a | — | Self-contained; easy to check against README |

Codex handoffs: A (review), F (guide). Switch needed: C and D in new sessions at sonnet/medium.

## Open decisions
1. Approve this plan and card.
2. Approve Flask as a new dependency (phase C).
3. Commit Stages 1–3 after the review (phase A).
