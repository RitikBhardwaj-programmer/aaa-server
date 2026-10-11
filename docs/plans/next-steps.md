# Next steps: merged AAA design after Stages 1–3

Date: 2026-10-11. Branch: `feature/merged-aaa-core` (cut from `feature/instant-disable`).

## Goal
Finish the merged AAA design from `reports/IIT Delhi AAA plan review.md` on the lab. The teacher's Kerberos decision (2026-10-11): not now, but keep a provision to add it later. The comparison is in `reports/ldap-vs-kerberos/LDAP-vs-Kerberos.pdf`.

## Done
Phase A: committed 5a0a4a3 after the Codex review (5 findings fixed). Phase B: Kerberos-ready provisions done (TTLS default, ALLOW_PEAP gate, {ARGON2}, PASSWORD_BACKEND, stored-uid accounting, self password change, decision record 0001); 8 password-store checks + 49 end-to-end tests pass with ALLOW_PEAP=yes and =no.

Stages 1–3: PostgreSQL accounting (partitions, buffered-sql spool, server receive time), 3-device limit (soft/enforce), stale-session reaper, user_devices, per-device reject rate limit, Disconnect via PostgreSQL. 46/46 tests in both modes after the phase A review fixes; logins survive a database outage.

## Phases

| Phase | Work | Files | Done when |
|---|---|---|---|
| A. Review + commit | Independent review of the Stages 1–3 diff; fix findings; commit | whole diff | Findings fixed, 44/44 tests, one commit |
| B. Kerberos-ready provisions | B1 EAP-TTLS/PAP as default EAP type; PEAP behind `ALLOW_PEAP` (on until the S23 moves) · B2 `{ARGON2}` password hashes in OpenLDAP; `add-user.sh` stops writing `sambaNTPassword` when PEAP is off · B3 `PASSWORD_BACKEND=ldap` switch in the inner tunnel (`krb5` documented, not built) · B4 username rule valid as a Kerberos principal; realm `NITSRINAGAR.EDU` reserved · B5 decision record | `radius/raddb/mods-available/eap`, `sites-available/inner-tunnel`, `ldap/Dockerfile`, `ldap/entrypoint.sh`, `ldap/add-user.sh`, `.env.example`, `docs/decisions/0001-ldap-now-kerberos-later.md`, tests | Tests: TTLS default works; PEAP refused when `ALLOW_PEAP=no`; new users have `{ARGON2}` and no NT hash; bind still works |
| C. Self-service portal (Stage 4) | Login by LDAP bind; password change through one backend function (LDAP Password Modify now, kadmin later); "my devices" from `user_devices` + live sessions; "disconnect this device" (says when the AP ignores Disconnect); CSRF protection, login rate limit, localhost-only in the lab | new `portal/` service, compose | Portal tests pass; security review clean |
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
