# Campus Wi-Fi AAA lab — OpenLDAP + FreeRADIUS

This lab replaces one shared Wi-Fi password with a personal login for each user.
It implements AAA for WPA2-Enterprise (802.1X):

| AAA | Question | Where it happens |
|---|---|---|
| **Authentication** | Who are you? | FreeRADIUS checks the password against OpenLDAP. EAP-TTLS/PAP is the default; PEAP-MSCHAPv2 only while `ALLOW_PEAP=yes` |
| **Authorization** | What may you do? | The LDAP group sets the session time limit and the VLAN, or rejects the user (`radius/raddb/policy.d/campus`) |
| **Accounting** | What happened? | Session start / update / stop records go to PostgreSQL and to daily text files. They also drive the 3-device limit |

```
 Laptop / phone ──EAPOL──▶ D-Link AP ──RADIUS (UDP 1812/1813)──▶ FreeRADIUS ──LDAP──▶ OpenLDAP
  (supplicant)            (authenticator, NAS)                    (AAA server)         (identities)
                                                                       │
                                                  detail files + spool ┴──▶ PostgreSQL ◀── maintenance
                                                                       (accounting, device limit)  (reaper, partitions)
```

Everything runs in Docker on this Windows PC.

## 1. Quick start

You need Docker Desktop (running) and PowerShell.

```powershell
cd "C:\Users\DELL\Networking Project\aaa-server"
.\scripts\init.ps1            # creates .env (random secrets) and the lab certificates
docker compose up -d --build  # starts ldap, postgres, maintenance, radius, portal, ldapadmin
.\scripts\test.ps1            # runs the 8 password-store checks, the 21 portal tests and the 49 end-to-end tests
```

All secrets are in `.env`. Git ignores `.env` and the `certs/` folder. Never share or commit them.

## 2. What runs

| Service | Image | Reachable at | Purpose |
|---|---|---|---|
| `ldap` | Debian 12 + `slapd` | internal network only | User directory `dc=nitsrinagar,dc=edu` |
| `radius` | `freeradius/freeradius-server:3.2.10` | UDP 1812 (auth), 1813 (acct) on all interfaces | AAA server |
| `postgres` | `postgres:17.6-bookworm` | internal network only | Accounting database (`radacct`, `radpostauth`, device-limit tables) |
| `maintenance` | `postgres:17.6-bookworm` | — | Every 5 min: closes stale sessions, manages monthly partitions, expires old devices |
| `ldapadmin` | `phpldapadmin/phpldapadmin:2.3.11` | http://127.0.0.1:8080 (this PC only) | Web UI to manage users |
| `portal` | `python:3.12.14-slim-bookworm` + Flask | http://127.0.0.1:8081 (this PC only) | Self-service portal for Wi-Fi users (section 5b) |
| `tests` | Debian 12 + `eapol_test` | runs on demand | Test suite (real 802.1X client, no Wi-Fi needed) |

### Directory layout

```
dc=nitsrinagar,dc=edu
├── cn=admin                 directory administrator (phpLDAPadmin login)
├── ou=Students   uid=student001, uid=24IT001, uid=disabled001
├── ou=Faculty    uid=faculty001
├── ou=Staff      uid=staff001
├── ou=Guests     uid=guest001
├── ou=Groups     cn=students, cn=faculty, cn=staff, cn=guests, cn=disabled
└── ou=Services   cn=radius  (read-only account that FreeRADIUS uses; can read NT hashes)
                 cn=portal  (read-only account of the portal; cannot read any password hash)
```

All test users have the password `TEST_USER_PASSWORD` from `.env`.

Each user has two password hashes:
- `userPassword` (`{ARGON2}`; users made before 11 Oct 2026 keep `{SSHA}` until their next password change) — EAP-TTLS/PAP checks it with an LDAP bind. Users may change their own password (RFC 3062 Password Modify), nobody can read it.
- `sambaNTPassword` (NT hash) — only while `ALLOW_PEAP=yes`, because PEAP-MSCHAPv2 needs it. Only the `cn=radius` account can read it.

Login names are matched without regard to case (`24it001` logs in as `24IT001`), but accounting, the device limit and the logs always use the uid as stored in LDAP. Why passwords are checked only by an LDAP bind: `docs/decisions/0002-no-kerberos.md`.

## 3. Authorization policy

The policy is in `radius/raddb/policy.d/campus`.

| LDAP group | Result | VLAN (`Tunnel-Private-Group-Id`) | `Class` |
|---|---|---|---|
| `disabled` | **Reject** (wins over every other group) | — | — |
| `faculty` | Accept | 20 | `faculty` |
| `staff` | Accept | 20 | `staff` |
| `students` | Accept | 10 | `students` |
| `guests` | Accept | 30 | `guests` |
| no group | **Reject** | — | — |

Every Accept also carries `Session-Timeout = REAUTH_INTERVAL` (from `.env`, lab default 300 s) and `Termination-Action = RADIUS-Request`.
The AP then re-checks each connected user at that interval **without disconnecting them**.
A user disabled in LDAP fails the next re-check, so access ends within `REAUTH_INTERVAL` even on APs that ignore Disconnect-Requests (see section 4).

The AP sends `Class` back in every accounting packet, so accounting records show the group.
The AP applies the VLAN only if it supports dynamic VLAN assignment. Consumer routers such as the DIR-X6060 usually do not. Then the VLAN attribute is ignored, but the other rules still apply.

## 4. Manage users

**Add a user** (prints a random password, unless you set `NEW_USER_PASSWORD`):

```powershell
docker compose exec ldap add-user.sh 24IT002 "IT Student 24IT002" Students students
```

**Disable a user** (blocks all new logins and re-checks, then disconnects open sessions):

```powershell
.\scripts\disable-user.ps1 24IT002
```

It does two things:
1. It adds the user to `cn=disabled,ou=Groups`.
2. It sends an RFC 5176 **Disconnect-Request** to the AP of each open session found in `radacct`. An AP that supports it drops the device at once.
   The DAP-X3060 (firmware v1.01) does not answer it, so there the device is dropped at the next re-check, within `REAUTH_INTERVAL`.

**Enable the user again:**

```powershell
.\scripts\enable-user.ps1 24IT002
```

On Docker Desktop every AP appears as `10.89.0.1`. So the disconnect goes to `AP_IP` from `.env`. Keep `AP_IP` equal to the AP's current address.

**Web UI:** open http://127.0.0.1:8080. Log in with DN `cn=admin,dc=nitsrinagar,dc=edu` and the password `LDAP_ADMIN_PASSWORD` from `.env`.
Only the admin entry can log in. Wi-Fi users cannot.

> If you change a password in the web UI while `ALLOW_PEAP=yes`, also update `sambaNTPassword`. If you do not, PEAP fails for that user.
> To be safe, delete the user and create them again with `add-user.sh`.

## 5. Accounting

```powershell
.\scripts\acct.ps1          # last 20 sessions (user, group, device MAC, IP, time, bytes)
.\scripts\acct.ps1 -Auth    # last 20 accept / reject events, with the real user name and device
.\scripts\acct.ps1 -Devices # users with the most live devices, and recent device-limit events
```

- PostgreSQL database `radius` (volume `aaa-lab_pg-data`). Tables:
  - `radacct`: sessions, one monthly partition each (`radacct_2026_10`, ...). Partitions older than `ACCT_RETENTION_MONTHS` are dropped.
  - `radpostauth`: login attempts, partitioned the same way. It has **no password column**.
  - `user_devices`: every device MAC each user was seen with (kept `DEVICE_EXPIRY_DAYS`).
  - `device_limit_events`: every login that found the user already at the device limit.
- How records get there: FreeRADIUS writes each accounting packet to a spool file (`radacct/spool/` in volume `aaa-lab_radius-acct`). The `buffered-sql` server reads it into PostgreSQL. If the database is down, records wait in the spool and are retried every 30 s. Logins still work.
- Times are the **server's receive time** (minus `Acct-Delay-Time`), not the AP clock. The AP's own `Event-Timestamp` stays in the text copy.
- Text copy, exactly as received: `radacct/<nas-ip>/detail-YYYYMMDD` in the same volume.
- Server log (each accept and reject, with the reason): `docker compose logs -f radius`.
- Old SQLite data from before the PostgreSQL change stays in `sqlite/radius.db` in volume `aaa-lab_radius-acct`. Nothing reads it any more.

### Device limit (3 devices per student)

A student may have `DEVICE_LIMIT_STUDENTS` devices online at the same time. At each login, FreeRADIUS counts the **distinct device MACs** with an open session that had an accounting update in the last `STALE_SESSION_MINUTES`. The device that is logging in now is not counted.
- `DEVICE_LIMIT_MODE=soft` (default): the device gets in, and the event is logged in `device_limit_events`. Use this for the first 4–6 weeks.
- `DEVICE_LIMIT_MODE=enforce`: the device gets an Access-Reject (with a `Reply-Message`).

Stale sessions (lost Stop, AP crash) stop counting after `STALE_SESSION_MINUTES`, and the `maintenance` service closes them (`AcctTerminateCause = Stale-Session-Reaped`). An `Accounting-On` from a rebooted AP closes all its sessions. If PostgreSQL is down, the limit is skipped (fails open).

Known limits: PMK-cached and 802.11r reconnects skip RADIUS, so the check runs only on a full login. Two devices that join in the same second can both pass.

### Failed-login rate limit (instead of lockout)

After `AUTH_REJECT_LIMIT` rejects for one user **from one device** in `AUTH_REJECT_WINDOW` minutes, that device is refused without a password check. The user's other devices still work, so nobody can lock a student out by guessing their password.

### Who had this IP?

```powershell
.\scripts\who-had-ip.ps1 -Ip 10.20.30.40 -At "2026-10-11 14:30"
```

It answers: which user, device MAC, access point and session had this IPv4 address at that time. This is the first question CERT-In asks after an incident. It reads `radacct` through the function `who_had_ip(ip, at)` (migration `postgres/migrations/003-who-had-ip.sql`, with an index on `FramedIPAddress, AcctStartTime` on every partition) in a read-only session.

- **Time zone.** A time without an offset is India time (+05:30). The script prints the exact UTC instant it searched. Write `...T09:00:00Z` or `...+05:30` to be explicit.
- **Server time.** Sessions are compared on the server receive time, not the AP clock (the DAP-X3060 shows 2024). Use a lookup time from a trusted clock (NIC/NPL).
- **Status.** `closed` (has a Stop, or was reaped: the stop time is the last update), `open` (still online, updates arriving), `stale-open` (open, but no update for more than `STALE_SESSION_MINUTES`; the AP may have lost the Stop; a time after the last update does not match).
- **Exit code.** 0 found, 1 not found, 2 bad input, 3 database error.
- **Limits.** IPv4 only (`FramedIPv6Address` is stored but not searched yet). Only devices whose AP sends `Framed-IP-Address` in accounting packets can be found. "Not found" does not prove nobody had the IP. Test it: connect a device, then search its IP.

### Log chain (CERT-In / DPDP)

RADIUS accounting is one of **three** logs. An incident usually starts with a public IP and port seen outside the campus. To reach a person, the three must be joined:

```
public IP:port --(NAT log)--> private IP --(DHCP log)--> MAC --(RADIUS accounting)--> user
```

The lab has no campus DHCP or NAT server, so nothing imports these logs yet. Expected import format, for a later step (keep 12 months, all on NIC/NPL time, same retention as `radacct`):

| Source | Fields | Example line |
|---|---|---|
| DHCP lease log | time, event (assign/renew/release), IP, MAC, hostname | `2026-10-11T14:02:11+05:30,assign,10.20.30.40,02-00-CA-15-0C-01,galaxy-s23` |
| NAT port-block log | time, event (alloc/free), private IP, public IP, port start, port end, protocol | `2026-10-11T14:02:12+05:30,alloc,10.20.30.40,203.0.113.7,20000,20999,tcp` |

`who-had-ip` gives the MAC and user for a private IP. The DHCP log is a cross-check for the same lookup (a MAC with no Framed-IP in accounting), and the NAT log turns a public IP and port into the private IP.
## 5b. Self-service portal

Open http://127.0.0.1:8081 on this PC. A Wi-Fi user logs in with the Wi-Fi ID and password and can:

- **Change the password.** 15 to 128 characters, no other rules (NIST SP 800-63B-4). The password must not contain the user ID and must not be in `portal/blocklist.txt` (about 100 common passwords). The portal uses RFC 3062 Password Modify as the user; slapd hashes the new password as `{ARGON2}` (decision 0002).
- **See their devices.** Live sessions (MAC, access point, IP, start, last update, bytes), every device seen, "N of 3 devices online" for students, and recent device-limit events.
- **Disconnect a device.** The portal sends an RFC 5176 Disconnect-Request for each open session of that MAC. It first checks that the session belongs to the logged-in user. The DAP-X3060 ignores the request, so the page says the device is dropped at the next re-check (within `REAUTH_INTERVAL`).

**PEAP after a password change.** Password Modify updates only `userPassword`, so the portal first **deletes** the user's NT hash (`sambaNTPassword`); otherwise the old password would keep working for PEAP. PEAP then stops working for that user, and their devices must be set up as EAP-TTLS/PAP. The password page says so. (The LDAP ACL lets a user delete, but not read or write, their own NT hash.)

Least privilege: the portal binds to LDAP as `cn=portal` (reads entries and groups, no password hashes) over one reused connection, and to PostgreSQL as role `portal` (SELECT on `radacct`, `user_devices`, `device_limit_events`). It never uses `cn=radius`. To check a login it finds the user with `cn=portal`, then binds as the user.

Abuse limits (all counted before the password is checked, so parallel requests cannot slip through): 5 attempts per (ID, client address) and 20 per client address in 15 minutes; 5 wrong "current password" tries per user in 15 minutes; at most 4 logins at once (each costs slapd up to three Argon2 checks); one Disconnect-Request at a time and 5 per 5 minutes per user. Every login failure gives the same message.

Sessions: CSRF tokens on every form; the cookie is `HttpOnly` and `SameSite=Strict`, ends after 15 minutes idle or 30 minutes after login. Every request re-checks the account in LDAP: a password change, a disabled account or a lost Wi-Fi group ends all sessions of that user, including a stolen copy of the cookie. A Content-Security-Policy forbids inline script and style. The AP secret reaches `radclient` through a private file (`-S`), never a command line. The portal refuses to start with a `PORTAL_SECRET_KEY` shorter than 32 characters.

Database role on an existing database (first start does it by itself; needs `POSTGRES_PORTAL_PASSWORD` in `.env`):

```powershell
docker compose up -d postgres
docker compose exec -T postgres psql -U postgres -d radius -v ON_ERROR_STOP=1 -f /migrations/002-portal-role.sql
docker compose exec -T postgres sh /migrations/002-portal-password.sh
```

The LDAP account is added when the `ldap` container starts (`docker compose up -d --build ldap`), also on an existing directory.

**Lab limits** (not for use by others on the LAN yet):
- http only, on `127.0.0.1`. Over https set `SESSION_COOKIE_SECURE=true`.
- Flask's built-in server. Production needs a real WSGI server, which is a new dependency and needs approval.
- The rate limits are in the memory of one process. Several portal processes would each count alone and would need a shared store.
- Behind Docker Desktop every client shows the same address, so the per-address limit (20 in 15 minutes) is shared by everyone using the portal in the lab.
- Login timing differs slightly between unknown and known IDs (a known ID costs an Argon2 check).
- The portal reaches LDAP over plain `ldap://` inside the Docker network.

**Before others may use it** (from the security review of 11 Oct 2026): https with `SESSION_COOKIE_SECURE=true`; a WSGI server; StartTLS/LDAPS to slapd; a shared store for the rate limits; a large breached-password list instead of `blocklist.txt`; the ppolicy overlay with `olcPPolicyHashCleartext` (today a user with direct LDAP access could write their own `userPassword` and skip the portal's rules; port 389 is not published, so only the portal can); a separate Disconnect (DAS) secret instead of the AP's RADIUS secret; restricting phpLDAPadmin logins to the admin DN (service accounts share its objectClass); and a real-AP check that accounting `User-Name` is the inner identity, because the portal shows sessions by that name.
## 6. Connect the D-Link DIR-X6060 (Phase 3)

### 6.1 Check that the router supports WPA-Enterprise

Open the router UI (default http://192.168.0.1) → **Settings → Wireless** → **Security Mode**.

- If there is a **WPA2-Enterprise** (or **WPA/WPA2-Enterprise**) option, continue below.
- If there is only **WPA2-Personal / WPA3-Personal**, this router cannot do 802.1X.
  Use an AP that supports Enterprise mode, for example a D-Link DAP business AP or an OpenWrt router.
  The server side does not change.

### 6.2 Prepare this PC

1. Connect this PC to the D-Link network (LAN cable or its Wi-Fi). Note the PC's IP address (`ipconfig`).
   In the router, give the PC a fixed IP (DHCP reservation), so the RADIUS address does not change.
2. Allow inbound RADIUS through Windows Firewall. Run this in an **administrator** PowerShell:
   ```powershell
   New-NetFirewallRule -DisplayName "FreeRADIUS lab (UDP 1812-1813)" -Direction Inbound -Protocol UDP -LocalPort 1812,1813 -Action Allow -Profile Private
   ```
   The network profile of that connection must be **Private** (Settings → Network → Properties).

### 6.3 Configure the router

| Field | Value |
|---|---|
| Security mode | WPA2-Enterprise (AES) |
| RADIUS server IP | this PC's IP from step 6.2 |
| RADIUS port | 1812 |
| Shared secret | `RADIUS_SECRET_AP` from `.env` |
| Accounting server (if the router has the field) | same IP, port 1813, same secret |

### 6.4 Why the AP's own IP does not matter

Docker Desktop on Windows rewrites the source address of all incoming LAN packets to `10.89.0.1`.
So `clients.conf` identifies the AP with that address, and the **shared secret** is the real proof of identity.
Keep `RADIUS_SECRET_AP` long and private.
A check on `NAS-IP-Address` would not add security, because any device that knows the secret can forge it.
`AP_IP` in `.env` is used only if you move the stack to a Linux host with host networking.

## 7. Configure client devices

Every device must check the server certificate. If it does not, a fake AP can collect passwords.

- CA certificate: `certs/ca.pem` ("NIT Srinagar Lab CA"). Copy it to the device.
- Server name (domain): `radius.nitsrinagar.lab`
- Anonymous (outer) identity: `anonymous`

| Device | Settings |
|---|---|
| **Android** | EAP method **TTLS**, Phase 2 **PAP**. CA certificate: install `ca.pem` (Settings → Security → Install certificate → Wi-Fi), then select it. Domain `radius.nitsrinagar.lab`. Identity = user ID, anonymous identity `anonymous`. (PEAP/MSCHAPV2 works only while `ALLOW_PEAP=yes`.) |
| **Windows 10/11** | Import `ca.pem` into *Trusted Root Certification Authorities* (Local Computer). Create a manual profile: EAP-TTLS, inner method PAP ("Unencrypted password (PAP)"), "Verify server identity", server `radius.nitsrinagar.lab`, trusted CA "NIT Srinagar Lab CA". |
| **iOS / macOS** | Join the SSID and enter the user ID and password. On the certificate screen, check that the certificate is `radius.nitsrinagar.lab` from "NIT Srinagar Lab CA", then tap Trust. |
| **Linux (NetworkManager)** | WPA & WPA2 Enterprise → TTLS (PAP). CA certificate `ca.pem`. Domain `radius.nitsrinagar.lab`. |

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Nothing arrives at FreeRADIUS | Firewall rule (6.2), PC IP in the router, both devices on the same network. Check `docker compose logs -f radius`. |
| `Ignoring request ... from unknown client` | The sender's source address is not in `clients.conf`. |
| `Login incorrect (... No NT-Password)` | The user has no `sambaNTPassword`. Create the user again with `add-user.sh`. |
| Client says certificate is not trusted | The CA is not installed on the device, or the domain is not `radius.nitsrinagar.lab`. |
| Need full detail | Run the debug mode below. |

**Debug mode** (prints every step of every request):

```powershell
docker compose stop radius
docker compose run --rm --service-ports radius -X
# Ctrl+C to stop, then:
docker compose up -d radius
```

**Start from zero** (deletes all users and accounting data):

```powershell
docker compose down -v
docker compose up -d --build
```

## 9. Security notes

- The NT hash (`sambaNTPassword`) is unsalted MD4 and works like the password itself for MSCHAPv2. It exists only while `ALLOW_PEAP=yes`. After the last PEAP device moves to TTLS/PAP, set `ALLOW_PEAP=no` and delete the existing values.
- Passwords are hashed with Argon2 (`{ARGON2}`, argon2i, 19 MiB, 2 passes).
- `certs/ca.key` signs server certificates. In a real deployment, keep it offline.
- phpLDAPadmin listens only on `127.0.0.1`. LDAP has no published port.
- `require_message_authenticator = yes` and `limit_proxy_state = yes` for the AP protect against BlastRADIUS (CVE-2024-3596).
- Weak EAP methods (MD5, GTC, LEAP) are not enabled. TLS 1.2 is the minimum and the maximum (TLS 1.3 inside PEAP/TTLS is unreliable on FreeRADIUS 3.2). The TLS session cache is off, so a disabled user cannot resume an old session.
- `radpostauth` never stores passwords. The stock FreeRADIUS query stores `User-Password`, which plain PAP requests carry.
- PostgreSQL has no published port. FreeRADIUS uses the non-superuser role `radius`. `acct.ps1` opens a read-only session.
- The portal uses its own read-only accounts (`cn=portal`, role `portal`). It is published on `127.0.0.1` only. See section 5b for its limits.

## 10. Files

| Path | Content |
|---|---|
| `docker-compose.yml` | Services, fixed network `10.89.0.0/24` (does not collide with the 172.17.x campus LAN) |
| `ldap/entrypoint.sh` | First-start build: config, ACLs, base entries, seed users |
| `ldap/add-user.sh` | Creates a user with both password hashes and group membership |
| `ldap/set-disabled.sh` | Adds a user to, or removes a user from, `cn=disabled` |
| `tests/disconnect-user.sh` | Sends Disconnect-Requests for a user's open sessions (run through the `tools` service) |
| `ldap/seed/users.txt` | Test users |
| `radius/raddb/` | Only the FreeRADIUS files that differ from stock: `clients.conf`, `mods-available/{ldap,eap,sql,sql_spool}`, `mods-config/sql/main/postgresql/queries.conf`, `sites-available/{default,inner-tunnel,buffered-sql}`, `policy.d/campus` |
| `postgres/initdb/` | First-start database setup: role `radius`, partitioned schema, device-limit tables, maintenance functions |
| `postgres/maintenance.sh` | Stale-session reaper, partition creation and retention, device expiry |
| `certs/make-certs.sh` | Lab CA and server certificate |
| `tests/run-tests.sh` | End-to-end tests |
| `portal/` | Self-service portal: `app.py`, `templates/`, `static/portal.css`, `blocklist.txt`, `requirements.txt` (pinned), `tests/test_portal.py` |
| `postgres/migrations/003-who-had-ip.sql` | Index and the `who_had_ip` function (used by `scripts/who-had-ip.ps1`) |
| `postgres/migrations/002-portal-*` | Read-only database role `portal` (SQL) and its password setter (script) |
| `tests/portal-test-user.sh` | Creates and deletes the temporary user for the portal tests |
| `tests/ldap-checks.sh` | Password-store checks run inside the ldap container (Argon2, NT hash, self-service password change) |
| `docs/decisions/` | Design decisions, e.g. `0002-no-kerberos.md` |
| `scripts/` | `init.ps1`, `test.ps1` (all three suites), `acct.ps1`, `who-had-ip.ps1`, `disable-user.ps1`, `enable-user.ps1` |
| `docs/aaa-lab-guide.html` | Illustrated explainer of the whole lab, with every component and diagram. Open it in a browser. |
