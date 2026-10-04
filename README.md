# Campus Wi-Fi AAA lab — OpenLDAP + FreeRADIUS

This lab replaces one shared Wi-Fi password with a personal login for each user.
It implements AAA for WPA2-Enterprise (802.1X):

| AAA | Question | Where it happens |
|---|---|---|
| **Authentication** | Who are you? | FreeRADIUS checks the password against OpenLDAP (PEAP-MSCHAPv2 or EAP-TTLS/PAP) |
| **Authorization** | What may you do? | The LDAP group sets the session time limit and the VLAN, or rejects the user (`radius/raddb/policy.d/campus`) |
| **Accounting** | What happened? | Session start / update / stop records go to SQLite and to daily text files |

```
 Laptop / phone ──EAPOL──▶ D-Link AP ──RADIUS (UDP 1812/1813)──▶ FreeRADIUS ──LDAP──▶ OpenLDAP
  (supplicant)            (authenticator, NAS)                    (AAA server)         (identities)
                                                                       │
                                                                       └──▶ SQLite + detail files (accounting)
```

Everything runs in Docker on this Windows PC.

## 1. Quick start

You need Docker Desktop (running) and PowerShell.

```powershell
cd "C:\Users\DELL\Networking Project\aaa-server"
.\scripts\init.ps1            # creates .env (random secrets) and the lab certificates
docker compose up -d --build  # starts ldap, radius, ldapadmin
.\scripts\test.ps1            # runs the 28 end-to-end tests
```

All secrets are in `.env`. Git ignores `.env` and the `certs/` folder. Never share or commit them.

## 2. What runs

| Service | Image | Reachable at | Purpose |
|---|---|---|---|
| `ldap` | Debian 12 + `slapd` | internal network only | User directory `dc=nitsrinagar,dc=edu` |
| `radius` | `freeradius/freeradius-server:3.2.10` | UDP 1812 (auth), 1813 (acct) on all interfaces | AAA server |
| `ldapadmin` | `phpldapadmin/phpldapadmin:2.3.11` | http://127.0.0.1:8080 (this PC only) | Web UI to manage users |
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
└── ou=Services   cn=radius  (read-only account that FreeRADIUS uses)
```

All test users have the password `TEST_USER_PASSWORD` from `.env`.

Each user has two password hashes:
- `userPassword` (`{SSHA}`) — EAP-TTLS/PAP checks it with an LDAP bind.
- `sambaNTPassword` (NT hash) — PEAP-MSCHAPv2 needs it. Only the `cn=radius` account can read it.

## 3. Authorization policy

The policy is in `radius/raddb/policy.d/campus`.

| LDAP group | Result | Session-Timeout | VLAN (`Tunnel-Private-Group-Id`) | `Class` |
|---|---|---|---|---|
| `disabled` | **Reject** (wins over every other group) | — | — | — |
| `faculty` | Accept | 12 h | 20 | `faculty` |
| `staff` | Accept | 12 h | 20 | `staff` |
| `students` | Accept | 8 h | 10 | `students` |
| `guests` | Accept | 2 h | 30 | `guests` |
| no group | **Reject** | — | — | — |

The AP sends `Class` back in every accounting packet, so accounting records show the group.
The AP applies the VLAN only if it supports dynamic VLAN assignment. Consumer routers such as the DIR-X6060 usually do not. Then the VLAN attribute is ignored, but the other rules still apply.

## 4. Manage users

**Add a user** (prints a random password, unless you set `NEW_USER_PASSWORD`):

```powershell
docker compose exec ldap add-user.sh 24IT002 "IT Student 24IT002" Students students
```

**Disable a user:** add the user to `cn=disabled,ou=Groups`. To enable the user again, remove them from the group.

```powershell
@"
dn: cn=disabled,ou=Groups,dc=nitsrinagar,dc=edu
changetype: modify
add: member
member: uid=24IT002,ou=Students,dc=nitsrinagar,dc=edu
"@ | docker compose exec -T ldap ldapmodify -Q -Y EXTERNAL -H ldapi:///
```

**Web UI:** open http://127.0.0.1:8080. Log in with DN `cn=admin,dc=nitsrinagar,dc=edu` and the password `LDAP_ADMIN_PASSWORD` from `.env`.
Only the admin entry can log in. Wi-Fi users cannot.

> If you change a password in the web UI, also update `sambaNTPassword`. If you do not, PEAP fails for that user.
> To be safe, delete the user and create them again with `add-user.sh`.

## 5. Accounting

```powershell
.\scripts\acct.ps1          # last 20 sessions (user, group, device MAC, IP, time, bytes)
.\scripts\acct.ps1 -Auth    # last 20 accept / reject events, with the real user name
```

- SQLite database: volume `aaa-lab_radius-acct`, file `sqlite/radius.db`. Tables are `radacct` (sessions) and `radpostauth` (login attempts).
- Text copy: `radacct/<nas-ip>/detail-YYYYMMDD` in the same volume.
- Server log (each accept and reject, with the reason): `docker compose logs -f radius`.

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
| **Android** | EAP method **PEAP**, Phase 2 **MSCHAPV2**. CA certificate: install `ca.pem` (Settings → Security → Install certificate → Wi-Fi), then select it. Domain `radius.nitsrinagar.lab`. Identity = user ID, anonymous identity `anonymous`. |
| **Windows 10/11** | Import `ca.pem` into *Trusted Root Certification Authorities* (Local Computer). Connect to the SSID and enter the user ID and password. When Windows shows the certificate prompt, check that the issuer is "NIT Srinagar Lab CA". For strict checking, create a manual profile: PEAP, "Verify server identity", server `radius.nitsrinagar.lab`, trusted CA "NIT Srinagar Lab CA". |
| **iOS / macOS** | Join the SSID and enter the user ID and password. On the certificate screen, check that the certificate is `radius.nitsrinagar.lab` from "NIT Srinagar Lab CA", then tap Trust. |
| **Linux (NetworkManager)** | WPA & WPA2 Enterprise → PEAP (MSCHAPv2) or TTLS (PAP). CA certificate `ca.pem`. Domain `radius.nitsrinagar.lab`. |

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

- The NT hash (`sambaNTPassword`) is weaker than SSHA. PEAP-MSCHAPv2 needs it. Only `cn=radius` and the admin can read it.
- `certs/ca.key` signs server certificates. In a real deployment, keep it offline.
- phpLDAPadmin listens only on `127.0.0.1`. LDAP has no published port.
- `require_message_authenticator = yes` and `limit_proxy_state = yes` for the AP protect against BlastRADIUS (CVE-2024-3596).
- Weak EAP methods (MD5, GTC, LEAP) are not enabled. TLS 1.2 is the minimum.

## 10. Files

| Path | Content |
|---|---|
| `docker-compose.yml` | Services, fixed network `10.89.0.0/24` (does not collide with the 172.17.x campus LAN) |
| `ldap/entrypoint.sh` | First-start build: config, ACLs, base entries, seed users |
| `ldap/add-user.sh` | Creates a user with both password hashes and group membership |
| `ldap/seed/users.txt` | Test users |
| `radius/raddb/` | Only the FreeRADIUS files that differ from stock: `clients.conf`, `mods-available/{ldap,eap,sql}`, `sites-available/{default,inner-tunnel}`, `policy.d/campus` |
| `certs/make-certs.sh` | Lab CA and server certificate |
| `tests/run-tests.sh` | End-to-end tests |
| `scripts/` | `init.ps1`, `test.ps1`, `acct.ps1` |
| `docs/aaa-lab-guide.html` | Illustrated explainer of the whole lab, with every component and diagram. Open it in a browser. |
