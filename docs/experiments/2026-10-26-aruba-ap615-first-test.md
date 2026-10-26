# Aruba AP-615 first test: 802.1X, accounting and revocation with the S23 (2026-10-26)

- **Status:** passed after fixes (one open bug: second radacct row after a failed re-auth, see expectation 7)
- **Who / where:** project student, hostel room (hostel LAN 172.17.28.0/24)
- **Report built from it:** none yet
- **Earlier test with the D-Link:** [2026-10-05-s23-real-ap.md](2026-10-05-s23-real-ap.md)

## Aim
Does an enterprise AP (Aruba AP-615) work with the lab FreeRADIUS + LDAP + PostgreSQL stack, and does it do what the D-Link DAP-X3060 could not: apply RADIUS attributes, report the client IP, and accept RFC 5176 Disconnect-Requests?

## Setup
| Item | Value |
|---|---|
| Device under test | Samsung Galaxy S23, Android, randomised MAC `66-1D-87-E6-C1-92`, EAP-TTLS / PAP, CA "NIT Lab CA", domain `radius.nitsrinagar.lab`, anonymous identity `anonymous` |
| Access point / NAS | Aruba AP-615-RW (R7J49A), Aruba Instant web UI, MAC `8C:79:09:C0:ED:F0`, IP `172.17.28.245` (DHCP), SSID `NITS-Lab` (WPA2-Enterprise), bridged onto the hostel LAN |
| AP RADIUS server entry | `nit-lab-radius` → `172.17.28.252`, ports 1812/1813, NAS-Identifier `aruba-ap615`, Dynamic Authorization on, Status-Server on (auth + acct), RadSec off |
| AP SSID settings | EAP offload off, reauth interval 0 (server Session-Timeout rules), accounting "Use authentication servers", accounting interval 10 min, authentication survivability off, MAC auth off |
| Server side | FreeRADIUS 3.2.10 (Docker), branch `feature/merged-aaa-core`, `REAUTH_INTERVAL=300`, `ACCT_INTERIM_INTERVAL=600`, **`SEND_VLAN=no`** (new setting, see Problems) |
| Network | Laptop (Docker Desktop host) `172.17.28.252` on the same LAN. Docker NAT shows the AP as `10.89.0.1` (client `ap-dirx6060`) |
| Clock used for times | Server (Asia/Kolkata). AP clock: **correct** (`Event-Timestamp = "Oct 26 2026 21:54:22 IST"`) |

## Expectations (written before the result)
| # | Expectation | Result |
|---|---|---|
| 1 | Status-Server from the AP is answered by FreeRADIUS on 1812 and 1813 | pass (radclient test from the tests container: `Access-Accept` on 1812, `Accounting-Response` on 1813; AP probes themselves not logged) |
| 2 | S23 logs in as `student001` over EAP-TTLS/PAP | pass after fixes (VLAN, Identity field) |
| 3 | AP sends Accounting-Start with the client IP and echoes `Class` | pass |
| 4 | AP sends Interim-Updates | pass (one Interim-Update 52 s after Start; next one not observed before the session ended) |
| 5 | Disabled user is rejected at the next re-check, and the AP drops the device | pass |
| 6 | Disconnect-Request to the AP gets a Disconnect-ACK (instant revocation) | first run **fail** (no reply, Docker bridge overlap); **pass** after the bridge fix: ACK, device dropped 2 s after the disable command, `Admin-Reset` |
| 6b | A Disconnect for a session the AP no longer has is refused | pass: Disconnect-NAK for the stale 21:54 row |
| 7 | Accounting Stop closes the same radacct row | first run **fail**: Stop came with `User-Name = "anonymous"` and created a second row. **Pass** after `campus_acct_unique` (re-test 22:35–22:45: one row, closed, user `student001`) |
| 9 | Without a Disconnect, the disabled user loses access within `REAUTH_INTERVAL` (300 s) | **fail in the re-test**: reject came 8 min 47 s after the disable (first run: 16 s) |
| 8 | Re-enabled user can log in again | pass |

## Timeline (server time)
| Time | Event | Evidence |
|---|---|---|
| ~19:17 | Lab started, all suites pass (59/59 e2e) | `scripts/test.ps1` |
| 20:08:33–37 | Rejects: phone had `anonymous` in the Identity field | radpostauth `anonymous / Access-Reject` |
| 20:09:21–20:19:38 | 6 × Access-Accept for student001, but phone returns to the settings screen, **no accounting** from the AP | radpostauth; `radacct/10.89.0.1/` untouched since 5 Oct |
| 20:22–20:25 | `SEND_VLAN` added, radius rebuilt, suites run in both modes (59/59 each), `.env` set to `SEND_VLAN=no` | test output |
| 21:53:39 | Login OK student001 | radius log `(302)` |
| 21:54:22 | Accounting **Start**, IP `172.17.28.110` | detail file |
| 21:55:14 | Interim-Update, 52 s, 762021 B in / 508696 B out | detail file |
| 21:59:10 | `disable-user.ps1 student001`: LDAP disabled; Disconnect step printed "No open sessions" (tools image had no `psql`) | script output |
| 21:59:26 | Re-auth from the AP → **Reject** | radius log `(317)` |
| 21:59:31 | Retry → Reject; AP sends **Stop**, `User-Name = "anonymous"`, `Lost-Service`, 308 s | radius log `(330)`, detail file |
| 21:59:57 | Tools image rebuilt; Disconnect-Request to `172.17.28.245:3799` → **no reply** (2 retries) | script output |
| ~22:00 | Verbose radclient: `No reply from server`; TCP 4343 from a container to the AP: **not reachable** | see Evidence |
| 22:01:26 | Phone retry → Reject (still disabled) | radpostauth |
| ~22:01:30 | `enable-user.ps1 student001` | script output |
| 22:01:48 | Login OK, new Accounting Start (new session ID) | radius log `(352)`, detail file |
| ~22:05 | Docker Engine `"bip": "192.168.200.1/24"` (backup `~/.docker/daemon.json.bak-20261026`), `docker desktop restart`; bridge now `192.168.200.0/24`, lab back up | `docker network inspect bridge` |
| ~22:06 | TCP 4343 from a container to the AP: **reachable** (was not before) | tools container |
| 22:07:04 | Scheduled re-check, Login OK (5 min 16 s after 22:01:48) | radius log `(367)` |
| 22:12:10 | Scheduled re-check, Login OK | radius log `(9)` |
| 22:12:11 | `disable-user.ps1 student001` | script output |
| 22:12:13 | **Disconnect-ACK**; AP sends Stop, `User-Name = "student001"`, `Admin-Reset`, 626 s | script output, radacct |
| 22:12:14–24 | Phone retries 3 × → Reject ("Rejected in post-auth") | radius log `(22)`, `(33)`, `(44)` |
| 22:12:50 | `enable-user.ps1 student001`; phone did not retry by itself | script output, radius log |
| 22:16:51 | S23 re-joins with a **new randomised MAC** `2E-C0-09-A6-4E-E0`; Start keyed by the old rule | detail file, radacct `d175…` |
| 22:22:29 | radius rebuilt with `campus_acct_unique` | radius log |
| 22:25:33 | Interim-Update gets the new key → second row `d8d2…` (expected switch-over effect) | radacct |
| 22:32:12 | Wi-Fi off on the phone → Stop, `Lost-Service`, closes `d8d2…` as student001 | radacct |
| 22:35:42 | Wi-Fi on → Login OK, Start keyed by the new rule (`d096…`), IP `172.17.28.192` | radius log `(313)`, radacct |
| 22:36:04 | `set-disabled.sh student001 on` (LDAP only, **no Disconnect**) | command output |
| 22:44:51 | Stop, `User-Name = "anonymous"`, `Supplicant-Restart`, 570 s; first Reject `(358)` in the same second | detail file, radius log |
| 22:44:52, 22:45:19 | Retries → Reject | radius log `(370)`, `(381)` |
| 22:45:50 | `set-disabled.sh student001 off` | command output |

## Evidence

### Login results (radpostauth, device 66-1D-87-E6-C1-92)
```
    t     |  username  |     reply     |      device       |  class
----------+------------+---------------+-------------------+----------
 20:08:33 | anonymous  | Access-Reject | 66-1D-87-E6-C1-92 |
 20:08:37 | anonymous  | Access-Reject | 66-1D-87-E6-C1-92 |
 20:09:21 | student001 | Access-Accept | 66-1D-87-E6-C1-92 | students
 20:10:46 | student001 | Access-Accept | 66-1D-87-E6-C1-92 | students
 20:11:06 | student001 | Access-Accept | 66-1D-87-E6-C1-92 | students
 20:14:00 | student001 | Access-Accept | 66-1D-87-E6-C1-92 | students
 20:19:17 | student001 | Access-Accept | 66-1D-87-E6-C1-92 | students
 20:19:38 | student001 | Access-Accept | 66-1D-87-E6-C1-92 | students
 21:53:39 | student001 | Access-Accept | 66-1D-87-E6-C1-92 | students
 21:59:26 | student001 | Access-Reject | 66-1D-87-E6-C1-92 |
 21:59:31 | student001 | Access-Reject | 66-1D-87-E6-C1-92 |
 22:01:26 | student001 | Access-Reject | 66-1D-87-E6-C1-92 |
 22:01:48 | student001 | Access-Accept | 66-1D-87-E6-C1-92 | students
```

### Accounting packets from the Aruba (detail files, server receive time)
| Received | Type | Session | User | Device | IP | Time (s) | In (B) | Out (B) | Cause |
|---|---|---|---|---|---|---|---|---|---|
| 21:54:22 | Start | 8C79098EDF01-661D87E6C192-6ADF7EB7-362AE | student001 | 66-1D-87-E6-C1-92 | 172.17.28.110 |  |  |  |  |
| 21:55:14 | Interim-Update | 8C79098EDF01-661D87E6C192-6ADF7EB7-362AE | student001 | 66-1D-87-E6-C1-92 | 172.17.28.110 | 52 | 762021 | 508696 |  |
| 21:59:31 | Stop | 8C79098EDF01-661D87E6C192-6ADF7EB7-362AE | anonymous | 66-1D-87-E6-C1-92 | 172.17.28.110 | 308 | 2179559 | 3563671 | Lost-Service |
| 22:01:48 | Start | 8C79098EDF11-661D87E6C192-6ADF8074-94DF1 | student001 | 66-1D-87-E6-C1-92 | 172.17.28.110 |  |  |  |  |

### First Accounting-Start from the Aruba (verbatim)
```
Mon Oct 26 21:54:22 2026
	Acct-Status-Type = Start
	NAS-IP-Address = 172.17.28.245
	User-Name = "student001"
	NAS-Port = 0
	NAS-Port-Type = Wireless-802.11
	Calling-Station-Id = "66-1D-87-E6-C1-92"
	Called-Station-Id = "8c7909c0edf0"
	Framed-IP-Address = 172.17.28.110
	Acct-Multi-Session-Id = "661D87E6C192-1793031588"
	Acct-Session-Id = "8C79098EDF01-661D87E6C192-6ADF7EB7-362AE"
	Acct-Delay-Time = 0
	Aruba-Essid-Name = "NITS-Lab"
	Aruba-Location-Id = "8c:79:09:c0:ed:f0"
	Aruba-User-Vlan = 1
	Aruba-User-Role = "NITS-Lab"
	Class = 0x73747564656e7473
	Aruba-Device-Type = "NOFP"
	Acct-Authentic = RADIUS
	Service-Type = Login-User
	NAS-Identifier = "aruba-ap615"
	Event-Timestamp = "Oct 26 2026 21:54:22 IST"
	Acct-Unique-Session-Id = "036fc8c37659d9894504befaa6148f56"
	Timestamp = 1793031862
```

### Two radacct rows for one Aruba session
```
           acctuniqueid           |  username  | callingstationid  | calledstationid |       acctstarttime       |       acctstoptime
----------------------------------+------------+-------------------+-----------------+---------------------------+---------------------------
 036fc8c37659d9894504befaa6148f56 | student001 | 66-1D-87-E6-C1-92 | 8c7909c0edf0    | 2026-10-26 21:54:22+05:30 |
 390beef2be8efced1cfd0cd923d07fa4 | anonymous  | 66-1D-87-E6-C1-92 | 8c7909c0edf0    | 2026-10-26 21:54:23+05:30 | 2026-10-26 21:59:31+05:30
```

### RADIUS log lines for the Aruba (current container)
```
Mon Oct 26 21:53:37 2026 : Error: (288) Ignoring duplicate packet from client ap-dirx6060 port 45359 - ID: 69 due to unfinished request in component <core> module <queue>
Mon Oct 26 21:53:39 2026 : Auth: (302)   Login OK: [student001] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92 via TLS tunnel)
Mon Oct 26 21:53:39 2026 : Auth: (303) Login OK: [anonymous] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92)
Mon Oct 26 21:59:26 2026 : Auth: (317)   Login incorrect: [student001] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92 via TLS tunnel)
Mon Oct 26 21:59:26 2026 : Auth: (318) Login incorrect (eap_peap: The users session was previously rejected: returning reject (again.)): [anonymous] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92)
Mon Oct 26 21:59:31 2026 : Auth: (330)   Login incorrect: [student001] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92 via TLS tunnel)
Mon Oct 26 21:59:31 2026 : Auth: (331) Login incorrect (eap_peap: The users session was previously rejected: returning reject (again.)): [anonymous] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92)
Mon Oct 26 22:01:26 2026 : Auth: (341)   Login incorrect: [student001] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92 via TLS tunnel)
Mon Oct 26 22:01:26 2026 : Auth: (342) Login incorrect (eap_peap: The users session was previously rejected: returning reject (again.)): [anonymous] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92)
Mon Oct 26 22:01:48 2026 : Auth: (352)   Login OK: [student001] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92 via TLS tunnel)
Mon Oct 26 22:01:48 2026 : Auth: (353) Login OK: [anonymous] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92)
```
Log lines from 20:08–20:14 are from the container replaced at 20:22; they were read live then and match the radpostauth rows above.

### Disconnect attempts
```
21:59:10  disable-user.ps1 student001
  Disabled: uid=student001,ou=Students,dc=nitsrinagar,dc=edu
  Disconnecting open sessions of student001:
  No open sessions for student001.            <- tools image had no psql: "sh: 1: psql: not found"

21:59:57  disconnect-user.sh student001 (tools image rebuilt)
  66-1D-87-E6-C1-92 on 172.17.28.245: no reply (AP does not support Disconnect-Request)
  0 of 1 session(s) disconnected at once. The rest end at the next re-check (REAUTH_INTERVAL).

radclient -x (from the tools container)
  Sent Disconnect-Request Id 55 from 0.0.0.0:43526 to 172.17.28.245:3799 length 69
  (0) No reply from server for ID 55 socket 3

TCP check from a container:  TCP 4343 to AP: NOT reachable
Docker networks:             bridge : 172.17.0.0/16      aaa-lab_aaa : 10.89.0.0/24
```

### Repeat after the Docker bridge fix (22:12)
```
bridge subnet after restart: 192.168.200.0/24
TCP 4343 to AP: reachable

T0 = 22:12:11
Disabled: uid=student001,ou=Students,dc=nitsrinagar,dc=edu
Disconnecting open sessions of student001:
  66-1D-87-E6-C1-92 on 172.17.28.245: refused by the AP (NAK)
  66-1D-87-E6-C1-92 on 172.17.28.245: disconnected (ACK)
1 of 2 session(s) disconnected at once. The rest end at the next re-check (REAUTH_INTERVAL).
T1 = 22:12:14

Stop in detail file:
	User-Name = "student001"
	Acct-Session-Id = "8C79098EDF11-661D87E6C192-6ADF8074-94DF1"
	Acct-Terminate-Cause = Admin-Reset
	Acct-Session-Time = 626

radacct (device 66-1D-87-E6-C1-92, from 21:50):
              acctsessionid               |  username  |       acctstarttime       |       acctstoptime        | acctterminatecause | acctsessiontime
------------------------------------------+------------+---------------------------+---------------------------+--------------------+-----------------
 8C79098EDF01-661D87E6C192-6ADF7EB7-362AE | student001 | 2026-10-26 21:54:22+05:30 |                           |                    |              52
 8C79098EDF01-661D87E6C192-6ADF7EB7-362AE | anonymous  | 2026-10-26 21:54:23+05:30 | 2026-10-26 21:59:31+05:30 | Lost-Service       |             308
 8C79098EDF11-661D87E6C192-6ADF8074-94DF1 | student001 | 2026-10-26 22:01:48+05:30 | 2026-10-26 22:12:13+05:30 | Admin-Reset        |             626

Mon Oct 26 22:12:14 2026 : Auth: (22)   Rejected in post-auth: [student001] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92 via TLS tunnel)
Mon Oct 26 22:12:19 2026 : Auth: (33)   Rejected in post-auth: [student001] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92 via TLS tunnel)
Mon Oct 26 22:12:24 2026 : Auth: (44)   Rejected in post-auth: [student001] (from client ap-dirx6060 port 0 cli 66-1D-87-E6-C1-92 via TLS tunnel)
```
The NAK is for the stale 21:54 row (still open because of the anonymous-Stop bug); the AP no longer had that session.

### Re-test of the anonymous Stop after the fix (22:35–22:45)
```
Stop packet (verbatim):
Mon Oct 26 22:44:51 2026
	Acct-Status-Type = Stop
	NAS-IP-Address = 172.17.28.245
	User-Name = "anonymous"
	NAS-Port = 0
	NAS-Port-Type = Wireless-802.11
	Calling-Station-Id = "2E-C0-09-A6-4E-E0"
	Called-Station-Id = "8c7909c0edf0"
	Framed-IP-Address = 172.17.28.192
	Acct-Multi-Session-Id = "2EC009A64EE0-1793033211"
	Acct-Session-Id = "8C79098EDF11-2EC009A64EE0-6ADF8866-E136F"
	Acct-Delay-Time = 0
	Aruba-Essid-Name = "NITS-Lab"
	Aruba-Location-Id = "8c:79:09:c0:ed:f0"
	Aruba-User-Vlan = 1
	Aruba-Device-Type = "Linux"
	Acct-Input-Octets = 538683
	Acct-Output-Octets = 3396630
	Acct-Input-Packets = 2798
	Acct-Output-Packets = 2829
	Acct-Input-Gigawords = 0
	Acct-Output-Gigawords = 0
	Acct-Terminate-Cause = Supplicant-Restart
	Acct-Session-Time = 570
	Service-Type = Login-User
	NAS-Identifier = "aruba-ap615"
	Event-Timestamp = "Oct 26 2026 22:44:51 IST"
	Acct-Unique-Session-Id = "d096d3b4b604bdd822a99d0375a1e7cc"
	Timestamp = 1793034891

radacct for that session ID (count = 1):
d096d3b4b604bdd822a99d0375a1e7cc|student001|2026-10-26 22:35:42+05:30|2026-10-26 22:44:51+05:30|Supplicant-Restart|570

S23 logins between 22:35 and 22:46:
Mon Oct 26 22:35:42 2026 : Auth: (313)   Login OK: [student001] (from client ap-dirx6060 port 0 cli 2E-C0-09-A6-4E-E0 via TLS tunnel)
Mon Oct 26 22:44:51 2026 : Auth: (358)   Rejected in post-auth: [student001] (from client ap-dirx6060 port 0 cli 2E-C0-09-A6-4E-E0 via TLS tunnel)
Mon Oct 26 22:44:52 2026 : Auth: (370)   Rejected in post-auth: [student001] (from client ap-dirx6060 port 0 cli 2E-C0-09-A6-4E-E0 via TLS tunnel)
Mon Oct 26 22:45:19 2026 : Auth: (381)   Rejected in post-auth: [student001] (from client ap-dirx6060 port 0 cli 2E-C0-09-A6-4E-E0 via TLS tunnel)
```
No RADIUS request came from the S23 between 22:35:42 and 22:44:51, so there was no re-check at the 5-minute mark.

## Observations
- The Aruba applies RADIUS VLAN attributes. With students on VLAN 10 the phone got Access-Accept but no DHCP address, and the AP sent no accounting.
- With `SEND_VLAN=no`, `Aruba-User-Vlan = 1` and the session works.
- The Aruba reports `Framed-IP-Address`, `NAS-Identifier`, `Class` and a correct `Event-Timestamp`. The D-Link did none of the first and had a 2024 clock.
- Accounting-Start came 43 s after Login OK.
- The disabled user was rejected 16 s after the LDAP change, at an AP re-authentication. The device lost service (Stop, `Lost-Service`).
- The Stop after the failed re-auth carries `User-Name = "anonymous"`, so FreeRADIUS computed another `Acct-Unique-Session-Id` and inserted a new row. The original row stays open.
- Containers on Docker Desktop cannot reach any host on 172.17.28.0/24. Inbound RADIUS to the laptop works.
- The `tools` image was 2 weeks old and had no `postgresql-client`. `disconnect-user.sh` then printed "No open sessions" instead of an error.

### Re-check gap investigation (22:50–22:56)
All S23 logins from radpostauth, with the gap to the previous one per MAC:
```
    t     |        dev        |  username  |     reply     |  gap
----------+-------------------+------------+---------------+-------
 21:53:39 | 66-1D-87-E6-C1-92 | student001 | Access-Accept |
 21:59:26 | 66-1D-87-E6-C1-92 | student001 | Access-Reject | 05:47
 21:59:31 | 66-1D-87-E6-C1-92 | student001 | Access-Reject | 00:04
 22:01:26 | 66-1D-87-E6-C1-92 | student001 | Access-Reject | 01:55
 22:01:48 | 66-1D-87-E6-C1-92 | student001 | Access-Accept | 00:21
 22:07:04 | 66-1D-87-E6-C1-92 | student001 | Access-Accept | 05:16
 22:12:10 | 66-1D-87-E6-C1-92 | student001 | Access-Accept | 05:05
 22:12:14 | 66-1D-87-E6-C1-92 | student001 | Access-Reject | 00:04
 22:12:19 | 66-1D-87-E6-C1-92 | student001 | Access-Reject | 00:04
 22:12:24 | 66-1D-87-E6-C1-92 | student001 | Access-Reject | 00:05
 22:16:50 | 2E-C0-09-A6-4E-E0 | student001 | Access-Accept |
 22:22:21 | 2E-C0-09-A6-4E-E0 | student001 | Access-Accept | 05:30
 22:27:26 | 2E-C0-09-A6-4E-E0 | student001 | Access-Accept | 05:05
 22:35:42 | 2E-C0-09-A6-4E-E0 | student001 | Access-Accept | 08:15
 22:44:51 | 2E-C0-09-A6-4E-E0 | student001 | Access-Reject | 09:08
 22:44:52 | 2E-C0-09-A6-4E-E0 | student001 | Access-Reject | 00:01
 22:45:19 | 2E-C0-09-A6-4E-E0 | student001 | Access-Reject | 00:26
 22:50:43 | 2E-C0-09-A6-4E-E0 | student001 | Access-Accept | 05:23
 22:55:57 | 2E-C0-09-A6-4E-E0 | student001 | Access-Accept | 05:14   <- control: re-check in place, same accounting session
```
(22:35:42 follows the Wi-Fi off at 22:32:12, so its 08:15 gap is not a re-check interval.)

A fresh eapol_test TTLS login (MAC 02:00:00:00:77:01) shows the Accept carries Attribute 27 (Session-Timeout) and 29 (Termination-Action). The 22:35:42 login took the same inner-tunnel path (`Login OK ... via TLS tunnel`), so it got them too (inference, same code path).

Result: re-checks came 5:05–5:47 after every Accept except the one at 22:35:42 (next request 9:09 later, cause `Supplicant-Restart`). The server side is the same in all cases. Open hypotheses, none tested:
- The Aruba did not start the re-auth timer for the association made right after the Wi-Fi toggle.
- The Aruba sent the re-auth request at about 22:40:45 but the phone did not answer (for example a power-save state); the phone restarted 802.1X itself at 22:44:51 (`Supplicant-Restart` = the client sent EAPOL-Start).
Test: repeat the Wi-Fi toggle, and during the gap read the Aruba auth trace for the client (`show auth-tracebuf` / client details), which shows whether an EAP-Request/Identity was sent.

## Confirmed after the repeat
- **Disconnect failed because Docker's default bridge `172.17.0.0/16` overlapped the hostel LAN `172.17.28.0/24`.** After moving the bridge to `192.168.200.0/24`, containers reach the AP and the Disconnect gets an ACK.
- The Aruba accepts RFC 5176 Disconnect on UDP 3799 from the laptop's IP (the configured server), with the AP shared secret, and NAKs unknown sessions.
- A Disconnect-caused Stop carries the real `User-Name`, so it closes the right radacct row. Only the failed-re-auth Stop uses `anonymous`.
- Re-checks came about every 5 min in the 22:01–22:12 session (22:01:48 → 22:07:04 → 22:12:10). **But** in the 22:35 session there was no request for 9 min 9 s, and access ended only at 22:44:51 with `Supplicant-Restart`. So the 5-minute re-check is **not** a reliable revocation bound on the Aruba; the Disconnect is.
- An anonymous Stop now closes the student's row (one row, `student001`), on the real AP.
- Android chose a new randomised MAC after the reconnect (`66-1D-…` → `2E-C0-…`). The device limit counts MACs, so one phone can briefly count as 2 devices.

## Inferences (not yet tested)
- The Aruba puts `User-Name` from the Access-Accept into accounting. After a failed re-auth there is no Accept, so it falls back to the EAP outer identity. Test: compare `User-Name` in a Stop after a normal disconnect (Wi-Fi off on the phone).
- The re-auth at 21:59:26 was the scheduled Session-Timeout re-check (5 min 47 s after login), not caused by the LDAP change. Test: log a second session without changes and time its re-auths.
- `eap_peap:` in the "previously rejected" line is a FreeRADIUS message prefix shared with TTLS, not a PEAP attempt. radpostauth and the phone settings show TTLS.

## Problems met and fixes
- Browser to `172.17.28.252:4343` refused → that is the laptop, not the AP → AP found at `172.17.28.245` (its DNS answer for `instant.arubanetworks.com`, MAC confirmed in ARP).
- Login OK but phone returns to settings, no accounting → Aruba applied VLAN 10, which the hostel LAN does not have → new `.env` setting `SEND_VLAN` (default yes; `no` leaves out Tunnel-Type, Tunnel-Medium-Type, Tunnel-Private-Group-Id). Tests pass in both modes. Not committed yet.
- Rejects for `anonymous` → Identity field held the outer identity → Identity `student001`, anonymous identity under "View more".
- `disable-user.ps1` printed "No open sessions" → stale `tools` image without psql → `docker compose --profile tools build tools`.
- Disconnect-Request no reply → Docker bridge `172.17.0.0/16` overlaps the hostel LAN → `"bip": "192.168.200.1/24"` in `~/.docker/daemon.json` + Docker Desktop restart → ACK.
- Second radacct row after the `anonymous` Stop → stock `acct_unique` hashes `User-Name` → new policy `campus_acct_unique` (NAS + Acct-Session-Id, no User-Name) in `default` and `buffered-sql`. New e2e test "Stop with User-Name anonymous -> closes the same row, user kept" failed before (`2|student001|f|Lost-Service`) and passes after; suites 8 + 33 + 60 pass. Sessions open at the switch keep their old key, so their next packet starts a new row; the reaper closes the old one.
- Collector `collect_aaa_evidence.py` could not read radpostauth → it still calls `sqlite3`, but the lab moved to PostgreSQL → read with `scripts/acct.ps1` instead.

## Next steps
- Find out why the 22:35 session had no re-check at 5 min (see "Re-check gap investigation"): reproduce with a Wi-Fi toggle and read the Aruba auth trace during the gap.
- Until then, treat Disconnect (`disable-user.ps1`) as the revocation path, and check its ACK.
- `disconnect-user.sh`: fail loudly when the query fails instead of printing "No open sessions".
- Update `collect_aaa_evidence.py` to read radpostauth from PostgreSQL.
- Watch a full 10-minute Interim-Update cycle and a normal Stop (Wi-Fi off).
- Commit `SEND_VLAN` (5 files) and this note.
- Set `SEND_VLAN=yes` again before any campus-style test.
