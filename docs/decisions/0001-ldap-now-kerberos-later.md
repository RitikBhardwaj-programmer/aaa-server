# 0001: LDAP password check now, Kerberos-ready for later

Date: 2026-10-11. Status: accepted.

## Context
The IIT Delhi plan stores passwords in MIT Kerberos and checks Wi-Fi passwords with rlm_krb5. Our comparison (`reports/ldap-vs-kerberos/LDAP-vs-Kerberos.pdf`) found that Wi-Fi cannot use Kerberos single sign-on: no deployed EAP method carries Kerberos tickets, so FreeRADIUS would only run a Kerberos login on the phone's behalf (about 3 KDC round trips instead of 1 bind), with extra servers and password-policy traps. The teacher's decision (2026-10-11): Kerberos may be used in the long run, not now; keep a provision to add it later.

## Decision
Check passwords with an LDAP bind now. Make these choices so that a move to Kerberos is a configuration change, not a rebuild:

| Choice | Where | Why it keeps Kerberos possible |
|---|---|---|
| EAP-TTLS/PAP is the default EAP method; PEAP only while `ALLOW_PEAP=yes` | `radius/raddb/mods-available/eap`, `peap_gate` in `policy.d/campus` (inner tunnel) | Kerberos can only check a plain password; MSCHAPv2 (PEAP) needs an NT hash Kerberos does not have |
| No NT hash for new users once `ALLOW_PEAP=no` | `ldap/add-user.sh` | Removes the weak, password-equivalent hash |
| Passwords stored as `{ARGON2}` (argon2i, m=19 MiB, t=2) | `ldap/Dockerfile`, `ldap/entrypoint.sh` | Strong storage in both designs; existing `{SSHA}` hashes upgrade at the next password change |
| `PASSWORD_BACKEND=ldap`; `krb5` reserved and rejects clearly until built | `password_backend` in `policy.d/campus` | Switching the checker is one setting plus the krb5 module |
| Users may change their own password (RFC 3062 Password Modify) | userPassword ACL in `ldap/entrypoint.sh` | The portal changes passwords through one backend function: LDAP now, kadmin later. (LTB Self Service Password would break Kerberos `{SASL}` pass-through.) |
| uid rule `[A-Za-z0-9._-]`; accounting uses the uid as stored in LDAP | `ldap/add-user.sh`, `control:Tmp-String-5` in `mods-available/ldap` | Every uid is a valid principal `uid@NITSRINAGAR.EDU`. Using the stored form also closes a case bypass of the device limit ("24it001" counted apart from "24IT001") |
| Realm name `NITSRINAGAR.EDU` reserved | this record | No renaming later |

## Consequences
- Devices set up for PEAP (the lab S23) must move to EAP-TTLS/PAP before `ALLOW_PEAP=no`. Then delete the existing `sambaNTPassword` values.
- TTLS/PAP needs a correct client profile (some Android/iOS/macOS clients default to MSCHAPv2), so geteduroam/CAT onboarding is needed in either design.
- An Argon2 bind costs more CPU than `{SSHA}`: about 83 ms per hash including process start in `slappasswd` (measured once in the lab); a campus burst of ~35 logins/s is an estimate of 1–2 cores on the LDAP servers. Load-test before launch.
- Not done: no KDC, keytab or rlm_krb5 configuration exists yet.

## When to add Kerberos
When NIT names real consumers (for example SSH and NFS home folders in Linux labs). Add it with the fixes from the IIT Delhi review: no password expiry, `disable_lockout = true` with the RADIUS reject rate limit, `krb5kdc -w` workers, keytab-verified rlm_krb5, an off-Wi-Fi password portal and a second password-change path. Run lab experiments 1–2 from the review first.
