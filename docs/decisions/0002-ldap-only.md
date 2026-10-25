# 0002: No Kerberos; LDAP bind is the only password check

Date: 2026-10-25. Status: accepted. Supersedes 0001.

## Context
Decision 0001 made the lab Kerberos-ready, because the teacher said Kerberos could come later. On 2026-10-25 the teacher decided that Kerberos is removed from the software.

## Decision
An LDAP bind is the only password check. The Kerberos stub and the `PASSWORD_BACKEND` setting are removed:

| Removed | Where |
|---|---|
| `password_backend` policy and its `krb5` reject | `radius/raddb/policy.d/campus` (now `password_check`, which always sets `Auth-Type := ldap`) |
| `PASSWORD_BACKEND` setting | `.env.example`, `docker-compose.yml` |
| `change_password_krb5` stub and the backend switch | `portal/app.py` (now one `change_password` function, RFC 3062 Password Modify) |

These choices from 0001 stay, for their own security reasons:

| Kept | Why |
|---|---|
| EAP-TTLS/PAP is the default EAP method | The server gets the password and checks the `{ARGON2}` hash. MSCHAPv2 needs the NT hash, which is weak and password-equivalent |
| PEAP only while `ALLOW_PEAP=yes` (`peap_gate`); no NT hash for new users once it is `no` | Lets us retire the NT hash |
| Passwords stored as `{ARGON2}` | Strong password storage |
| Accounting and both limits use the uid as stored in LDAP (`control:Tmp-String-5`) | Closes the case bypass of the device limit ("24it001" counted apart from "24IT001") |
| uid rule `[A-Za-z0-9._-]` | Simple, safe login names |
| Users may change their own password (RFC 3062 Password Modify) | Self service without a direct userPassword write |

## Consequences
- The `.env` files on lab machines may still hold `PASSWORD_BACKEND=ldap`. It is now unused and harmless.
- 0001 stays as history.
