#!/bin/sh
# Password-store checks that need the directory itself. Runs INSIDE the ldap container:
#   docker compose cp tests/ldap-checks.sh ldap:/tmp/ && docker compose exec -T ldap sh /tmp/ldap-checks.sh
#   (scripts/test.ps1 does this)
# Creates a temporary user, checks how its password is stored, changes the password the way the
# portal will (RFC 3062 Password Modify), and deletes the user again.
set -u
base=$LDAP_BASE_DN
uid="hashtest$$"
dn="uid=$uid,ou=Students,$base"
pw1=$(openssl rand -hex 12); pw2=$(openssl rand -hex 12)
pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; fail=$((fail + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$3', got '$2')"; fi; }
root() { "$@" -Q -Y EXTERNAL -H ldapi:///; }
attr() { root ldapsearch -LLL -o ldif-wrap=no -b "$dn" -s base "$1" | sed -n "s/^$1:: *//p; s/^$1: *//p" | head -1; }
scheme() { attr userPassword | base64 -d 2>/dev/null | sed -n 's/^\({[A-Z0-9]*}\).*/\1/p'; }

echo "== L. Password store (ALLOW_PEAP=${ALLOW_PEAP:-yes})"
check "slapd hashes new passwords with {ARGON2}" \
      "$(root ldapsearch -LLL -b 'olcDatabase={-1}frontend,cn=config' -s base olcPasswordHash 2>/dev/null | sed -n 's/^olcPasswordHash: //p')" "{ARGON2}"

NEW_USER_PASSWORD=$pw1 add-user.sh "$uid" "Hash Test" Students students > /dev/null
check "new user's password is stored as {ARGON2}" "$(scheme)" "{ARGON2}"
if [ "${ALLOW_PEAP:-yes}" = yes ]; then
    check "PEAP allowed -> new user has an NT hash" "$([ -n "$(attr sambaNTPassword)" ] && echo yes)" yes
else
    check "PEAP off -> new user has no NT hash" "$(attr sambaNTPassword)" ""
fi
check "bind with the right password works (what FreeRADIUS does)" \
      "$(ldapwhoami -x -H ldap://localhost -D "$dn" -w "$pw1" 2>/dev/null)" "dn:$dn"
check "bind with a wrong password fails" \
      "$(ldapwhoami -x -H ldap://localhost -D "$dn" -w wrong-password >/dev/null 2>&1 && echo bound || echo refused)" refused

# Password change by the user (RFC 3062 Password Modify), as the self-service portal will do it
ldappasswd -x -H ldap://localhost -D "$dn" -w "$pw1" -a "$pw1" -s "$pw2" > /dev/null 2>&1
check "password change by the user -> new password works" \
      "$(ldapwhoami -x -H ldap://localhost -D "$dn" -w "$pw2" 2>/dev/null)" "dn:$dn"
check "password change by the user -> stored as {ARGON2}" "$(scheme)" "{ARGON2}"

root ldapmodify > /dev/null 2>&1 <<EOF
dn: cn=students,ou=Groups,$base
changetype: modify
delete: member
member: $dn
EOF
root ldapdelete "$dn"
check "temporary user removed" "$(root ldapsearch -LLL -b "$dn" -s base dn 2>/dev/null | grep -c '^dn:')" 0

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
