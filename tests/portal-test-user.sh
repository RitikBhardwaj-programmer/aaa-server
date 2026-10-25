#!/bin/sh
# Creates or deletes the temporary Students user for the portal tests. Runs INSIDE the ldap
# container (scripts/test.ps1 copies it there). The password is read from $PORTAL_TEST_PASSWORD.
#   sh portal-test-user.sh create <uid>
#   sh portal-test-user.sh delete <uid>
set -eu
action=${1:-}; uid=${2:-}
case "$uid" in *[!A-Za-z0-9._-]*|'') echo "Invalid uid" >&2; exit 2;; esac
base=$LDAP_BASE_DN
dn="uid=$uid,ou=Students,$base"
root() { "$@" -Q -Y EXTERNAL -H ldapi:///; }

case "$action" in
    create)
        NEW_USER_PASSWORD=${PORTAL_TEST_PASSWORD:?PORTAL_TEST_PASSWORD not set} \
            add-user.sh "$uid" "Portal Test" Students students > /dev/null
        ;;
    delete)
        root ldapmodify > /dev/null 2>&1 <<EOF || true
dn: cn=students,ou=Groups,$base
changetype: modify
delete: member
member: $dn
EOF
        root ldapdelete "$dn" > /dev/null 2>&1 || true
        ;;
    *) echo "Usage: portal-test-user.sh create|delete <uid>" >&2; exit 2;;
esac
