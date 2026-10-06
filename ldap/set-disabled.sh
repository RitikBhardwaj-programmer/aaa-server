#!/bin/sh
# Add a user to, or remove a user from, cn=disabled,ou=Groups (blocks / restores Wi-Fi access).
#
# Usage (from the aaa-server folder):
#   docker compose exec ldap set-disabled.sh <uid> on    # disable
#   docker compose exec ldap set-disabled.sh <uid> off   # enable again
set -u

if [ $# -ne 2 ] || { [ "$2" != on ] && [ "$2" != off ]; }; then
    sed -n '2,6p' "$0" >&2
    exit 2
fi
uid=$1; mode=$2
base=${LDAP_BASE_DN:?LDAP_BASE_DN not set}
ldap() { "$@" -Q -Y EXTERNAL -H ldapi:///; }   # root inside the container = directory manager

case "$uid" in *[!A-Za-z0-9._-]*|'') echo "Invalid uid: $uid" >&2; exit 2;; esac

dn=$(ldap ldapsearch -LLL -o ldif-wrap=no -b "$base" "(&(objectClass=inetOrgPerson)(uid=$uid))" dn | sed -n 's/^dn: //p')
if [ -z "$dn" ]; then
    echo "No such user: $uid" >&2
    exit 1
fi

op=add; [ "$mode" = off ] && op=delete
printf 'dn: cn=disabled,ou=Groups,%s\nchangetype: modify\n%s: member\nmember: %s\n' "$base" "$op" "$dn" \
    | ldap ldapmodify >/dev/null 2>&1
rc=$?
# 20 = already a member (on), 16 = was not a member (off): the wanted state already holds
case "$rc" in
    0|20|16) ;;
    65) echo "Cannot remove the last member of cn=disabled (groupOfNames needs one)." >&2; exit 1 ;;
    *) echo "ldapmodify failed with code $rc" >&2; exit 1 ;;
esac

if [ "$mode" = on ]; then echo "Disabled: $dn"; else echo "Enabled: $dn"; fi
