#!/bin/sh
# Create a Wi-Fi user in LDAP and add it to one or more groups.
#
# Usage (from the aaa-server folder):
#   docker compose exec ldap add-user.sh <uid> "<Full Name>" <OU> <group[,group...]>
# Example:
#   docker compose exec ldap add-user.sh 24IT002 "IT Student 24IT002" Students students
#
# Password: taken from $NEW_USER_PASSWORD if set, otherwise a random one is generated and printed once.
# Stores userPassword ({SSHA}, for EAP-TTLS/PAP bind) and sambaNTPassword (NT hash, for PEAP-MSCHAPv2).
set -eu

if [ $# -ne 4 ]; then
    sed -n '2,10p' "$0" >&2
    exit 2
fi
uid=$1; full_name=$2; ou=$3; groups=$4
base=${LDAP_BASE_DN:?LDAP_BASE_DN not set}
domain_sid="S-1-5-21-1000-2000-3000"   # fixed lab domain SID (required by sambaSamAccount)
ldap() { "$@" -Q -Y EXTERNAL -H ldapi:///; }   # root inside the container = directory manager

case "$uid" in *[!A-Za-z0-9._-]*|'') echo "Invalid uid: $uid" >&2; exit 2;; esac

generated=no
if [ -n "${NEW_USER_PASSWORD:-}" ]; then
    password=$NEW_USER_PASSWORD
else
    password=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)
    generated=yes
fi

ssha=$(slappasswd -h '{SSHA}' -s "$password")
nt_hash=$(printf '%s' "$password" | iconv -f UTF-8 -t UTF-16LE \
    | openssl dgst -md4 -provider default -provider legacy | awk '{print toupper($NF)}')
count=$(ldap ldapsearch -LLL -b "$base" '(objectClass=sambaSamAccount)' dn | grep -c '^dn:' || true)
rid=$((1001 + count))
sn=${full_name##* }
user_dn="uid=$uid,ou=$ou,$base"

ldap ldapadd >/dev/null <<EOF
dn: $user_dn
objectClass: inetOrgPerson
objectClass: sambaSamAccount
uid: $uid
cn: $full_name
sn: $sn
mail: $uid@${LDAP_DOMAIN:-example.edu}
ou: $ou
userPassword: $ssha
sambaSID: $domain_sid-$rid
sambaNTPassword: $nt_hash
sambaAcctFlags: [U          ]
EOF

for group in $(echo "$groups" | tr ',' ' '); do
    group_dn="cn=$group,ou=Groups,$base"
    if ldap ldapsearch -LLL -b "$group_dn" -s base dn >/dev/null 2>&1; then
        ldap ldapmodify >/dev/null <<EOF
dn: $group_dn
changetype: modify
add: member
member: $user_dn
EOF
    else
        ldap ldapadd >/dev/null <<EOF
dn: $group_dn
objectClass: groupOfNames
cn: $group
member: $user_dn
EOF
    fi
done

echo "Created $user_dn (groups: $groups)"
[ "$generated" = yes ] && echo "Password: $password"
exit 0
