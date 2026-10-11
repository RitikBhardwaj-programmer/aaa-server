#!/bin/sh
# Builds the directory on first start (empty volumes), then runs slapd in the foreground.
set -eu
: "${LDAP_BASE_DN:?}" "${LDAP_ORG:?}" "${LDAP_ADMIN_PASSWORD:?}" "${LDAP_RADIUS_PASSWORD:?}" "${LDAP_PORTAL_PASSWORD:?}" "${TEST_USER_PASSWORD:?}"

CONF=/etc/ldap/slapd.d
DATA=/var/lib/ldap
BASE=$LDAP_BASE_DN
ROOT_PEER="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
RADIUS_DN="cn=radius,ou=Services,$BASE"
PORTAL_DN="cn=portal,ou=Services,$BASE"
DC=$(echo "$BASE" | sed 's/^dc=\([^,]*\).*/\1/')

mkdir -p /run/slapd
chown openldap:openldap /run/slapd

# The password goes through a private temporary file (-T), not the command line, where any
# process in the container could read it from /proc while slappasswd runs
hash_pw() {
    pwfile=$(mktemp)
    printf '%s' "$1" > "$pwfile"
    slappasswd -o module-load="$ARGON2_MODULE" -h '{ARGON2}' -T "$pwfile"
    rm -f "$pwfile"
}

# slapd on the local socket only, for setup steps before the real start
start_local() {
    slapd -h ldapi:/// -u openldap -g openldap -F "$CONF"
    i=0
    until ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b "" -s base >/dev/null 2>&1; do
        i=$((i + 1)); [ $i -gt 30 ] && { echo "slapd did not start" >&2; exit 1; }
        sleep 1
    done
}
stop_local() {
    kill "$(cat /run/slapd/slapd.pid)"
    while [ -f /run/slapd/slapd.pid ]; do sleep 1; done
}

# Who may do what with userPassword: root manages, a user may change their own (self-service
# password change, RFC 3062 Password Modify), anyone may use it to log in (bind), nobody reads it.
PW_ACL="to attrs=userPassword by dn.exact=$ROOT_PEER manage by self =wx by anonymous auth by * none"
# NT hashes (PEAP-MSCHAPv2): only FreeRADIUS reads them. A user may DELETE their own (=z, no read,
# no write): the portal removes it on a password change, or the old password would keep working
# for PEAP, since Password Modify updates only userPassword.
NT_ACL="to attrs=sambaNTPassword,sambaLMPassword by dn.exact=$ROOT_PEER manage by dn.exact=$RADIUS_DN read by self =z by * none"
# Everything else: the portal account (self-service portal) may read entries and group members. It
# is not listed in the userPassword and NT-hash rules above, which match first, so it reads no hashes.
ALL_ACL="to * by dn.exact=$ROOT_PEER manage by dn.exact=$RADIUS_DN read by dn.exact=$PORTAL_DN read by self read by * none"

# Upgrades for a directory made by an older version of this script (each step runs once)
if [ -f "$CONF/cn=config.ldif" ]; then
    current=$(slapcat -n0 -F "$CONF" -o ldif-wrap=no 2>/dev/null)
    if ! echo "$current" | grep -q '^olcModuleLoad: {[0-9]*}argon2'; then
        # Existing {SSHA} passwords keep working and become {ARGON2} at the next password change
        echo "Upgrade: enabling {ARGON2} password hashing"
        start_local
        ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null <<EOF
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: $ARGON2_MODULE

dn: olcDatabase={-1}frontend,cn=config
changetype: modify
replace: olcPasswordHash
olcPasswordHash: {ARGON2}
EOF
        stop_local
    fi
    if ! echo "$current" | grep -q '^olcAccess: {0}to attrs=userPassword .*by self =wx'; then
        echo "Upgrade: letting users change their own password"
        start_local
        ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcAccess
olcAccess: {0}
-
add: olcAccess
olcAccess: {0}$PW_ACL
EOF
        stop_local
    fi
    if ! echo "$current" | grep -q "^olcAccess: {3}.*cn=portal,"; then
        echo "Upgrade: adding the read-only portal account"
        start_local
        if ! ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b "$PORTAL_DN" -s base dn >/dev/null 2>&1; then
            portal_hash=$(hash_pw "$LDAP_PORTAL_PASSWORD")
            ldapadd -Q -Y EXTERNAL -H ldapi:/// >/dev/null <<EOF
dn: $PORTAL_DN
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: portal
description: Read-only bind account for the self-service portal (no password hashes)
userPassword: $portal_hash
EOF
        fi
        ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcAccess
olcAccess: {3}
-
add: olcAccess
olcAccess: {3}$ALL_ACL
EOF
        stop_local
    fi
    if ! echo "$current" | grep -q '^olcAccess: {1}to attrs=sambaNTPassword.*by self =z'; then
        echo "Upgrade: letting users delete their own NT hash (password change)"
        start_local
        ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
delete: olcAccess
olcAccess: {1}
-
add: olcAccess
olcAccess: {1}$NT_ACL
EOF
        stop_local
    fi
fi

if [ ! -f "$CONF/cn=config.ldif" ]; then
    echo "First start: creating directory $BASE"
    admin_hash=$(hash_pw "$LDAP_ADMIN_PASSWORD")
    cat > /tmp/config.ldif <<EOF
dn: cn=config
objectClass: olcGlobal
cn: config
olcPidFile: /run/slapd/slapd.pid
olcArgsFile: /run/slapd/slapd.args

dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/ldap
olcModuleLoad: back_mdb
olcModuleLoad: $ARGON2_MODULE

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file:///etc/ldap/schema/core.ldif
include: file:///etc/ldap/schema/cosine.ldif
include: file:///etc/ldap/schema/nis.ldif
include: file:///etc/ldap/schema/inetorgperson.ldif
include: file:///etc/ldap/schema/samba.ldif

dn: olcDatabase={-1}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {-1}frontend
olcSizeLimit: 500
olcPasswordHash: {ARGON2}

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcAccess: {0}to * by dn.exact=$ROOT_PEER manage by * none

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcDbDirectory: $DATA
olcSuffix: $BASE
olcRootDN: cn=admin,$BASE
olcRootPW: $admin_hash
olcDbMaxSize: 1073741824
olcDbIndex: objectClass eq
olcDbIndex: uid eq
olcDbIndex: member eq
olcDbIndex: cn eq
olcAccess: {0}$PW_ACL
olcAccess: {1}$NT_ACL
olcAccess: {2}to dn.exact="cn=admin,$BASE" attrs=entry,objectClass,cn by anonymous read by * break
olcAccess: {3}$ALL_ACL
EOF
    slapadd -n0 -F "$CONF" -l /tmp/config.ldif
    rm -f /tmp/config.ldif
    chown -R openldap:openldap "$CONF" "$DATA"

    start_local

    radius_hash=$(hash_pw "$LDAP_RADIUS_PASSWORD")
    portal_hash=$(hash_pw "$LDAP_PORTAL_PASSWORD")
    ldapadd -Q -Y EXTERNAL -H ldapi:/// >/dev/null <<EOF
dn: $BASE
objectClass: dcObject
objectClass: organization
dc: $DC
o: $LDAP_ORG

# Entry for the rootDN, so phpLDAPadmin can log in as cn=admin (the bind still uses olcRootPW)
dn: cn=admin,$BASE
objectClass: organizationalRole
cn: admin
description: Directory administrator

dn: ou=Students,$BASE
objectClass: organizationalUnit
ou: Students

dn: ou=Faculty,$BASE
objectClass: organizationalUnit
ou: Faculty

dn: ou=Staff,$BASE
objectClass: organizationalUnit
ou: Staff

dn: ou=Guests,$BASE
objectClass: organizationalUnit
ou: Guests

dn: ou=Groups,$BASE
objectClass: organizationalUnit
ou: Groups

dn: ou=Services,$BASE
objectClass: organizationalUnit
ou: Services

dn: $RADIUS_DN
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: radius
description: Read-only bind account for FreeRADIUS
userPassword: $radius_hash

dn: $PORTAL_DN
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: portal
description: Read-only bind account for the self-service portal (no password hashes)
userPassword: $portal_hash
EOF

    grep -v '^#' /seed/users.txt | grep -v '^[[:space:]]*$' | while IFS='|' read -r uid name ou groups; do
        NEW_USER_PASSWORD=$TEST_USER_PASSWORD add-user.sh "$uid" "$name" "$ou" "$groups"
    done

    stop_local
    echo "Directory created."
fi

exec slapd -h "ldap:/// ldapi:///" -u openldap -g openldap -F "$CONF" -d stats
