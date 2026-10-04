#!/bin/sh
# Builds the directory on first start (empty volumes), then runs slapd in the foreground.
set -eu
: "${LDAP_BASE_DN:?}" "${LDAP_ORG:?}" "${LDAP_ADMIN_PASSWORD:?}" "${LDAP_RADIUS_PASSWORD:?}" "${TEST_USER_PASSWORD:?}"

CONF=/etc/ldap/slapd.d
DATA=/var/lib/ldap
BASE=$LDAP_BASE_DN
ROOT_PEER="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
RADIUS_DN="cn=radius,ou=Services,$BASE"
DC=$(echo "$BASE" | sed 's/^dc=\([^,]*\).*/\1/')

mkdir -p /run/slapd
chown openldap:openldap /run/slapd

if [ ! -f "$CONF/cn=config.ldif" ]; then
    echo "First start: creating directory $BASE"
    admin_hash=$(slappasswd -h '{SSHA}' -s "$LDAP_ADMIN_PASSWORD")
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
olcAccess: {0}to attrs=userPassword by dn.exact=$ROOT_PEER manage by anonymous auth by * none
olcAccess: {1}to attrs=sambaNTPassword,sambaLMPassword by dn.exact=$ROOT_PEER manage by dn.exact=$RADIUS_DN read by * none
olcAccess: {2}to dn.exact="cn=admin,$BASE" attrs=entry,objectClass,cn by anonymous read by * break
olcAccess: {3}to * by dn.exact=$ROOT_PEER manage by dn.exact=$RADIUS_DN read by self read by * none
EOF
    slapadd -n0 -F "$CONF" -l /tmp/config.ldif
    rm -f /tmp/config.ldif
    chown -R openldap:openldap "$CONF" "$DATA"

    slapd -h ldapi:/// -u openldap -g openldap -F "$CONF"
    i=0
    until ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b "" -s base >/dev/null 2>&1; do
        i=$((i + 1)); [ $i -gt 30 ] && { echo "slapd did not start" >&2; exit 1; }
        sleep 1
    done

    radius_hash=$(slappasswd -h '{SSHA}' -s "$LDAP_RADIUS_PASSWORD")
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
EOF

    grep -v '^#' /seed/users.txt | grep -v '^[[:space:]]*$' | while IFS='|' read -r uid name ou groups; do
        NEW_USER_PASSWORD=$TEST_USER_PASSWORD add-user.sh "$uid" "$name" "$ou" "$groups"
    done

    kill "$(cat /run/slapd/slapd.pid)"
    while [ -f /run/slapd/slapd.pid ]; do sleep 1; done
    echo "Directory created."
fi

exec slapd -h "ldap:/// ldapi:///" -u openldap -g openldap -F "$CONF" -d stats
