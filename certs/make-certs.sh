#!/bin/sh
# Creates the lab CA, the RADIUS server certificate used by PEAP / EAP-TTLS, and the certificate
# that signs the Apple Wi-Fi profiles of the portal (/setup).
# Output (all in this folder, gitignored):
#   ca.pem           - CA certificate. Install / select it on client devices.
#   ca.key           - CA private key. Keep offline in a real deployment.
#   server.pem       - server certificate (CN=radius.nitsrinagar.lab)
#   server.key       - server private key
#   profile-sign.pem - profile-signing certificate (signed by the CA, S/MIME signing only)
#   profile-sign.key - profile-signing private key (a separate key, not the server key)
#   device-ca.pem    - Device CA (intermediate, signed by the CA): signs the EAP-TLS device
#                      certificates of the portal (/certs, POST /api/v1/certs)
#   device-ca.key    - Device CA private key (mounted read-only into the portal)
# Each part is made only if its certificate does not exist yet, so you can run the script again
# after an update: it adds the new files and never overwrites the old ones.
# ca.key is used only by this script. Keep it offline in a real deployment.
#
# Usage:  sh certs/make-certs.sh
# Windows Git Bash:  MSYS_NO_PATHCONV=1 sh certs/make-certs.sh
#   (without it, Git Bash turns -subj "/C=IN/..." into a Windows path and openssl fails).
#   scripts/init.ps1 runs it in the FreeRADIUS image instead, which needs no such setting.
set -eu
cd "$(dirname "$0")"

CA_CN="NIT Srinagar Lab CA"
SERVER_CN="radius.nitsrinagar.lab"
SIGN_CN="NIT Srinagar Wi-Fi Profile Signing"
# FreeRADIUS accepts client certificates from this exact issuer only (check_cert_issuer in
# radius/raddb/mods-available/eap): change both together
DEVICE_CA_CN="NIT Srinagar Device CA"

umask 077

if [ -f server.pem ]; then
    echo "server.pem already exists - not overwriting." >&2
else
    openssl req -x509 -new -nodes -newkey rsa:3072 -sha256 -days 3650 \
        -keyout ca.key -out ca.pem \
        -subj "/C=IN/O=NIT Srinagar/OU=Network Lab/CN=${CA_CN}" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SERVER_CN}
EOF

    openssl req -new -nodes -newkey rsa:3072 -sha256 \
        -keyout server.key -out server.csr \
        -subj "/C=IN/O=NIT Srinagar/OU=Network Lab/CN=${SERVER_CN}"
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 730 -sha256 -extfile server.ext -out server.pem
    rm -f server.csr server.ext ca.srl

    # The radius container copies server.key to a freerad-owned 0640 file at start-up
    chmod 644 ca.pem server.pem
    chmod 600 ca.key server.key
    openssl x509 -in server.pem -noout -subject -issuer -enddate
fi

if [ -f profile-sign.pem ]; then
    echo "profile-sign.pem already exists - not overwriting." >&2
elif [ ! -f ca.key ]; then
    echo "ca.key is missing: cannot make profile-sign.pem. Put ca.key back in this folder, then run again." >&2
    exit 1
else
    # Extended key usage emailProtection (S/MIME signing) only: the key can sign a profile (CMS),
    # but a device never accepts this certificate as a Wi-Fi (TLS) server.
    cat > profile-sign.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=emailProtection
EOF

    openssl req -new -nodes -newkey rsa:3072 -sha256 \
        -keyout profile-sign.key -out profile-sign.csr \
        -subj "/C=IN/O=NIT Srinagar/OU=Network Lab/CN=${SIGN_CN}"
    openssl x509 -req -in profile-sign.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 730 -sha256 -extfile profile-sign.ext -out profile-sign.pem
    rm -f profile-sign.csr profile-sign.ext ca.srl

    # The portal container runs as uid 10001 and reads this key through a read-only bind mount,
    # so the key must be readable by other users of this PC. It can only sign Wi-Fi profiles.
    chmod 644 profile-sign.pem profile-sign.key
    openssl x509 -in profile-sign.pem -noout -subject -issuer -enddate
fi

if [ -f device-ca.pem ]; then
    echo "device-ca.pem already exists - not overwriting." >&2
elif [ -f device-ca.key ]; then
    echo "device-ca.key exists without device-ca.pem - not overwriting it. Move it away, then run again." >&2
    exit 1
elif [ ! -f ca.key ]; then
    echo "ca.key is missing: cannot make device-ca.pem. Put ca.key back in this folder, then run again." >&2
    exit 1
else
    # An intermediate CA for end-entity certificates only (pathlen 0). The portal holds this key,
    # never ca.key: a stolen portal could issue device certificates (FreeRADIUS still refuses every
    # serial that is not in the database, sites-available/check-eap-tls), but no CA certificate,
    # and FreeRADIUS accepts client certificates from this issuer only.
    cat > device-ca.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

    openssl req -new -nodes -newkey rsa:3072 -sha256 \
        -keyout device-ca.key -out device-ca.csr \
        -subj "/C=IN/O=NIT Srinagar/OU=Network Lab/CN=${DEVICE_CA_CN}"
    openssl x509 -req -in device-ca.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 1825 -sha256 -extfile device-ca.ext -out device-ca.pem
    rm -f device-ca.csr device-ca.ext ca.srl

    # Like profile-sign.key: the portal (uid 10001) reads it through a read-only bind mount, so it
    # must be readable by other users of this PC (plan risk: move it to a signing service later)
    chmod 644 device-ca.pem device-ca.key
    openssl x509 -in device-ca.pem -noout -subject -issuer -enddate
fi
