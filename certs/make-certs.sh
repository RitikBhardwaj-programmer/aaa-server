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
# Each part is made only if its certificate does not exist yet, so you can run the script again
# after an update: it adds the new files and never overwrites the old ones.
set -eu
cd "$(dirname "$0")"

CA_CN="NIT Srinagar Lab CA"
SERVER_CN="radius.nitsrinagar.lab"
SIGN_CN="NIT Srinagar Wi-Fi Profile Signing"

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
