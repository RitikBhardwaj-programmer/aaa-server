#!/bin/sh
# Creates the lab CA and the RADIUS server certificate used by PEAP / EAP-TTLS.
# Output (all in this folder, gitignored):
#   ca.pem      - CA certificate. Install / select it on client devices.
#   ca.key      - CA private key. Keep offline in a real deployment.
#   server.pem  - server certificate (CN=radius.nitsrinagar.lab)
#   server.key  - server private key
set -eu
cd "$(dirname "$0")"

CA_CN="NIT Srinagar Lab CA"
SERVER_CN="radius.nitsrinagar.lab"

if [ -f server.pem ]; then
    echo "server.pem already exists - not overwriting." >&2
    exit 0
fi

umask 077
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
