#!/bin/sh
# Installs the lab certificates with safe ownership, prepares the accounting folder, then starts FreeRADIUS.
set -eu
SRC=/certs-src
DST=/etc/freeradius/certs/lab

for f in ca.pem server.pem server.key device-ca.pem; do
    [ -f "$SRC/$f" ] || { echo "Missing $SRC/$f - run scripts/init.ps1 (or certs/make-certs.sh) first." >&2; exit 1; }
done
install -d -o root -g freerad -m 0750 "$DST"
install -o root -g freerad -m 0644 "$SRC/ca.pem"     "$DST/ca.pem"
install -o root -g freerad -m 0644 "$SRC/server.pem" "$DST/server.pem"
install -o root -g freerad -m 0640 "$SRC/server.key" "$DST/server.key"
# EAP-TLS trust: client certificates must chain through the Device CA to the root
# (mods-available/eap, tls-device). Never device-ca.key: FreeRADIUS only verifies.
cat "$SRC/device-ca.pem" "$SRC/ca.pem" > "$DST/device-chain.pem"
chown root:freerad "$DST/device-chain.pem"
chmod 0644 "$DST/device-chain.pem"

install -d -o freerad -g freerad -m 0750 /var/log/freeradius/radacct /var/log/freeradius/radacct/spool

exec /docker-entrypoint.sh "$@"
