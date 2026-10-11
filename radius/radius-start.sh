#!/bin/sh
# Installs the lab certificates with safe ownership, prepares the accounting folder, then starts FreeRADIUS.
set -eu
SRC=/certs-src
DST=/etc/freeradius/certs/lab

for f in ca.pem server.pem server.key; do
    [ -f "$SRC/$f" ] || { echo "Missing $SRC/$f - run scripts/init.ps1 first." >&2; exit 1; }
done
install -d -o root -g freerad -m 0750 "$DST"
install -o root -g freerad -m 0644 "$SRC/ca.pem"     "$DST/ca.pem"
install -o root -g freerad -m 0644 "$SRC/server.pem" "$DST/server.pem"
install -o root -g freerad -m 0640 "$SRC/server.key" "$DST/server.key"

install -d -o freerad -g freerad -m 0750 /var/log/freeradius/radacct /var/log/freeradius/radacct/spool

exec /docker-entrypoint.sh "$@"
