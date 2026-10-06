#!/bin/bash
# Sends an RFC 5176 Disconnect-Request for every OPEN accounting session of a user,
# so the access point drops the device at once instead of at the next re-check.
#
# Usage: docker compose --profile tools run --rm tools disconnect-user.sh <uid>
#
# The target of each request is the session's NAS address from radacct. On Docker Desktop
# every NAS appears as the Docker gateway, so that address is replaced with AP_IP from .env.
set -u
DB="file:/radius-acct/sqlite/radius.db?immutable=1"
DOCKER_GATEWAY=10.89.0.1
DAS_PORT=3799

uid=${1:-}
case "$uid" in *[!A-Za-z0-9._-]*|'') echo "Usage: disconnect-user.sh <uid>" >&2; exit 2;; esac

sessions=$(sqlite3 -separator '|' "$DB" \
    "SELECT nasipaddress, acctsessionid, callingstationid FROM radacct
     WHERE username = '$uid' AND acctstoptime IS NULL;")
if [ -z "$sessions" ]; then
    echo "No open sessions for $uid."
    exit 0
fi

sent=0; acked=0
while IFS='|' read -r nas session station; do
    target=$nas
    [ "$nas" = "$DOCKER_GATEWAY" ] && target=${AP_IP:?AP_IP not set}
    reply=$(printf 'User-Name = "%s", Acct-Session-Id = "%s", Calling-Station-Id = "%s", Message-Authenticator = 0x00\n' \
                "$uid" "$session" "$station" \
            | radclient -r 2 -t 3 "$target:$DAS_PORT" disconnect "$RADIUS_SECRET_AP" 2>&1 | grep -o 'Disconnect-[A-Z]*' | tail -1)
    sent=$((sent + 1))
    case "$reply" in
        Disconnect-ACK) acked=$((acked + 1)); echo "  $station on $target: disconnected (ACK)";;
        Disconnect-NAK) echo "  $station on $target: refused by the AP (NAK)";;
        *)              echo "  $station on $target: no reply (AP does not support Disconnect-Request)";;
    esac
done <<< "$sessions"

echo "$acked of $sent session(s) disconnected at once. The rest end at the next re-check (REAUTH_INTERVAL)."
