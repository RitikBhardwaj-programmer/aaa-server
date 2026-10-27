#!/bin/bash
# End-to-end AAA tests. Run with:  docker compose --profile test run --rm tests
# Uses a real 802.1X supplicant (eapol_test) against FreeRADIUS, which checks LDAP,
# and reads the results back from PostgreSQL.
set -u
RADIUS=10.89.0.20
NAS=10.89.0.50          # this container: accounting rows from this NAS come from the tests
SECRET=$RADIUS_SECRET_LOCAL
PW=$TEST_USER_PASSWORD
SERVER_NAME=radius.nitsrinagar.lab
export PGHOST=postgres PGUSER=radius PGDATABASE=radius PGPASSWORD=$POSTGRES_RADIUS_PASSWORD
pass=0; fail=0
work=$(mktemp -d)
run=$(printf "%04X" $(( ($(date +%s) + $$) % 65536 )))   # per-run tag (the PID alone repeats in a fresh container)

ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; fail=$((fail + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$3', got '$2')"; fi; }
q() { psql -qAt -c "$1"; }
# On every exit, also an aborted run: no active test certificates (section 11) stay behind
cleanup() { q "DELETE FROM device_certs WHERE label = 'e2e-$run';" > /dev/null 2>&1; rm -rf "$work"; }
trap cleanup EXIT

# Accounting goes through the buffered-sql spool, so it reaches PostgreSQL a moment later.
# wait_for <sql> <expected>: re-runs the query for up to 10 s and prints the last result.
wait_for() {
    local got i
    for i in $(seq 1 20); do
        got=$(q "$1"); [ "$got" = "$2" ] && break; sleep 0.5
    done
    echo "$got"
}

# Last value of RADIUS attribute number $1 in eapol_test output $2 (the Access-Accept is the last packet)
attr() { awk -v n="$1" '$1=="Attribute" && $2==n {getline; v=$2} END {print v}' "$2" | tr -d "'"; }
hex2str() { [ -n "$1" ] && printf '%b' "$(echo "$1" | sed 's/../\\x&/g')"; }

# eap_login <PEAP|TTLS> <user> <password> [server name to verify] [device MAC]
eap_login() {
    local method=$1 user=$2 password=$3 name=${4:-$SERVER_NAME} mac=${5:-02:00:00:00:00:01} phase2
    [ "$method" = PEAP ] && phase2="auth=MSCHAPV2" || phase2="auth=PAP"
    cat > "$work/eap.conf" <<EOF
network={
  key_mgmt=WPA-EAP
  eap=$method
  identity="$user"
  anonymous_identity="anonymous"
  password="$password"
  ca_cert="/certs/ca.pem"
  domain_match="$name"
  phase2="$phase2"
}
EOF
    eapol_test -c "$work/eap.conf" -a "$RADIUS" -s "$SECRET" -M "$mac" -t 10 > "$work/out" 2>&1
    tail -1 "$work/out"
}

# acct <user> <Status> <session id> <MAC> [extra attributes]: one accounting packet from this NAS
acct() {
    printf 'User-Name = "%s", Acct-Status-Type = %s, Acct-Session-Id = "%s", NAS-IP-Address = %s, NAS-Port-Type = Wireless-802.11, Calling-Station-Id = "%s"%s\n' \
        "$1" "$2" "$3" "$NAS" "$4" "${5:+, $5}" \
        | radclient -r 1 -t 3 "$RADIUS:1813" acct "$SECRET" > /dev/null 2>&1
    echo $?
}

# Close sessions left open by an earlier (interrupted) run, as a rebooting AP would
acct_on() { echo "Acct-Status-Type = Accounting-On, NAS-IP-Address = $NAS" | radclient -r 1 -t 3 "$RADIUS:1813" acct "$SECRET" > /dev/null 2>&1; }
acct_on
wait_for "SELECT COUNT(*) FROM radacct WHERE nasipaddress = '$NAS' AND acctstoptime IS NULL;" 0 > /dev/null

echo "== 1. Authentication + authorization over EAP (user, group -> VLAN / Class, re-check every ${REAUTH_INTERVAL}s, interim every ${ACCT_INTERIM_INTERVAL}s)"
# Attribute 29 = Termination-Action (1 = RADIUS-Request: re-authenticate, do not disconnect); 85 = Acct-Interim-Interval
while read -r user vlan group; do
    [ "${SEND_VLAN:-yes}" = no ] && vlan=""   # SEND_VLAN=no: the Accept carries no VLAN
    for method in PEAP TTLS; do
        result=$(eap_login "$method" "$user" "$PW")
        if [ "$method" = PEAP ] && [ "$ALLOW_PEAP" != yes ]; then
            check "PEAP $user -> Reject (ALLOW_PEAP=no)" "$result" FAILURE
            continue
        fi
        got="$result $(attr 27 "$work/out") $(attr 29 "$work/out") $(attr 85 "$work/out") $(hex2str "$(attr 81 "$work/out")") $(hex2str "$(attr 25 "$work/out")") $(attr 1 "$work/out")"
        check "$method $user -> Accept, VLAN ${vlan:-none}, Class $group" "$got" "SUCCESS $REAUTH_INTERVAL 1 $ACCT_INTERIM_INTERVAL $vlan $group $user"
    done
done <<EOF
student001 10 students
24IT001 10 students
faculty001 20 faculty
staff001 20 staff
guest001 30 guests
EOF

echo "== 1b. Secure defaults: EAP-TTLS first, stored uid in accounting"
# A client that accepts both methods gets the server's default method (EAP type 21 = TTLS)
cat > "$work/both.conf" <<EOF
network={
  key_mgmt=WPA-EAP
  eap=PEAP TTLS
  identity="student001"
  anonymous_identity="anonymous"
  password="$PW"
  ca_cert="/certs/ca.pem"
  domain_match="$SERVER_NAME"
  phase2="auth=PAP"
}
EOF
eapol_test -c "$work/both.conf" -a "$RADIUS" -s "$SECRET" -M 02:00:00:00:00:01 -t 10 > "$work/out" 2>&1
check "server proposes EAP-TTLS first" "$(grep -o 'EAP vendor 0 method [0-9]* ([A-Z]*) selected' "$work/out" | tail -1)" "EAP vendor 0 method 21 (TTLS) selected"
# LDAP matches uid without regard to case; accounting must still get the stored form,
# or a student could pass the device limit by typing the name in another case
check "TTLS login as '24it001' -> Accept carries User-Name 24IT001" \
      "$(eap_login TTLS 24it001 "$PW") $(attr 1 "$work/out")" "SUCCESS 24IT001"
out=$(echo "User-Name = \"STAFF001\", User-Password = \"$PW\", Message-Authenticator = 0x00" | radclient -x -r 1 -t 3 "$RADIUS:1812" auth "$SECRET" 2>&1)
check "PAP login as 'STAFF001' -> Accept carries User-Name staff001" "$(echo "$out" | sed -n 's/^\s*User-Name = "\(.*\)"$/\1/p' | tail -1)" staff001

echo "== 2. Rejections"
for method in PEAP TTLS; do
    check "$method wrong password -> Reject"   "$(eap_login "$method" student001 wrong-password "" 02:00:00:00:0E:01)" FAILURE
    check "$method unknown user -> Reject"     "$(eap_login "$method" nosuchuser "$PW")" FAILURE
    check "$method disabled001 -> Reject"      "$(eap_login "$method" disabled001 "$PW")" FAILURE
done

echo "== 3. Client verifies the server certificate"
check "TTLS with wrong expected server name -> client aborts" "$(eap_login TTLS student001 "$PW" evil.example.com)" FAILURE
if grep -q 'CTRL-EVENT-EAP-TLS-CERT-ERROR\|Domain name mismatch\|did not match' "$work/out"; then
    ok "abort reason is certificate name mismatch"
else
    bad "abort reason is certificate name mismatch"
fi

echo "== 4. Plain RADIUS (PAP via LDAP bind) and NAS shared secret"
pap() { echo "User-Name = \"$1\", User-Password = \"$2\", Message-Authenticator = 0x00" | radclient -r 1 -t 3 "$RADIUS:1812" auth "$3" 2>&1; }
out=$(pap student001 "$PW" "$SECRET")
check "PAP student001 -> Accept" "$(echo "$out" | grep -o 'Access-Accept' | head -1)" Access-Accept
out=$(pap student001 wrong-password "$SECRET")
check "PAP wrong password -> Reject" "$(echo "$out" | grep -o 'Access-Reject' | head -1)" Access-Reject
out=$(pap student001 "$PW" wrong-shared-secret)
check "wrong NAS shared secret -> request dropped (no reply)" "$(echo "$out" | grep -c 'Received Access')" 0

echo "== 5. Accounting (Start / Interim-Update / Stop) in PostgreSQL"
session="test-$(date +%s)-$$"
common='Called-Station-Id = "AA-BB-CC-DD-EE-FF:CampusWiFi", Framed-IP-Address = 192.168.10.23, Class = "students"'
# The AP clock is wrong (2024-04-16, as on the lab DAP-X3060) and the MAC uses colons
check "Accounting-Start answered" "$(acct student001 Start "$session" 02:00:00:00:00:01 "$common, Event-Timestamp = 1713225600")" 0
check "Interim-Update answered"   "$(acct student001 Interim-Update "$session" 02:00:00:00:00:01 "$common, Acct-Session-Time = 60, Acct-Input-Octets = 1000, Acct-Output-Octets = 5000")" 0
check "Accounting-Stop answered"  "$(acct student001 Stop "$session" 02:00:00:00:00:01 "$common, Acct-Session-Time = 120, Acct-Input-Octets = 2048, Acct-Output-Octets = 8192")" 0
row=$(wait_for "SELECT username, class, acctsessiontime, acctinputoctets, acctoutputoctets, acctstoptime IS NOT NULL FROM radacct WHERE acctsessionid = '$session';" \
               "student001|students|120|2048|8192|t")
check "radacct row (user|class|time|in|out|closed)" "$row" "student001|students|120|2048|8192|t"
check "start time is the server's receive time, not the AP clock (2024)" \
      "$(q "SELECT acctstarttime > now() - interval '5 minutes' FROM radacct WHERE acctsessionid = '$session';")" t
check "MAC stored as AA-BB-CC-DD-EE-FF" "$(q "SELECT callingstationid FROM radacct WHERE acctsessionid = '$session';")" "02-00-00-00-00-01"
check "row is in this month's partition" \
      "$(q "SELECT tableoid::regclass FROM radacct WHERE acctsessionid = '$session';")" "radacct_$(date +%Y_%m)"
if grep -qs "$session" /radius-acct/radacct/$NAS/detail-*; then ok "detail file has the session"; else bad "detail file has the session"; fi
dup="dup-$(date +%s)-$$"
acct guest001 Start "$dup" 02:00:00:00:00:02 > /dev/null; acct guest001 Start "$dup" 02:00:00:00:00:02 > /dev/null
acct guest001 Stop "$dup" 02:00:00:00:00:02 "Acct-Session-Time = 5" > /dev/null
check "duplicate Start -> one row, closed by the Stop" \
      "$(wait_for "SELECT COUNT(*), bool_and(acctstoptime IS NOT NULL) FROM radacct WHERE acctsessionid = '$dup';" "1|t")" "1|t"
# After a failed re-check the Aruba AP-615 sends the Stop with the outer identity and no Class
# (docs/experiments/2026-10-26-aruba-ap615-first-test.md). It must close the student's row.
anon="anon-$(date +%s)-$$"
acct student001 Start "$anon" 02:00:00:00:00:03 'Class = "students"' > /dev/null
wait_for "SELECT COUNT(*) FROM radacct WHERE acctsessionid = '$anon';" 1 > /dev/null
acct anonymous Stop "$anon" 02:00:00:00:00:03 "Acct-Session-Time = 308, Acct-Terminate-Cause = Lost-Service" > /dev/null
check "Stop with User-Name anonymous -> closes the same row, user kept" \
      "$(wait_for "SELECT COUNT(*), MAX(username), bool_and(acctstoptime IS NOT NULL), MAX(acctterminatecause) FROM radacct WHERE acctsessionid = '$anon';" "1|student001|t|Lost-Service")" \
      "1|student001|t|Lost-Service"

echo "== 6. Post-auth log (real inner identity, never the password)"
row=$(q "SELECT reply FROM radpostauth WHERE username = 'faculty001' ORDER BY authdate DESC LIMIT 1;")
check "radpostauth has faculty001 Access-Accept" "$row" "Access-Accept"
row=$(q "SELECT reply FROM radpostauth WHERE username = 'disabled001' ORDER BY authdate DESC LIMIT 1;")
check "radpostauth has disabled001 Access-Reject" "$row" "Access-Reject"
check "radpostauth has no password column" \
      "$(q "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'radpostauth' AND column_name = 'pass';")" 0

echo "== 7. Disconnect-Request for open sessions (disconnect-user.sh)"
# An open session whose NAS is this container: nothing listens on 3799 here, so "no reply" is expected.
# This proves the session lookup and the request; an RFC 5176-capable AP would answer with an ACK.
session="dm-$(date +%s)-$$"
acct guest001 Start "$session" 02-00-00-00-00-02 > /dev/null
wait_for "SELECT COUNT(*) FROM radacct WHERE acctsessionid = '$session';" 1 > /dev/null
out=$(RADIUS_SECRET_AP=$SECRET AP_IP=unused disconnect-user.sh guest001)
if echo "$out" | grep -q "02-00-00-00-00-02 on $NAS: no reply"; then
    ok "open session found and Disconnect-Request sent to its NAS"
else
    bad "open session found and Disconnect-Request sent to its NAS (got: $out)"
fi
acct guest001 Stop "$session" 02-00-00-00-00-02 "Acct-Session-Time = 1" > /dev/null
wait_for "SELECT COUNT(*) FROM radacct WHERE acctsessionid = '$session' AND acctstoptime IS NULL;" 0 > /dev/null
check "user without open sessions -> nothing sent" "$(RADIUS_SECRET_AP=$SECRET AP_IP=unused disconnect-user.sh faculty001)" "No open sessions for faculty001."

echo "== 8. Device limit ($DEVICE_LIMIT_STUDENTS devices per student, mode $DEVICE_LIMIT_MODE)"
u=24IT001
events() { q "SELECT COUNT(*) FROM device_limit_events WHERE username = '$u' AND callingstationid = '$1' AND eventtime > now() - interval '1 minute';"; }
for i in 1 2 3; do acct $u Start "dl-$run-$i" "02:00:${run:0:2}:${run:2:2}:0A:0$i" > /dev/null; done
# The same phone roaming to a second AP: a second open row with the same MAC (must count once)
acct $u Start "dl-$run-1b" "02:00:${run:0:2}:${run:2:2}:0A:01" > /dev/null
mac() { echo "02-00-${run:0:2}-${run:2:2}-0A-0$1"; }
wait_for "SELECT COUNT(DISTINCT callingstationid) FROM radacct WHERE username = '$u' AND acctstoptime IS NULL;" 3 > /dev/null
# The 4th device logs in with the name in lower case: it must still count as 24IT001
result=$(eap_login TTLS "$(echo $u | tr A-Z a-z)" "$PW" "" "02:00:${run:0:2}:${run:2:2}:0A:04")
if [ "$DEVICE_LIMIT_MODE" = enforce ]; then
    check "4th device -> Reject (enforce)" "$result" FAILURE
else
    check "4th device -> Accept (soft mode logs only)" "$result" SUCCESS
fi
check "4th device -> device_limit_events row" "$(events "$(mac 4)")" 1
check "device already online re-checks -> Accept, no event" "$(eap_login TTLS $u "$PW" "" "02:00:${run:0:2}:${run:2:2}:0A:01") $(events "$(mac 1)")" "SUCCESS 0"
# Device 3 lost its Stop and sent nothing for longer than STALE_SESSION_MINUTES
q "UPDATE radacct SET acctupdatetime = now() - interval '$((STALE_SESSION_MINUTES + 5)) minutes' WHERE acctsessionid = 'dl-$run-3';" > /dev/null
check "stale session does not count -> 5th device Accept, no event" "$(eap_login TTLS $u "$PW" "" "02:00:${run:0:2}:${run:2:2}:0A:05") $(events "$(mac 5)")" "SUCCESS 0"
check "reaper closes the stale session" "$(q "SELECT reap_stale_sessions($STALE_SESSION_MINUTES) >= 1;") $(q "SELECT acctterminatecause FROM radacct WHERE acctsessionid = 'dl-$run-3';")" "t Stale-Session-Reaped"
# Device 3 was online after all (its updates were delayed, e.g. by a database outage): a newer
# Interim-Update reopens the reaped session, so it counts again
acct $u Interim-Update "dl-$run-3" "02:00:${run:0:2}:${run:2:2}:0A:03" "Acct-Session-Time = 1800" > /dev/null
check "newer Interim-Update reopens a reaped session" \
      "$(wait_for "SELECT acctstoptime IS NULL AND acctterminatecause IS NULL FROM radacct WHERE acctsessionid = 'dl-$run-3';" t)" t
check "user_devices lists the student's devices" \
      "$(q "SELECT COUNT(*) FROM user_devices WHERE username = '$u' AND callingstationid LIKE '02-00-${run:0:2}-${run:2:2}-0A-%';")" 3
acct_on
check "Accounting-On (AP reboot) closes all its sessions" \
      "$(wait_for "SELECT COUNT(*) FROM radacct WHERE username = '$u' AND acctstoptime IS NULL;" 0)" 0

echo "== 8b. Duplicate-safe inserts under concurrency (two RADIUS servers spooling the same session)"
for i in $(seq 1 10); do q "SELECT radacct_claim('race-$run', now());" > "$work/claim.$i" & done; wait
check "10 concurrent claims of one session ID -> exactly one wins" "$(cat "$work"/claim.* | grep -c '^t$')" 1
q "DELETE FROM radacct_claims WHERE acctuniqueid = 'race-$run';" > /dev/null

echo "== 9. Failed-login rate limit ($AUTH_REJECT_LIMIT rejects per user and device, instead of lockout)"
for i in $(seq 1 "$AUTH_REJECT_LIMIT"); do eap_login TTLS staff001 wrong-password "" "02:00:${run:0:2}:${run:2:2}:0B:01" > /dev/null; done
check "correct password from the same device -> Reject (rate limited)" "$(eap_login TTLS staff001 "$PW" "" "02:00:${run:0:2}:${run:2:2}:0B:01")" FAILURE
check "correct password from another device -> Accept (no lockout)" "$(eap_login TTLS staff001 "$PW" "" "02:00:${run:0:2}:${run:2:2}:0B:02")" SUCCESS

echo "== 10. Who had this IP (who_had_ip over radacct, server receive times)"
# One IP, used by guest001 and then by faculty001. Times are moved into the past with UPDATE, so
# the checks use fixed offsets from now(). The IPs are 10.99.<x>.<y>, taken from the run tag.
ipx=$((16#${run:0:2})); ipy=$((16#${run:2:2}))
ip="10.99.$ipx.$ipy"; ip_reap="10.99.$(( (ipx + 1) % 256 )).$ipy"
mac_a="02:00:${run:0:2}:${run:2:2}:0C:01"; mac_b="02:00:${run:0:2}:${run:2:2}:0C:02"
who() { q "SELECT string_agg(username || ' ' || status, ',') FROM who_had_ip('$1', now() - interval '$2 minutes');"; }
acct guest001 Start "wi-$run-a" "$mac_a" "Framed-IP-Address = $ip" > /dev/null
acct guest001 Stop "wi-$run-a" "$mac_a" "Framed-IP-Address = $ip, Acct-Session-Time = 1200" > /dev/null
wait_for "SELECT COUNT(*) FROM radacct WHERE acctsessionid = 'wi-$run-a' AND acctstoptime IS NOT NULL;" 1 > /dev/null
acct faculty001 Start "wi-$run-b" "$mac_b" "Framed-IP-Address = $ip" > /dev/null
wait_for "SELECT COUNT(*) FROM radacct WHERE acctsessionid = 'wi-$run-b';" 1 > /dev/null
# A: 60..40 minutes ago (closed). B: from 30 minutes ago, still open, last update 1 minute ago.
q "UPDATE radacct SET acctstarttime = now() - interval '60 minutes', acctupdatetime = now() - interval '40 minutes', acctstoptime = now() - interval '40 minutes' WHERE acctsessionid = 'wi-$run-a';" > /dev/null
q "UPDATE radacct SET acctstarttime = now() - interval '30 minutes', acctupdatetime = now() - interval '1 minute' WHERE acctsessionid = 'wi-$run-b';" > /dev/null
check "same IP, time inside the first session -> the first user" "$(who "$ip" 50)" "guest001 closed"
check "same IP, time inside the second session -> the second user only" "$(who "$ip" 10)" "faculty001 open"
check "time between the two sessions -> no rows" "$(who "$ip" 35)" ""
check "time before any session -> no rows" "$(who "$ip" 90)" ""
check "another IP -> no rows" "$(who "10.99.$ipx.$(( (ipy + 1) % 256 ))" 50)" ""
check "row carries MAC, AP, NAS and session ID" \
      "$(q "SELECT callingstationid || ' ' || nas || ' ' || acctsessionid FROM who_had_ip('$ip', now() - interval '10 minutes');")" "02-00-${run:0:2}-${run:2:2}-0C-02 $NAS wi-$run-b"
# A session reaped after a lost Stop: its stop time is the last update, so later times do not match
acct guest001 Start "wi-$run-c" "$mac_a" "Framed-IP-Address = $ip_reap" > /dev/null
wait_for "SELECT COUNT(*) FROM radacct WHERE acctsessionid = 'wi-$run-c';" 1 > /dev/null
q "UPDATE radacct SET acctstarttime = now() - interval '3 hours', acctupdatetime = now() - interval '2 hours' WHERE acctsessionid = 'wi-$run-c';" > /dev/null
check "silent open session -> stale-open (up to its last update)" "$(who "$ip_reap" 150)" "guest001 stale-open"
check "silent open session, time after its last update -> no rows" "$(who "$ip_reap" 90)" ""
q "SELECT reap_stale_sessions($STALE_SESSION_MINUTES);" > /dev/null
check "reaped session -> closed, Stale-Session-Reaped" \
      "$(q "SELECT status || ' ' || acctterminatecause FROM who_had_ip('$ip_reap', now() - interval '150 minutes');")" "closed Stale-Session-Reaped"
check "reaped session, time after its last update -> no rows" "$(who "$ip_reap" 90)" ""
acct faculty001 Stop "wi-$run-b" "$mac_b" "Framed-IP-Address = $ip, Acct-Session-Time = 1800" > /dev/null
wait_for "SELECT COUNT(*) FROM radacct WHERE acctsessionid = 'wi-$run-b' AND acctstoptime IS NULL;" 0 > /dev/null

echo "== 11. EAP-TLS with device certificates (Device CA, sites-available/check-eap-tls)"
# tls_cert <CN> <name>: a key and a certificate of the Device CA, made the way portal/pki.py makes
# them (CN = uid, clientAuth, 20-byte random serial); prints the serial as FreeRADIUS writes it.
# The row in device_certs is what the portal would INSERT; written here as role radius.
tls_cert() {
    local serial
    serial=4$(openssl rand -hex 20 | cut -c2-)      # first byte 0x40-0x4f: positive, always 20 bytes
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
        -keyout "$work/$2.key" -out "$work/$2.csr" 2> /dev/null
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "$work/tls.ext"
    openssl x509 -req -in "$work/$2.csr" -CA /certs/device-ca.pem -CAkey /certs/device-ca.key -set_serial "0x$serial" \
        -days 365 -sha256 -extfile "$work/tls.ext" -out "$work/$2.pem" 2> /dev/null
    echo "$serial"
}
# add_cert <serial> <uid> [days the row ended ago]: an active row, or one that expired that many days ago
add_cert() {
    local end="now() + interval '1 year'" start="now()"
    [ -n "${3:-}" ] && end="now() - interval '$3 days'" && start="now() - interval '2 years'"
    q "INSERT INTO device_certs (serial, username, label, pubkey_sha256, issued_at, not_after, via) VALUES ('$1', '$2', 'e2e-$run', repeat('0', 64), $start, $end, 'app');" > /dev/null
}
# tls_login <identity> <name> [device MAC]
tls_login() {
    cat > "$work/tls.conf" <<EOF
network={
  key_mgmt=WPA-EAP
  eap=TLS
  identity="$1"
  ca_cert="/certs/ca.pem"
  domain_match="$SERVER_NAME"
  client_cert="$work/$2.pem"
  private_key="$work/$2.key"
}
EOF
    eapol_test -c "$work/tls.conf" -a "$RADIUS" -s "$SECRET" -M "${3:-02:00:00:00:0C:01}" -t 10 > "$work/out" 2>&1
    tail -1 "$work/out"
}
tls_mac="02:00:${run:0:2}:${run:2:2}:0C:01"
s_ok=$(tls_cert student001 ok); add_cert "$s_ok" student001
[ "${SEND_VLAN:-yes}" = no ] && vlan="" || vlan=10
got="$(tls_login student001 ok "$tls_mac") $(hex2str "$(attr 81 "$work/out")") $(hex2str "$(attr 25 "$work/out")") $(attr 1 "$work/out")"
check "EAP-TLS student001, valid certificate -> Accept, VLAN ${vlan:-none}, Class students" "$got" "SUCCESS $vlan students student001"
check "the device and the serial are recorded (device_cert_seen)" \
      "$(q "SELECT username || ' ' || callingstationid FROM device_cert_seen WHERE serial = '$s_ok';")" "student001 $(echo "$tls_mac" | tr : - | tr a-f A-F)"
check "the Accept is logged with the uid (radpostauth)" \
      "$(q "SELECT reply FROM radpostauth WHERE username = 'student001' AND callingstationid = '$(echo "$tls_mac" | tr : - | tr a-f A-F)' ORDER BY authdate DESC LIMIT 1;")" "Access-Accept"
check "EAP-TLS with another user's identity (CN student001, identity faculty001) -> Reject" "$(tls_login faculty001 ok)" FAILURE
q "UPDATE device_certs SET revoked_at = now(), revoke_reason = 'user' WHERE serial = '$s_ok';" > /dev/null
check "EAP-TLS after the certificate is revoked -> Reject" "$(tls_login student001 ok "$tls_mac")" FAILURE
tls_cert student001 unknown > /dev/null
check "EAP-TLS with a Device CA certificate that is not in device_certs -> Reject" "$(tls_login student001 unknown)" FAILURE
s_other=$(tls_cert faculty001 other); add_cert "$s_other" student001
check "EAP-TLS whose serial belongs to another user (CN faculty001, row of student001) -> Reject" "$(tls_login faculty001 other)" FAILURE
s_exp=$(tls_cert guest001 expired); add_cert "$s_exp" guest001 1
check "EAP-TLS with an expired device_certs row -> Reject" "$(tls_login guest001 expired)" FAILURE
s_dis=$(tls_cert disabled001 disabled); add_cert "$s_dis" disabled001
check "EAP-TLS disabled001 with an active certificate -> Reject (LDAP group)" "$(tls_login disabled001 disabled)" FAILURE
s_fac=$(tls_cert faculty001 faculty); add_cert "$s_fac" faculty001
[ "${SEND_VLAN:-yes}" = no ] && vlan="" || vlan=20
got="$(tls_login faculty001 faculty) $(hex2str "$(attr 81 "$work/out")") $(hex2str "$(attr 25 "$work/out")")"
check "EAP-TLS faculty001 -> Accept, VLAN ${vlan:-none}, Class faculty" "$got" "SUCCESS $vlan faculty"
# EAP-TLS is an outer method only (mods-available/inner-eap): inside a tunnel the serial would
# not be recorded, so revoke-disconnect and "Not me" could not find the device
cat > "$work/tunnel.conf" <<EOF
network={
  key_mgmt=WPA-EAP
  eap=TTLS
  identity="faculty001"
  anonymous_identity="anonymous"
  ca_cert="/certs/ca.pem"
  domain_match="$SERVER_NAME"
  phase2="autheap=TLS"
  ca_cert2="/certs/ca.pem"
  client_cert2="$work/faculty.pem"
  private_key2="$work/faculty.key"
}
EOF
eapol_test -c "$work/tunnel.conf" -a "$RADIUS" -s "$SECRET" -M 02:00:00:00:0C:02 -t 10 > "$work/out" 2>&1
check "EAP-TLS inside an EAP-TTLS tunnel (active certificate) -> Reject" "$(tail -1 "$work/out")" FAILURE
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=student001" -days 1 \
    -keyout "$work/self.key" -out "$work/self.pem" 2> /dev/null
check "EAP-TLS with a self-signed certificate -> Reject" "$(tls_login student001 self)" FAILURE
# The revocation is final: even role radius cannot take it back (trigger of migration 006)
check "a revoked certificate cannot be brought back" \
      "$(q "UPDATE device_certs SET revoked_at = NULL, revoke_reason = NULL WHERE serial = '$s_ok';" 2>&1 | grep -c 'cannot be changed')" 1

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
