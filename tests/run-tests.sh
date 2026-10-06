#!/bin/bash
# End-to-end AAA tests. Run with:  docker compose --profile test run --rm tests
# Uses a real 802.1X supplicant (eapol_test) against FreeRADIUS, which checks LDAP.
set -u
RADIUS=10.89.0.20
SECRET=$RADIUS_SECRET_LOCAL
PW=$TEST_USER_PASSWORD
SERVER_NAME=radius.nitsrinagar.lab
DB="file:/radius-acct/sqlite/radius.db?immutable=1"
pass=0; fail=0
work=$(mktemp -d)

ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; fail=$((fail + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$3', got '$2')"; fi; }

# Last value of RADIUS attribute number $1 in eapol_test output $2 (the Access-Accept is the last packet)
attr() { awk -v n="$1" '$1=="Attribute" && $2==n {getline; v=$2} END {print v}' "$2" | tr -d "'"; }
hex2str() { [ -n "$1" ] && printf '%b' "$(echo "$1" | sed 's/../\\x&/g')"; }

# eap_login <PEAP|TTLS> <user> <password> [server name to verify]
eap_login() {
    local method=$1 user=$2 password=$3 name=${4:-$SERVER_NAME} phase2
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
    eapol_test -c "$work/eap.conf" -a "$RADIUS" -s "$SECRET" -M 02:00:00:00:00:01 -t 10 > "$work/out" 2>&1
    tail -1 "$work/out"
}

echo "== 1. Authentication + authorization over EAP (user, group -> VLAN / Class, re-check every ${REAUTH_INTERVAL}s)"
# Attribute 29 = Termination-Action; value 1 = RADIUS-Request (re-authenticate, do not disconnect)
while read -r user vlan group; do
    for method in PEAP TTLS; do
        result=$(eap_login "$method" "$user" "$PW")
        got="$result $(attr 27 "$work/out") $(attr 29 "$work/out") $(hex2str "$(attr 81 "$work/out")") $(hex2str "$(attr 25 "$work/out")") $(attr 1 "$work/out")"
        check "$method $user -> Accept, re-check ${REAUTH_INTERVAL}s, VLAN $vlan, Class $group" "$got" "SUCCESS $REAUTH_INTERVAL 1 $vlan $group $user"
    done
done <<EOF
student001 10 students
24IT001 10 students
faculty001 20 faculty
staff001 20 staff
guest001 30 guests
EOF

echo "== 2. Rejections"
for method in PEAP TTLS; do
    check "$method wrong password -> Reject"   "$(eap_login "$method" student001 wrong-password)" FAILURE
    check "$method unknown user -> Reject"     "$(eap_login "$method" nosuchuser "$PW")" FAILURE
    check "$method disabled001 -> Reject"      "$(eap_login "$method" disabled001 "$PW")" FAILURE
done

echo "== 3. Client verifies the server certificate"
check "PEAP with wrong expected server name -> client aborts" "$(eap_login PEAP student001 "$PW" evil.example.com)" FAILURE
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

echo "== 5. Accounting (Start / Interim-Update / Stop)"
session="test-$(date +%s)-$$"
acct() {
    cat <<EOF | radclient -r 1 -t 3 "$RADIUS:1813" acct "$SECRET" > /dev/null 2>&1
User-Name = "student001", Acct-Status-Type = $1, Acct-Session-Id = "$session",
NAS-IP-Address = 10.89.0.50, NAS-Port-Type = Wireless-802.11, Calling-Station-Id = "02-00-00-00-00-01",
Called-Station-Id = "AA-BB-CC-DD-EE-FF:CampusWiFi", Framed-IP-Address = 192.168.10.23, Class = "students",
Acct-Session-Time = $2, Acct-Input-Octets = $3, Acct-Output-Octets = $4
EOF
    echo $?
}
check "Accounting-Start answered"   "$(acct Start 0 0 0)" 0
check "Interim-Update answered"     "$(acct Interim-Update 60 1000 5000)" 0
check "Accounting-Stop answered"    "$(acct Stop 120 2048 8192)" 0
sleep 1
row=$(sqlite3 "$DB" "SELECT username, class, acctsessiontime, acctinputoctets, acctoutputoctets, acctstoptime IS NOT NULL FROM radacct WHERE acctsessionid = '$session';")
check "SQLite radacct row (user|class|time|in|out|closed)" "$row" "student001|students|120|2048|8192|1"
if grep -qs "$session" /radius-acct/radacct/10.89.0.50/detail-*; then ok "detail file has the session"; else bad "detail file has the session"; fi

echo "== 6. Post-auth log (real inner identity, not 'anonymous')"
row=$(sqlite3 "$DB" "SELECT reply FROM radpostauth WHERE username = 'faculty001' ORDER BY id DESC LIMIT 1;")
check "radpostauth has faculty001 Access-Accept" "$row" "Access-Accept"
row=$(sqlite3 "$DB" "SELECT reply FROM radpostauth WHERE username = 'disabled001' ORDER BY id DESC LIMIT 1;")
check "radpostauth has disabled001 Access-Reject" "$row" "Access-Reject"

echo "== 7. Disconnect-Request for open sessions (disconnect-user.sh)"
# An open session whose NAS is this container: nothing listens on 3799 here, so "no reply" is expected.
# This proves the session lookup and the request; an RFC 5176-capable AP would answer with an ACK.
session="dm-$(date +%s)-$$"
cat <<EOF | radclient -r 1 -t 3 "$RADIUS:1813" acct "$SECRET" > /dev/null 2>&1
User-Name = "guest001", Acct-Status-Type = Start, Acct-Session-Id = "$session",
NAS-IP-Address = 10.89.0.50, Calling-Station-Id = "02-00-00-00-00-02"
EOF
sleep 1
out=$(RADIUS_SECRET_AP=$SECRET AP_IP=unused disconnect-user.sh guest001)
if echo "$out" | grep -q "02-00-00-00-00-02 on 10.89.0.50: no reply"; then
    ok "open session found and Disconnect-Request sent to its NAS"
else
    bad "open session found and Disconnect-Request sent to its NAS (got: $out)"
fi
cat <<EOF | radclient -r 1 -t 3 "$RADIUS:1813" acct "$SECRET" > /dev/null 2>&1
User-Name = "guest001", Acct-Status-Type = Stop, Acct-Session-Id = "$session",
NAS-IP-Address = 10.89.0.50, Calling-Station-Id = "02-00-00-00-00-02", Acct-Session-Time = 1
EOF
check "user without open sessions -> nothing sent" "$(RADIUS_SECRET_AP=$SECRET AP_IP=unused disconnect-user.sh faculty001)" "No open sessions for faculty001."

rm -rf "$work"
echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
