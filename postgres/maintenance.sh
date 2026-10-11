#!/bin/sh
# Accounting housekeeping, every MAINTENANCE_INTERVAL seconds:
#   - close stale sessions (no accounting packet for STALE_SESSION_MINUTES), so a lost Stop
#     never blocks a student at the device limit
#   - create next months' partitions, drop partitions older than ACCT_RETENTION_MONTHS
#   - forget devices not seen for DEVICE_EXPIRY_DAYS
set -u
export PGHOST=postgres PGUSER=radius PGDATABASE=radius PGPASSWORD="$POSTGRES_RADIUS_PASSWORD"

until pg_isready -q; do sleep 2; done
while true; do
    psql -v ON_ERROR_STOP=1 -qAt <<EOF | sed "s/^/$(date -u +%FT%TZ) /"
SET client_min_messages = warning;
SELECT 'reaped stale sessions: ' || reap_stale_sessions($STALE_SESSION_MINUTES);
SELECT 'partitions ready' FROM ensure_monthly_partitions('radacct') a, ensure_monthly_partitions('radpostauth') p;
SELECT 'dropped old partitions: ' || (drop_old_partitions('radacct', $ACCT_RETENTION_MONTHS)
                                    + drop_old_partitions('radpostauth', $ACCT_RETENTION_MONTHS));
WITH d AS (DELETE FROM user_devices WHERE last_seen < now() - make_interval(days => $DEVICE_EXPIRY_DAYS) RETURNING 1)
SELECT 'expired devices: ' || count(*) FROM d;
-- Same retention for data outside the monthly partitions: the default partitions,
-- device-limit events (user + MAC) and session claims
WITH a AS (DELETE FROM radacct_default WHERE acctstarttime < date_trunc('month', now()) - make_interval(months => $ACCT_RETENTION_MONTHS) RETURNING 1),
     p AS (DELETE FROM radpostauth_default WHERE authdate < date_trunc('month', now()) - make_interval(months => $ACCT_RETENTION_MONTHS) RETURNING 1),
     e AS (DELETE FROM device_limit_events WHERE eventtime < date_trunc('month', now()) - make_interval(months => $ACCT_RETENTION_MONTHS) RETURNING 1),
     c AS (DELETE FROM radacct_claims WHERE acctstarttime < date_trunc('month', now()) - make_interval(months => $ACCT_RETENTION_MONTHS) RETURNING 1)
SELECT 'expired outside partitions: ' || (SELECT count(*) FROM a) + (SELECT count(*) FROM p)
       + (SELECT count(*) FROM e) + (SELECT count(*) FROM c);
EOF
    sleep "$MAINTENANCE_INTERVAL"
done
