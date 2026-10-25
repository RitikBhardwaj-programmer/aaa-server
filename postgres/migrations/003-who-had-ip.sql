-- "Who had this IP at this time?" lookup over radacct (CERT-In / DPDP log duty).
-- Included by initdb/02-schema.sql; safe to run again on an existing database, as role radius:
--   docker compose exec -T postgres psql -U radius -d radius < postgres/migrations/003-who-had-ip.sql
-- Read it with scripts/who-had-ip.ps1 (read-only session).

-- Index for the lookup. Created on the partitioned parent, so PostgreSQL builds it on every
-- partition (including the default one) and on each partition created later.
CREATE INDEX IF NOT EXISTS radacct_framedip_idx ON radacct (FramedIPAddress, AcctStartTime);

-- Sessions that had <ip> at the instant <at>, oldest first.
--
-- All times in radacct are the SERVER's receive time (see README section 5), not the AP clock.
-- The AP clock can be wrong (the DAP-X3060 shows 2024), so the AP's own timestamps would give
-- wrong answers. A lookup time must be on a trusted clock (NIC/NPL time) and is compared with
-- the server time. Sessions are matched on AcctStartTime <= at <= end, where end is:
--   closed      AcctStopTime
--   open        now()                  (last update within <stale_minutes>)
--   stale-open  last update            (open, but silent for more than <stale_minutes>: the AP may
--                                       have lost the Stop. Same rule as reap_stale_sessions(),
--                                       which later closes it with this stop time. A time after the
--                                       last update does NOT match.)
-- A session reaped by the maintenance job is simply "closed" here (cause Stale-Session-Reaped).
--
-- IPv4 only: it matches FramedIPAddress. IPv6 (FramedIPv6Address, FramedIPv6Prefix) is future work.
-- Only devices whose AP sends Framed-IP-Address in accounting packets can be found.
CREATE OR REPLACE FUNCTION who_had_ip(ip inet, at timestamp with time zone, stale_minutes integer DEFAULT 25)
RETURNS TABLE (
	username		text,
	callingstationid	text,
	calledstationid		text,
	nas			text,
	acctsessionid		text,
	acctstarttime		timestamp with time zone,
	effective_stop		timestamp with time zone,
	acctterminatecause	text,
	status			text
) LANGUAGE sql STABLE AS $$
	SELECT s.username, s.callingstationid, s.calledstationid, host(s.nasipaddress), s.acctsessionid,
	       s.acctstarttime, s.effective_stop, s.acctterminatecause, s.status
	FROM (
		SELECT r.*,
		       CASE
		           WHEN r.acctstoptime IS NOT NULL THEN r.acctstoptime
		           WHEN COALESCE(r.acctupdatetime, r.acctstarttime) < now() - make_interval(mins => stale_minutes)
		               THEN COALESCE(r.acctupdatetime, r.acctstarttime)
		           ELSE now()
		       END AS effective_stop,
		       CASE
		           WHEN r.acctstoptime IS NOT NULL THEN 'closed'
		           WHEN COALESCE(r.acctupdatetime, r.acctstarttime) < now() - make_interval(mins => stale_minutes)
		               THEN 'stale-open'
		           ELSE 'open'
		       END AS status
		FROM radacct r
		WHERE r.framedipaddress = ip AND r.acctstarttime <= at
	) s
	WHERE s.effective_stop >= at
	ORDER BY s.acctstarttime, s.acctsessionid;
$$;
