-- Accounting schema for the AAA lab. Based on the FreeRADIUS 3.2.10 PostgreSQL schema, with
-- three changes for a campus of ~30,000 devices:
--   1. radacct and radpostauth are split into monthly partitions, so an old month is dropped
--      in one step and queries touch only small tables (FreeRADIUS issue #5628: trouble from
--      ~2 million rows). The partition key must be part of every unique key, so the primary
--      keys include the time column and AcctUniqueId is indexed but not UNIQUE.
--   2. Extra tables for the 3-device limit: user_devices (every MAC a user was seen with)
--      and device_limit_events (every login that hit the limit).
--   3. Maintenance functions, run every few minutes by the "maintenance" service.
-- Runs once, when the database volume is empty.

SET ROLE radius;

-- Sessions (Start / Interim-Update / Stop). Times are the server's receive time.
CREATE TABLE radacct (
	RadAcctId		bigserial,
	AcctSessionId		text NOT NULL,
	AcctUniqueId		text NOT NULL,
	UserName		text,
	Realm			text,
	NASIPAddress		inet NOT NULL,
	NASPortId		text,
	NASPortType		text,
	AcctStartTime		timestamp with time zone NOT NULL,
	AcctUpdateTime		timestamp with time zone,
	AcctStopTime		timestamp with time zone,
	AcctInterval		bigint,
	AcctSessionTime		bigint,
	AcctAuthentic		text,
	ConnectInfo_start	text,
	ConnectInfo_stop	text,
	AcctInputOctets		bigint,
	AcctOutputOctets	bigint,
	CalledStationId		text,
	CallingStationId	text,
	AcctTerminateCause	text,
	ServiceType		text,
	FramedProtocol		text,
	FramedIPAddress		inet,
	FramedIPv6Address	inet,
	FramedIPv6Prefix	inet,
	FramedInterfaceId	text,
	DelegatedIPv6Prefix	inet,
	Class			text,
	PRIMARY KEY (RadAcctId, AcctStartTime)
) PARTITION BY RANGE (AcctStartTime);

-- Looks up a session by its unique ID (update and stop queries, duplicate check)
CREATE INDEX radacct_uniqueid_idx ON radacct (AcctUniqueId);
CREATE INDEX radacct_active_session_idx ON radacct (AcctUniqueId) WHERE AcctStopTime IS NULL;
-- Accounting-On / Accounting-Off: close every open session of one NAS
CREATE INDEX radacct_bulk_close ON radacct (NASIPAddress, AcctStartTime) WHERE AcctStopTime IS NULL;
-- Device limit: open sessions of one user (the stock schema has no such index)
CREATE INDEX radacct_open_user_idx ON radacct (UserName) WHERE AcctStopTime IS NULL;
-- Stale-session reaper
CREATE INDEX radacct_open_update_idx ON radacct (AcctUpdateTime) WHERE AcctStopTime IS NULL;
CREATE INDEX radacct_start_user_idx ON radacct (AcctStartTime, UserName);
CREATE INDEX radacct_class_idx ON radacct (Class);

-- Rows whose start time has no monthly partition (for example a clock far in the past)
CREATE TABLE radacct_default PARTITION OF radacct DEFAULT;

-- Duplicate-safe inserts (radacct_claims); the file is mounted at /migrations by docker-compose.yml
\i /migrations/001-session-claims.sql

-- Login attempts (Access-Accept / Access-Reject). The password is never stored.
CREATE TABLE radpostauth (
	id			bigserial,
	username		text NOT NULL,
	reply			text,
	CalledStationId		text,
	CallingStationId	text,
	authdate		timestamp with time zone NOT NULL DEFAULT now(),
	Class			text,
	PRIMARY KEY (id, authdate)
) PARTITION BY RANGE (authdate);

CREATE INDEX radpostauth_username_idx ON radpostauth (username, authdate);
-- Reject rate limit: recent rejects of one user from one device
CREATE INDEX radpostauth_reject_idx ON radpostauth (username, CallingStationId, authdate) WHERE reply = 'Access-Reject';
CREATE INDEX radpostauth_class_idx ON radpostauth (Class);

CREATE TABLE radpostauth_default PARTITION OF radpostauth DEFAULT;

-- Every device (MAC) each user was seen with, for the "my devices" page and abuse cases.
-- Information only: the limit itself counts live sessions in radacct.
CREATE TABLE user_devices (
	username		text NOT NULL,
	callingstationid	text NOT NULL,
	first_seen		timestamp with time zone NOT NULL,
	last_seen		timestamp with time zone NOT NULL,
	PRIMARY KEY (username, callingstationid)
);
CREATE INDEX user_devices_last_seen_idx ON user_devices (last_seen);

-- Every login that found the user already at the device limit (soft mode logs, enforce mode rejects)
CREATE TABLE device_limit_events (
	id			bigserial PRIMARY KEY,
	eventtime		timestamp with time zone NOT NULL DEFAULT now(),
	username		text NOT NULL,
	callingstationid	text,
	live_devices		integer NOT NULL,
	device_limit		integer NOT NULL,
	mode			text NOT NULL
);
CREATE INDEX device_limit_events_user_idx ON device_limit_events (username, eventtime);

-- Keeps user_devices current from accounting: one row per (user, MAC)
CREATE FUNCTION user_devices_touch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF NEW.UserName IS NOT NULL AND NEW.UserName <> '' AND NEW.CallingStationId IS NOT NULL AND NEW.CallingStationId <> '' THEN
		INSERT INTO user_devices (username, callingstationid, first_seen, last_seen)
		VALUES (NEW.UserName, NEW.CallingStationId, NEW.AcctStartTime, COALESCE(NEW.AcctUpdateTime, NEW.AcctStartTime))
		ON CONFLICT (username, callingstationid)
		DO UPDATE SET last_seen = GREATEST(user_devices.last_seen, EXCLUDED.last_seen);
	END IF;
	RETURN NULL;
END $$;

CREATE TRIGGER radacct_user_devices
	AFTER INSERT OR UPDATE OF AcctUpdateTime ON radacct
	FOR EACH ROW EXECUTE FUNCTION user_devices_touch();

-- Creates the monthly partitions of <parent> from this month to <months_ahead> months ahead.
-- Partitions are created ahead of time so that rows never pile up in the default partition.
CREATE FUNCTION ensure_monthly_partitions(parent text, months_ahead integer DEFAULT 3)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
	m date;
BEGIN
	FOR i IN 0..months_ahead LOOP
		m := (date_trunc('month', now()) + make_interval(months => i))::date;
		EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
			parent || '_' || to_char(m, 'YYYY_MM'), parent, m, (m + interval '1 month')::date);
	END LOOP;
END $$;

-- Drops monthly partitions of <parent> that ended more than <keep_months> months ago.
-- Returns the number of partitions dropped.
CREATE FUNCTION drop_old_partitions(parent text, keep_months integer DEFAULT 12)
RETURNS integer LANGUAGE plpgsql AS $$
DECLARE
	part record;
	cutoff text := parent || '_' || to_char(date_trunc('month', now()) - make_interval(months => keep_months), 'YYYY_MM');
	dropped integer := 0;
BEGIN
	FOR part IN
		SELECT c.relname FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = parent AND c.relname ~ ('^' || parent || '_[0-9]{4}_[0-9]{2}$')
	LOOP
		-- Names sort by date (YYYY_MM), so a plain string compare finds the old ones
		IF part.relname < cutoff THEN
			EXECUTE format('DROP TABLE %I', part.relname);
			dropped := dropped + 1;
		END IF;
	END LOOP;
	RETURN dropped;
END $$;

-- Closes open sessions with no accounting packet for <stale_minutes> (lost Stop, AP crash).
-- The stop time is the last packet seen, not "now", so session length stays honest.
-- Returns the number of sessions closed.
CREATE FUNCTION reap_stale_sessions(stale_minutes integer)
RETURNS integer LANGUAGE plpgsql AS $$
DECLARE
	closed integer;
BEGIN
	UPDATE radacct
	SET AcctStopTime = COALESCE(AcctUpdateTime, AcctStartTime),
	    AcctSessionTime = EXTRACT(EPOCH FROM (COALESCE(AcctUpdateTime, AcctStartTime) - AcctStartTime))::bigint,
	    AcctTerminateCause = 'Stale-Session-Reaped'
	WHERE AcctStopTime IS NULL
	  AND COALESCE(AcctUpdateTime, AcctStartTime) < now() - make_interval(mins => stale_minutes);
	GET DIAGNOSTICS closed = ROW_COUNT;
	RETURN closed;
END $$;

SELECT ensure_monthly_partitions('radacct');
SELECT ensure_monthly_partitions('radpostauth');

-- "Who had this IP at this time?" lookup (index + who_had_ip function)
\i /migrations/003-who-had-ip.sql

RESET ROLE;

-- Read-only role for the self-service portal; needs the superuser, so it comes after RESET ROLE
\i /migrations/002-portal-role.sql

-- Portal sign-in history (function portal_signins) and alert reviews (table device_reviews).
-- Both need the role "portal"; each file makes its objects as role radius (SET ROLE in the file).
\i /migrations/004-portal-signins.sql
\i /migrations/005-device-reviews.sql
-- EAP-TLS device certificates (portal/pki.py) and the devices that used them (FreeRADIUS
-- check-eap-tls). Needs the role "portal"; makes its objects as role radius (SET ROLE in the file).
\i /migrations/006-device-certs.sql
