-- Duplicate-safe session inserts for the partitioned radacct table.
-- A partitioned table cannot have a UNIQUE key on AcctUniqueId alone, and "INSERT ... WHERE
-- NOT EXISTS" lets two concurrent inserts (for example two RADIUS servers spooling the same
-- session) both succeed. This small unpartitioned table holds one row per session ID; every
-- radacct insert must first claim the ID here. The claim and the insert run in one statement,
-- so a failed insert also undoes the claim.
-- Included by initdb/02-schema.sql; safe to run again on an existing database:
--   docker compose exec -T postgres psql -U radius -d radius < postgres/migrations/001-session-claims.sql

CREATE TABLE IF NOT EXISTS radacct_claims (
	AcctUniqueId		text PRIMARY KEY,
	AcctStartTime		timestamp with time zone NOT NULL
);
CREATE INDEX IF NOT EXISTS radacct_claims_start_idx ON radacct_claims (AcctStartTime);

-- Returns true for exactly one caller per session ID. A second caller waits until the first
-- commits, then gets false (ON CONFLICT DO NOTHING).
CREATE OR REPLACE FUNCTION radacct_claim(unique_id text, start_time timestamp with time zone)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
	INSERT INTO radacct_claims (AcctUniqueId, AcctStartTime) VALUES (unique_id, start_time)
	ON CONFLICT (AcctUniqueId) DO NOTHING;
	RETURN FOUND;
END $$;

-- Sessions that existed before this table: claim them too
INSERT INTO radacct_claims (AcctUniqueId, AcctStartTime)
SELECT AcctUniqueId, min(AcctStartTime) FROM radacct GROUP BY AcctUniqueId
ON CONFLICT (AcctUniqueId) DO NOTHING;
