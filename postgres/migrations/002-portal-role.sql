-- Read-only database role for the self-service portal ("portal" service).
-- It may only SELECT from the three tables the "my devices" page shows. It cannot write, cannot
-- see radpostauth, and cannot create objects.
-- This file creates the role WITHOUT a password (a role with no password cannot log in over
-- the network). The password comes from POSTGRES_PORTAL_PASSWORD, because SQL files cannot read
-- environment variables; 002-portal-password.sh sets it.
-- Included by initdb/02-schema.sql (as the postgres superuser); safe to run again. On an existing database:
--   docker compose exec -T postgres psql -U postgres -d radius -v ON_ERROR_STOP=1 -f /migrations/002-portal-role.sql
--   docker compose exec -T postgres sh /migrations/002-portal-password.sh
-- (the postgres container needs POSTGRES_PORTAL_PASSWORD in its environment: docker compose up -d postgres)

DO $$
BEGIN
	IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'portal') THEN
		CREATE ROLE portal LOGIN;
	END IF;
END $$;

GRANT USAGE ON SCHEMA public TO portal;
-- On the partitioned parent: monthly partitions made later need no grant of their own
GRANT SELECT ON radacct, user_devices, device_limit_events TO portal;