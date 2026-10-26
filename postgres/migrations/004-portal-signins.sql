-- Sign-in history for the self-service portal ("Sign-in activity" page, GET /api/v1/activity).
-- The role "portal" must not read radpostauth: it holds every user's logins, access points and
-- Class values. This SECURITY DEFINER function gives the portal four columns of one user's rows,
-- for at most 30 days and at most 100 rows. It never returns Class, id or any other column.
-- The portal calls it with the uid of the logged-in user only (portal/activity.py).
--
-- Included by initdb/02-schema.sql (after 002-portal-role.sql: the role "portal" must exist).
-- Safe to run again. On an existing database:
--   docker compose exec -T postgres psql -U postgres -d radius -v ON_ERROR_STOP=1 -f /migrations/004-portal-signins.sql
-- The objects are made as role radius (SET ROLE below), so the function runs with the rights of
-- radius, the owner of radpostauth, and never with superuser rights.

SET ROLE radius;

-- search_path is pinned, so a caller cannot put its own "radpostauth" or operators earlier in the
-- path. p_days is clamped to 1..30 and p_limit to 1..100; NULL gives 7 days and 100 rows.
CREATE OR REPLACE FUNCTION portal_signins(p_user text, p_days integer, p_limit integer)
RETURNS TABLE (
	authdate		timestamp with time zone,
	reply			text,
	calledstationid		text,
	callingstationid	text
) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
	SELECT r.authdate, r.reply, r.calledstationid, r.callingstationid
	FROM public.radpostauth r
	WHERE r.username = p_user
	  AND r.authdate > now() - make_interval(days => LEAST(GREATEST(COALESCE(p_days, 7), 1), 30))
	ORDER BY r.authdate DESC
	LIMIT LEAST(GREATEST(COALESCE(p_limit, 100), 1), 100);
$$;

-- A new function is executable by PUBLIC: take that away, then give it to the portal only
REVOKE ALL ON FUNCTION portal_signins(text, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION portal_signins(text, integer, integer) TO portal;

RESET ROLE;
