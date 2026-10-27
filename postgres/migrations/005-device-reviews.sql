-- Answers to the portal's "new device signed in" alerts (portal/activity.py, POST /api/v1/alerts/{mac}).
-- One row per (user, device): "me" (This was me) or "not_me". A second answer replaces the first.
-- An alert is a user_devices row first seen in the last 30 days with no row here.
--
-- The row belongs to the user_devices row (foreign key, ON DELETE CASCADE): when the maintenance
-- job forgets a device (DEVICE_EXPIRY_DAYS), its review goes too, and a later return of that MAC
-- shows a new alert. A review for a device that the user never used is refused.
--
-- The role "portal" may SELECT and INSERT, and UPDATE only verdict and reviewed_at. It cannot
-- DELETE a review or move it to another user or device.
--
-- Included by initdb/02-schema.sql (after 002-portal-role.sql). Safe to run again. On an existing database:
--   docker compose exec -T postgres psql -U postgres -d radius -v ON_ERROR_STOP=1 -f /migrations/005-device-reviews.sql

SET ROLE radius;

CREATE TABLE IF NOT EXISTS device_reviews (
	username		text NOT NULL,
	callingstationid	text NOT NULL,
	verdict			text NOT NULL CHECK (verdict IN ('me', 'not_me')),
	reviewed_at		timestamp with time zone NOT NULL DEFAULT now(),
	PRIMARY KEY (username, callingstationid),
	FOREIGN KEY (username, callingstationid) REFERENCES user_devices (username, callingstationid) ON DELETE CASCADE
);

-- Start from no rights, so a second run also takes back anything granted by hand
REVOKE ALL ON device_reviews FROM PUBLIC, portal;
GRANT SELECT, INSERT ON device_reviews TO portal;
GRANT UPDATE (verdict, reviewed_at) ON device_reviews TO portal;

RESET ROLE;
