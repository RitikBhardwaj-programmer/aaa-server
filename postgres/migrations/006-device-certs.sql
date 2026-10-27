-- EAP-TLS device certificates (stage S5: portal/pki.py, radius/raddb/sites-available/check-eap-tls).
--
-- device_certs: one row per certificate that the portal issued (Device CA, CN = uid). FreeRADIUS
-- accepts a client certificate only when its serial is here, for the same user, not revoked and
-- not expired. That table lookup is the revocation check: there is no CRL or OCSP service.
-- Never a private key or a passphrase: only the public key's SHA-256 (of SubjectPublicKeyInfo).
--
-- device_cert_seen: which device (Calling-Station-Id) signed in with which certificate, written by
-- FreeRADIUS on every EAP-TLS Access-Accept. The portal uses it to find the certificates of a MAC
-- (pki.certs_for_mac: "Not me" revokes them) and the devices to disconnect when a certificate is
-- revoked. It holds the user's MACs only, like user_devices: no access point, no time of each
-- login (radpostauth keeps those, and the portal still cannot read radpostauth).
--
-- Rights of the role "portal": SELECT and INSERT on device_certs, UPDATE of revoked_at and
-- revoke_reason only, nothing else; SELECT on device_cert_seen. No DELETE. A trigger keeps a
-- revocation final, so not even a compromised portal can bring a revoked certificate back.
-- FreeRADIUS and the maintenance job use the role radius, the owner of both tables.
--
-- Included by initdb/02-schema.sql (after 002-portal-role.sql: the role "portal" must exist).
-- Safe to run again. On an existing database:
--   docker compose exec -T postgres psql -U postgres -d radius -v ON_ERROR_STOP=1 -f /migrations/006-device-certs.sql
-- One transaction: the grants never exist without the trigger, and a failed run changes nothing.

BEGIN;
SET ROLE radius;

CREATE TABLE IF NOT EXISTS device_certs (
	-- Lower-case hex of the serial's bytes, exactly as FreeRADIUS writes TLS-Client-Cert-Serial
	serial			text PRIMARY KEY CHECK (serial ~ '^([0-9a-f]{2}){1,20}$'),
	username		text NOT NULL,
	label			text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 40),
	pubkey_sha256		text NOT NULL CHECK (pubkey_sha256 ~ '^[0-9a-f]{64}$'),
	issued_at		timestamp with time zone NOT NULL DEFAULT now(),
	not_after		timestamp with time zone NOT NULL,
	revoked_at		timestamp with time zone,
	revoke_reason		text CHECK (revoke_reason IN ('user', 'not_me', 'admin')),
	via			text NOT NULL CHECK (via IN ('app', 'web')),
	CHECK (not_after > issued_at),
	CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
	-- Target of the foreign key below: a sign-in row always names the certificate's own user
	UNIQUE (serial, username)
);
-- The user's certificates (list, and the count of active ones under the advisory lock)
CREATE INDEX IF NOT EXISTS device_certs_user_idx ON device_certs (username, issued_at);

CREATE TABLE IF NOT EXISTS device_cert_seen (
	serial			text NOT NULL,
	username		text NOT NULL,
	callingstationid	text NOT NULL,
	first_seen		timestamp with time zone NOT NULL DEFAULT now(),
	last_seen		timestamp with time zone NOT NULL DEFAULT now(),
	PRIMARY KEY (serial, callingstationid),
	FOREIGN KEY (serial, username) REFERENCES device_certs (serial, username) ON DELETE CASCADE
);
-- pki.certs_for_mac: the certificates one device of one user used lately
CREATE INDEX IF NOT EXISTS device_cert_seen_mac_idx ON device_cert_seen (username, callingstationid, last_seen);
-- Maintenance: forget old rows
CREATE INDEX IF NOT EXISTS device_cert_seen_last_seen_idx ON device_cert_seen (last_seen);

-- A revocation is final, and only the revocation columns of a row can change (the column grants
-- say the same for the portal; this holds for every role but a superuser who disables it)
CREATE OR REPLACE FUNCTION device_certs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
	IF OLD.revoked_at IS NOT NULL
	   AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
		RAISE EXCEPTION 'device certificate % is revoked; a revocation cannot be changed', OLD.serial
			USING ERRCODE = 'check_violation';
	END IF;
	IF (NEW.serial, NEW.username, NEW.label, NEW.pubkey_sha256, NEW.issued_at, NEW.not_after, NEW.via)
	   IS DISTINCT FROM (OLD.serial, OLD.username, OLD.label, OLD.pubkey_sha256, OLD.issued_at, OLD.not_after, OLD.via) THEN
		RAISE EXCEPTION 'only revoked_at and revoke_reason of a device certificate can change'
			USING ERRCODE = 'check_violation';
	END IF;
	RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION device_certs_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS device_certs_guard ON device_certs;
CREATE TRIGGER device_certs_guard BEFORE UPDATE ON device_certs
	FOR EACH ROW EXECUTE FUNCTION device_certs_guard();

-- Start from no rights, so a second run also takes back anything granted by hand
REVOKE ALL ON device_certs, device_cert_seen FROM PUBLIC, portal;
GRANT SELECT, INSERT ON device_certs TO portal;
GRANT UPDATE (revoked_at, revoke_reason) ON device_certs TO portal;
GRANT SELECT ON device_cert_seen TO portal;

RESET ROLE;
COMMIT;
