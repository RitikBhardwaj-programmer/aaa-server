"""Live tests of the device certificates (pki.py, migration 006) against the live LDAP and PostgreSQL.

Run by scripts/test.ps1 in the portal-test container, with the temporary user of test_portal.py.
Only what the unit tests (tests/unit/test_pki.py, mocks) cannot cover: the real SQL, the real
advisory lock under parallel requests, the grants of the role "portal", the trigger that keeps a
revocation final, and the API and web flows with a real login.

The certificates are signed by a throwaway Device CA made here (the real one is only needed by
FreeRADIUS: tests/run-tests.sh covers EAP-TLS end to end). Test rows are deleted as role "radius".
"""
import base64
import os
import re
import secrets
import shutil
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import psycopg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

import app as portal     # first: app loads pki.py (register_features), which imports app
import pki

from tests.test_portal import PASSWORD, TEST_NAS, UID, login, radius_db, token

OTHER_UID = "pki-other-" + secrets.token_hex(3)
MY_MAC, OTHER_MAC = "DE-AD-BE-EF-20-01", "DE-AD-BE-EF-20-02"


def make_ca(name, issuer=None, issuer_key=None, path_length=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject if issuer else subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .sign(issuer_key or key, hashes.SHA256()))
    return cert, key


def new_public_key():
    return ec.generate_private_key(ec.SECP256R1()).public_key()


def csr_pem(cn="someone-else"):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])).sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def clean():
    with radius_db() as conn:
        # device_cert_seen goes with its certificate (ON DELETE CASCADE)
        conn.execute("DELETE FROM device_certs WHERE username = ANY(%s)", ([UID, OTHER_UID],))
        conn.execute("DELETE FROM radacct WHERE username = ANY(%s)", ([UID, OTHER_UID],))


def portal_rows(sql, params=()):
    with portal.db() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def radius_rows(sql, params=()):
    with radius_db() as conn:
        cur = conn.execute(sql, params)
        return cur.fetchall() if cur.description else None


class PkiLiveCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root, root_key = make_ca("Live Test Root CA")
        ca, ca_key = make_ca("Live Test Device CA", root, root_key, path_length=0)
        cls.ca = ca
        cls.dir = tempfile.mkdtemp()
        files = {"ca.pem": root.public_bytes(serialization.Encoding.PEM),
                 "device-ca.pem": ca.public_bytes(serialization.Encoding.PEM),
                 "device-ca.key": ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption())}
        for name, data in files.items():
            with open(os.path.join(cls.dir, name), "wb") as f:
                f.write(data)
        clean()

    @classmethod
    def tearDownClass(cls):
        clean()
        shutil.rmtree(cls.dir)

    def setUp(self):
        for limiter in portal.LIMITERS + (pki.ISSUES,):
            limiter.reset()
        for name, file in (("CA_CERT_FILE", "device-ca.pem"), ("CA_KEY_FILE", "device-ca.key"),
                           ("ROOT_CA_FILE", "ca.pem")):
            p = mock.patch.object(pki, name, os.path.join(self.dir, file))
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(pki, "WEB_KEY_BITS", 2048)
        p.start()
        self.addCleanup(p.stop)
        clean()

    def add_cert(self, user=UID, revoked=False, expired=False):
        serial = pki.serial_hex(pki.new_serial())
        radius_rows("""INSERT INTO device_certs (serial, username, label, pubkey_sha256, issued_at, not_after,
                                                 revoked_at, revoke_reason, via)
                       VALUES (%s, %s, 'test', repeat('a', 64), now() - interval '400 days',
                               now() + CASE WHEN %s THEN interval '-1 day' ELSE interval '300 days' END,
                               CASE WHEN %s THEN now() END, CASE WHEN %s THEN 'admin' END, 'app')""",
                    (serial, user, expired, revoked, revoked))
        return serial


class PkiDatabaseTests(PkiLiveCase):
    """The SQL of pki.py as role portal, and what that role may not do."""

    def test_parallel_issues_stop_at_three(self):
        results = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            try:
                pki.issue_core(UID, "parallel", "app", new_public_key())
                results.append("ok")
            except pki.CertLimit:
                results.append("limit")

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), ["limit"] * 5 + ["ok"] * 3)
        self.assertEqual(radius_rows("SELECT count(*) FROM device_certs WHERE username = %s", (UID,))[0][0], 3)

    def test_revoked_and_expired_do_not_count_and_others_are_apart(self):
        self.add_cert(revoked=True)
        self.add_cert(expired=True)
        for _ in range(3):
            self.add_cert(user=OTHER_UID)
        for _ in range(3):
            pki.issue_core(UID, "phone", "app", new_public_key())
        with self.assertRaises(pki.CertLimit):
            pki.issue_core(UID, "phone", "app", new_public_key())
        listed = pki.list_core(UID)
        self.assertEqual([c["active"] for c in listed].count(True), 3)
        self.assertEqual(len(listed), 5)
        self.assertTrue(all(c["issued_at"].tzinfo for c in listed))

    def test_revoke_is_idempotent_and_owned(self):
        mine, theirs = self.add_cert(), self.add_cert(user=OTHER_UID)
        first = pki.revoke_core(UID, mine, "user")
        second = pki.revoke_core(UID, mine, "not_me")
        self.assertEqual(first["revoked_at"], second["revoked_at"])
        self.assertEqual(radius_rows("SELECT revoke_reason FROM device_certs WHERE serial = %s", (mine,))[0][0], "user")
        with self.assertRaises(portal.NotFound):
            pki.revoke_core(UID, theirs, "user")
        self.assertIsNone(radius_rows("SELECT revoked_at FROM device_certs WHERE serial = %s", (theirs,))[0][0])

    def test_certs_for_mac(self):
        recent, revoked, old = self.add_cert(), self.add_cert(revoked=True), self.add_cert()
        theirs = self.add_cert(user=OTHER_UID)
        radius_rows("""INSERT INTO device_cert_seen (serial, username, callingstationid, first_seen, last_seen)
                       VALUES (%s, %s, %s, now(), now()), (%s, %s, %s, now(), now()),
                              (%s, %s, %s, now() - interval '40 days', now() - interval '31 days'),
                              (%s, %s, %s, now(), now())""",
                    (recent, UID, MY_MAC, revoked, UID, MY_MAC, old, UID, MY_MAC, theirs, OTHER_UID, MY_MAC))
        self.assertEqual(pki.certs_for_mac(UID, MY_MAC), [recent])
        self.assertEqual(pki.certs_for_mac(UID, OTHER_MAC), [])
        self.assertEqual(pki.certs_for_mac(OTHER_UID, MY_MAC), [theirs])

    def test_seen_row_must_name_the_certificates_own_user(self):
        mine = self.add_cert()
        with self.assertRaises(psycopg.errors.ForeignKeyViolation):
            radius_rows("INSERT INTO device_cert_seen (serial, username, callingstationid) VALUES (%s, %s, %s)",
                        (mine, OTHER_UID, MY_MAC))

    def test_freeradius_record_query_ignores_unknown_serials(self):
        # The INSERT ... SELECT of sites-available/default: no row, and no error, for a serial not in device_certs
        mine = self.add_cert()
        sql = """INSERT INTO device_cert_seen (serial, username, callingstationid)
                 SELECT serial, username, %s FROM device_certs WHERE serial = %s AND username = %s
                 ON CONFLICT (serial, callingstationid) DO UPDATE SET last_seen = now()"""
        with radius_db() as conn:
            self.assertEqual(conn.execute(sql, (MY_MAC, "ab" * 20, UID)).rowcount, 0)
            self.assertEqual(conn.execute(sql, (MY_MAC, mine, OTHER_UID)).rowcount, 0)
            self.assertEqual(conn.execute(sql, (MY_MAC, mine, UID)).rowcount, 1)
            self.assertEqual(conn.execute(sql, (MY_MAC, mine, UID)).rowcount, 1)     # second login: update
        self.assertEqual(radius_rows("SELECT count(*) FROM device_cert_seen WHERE serial = %s", (mine,))[0][0], 1)

    def test_portal_role_limits(self):
        mine = self.add_cert()
        refused = psycopg.errors.InsufficientPrivilege
        for sql, params in (("DELETE FROM device_certs WHERE serial = %s", (mine,)),
                            ("UPDATE device_certs SET username = %s WHERE serial = %s", (OTHER_UID, mine)),
                            ("UPDATE device_certs SET not_after = now() + interval '10 years' WHERE serial = %s", (mine,)),
                            ("INSERT INTO device_cert_seen (serial, username, callingstationid) VALUES (%s, %s, %s)",
                             (mine, UID, MY_MAC)),
                            ("DELETE FROM device_cert_seen", ()),
                            ("SELECT count(*) FROM radpostauth", ())):
            with self.subTest(sql=sql):
                with self.assertRaises(refused):
                    portal_rows(sql, params)
        # A revocation is final, even for the columns the portal may write
        portal_rows("UPDATE device_certs SET revoked_at = now(), revoke_reason = 'user' WHERE serial = %s", (mine,))
        with self.assertRaises(psycopg.errors.CheckViolation):
            portal_rows("UPDATE device_certs SET revoked_at = NULL, revoke_reason = NULL WHERE serial = %s", (mine,))
        with self.assertRaises(psycopg.errors.CheckViolation):
            radius_rows("UPDATE device_certs SET revoked_at = NULL, revoke_reason = NULL WHERE serial = %s", (mine,))

    def test_lock_waits_for_the_other_transaction(self):
        # A second transaction of the same user waits on the advisory lock until the first one ends
        with portal.db() as first, first.transaction():
            first.execute("SELECT pg_advisory_xact_lock(%s, hashtext(%s))", (pki.LOCK_NAMESPACE, UID))
            with portal.db() as second:
                got = second.execute("SELECT pg_try_advisory_xact_lock(%s, hashtext(%s))",
                                     (pki.LOCK_NAMESPACE, UID)).fetchone()
                self.assertFalse(list(got.values())[0])
                other = second.execute("SELECT pg_try_advisory_xact_lock(%s, hashtext(%s))",
                                       (pki.LOCK_NAMESPACE, OTHER_UID)).fetchone()
                self.assertTrue(list(other.values())[0])


class PkiApiTests(PkiLiveCase):
    """The API with a real login token."""

    def setUp(self):
        super().setUp()
        self.client = portal.app.test_client()
        resp = self.client.post("/api/v1/auth/token", json={"uid": UID, "password": PASSWORD})
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.headers = {"Authorization": "Bearer " + resp.get_json()["access_token"]}

    def test_issue_list_revoke(self):
        resp = self.client.post("/api/v1/certs", json={"csr_pem": csr_pem(), "label": "Live phone"}, headers=self.headers)
        self.assertEqual(resp.status_code, 201, resp.get_data(as_text=True))
        body = resp.get_json()
        cert = x509.load_pem_x509_certificate(body["cert_pem"].encode())
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, UID)
        cert.verify_directly_issued_by(self.ca)
        row = radius_rows("SELECT username, via, label FROM device_certs WHERE serial = %s", (body["serial"],))
        self.assertEqual(row, [(UID, "app", "Live phone")])
        other = self.add_cert(user=OTHER_UID)
        listed = self.client.get("/api/v1/certs", headers=self.headers).get_json()
        self.assertEqual([c["serial"] for c in listed["certs"]], [body["serial"]])
        self.assertIsNotNone(datetime.fromisoformat(listed["certs"][0]["issued_at"]).tzinfo)
        # Another user's serial: 404, and it stays active
        resp = self.client.delete("/api/v1/certs/" + other, headers=self.headers)
        self.assertEqual(resp.status_code, 404)
        self.assertIsNone(radius_rows("SELECT revoked_at FROM device_certs WHERE serial = %s", (other,))[0][0])
        first = self.client.delete("/api/v1/certs/" + body["serial"], headers=self.headers)
        second = self.client.delete("/api/v1/certs/" + body["serial"], headers=self.headers)
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertEqual(first.get_json()["revoked_at"], second.get_json()["revoked_at"])

    def test_fourth_certificate_is_409(self):
        for _ in range(3):
            self.add_cert()
        resp = self.client.post("/api/v1/certs", json={"csr_pem": csr_pem(), "label": "One more"}, headers=self.headers)
        self.assertEqual((resp.status_code, resp.get_json()["error"]["code"]), (409, "cert_limit"))

    def test_revoke_disconnects_the_device_that_used_the_cert(self):
        serial = self.add_cert()
        with radius_db() as conn:
            conn.execute("INSERT INTO device_cert_seen (serial, username, callingstationid) VALUES (%s, %s, %s)",
                         (serial, UID, MY_MAC))
            for mac in (MY_MAC, OTHER_MAC):
                conn.execute("""INSERT INTO radacct (acctsessionid, acctuniqueid, username, nasipaddress, acctstarttime,
                                                     acctupdatetime, callingstationid)
                                VALUES (%s, %s, %s, %s, now(), now(), %s)""",
                             (secrets.token_hex(4), secrets.token_hex(8), UID, TEST_NAS, mac))
        resp = self.client.delete("/api/v1/certs/" + serial, headers=self.headers)
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        # One Disconnect-Request, for the device that used the certificate; nothing answers at the test NAS
        self.assertEqual(resp.get_json()["disconnect"], [{"nas": TEST_NAS, "result": "none"}])


class PkiWebTests(PkiLiveCase):
    def test_pkcs12_download(self):
        client = portal.app.test_client()
        self.assertEqual(login(client, UID, PASSWORD).status_code, 302)
        resp = client.post("/certs/new", data={"csrf_token": token(client, "/certs"), "label": "Live laptop"})
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        passphrase = re.search(r'class="passphrase"><code>([^<]+)</code>', html).group(1)
        blob = base64.b64decode(re.search(r'base64,([^"]+)"', html).group(1))
        key, cert, _ = pkcs12.load_key_and_certificates(blob, passphrase.encode())
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, UID)
        row = radius_rows("SELECT via, serial FROM device_certs WHERE username = %s", (UID,))
        self.assertEqual(row, [("web", format(cert.serial_number, "040x"))])
        # Nothing of the passphrase in the database
        dump = repr(radius_rows("SELECT * FROM device_certs WHERE username = %s", (UID,)))
        self.assertNotIn(passphrase, dump)
        self.assertNotIn(passphrase.replace("-", ""), dump)
