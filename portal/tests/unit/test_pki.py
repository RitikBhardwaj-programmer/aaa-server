"""Device certificates (pki.py, docs/api/v1.md section 6), with mocks only.

A throwaway root CA and Device CA are made in the test (certs/ is not in git). The database is an
in-memory fake that understands the few statements of pki.py, including the per-user advisory lock,
so the limit of 3 is also tested with parallel requests.
"""
import base64
import hashlib
import logging
import os
import re
import shutil
import tempfile
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import app as portal
import pki

from .helpers import MAC, PASSWORD, UID, CoreCase, csrf_token, live_row

OTHER_UID = "student077"
OTHER_MAC = "DE-AD-BE-EF-00-09"


# ---- Throwaway CA ---------------------------------------------------------------------------------

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


def pem_of(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def make_csr(key=None, cn="evil-name", sign_key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Someone Else")])
    builder = (x509.CertificateSigningRequestBuilder().subject_name(subject)
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True))
    return builder.sign(sign_key or key, hashes.SHA256()), key


def csr_pem(csr):
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


# ---- In-memory database ---------------------------------------------------------------------------

class PkiDb:
    """device_certs, device_cert_seen and the live sessions of radacct, in memory.
    use_lock=False ignores pg_advisory_xact_lock (to show that the race exists without it);
    delay widens the gap between the count and the INSERT."""

    def __init__(self):
        self.certs, self.seen, self.live = [], [], defaultdict(list)
        self.locks = defaultdict(threading.Lock)
        self.use_lock, self.delay = True, 0.0
        self.statements = []
        self.mutex = threading.Lock()

    def now(self):
        return datetime.now(timezone.utc)

    def active(self, row):
        return row["revoked_at"] is None and row["not_after"] > self.now()


class PkiCursor:
    def __init__(self, conn):
        self.conn, self.db, self.result = conn, conn.db, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def fetchall(self):
        return self.result

    def execute(self, sql, params=()):
        db, sql1 = self.db, " ".join(sql.split())
        db.statements.append((sql1, params))
        if sql1.startswith("SELECT pg_advisory_xact_lock"):
            assert self.conn.in_tx, "the advisory lock must be taken inside the transaction"
            if db.use_lock:
                lock = db.locks[params]
                lock.acquire()
                self.conn.held.append(lock)
            self.result = [{"pg_advisory_xact_lock": ""}]
        elif sql1.startswith("SELECT count(*) AS active FROM device_certs"):
            with db.mutex:
                self.result = [{"active": sum(1 for r in db.certs if r["username"] == params[0] and db.active(r))}]
            time.sleep(db.delay)
        elif sql1.startswith("INSERT INTO device_certs"):
            serial, user, label, pub, issued, not_after, via = params
            row = {"serial": serial, "username": user, "label": label, "pubkey_sha256": pub, "issued_at": issued,
                   "not_after": not_after, "revoked_at": None, "revoke_reason": None, "via": via}
            with db.mutex:
                assert all(r["serial"] != serial for r in db.certs)
                self.conn.pending.append(row)
            self.result = [{k: row[k] for k in ("serial", "label", "issued_at", "not_after", "revoked_at",
                                                 "revoke_reason", "via")}]
        elif sql1.startswith("SELECT serial, label, issued_at"):
            rows = sorted((r for r in db.certs if r["username"] == params[0]), key=lambda r: r["issued_at"],
                          reverse=True)
            self.result = [{**{k: r[k] for k in ("serial", "label", "issued_at", "not_after", "revoked_at",
                                                 "revoke_reason", "via")}, "active": db.active(r)} for r in rows]
        elif sql1.startswith("UPDATE device_certs SET revoked_at") and len(params) == 2:   # revoke_all_core
            reason, user = params
            self.result = []
            for r in db.certs:
                if r["username"] == user and db.active(r):
                    r["revoked_at"], r["revoke_reason"] = db.now(), reason
                    self.result.append({"serial": r["serial"]})
        elif sql1.startswith("SELECT DISTINCT callingstationid FROM device_cert_seen"):
            serials, user, days = params
            self.result = [{"callingstationid": m} for m in sorted({
                s["mac"] for s in db.seen if s["serial"] in serials and s["username"] == user
                and s["last_seen"] > db.now() - timedelta(days=days)})]
        elif sql1.startswith("UPDATE device_certs SET revoked_at"):
            reason, serial, user = params
            self.result = []
            for r in db.certs:
                if r["serial"] == serial and r["username"] == user and r["revoked_at"] is None:
                    r["revoked_at"], r["revoke_reason"] = db.now(), reason
                    self.result = [{"revoked_at": r["revoked_at"]}]
        elif sql1.startswith("SELECT revoked_at FROM device_certs"):
            self.result = [{"revoked_at": r["revoked_at"]} for r in db.certs
                           if r["serial"] == params[0] and r["username"] == params[1]]
        elif sql1.startswith("SELECT callingstationid FROM device_cert_seen"):
            serial, user, days = params
            self.result = [{"callingstationid": s["mac"]} for s in db.seen
                           if s["serial"] == serial and s["username"] == user
                           and s["last_seen"] > db.now() - timedelta(days=days)]
        elif sql1.startswith("SELECT c.serial FROM device_cert_seen"):
            user, mac, days = params
            certs = {r["serial"]: r for r in db.certs}
            self.result = [{"serial": s["serial"]} for s in db.seen
                           if s["username"] == user and s["mac"] == mac
                           and s["last_seen"] > db.now() - timedelta(days=days)
                           and db.active(certs[s["serial"]]) and certs[s["serial"]]["username"] == user]
        elif "FROM radacct" in sql1:
            self.result = list(db.live[params[0]])
        else:
            raise AssertionError("unexpected SQL: " + sql1)


class PkiConnection:
    def __init__(self, db):
        self.db, self.in_tx, self.held, self.pending = db, False, [], []

    def cursor(self):
        return PkiCursor(self)

    @contextmanager
    def transaction(self):
        self.in_tx = True
        self.db.statements.append(("BEGIN", None))
        try:
            yield
            with self.db.mutex:
                self.db.certs.extend(self.pending)
            self.db.statements.append(("COMMIT", None))
        except BaseException:
            self.db.statements.append(("ROLLBACK", None))
            raise
        finally:
            self.pending = []
            self.in_tx = False
            while self.held:
                self.held.pop().release()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if not self.in_tx:
            with self.db.mutex:              # autocommit: a write outside a transaction stays
                self.db.certs.extend(self.pending)
            self.pending = []
        return False


# ---- Test base ------------------------------------------------------------------------------------

class PkiCase(CoreCase):
    @classmethod
    def setUpClass(cls):
        cls.root, cls.root_key = make_ca("Test Root CA")
        cls.ca, cls.ca_key = make_ca("Test Device CA", cls.root, cls.root_key, path_length=0)
        cls.dir = tempfile.mkdtemp()
        files = {"ca.pem": pem_of(cls.root), "device-ca.pem": pem_of(cls.ca),
                 "device-ca.key": cls.ca_key.private_bytes(serialization.Encoding.PEM,
                                                           serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption())}
        for name, data in files.items():
            with open(os.path.join(cls.dir, name), "wb") as f:
                f.write(data)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def setUp(self):
        self.pdb = PkiDb()
        super().setUp()
        pki.ISSUES.reset()
        for name, file in (("CA_CERT_FILE", "device-ca.pem"), ("CA_KEY_FILE", "device-ca.key"),
                           ("ROOT_CA_FILE", "ca.pem")):
            p = mock.patch.object(pki, name, os.path.join(self.dir, file))
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(pki, "WEB_KEY_BITS", 2048)       # faster; the size is not under test
        p.start()
        self.addCleanup(p.stop)
        self.token = self.api_token()

    def fake_db(self):
        if self.db_error:
            raise portal.psycopg.OperationalError("down")
        return PkiConnection(self.pdb)

    def add_cert(self, user=UID, serial=None, revoked=False, expired=False, via="app", label="Old phone"):
        now = datetime.now(timezone.utc)
        row = {"serial": serial or pki.serial_hex(pki.new_serial()), "username": user, "label": label,
               "pubkey_sha256": "a" * 64, "issued_at": now - timedelta(days=400 if expired else 1),
               "not_after": now - timedelta(days=35) if expired else now + timedelta(days=300),
               "revoked_at": now - timedelta(hours=1) if revoked else None,
               "revoke_reason": "user" if revoked else None, "via": via}
        self.pdb.certs.append(row)
        return row["serial"]

    def issue(self, csr=None, label="Pixel 8", token=None):
        if csr is None:
            csr, _ = make_csr()
        body = {"csr_pem": csr if isinstance(csr, str) else csr_pem(csr), "label": label}
        return self.client.post("/api/v1/certs", json=body, headers=self.bearer(token or self.token))

    def assertError(self, resp, status, code):
        self.assertEqual(resp.status_code, status, resp.get_data(as_text=True))
        body = resp.get_json()
        self.assertEqual(set(body), {"error"})
        self.assertEqual(body["error"]["code"], code)


# ---- Tests ----------------------------------------------------------------------------------------

class AuthTests(PkiCase):
    ROUTES = (("POST", "/api/v1/certs"), ("GET", "/api/v1/certs"), ("DELETE", "/api/v1/certs/" + "ab" * 20))

    def call(self, method, path, headers):
        if method == "POST":
            return self.client.post(path, json={"csr_pem": csr_pem(make_csr()[0]), "label": "x"}, headers=headers)
        return self.client.open(path, method=method, headers=headers)

    def test_every_route_needs_a_token(self):
        for method, path in self.ROUTES:
            for headers in ({}, self.bearer("junk")):
                with self.subTest(method=method, headers=headers):
                    resp = self.call(method, path, headers)
                    self.assertError(resp, 401, "unauthorized")
                    self.assertIn("Bearer", resp.headers["WWW-Authenticate"])
        self.assertEqual(self.pdb.statements, [])

    def test_web_session_cookie_alone_is_refused(self):
        self.web_login()
        for method, path in self.ROUTES:
            with self.subTest(method=method):
                self.assertError(self.call(method, path, {}), 401, "unauthorized")
        self.assertEqual(self.pdb.statements, [])

    def test_issue_needs_a_json_content_type(self):
        resp = self.client.post("/api/v1/certs", data={"csr_pem": "x", "label": "y"}, headers=self.bearer(self.token))
        self.assertError(resp, 415, "unsupported_media_type")

    def test_web_pages_need_a_login(self):
        self.assertEqual(self.client.get("/certs").status_code, 302)
        self.assertEqual(self.pdb.statements, [])


class IssueTests(PkiCase):
    def test_issue_ignores_the_csr_subject_and_extensions(self):
        csr, key = make_csr(cn="admin")
        resp = self.issue(csr)
        self.assertEqual(resp.status_code, 201, resp.get_data(as_text=True))
        body = resp.get_json()
        self.assertEqual(set(body), {"serial", "label", "issued_at", "not_after", "cert_pem", "chain_pem"})
        cert = x509.load_pem_x509_certificate(body["cert_pem"].encode())
        self.assertEqual(cert.subject, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, UID)]))
        self.assertEqual(cert.issuer, self.ca.subject)
        cert.verify_directly_issued_by(self.ca)
        self.assertEqual(cert.public_key().public_numbers(), key.public_key().public_numbers())
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
                         [ExtendedKeyUsageOID.CLIENT_AUTH])
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(usage.critical)
        self.assertTrue(usage.value.digital_signature)
        self.assertFalse(usage.value.key_cert_sign)
        self.assertEqual(cert.not_valid_after_utc - cert.not_valid_before_utc, timedelta(days=365))
        self.assertLess(abs(cert.not_valid_before_utc - datetime.now(timezone.utc)), timedelta(minutes=1))
        # Serial: 40 lower-case hex digits, the form of TLS-Client-Cert-Serial in FreeRADIUS
        self.assertRegex(body["serial"], r"^[0-9a-f]{40}$")
        self.assertEqual(int(body["serial"], 16), cert.serial_number)
        self.assertEqual(cert.serial_number.to_bytes(20, "big").hex(), body["serial"])
        self.assertEqual(body["chain_pem"], (pem_of(self.ca) + pem_of(self.root)).decode())
        self.assertEqual(body["label"], "Pixel 8")
        row = self.pdb.certs[0]
        spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual((row["username"], row["via"], row["pubkey_sha256"]),
                         (UID, "app", hashlib.sha256(spki).hexdigest()))

    def test_strong_keys_are_accepted(self):
        for key in (rsa.generate_private_key(public_exponent=65537, key_size=2048),
                    ec.generate_private_key(ec.SECP384R1())):
            with self.subTest(key=type(key).__name__):
                pki.ISSUES.reset()
                self.pdb.certs.clear()
                self.assertEqual(self.issue(make_csr(key)[0]).status_code, 201)

    def test_weak_or_unknown_keys_are_refused(self):
        for key in (rsa.generate_private_key(public_exponent=65537, key_size=1024),
                    rsa.generate_private_key(public_exponent=3, key_size=2048),
                    ec.generate_private_key(ec.SECP521R1()),
                    ec.generate_private_key(ec.SECP256K1()),
                    ed25519.Ed25519PrivateKey.generate()):
            with self.subTest(key=key):
                csr = (x509.CertificateSigningRequestBuilder()
                       .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
                       .sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()))
                self.assertError(self.issue(csr), 400, "bad_csr")
        self.assertEqual(self.pdb.certs, [])

    def test_bad_signature_or_garbage_is_refused(self):
        csr, _ = make_csr()
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        der[-1] ^= 0x01                          # last byte of the signature
        tampered = x509.load_der_x509_csr(bytes(der))
        self.assertError(self.issue(tampered), 400, "bad_csr")
        for junk in ("", "hello", "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
                     pem_of(self.ca).decode(), "é" * 10):
            with self.subTest(junk=junk[:20]):
                self.assertError(self.issue(junk), 400, "bad_csr")
        self.assertEqual(self.pdb.certs, [])

    def test_input_checks(self):
        good = csr_pem(make_csr()[0])
        for body in ({}, {"csr_pem": good}, {"label": "x"}, {"csr_pem": good, "label": 5},
                     {"csr_pem": ["x"], "label": "x"}, {"csr_pem": good, "label": ""},
                     {"csr_pem": good, "label": "   "}, {"csr_pem": good, "label": "x" * 41},
                     {"csr_pem": good, "label": "bad\nname"}, {"csr_pem": good, "label": "rtl‮name"}):
            with self.subTest(body=body):
                resp = self.client.post("/api/v1/certs", json=body, headers=self.bearer(self.token))
                self.assertError(resp, 400, "invalid_input")
        self.assertEqual(self.issue(label="  Lab PC  ").get_json()["label"], "Lab PC")

    def test_limit_of_three_active(self):
        self.add_cert(revoked=True)
        self.add_cert(expired=True)
        self.add_cert(user=OTHER_UID)
        self.add_cert(user=OTHER_UID)
        self.add_cert(user=OTHER_UID)
        for _ in range(3):
            self.assertEqual(self.issue().status_code, 201)
        self.assertError(self.issue(), 409, "cert_limit")
        self.assertEqual(sum(1 for r in self.pdb.certs if r["username"] == UID and self.pdb.active(r)), 3)
        # Revoking one frees a slot
        serial = next(r["serial"] for r in self.pdb.certs if r["username"] == UID and self.pdb.active(r))
        self.assertEqual(self.client.delete("/api/v1/certs/" + serial, headers=self.bearer(self.token)).status_code, 200)
        self.assertEqual(self.issue().status_code, 201)

    def test_web_certificates_count_in_the_same_limit(self):
        for _ in range(3):
            self.add_cert(via="web")
        self.assertError(self.issue(), 409, "cert_limit")

    def test_lock_count_and_insert_are_one_transaction(self):
        self.assertEqual(self.issue().status_code, 201)
        names = [s[0].split(" (")[0][:40] for s in self.pdb.statements]
        self.assertEqual(names[0], "BEGIN")
        self.assertTrue(names[1].startswith("SELECT pg_advisory_xact_lock"))
        self.assertEqual(self.pdb.statements[1][1], (pki.LOCK_NAMESPACE, UID))
        self.assertTrue(names[2].startswith("SELECT count(*) AS active"))
        self.assertTrue(names[3].startswith("INSERT INTO device_certs"))
        self.assertEqual(names[4], "COMMIT")

    def run_parallel(self, n=8):
        self.pdb.delay = 0.05
        results = []
        barrier = threading.Barrier(n)

        def worker():
            barrier.wait()
            try:
                pki.issue_core(UID, "parallel", "app", ec.generate_private_key(ec.SECP256R1()).public_key())
                results.append("ok")
            except pki.CertLimit:
                results.append("limit")

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return results

    def test_parallel_requests_cannot_pass_the_limit(self):
        results = self.run_parallel()
        self.assertEqual(results.count("ok"), 3)
        self.assertEqual(results.count("limit"), 5)
        self.assertEqual(len(self.pdb.certs), 3)

    def test_without_the_lock_the_race_is_real(self):
        # Shows that the test above can fail: with the lock ignored, more than 3 get through
        self.pdb.use_lock = False
        self.assertGreater(self.run_parallel().count("ok"), 3)

    def test_issue_rate_limit(self):
        for _ in range(10):
            self.pdb.certs.clear()
            self.assertEqual(self.issue().status_code, 201)
        self.pdb.certs.clear()
        self.assertError(self.issue(), 429, "rate_limited")

    def test_refused_at_the_limit_is_not_counted_as_an_issue(self):
        for _ in range(3):
            self.add_cert()
        for _ in range(12):
            self.assertError(self.issue(), 409, "cert_limit")
        self.pdb.certs.clear()
        self.assertEqual(self.issue().status_code, 201)

    def test_missing_device_ca_gives_503(self):
        with mock.patch.object(pki, "CA_KEY_FILE", os.path.join(self.dir, "missing.key")):
            self.assertError(self.issue(), 503, "unavailable")
        with mock.patch.object(pki, "CA_KEY_FILE", os.path.join(self.dir, "ca.pem")):
            self.assertError(self.issue(), 503, "unavailable")
        self.assertEqual(self.pdb.certs, [])

    def test_mismatched_device_ca_key_gives_503(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path = os.path.join(self.dir, "other.key")
        with open(path, "wb") as f:
            f.write(other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        with mock.patch.object(pki, "CA_KEY_FILE", path):
            self.assertError(self.issue(), 503, "unavailable")

    def test_database_down_gives_503(self):
        self.db_error = True
        self.assertError(self.issue(), 503, "unavailable")
        self.assertError(self.client.get("/api/v1/certs", headers=self.bearer(self.token)), 503, "unavailable")


class ListAndRevokeTests(PkiCase):
    def delete(self, serial, token=None):
        return self.client.delete("/api/v1/certs/" + serial, headers=self.bearer(token or self.token))

    def test_list_is_own_certificates_newest_first(self):
        old = self.add_cert(revoked=True)
        self.add_cert(user=OTHER_UID)
        new = self.issue().get_json()["serial"]
        resp = self.client.get("/api/v1/certs", headers=self.bearer(self.token))
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["limit"], 3)
        self.assertEqual([c["serial"] for c in body["certs"]], [new, old])
        self.assertEqual(set(body["certs"][0]), {"serial", "label", "issued_at", "not_after", "revoked_at",
                                                 "revoke_reason", "via", "active"})
        self.assertEqual((body["certs"][0]["active"], body["certs"][0]["via"], body["certs"][0]["revoked_at"]),
                         (True, "app", None))
        self.assertEqual((body["certs"][1]["active"], body["certs"][1]["revoke_reason"]), (False, "user"))
        datetime.fromisoformat(body["certs"][1]["revoked_at"])

    def test_revoke_is_idempotent_and_disconnects_the_device_of_that_cert(self):
        serial = self.issue().get_json()["serial"]
        now = datetime.now(timezone.utc)
        self.pdb.seen += [{"serial": serial, "username": UID, "mac": MAC, "last_seen": now},
                          {"serial": serial, "username": UID, "mac": "DE-AD-BE-EF-00-05",
                           "last_seen": now - timedelta(days=40)}]
        self.pdb.live[UID] = [live_row(MAC), live_row(OTHER_MAC)]
        first = self.delete(serial)
        self.assertEqual(first.status_code, 200, first.get_data(as_text=True))
        body = first.get_json()
        self.assertEqual(set(body), {"serial", "revoked_at", "disconnect"})
        self.assertEqual(body["disconnect"], [{"nas": "10.89.0.1", "result": "ACK"}])
        sent = [c.args[1]["callingstationid"] for c in self.mocks["send_disconnect"].call_args_list]
        self.assertEqual(sent, [MAC])            # not the other device, not the one seen 40 days ago
        second = self.delete(serial).get_json()
        self.assertEqual(second["revoked_at"], body["revoked_at"])
        self.assertEqual(self.pdb.certs[0]["revoke_reason"], "user")

    def test_revoke_of_another_users_or_unknown_serial_is_404(self):
        theirs = self.add_cert(user=OTHER_UID)
        for serial in (theirs, "ab" * 20, "AB" * 20, "xyz", "a" * 41):
            with self.subTest(serial=serial):
                self.assertError(self.delete(serial), 404, "not_found")
        self.assertIsNone(self.pdb.certs[0]["revoked_at"])
        self.mocks["send_disconnect"].assert_not_called()

    def test_revoke_while_a_disconnect_runs_keeps_the_revocation(self):
        serial = self.add_cert()
        self.pdb.seen.append({"serial": serial, "username": UID, "mac": MAC, "last_seen": datetime.now(timezone.utc)})
        self.pdb.live[UID] = [live_row(MAC)]
        portal.DISCONNECTS_RUNNING.add(UID)
        self.addCleanup(portal.DISCONNECTS_RUNNING.discard, UID)
        self.assertError(self.delete(serial), 409, "disconnect_in_progress")
        self.assertIsNotNone(self.pdb.certs[0]["revoked_at"])

    def test_revoke_core_shared_interface(self):
        serial = self.add_cert()
        result = pki.revoke_core(UID, serial, "not_me")
        self.assertEqual(set(result), {"serial", "revoked_at", "disconnect"})
        self.assertEqual((result["serial"], result["disconnect"]), (serial, []))
        self.assertIsInstance(result["revoked_at"], datetime)
        again = pki.revoke_core(UID, serial, "admin")
        self.assertEqual(again["revoked_at"], result["revoked_at"])
        self.assertEqual(self.pdb.certs[0]["revoke_reason"], "not_me")      # the first reason stays
        with self.assertRaises(portal.InvalidInput):
            pki.revoke_core(UID, serial, "because")
        with self.assertRaises(portal.NotFound):
            pki.revoke_core(OTHER_UID, serial, "user")

    def test_revoke_core_without_disconnect(self):
        serial = self.add_cert()
        self.pdb.seen.append({"serial": serial, "username": UID, "mac": MAC, "last_seen": datetime.now(timezone.utc)})
        self.pdb.live[UID] = [live_row(MAC)]
        portal.DISCONNECTS_RUNNING.add(UID)             # would be 409 with the disconnect
        self.addCleanup(portal.DISCONNECTS_RUNNING.discard, UID)
        result = pki.revoke_core(UID, serial, "not_me", disconnect=False)
        self.assertEqual(result["disconnect"], [])
        self.assertEqual(self.pdb.certs[0]["revoke_reason"], "not_me")
        self.mocks["send_disconnect"].assert_not_called()

    def test_revoke_all_core_revokes_every_active_cert_of_the_user_only(self):
        now = datetime.now(timezone.utc)
        a, b = self.add_cert(), self.add_cert()
        old, expired, theirs = self.add_cert(revoked=True), self.add_cert(expired=True), self.add_cert(user=OTHER_UID)
        self.pdb.seen += [{"serial": a, "username": UID, "mac": MAC, "last_seen": now},
                          {"serial": b, "username": UID, "mac": MAC, "last_seen": now}]
        self.pdb.live[UID] = [live_row(MAC)]
        self.assertEqual(sorted(pki.revoke_all_core(UID, "password")), sorted([a, b]))
        reasons = {r["serial"]: r["revoke_reason"] for r in self.pdb.certs}
        self.assertEqual((reasons[a], reasons[b], reasons[old], reasons[expired], reasons[theirs]),
                         ("password", "password", "user", None, None))
        sent = [c.args[1]["callingstationid"] for c in self.mocks["send_disconnect"].call_args_list]
        self.assertEqual(sent, [MAC])                   # each device once
        self.assertEqual(pki.revoke_all_core(UID, "password"), [])
        with self.assertRaises(portal.InvalidInput):
            pki.revoke_all_core(UID, "because")

    def test_revoke_all_core_keeps_the_revocation_when_the_disconnect_fails(self):
        serial = self.add_cert()
        self.pdb.seen.append({"serial": serial, "username": UID, "mac": MAC, "last_seen": datetime.now(timezone.utc)})
        self.pdb.live[UID] = [live_row(MAC)]
        portal.DISCONNECTS_RUNNING.add(UID)
        self.addCleanup(portal.DISCONNECTS_RUNNING.discard, UID)
        self.assertEqual(pki.revoke_all_core(UID, "password"), [serial])
        self.assertIsNotNone(self.pdb.certs[0]["revoked_at"])

    def test_password_change_revokes_every_certificate(self):
        a, b, theirs = self.add_cert(), self.add_cert(), self.add_cert(user=OTHER_UID)
        resp = self.client.post("/api/v1/password", json={"old": PASSWORD, "new": "purple tractor rain 42"},
                                headers=self.bearer(self.token))
        self.assertEqual(resp.status_code, 204, resp.get_data(as_text=True))
        reasons = {r["serial"]: r["revoke_reason"] for r in self.pdb.certs}
        self.assertEqual((reasons[a], reasons[b], reasons[theirs]), ("password", "password", None))

    def test_password_change_stands_when_revoking_fails(self):
        self.add_cert()
        with mock.patch.object(pki, "revoke_all_core", side_effect=portal.Unavailable("down")):
            resp = self.client.post("/api/v1/password", json={"old": PASSWORD, "new": "purple tractor rain 42"},
                                    headers=self.bearer(self.token))
        self.assertEqual(resp.status_code, 204)
        self.mocks["change_password"].assert_called_once()

    def test_certs_for_mac(self):
        now = datetime.now(timezone.utc)
        recent, revoked, old, theirs, other_mac = (self.add_cert(), self.add_cert(revoked=True), self.add_cert(),
                                                   self.add_cert(user=OTHER_UID), self.add_cert())
        self.pdb.seen += [{"serial": recent, "username": UID, "mac": MAC, "last_seen": now},
                          {"serial": revoked, "username": UID, "mac": MAC, "last_seen": now},
                          {"serial": old, "username": UID, "mac": MAC, "last_seen": now - timedelta(days=31)},
                          {"serial": theirs, "username": OTHER_UID, "mac": MAC, "last_seen": now},
                          {"serial": other_mac, "username": UID, "mac": OTHER_MAC, "last_seen": now}]
        self.assertEqual(pki.certs_for_mac(UID, MAC), [recent])
        self.assertEqual(pki.certs_for_mac(OTHER_UID, MAC), [theirs])
        self.assertEqual(pki.certs_for_mac(UID, "bad mac!"), [])
        self.db_error = True
        with self.assertRaises(portal.Unavailable):
            pki.certs_for_mac(UID, MAC)


class WebTests(PkiCase):
    def setUp(self):
        super().setUp()
        self.web_login()

    def new_cert(self, label="MacBook"):
        token = csrf_token(self.client, "/certs")
        return self.client.post("/certs/new", data={"csrf_token": token, "label": label})

    def test_page_lists_certificates(self):
        self.add_cert(label="Old <phone>")
        self.add_cert(user=OTHER_UID, label="Their laptop")
        html = self.client.get("/certs").get_data(as_text=True)
        self.assertIn("Old &lt;phone&gt;", html)
        self.assertNotIn("Their laptop", html)
        self.assertIn("1 of 3 certificates active", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("style=", html)

    def test_forms_need_csrf(self):
        self.assertEqual(self.client.post("/certs/new", data={"label": "x"}).status_code, 400)
        self.assertEqual(self.client.post("/certs/revoke", data={"serial": "ab" * 20}).status_code, 400)
        self.assertEqual(self.pdb.certs, [])

    def test_pkcs12_download_decrypts_with_the_passphrase_only(self):
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        logging.disable(logging.NOTSET)
        root = logging.getLogger()
        old_handlers, old_level = root.handlers[:], root.level
        root.handlers, root.level = [handler], logging.DEBUG     # every record, printed nowhere
        try:
            resp = self.new_cert()
        finally:
            root.handlers, root.level = old_handlers, old_level
            logging.disable(logging.CRITICAL)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("no-store", resp.headers["Cache-Control"])
        html = resp.get_data(as_text=True)
        passphrase = re.search(r'class="passphrase"><code>([^<]+)</code>', html).group(1)
        self.assertRegex(passphrase, r"^([a-z2-9]{4}-){4}[a-z2-9]{4}$")
        blob = base64.b64decode(re.search(r'href="data:application/x-pkcs12;base64,([^"]+)"', html).group(1))
        key, cert, extra = pkcs12.load_key_and_certificates(blob, passphrase.encode())
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, UID)
        self.assertEqual(cert.public_key().public_numbers(), key.public_key().public_numbers())
        self.assertEqual([c.subject for c in extra], [self.ca.subject])
        cert.verify_directly_issued_by(self.ca)
        with self.assertRaises(ValueError):
            pkcs12.load_key_and_certificates(blob, b"wrong-pass")
        row = self.pdb.certs[0]
        self.assertEqual((row["via"], row["label"], row["serial"]), ("web", "MacBook", format(cert.serial_number, "040x")))
        # Nothing secret in the logs or the database
        logged = " ".join(r.getMessage() for r in records)
        self.assertIn(row["serial"], logged)
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
        for secret in (passphrase, passphrase.replace("-", ""), key_pem.splitlines()[1], base64.b64encode(blob)[:40].decode()):
            self.assertNotIn(secret, logged)
            self.assertNotIn(secret, repr(self.pdb.certs))
            self.assertNotIn(secret, repr(self.pdb.statements))
        # Shown once: the next page view has neither
        again = self.client.get("/certs").get_data(as_text=True)
        self.assertNotIn(passphrase, again)
        self.assertNotIn("data:application/x-pkcs12", again)

    def test_each_download_has_its_own_passphrase(self):
        first = re.search(r'class="passphrase"><code>([^<]+)<', self.new_cert().get_data(as_text=True)).group(1)
        second = re.search(r'class="passphrase"><code>([^<]+)<', self.new_cert().get_data(as_text=True)).group(1)
        self.assertNotEqual(first, second)

    def test_limit_applies_to_the_web(self):
        for _ in range(3):
            self.add_cert()
        resp = self.new_cert()
        self.assertEqual(resp.status_code, 302)
        html = self.client.get("/certs").get_data(as_text=True)
        self.assertIn("You already have 3 active certificates", html)
        self.assertNotIn('action="/certs/new"', html)
        self.assertEqual(len(self.pdb.certs), 3)

    def test_bad_label_is_refused(self):
        self.assertEqual(self.new_cert(label="").status_code, 302)
        self.assertIn("1 to 40 characters", self.client.get("/certs").get_data(as_text=True))
        self.assertEqual(self.pdb.certs, [])

    def test_revoke_from_the_page(self):
        mine, theirs = self.add_cert(), self.add_cert(user=OTHER_UID)
        token = csrf_token(self.client, "/certs")
        resp = self.client.post("/certs/revoke", data={"csrf_token": token, "serial": mine}, follow_redirects=True)
        self.assertIn("The certificate was revoked", resp.get_data(as_text=True))
        self.assertIsNotNone(self.pdb.certs[0]["revoked_at"])
        resp = self.client.post("/certs/revoke", data={"csrf_token": token, "serial": theirs}, follow_redirects=True)
        self.assertIn("No certificate of yours", resp.get_data(as_text=True))
        self.assertIsNone(self.pdb.certs[1]["revoked_at"])

    def test_revoke_from_the_page_while_a_disconnect_runs_says_revoked(self):
        serial = self.add_cert()
        self.pdb.seen.append({"serial": serial, "username": UID, "mac": MAC, "last_seen": datetime.now(timezone.utc)})
        self.pdb.live[UID] = [live_row(MAC)]
        portal.DISCONNECTS_RUNNING.add(UID)
        self.addCleanup(portal.DISCONNECTS_RUNNING.discard, UID)
        token = csrf_token(self.client, "/certs")
        html = self.client.post("/certs/revoke", data={"csrf_token": token, "serial": serial},
                                follow_redirects=True).get_data(as_text=True)
        self.assertIn("The certificate was revoked", html)
        self.assertIn("A disconnect could not be sent now", html)
        self.assertNotIn("in progress", html)
        self.assertIsNotNone(self.pdb.certs[0]["revoked_at"])

    def test_nav_link(self):
        self.assertIn('href="/certs"', self.client.get("/certs").get_data(as_text=True))
