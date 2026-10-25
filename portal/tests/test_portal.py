"""Portal tests against the live LDAP and PostgreSQL, with Flask's test client (stdlib unittest).

Run by scripts/test.ps1 (service "portal-test"). Needs PORTAL_TEST_UID / PORTAL_TEST_PASSWORD: a
temporary Students user that the script creates and deletes. Test rows in radacct, user_devices and
device_limit_events are written as role "radius" and deleted again.
"""
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import psycopg

import app as portal

UID = os.environ["PORTAL_TEST_UID"]
PASSWORD = os.environ["PORTAL_TEST_PASSWORD"]
DISABLED_UID = "disabled001"
SEED_PASSWORD = os.environ["TEST_USER_PASSWORD"]
OTHER_UID = "portal-other-" + secrets.token_hex(3)
MY_MAC, OTHER_MAC = "DE-AD-BE-EF-00-01", "DE-AD-BE-EF-00-02"
MY_EVENT_MAC, OTHER_EVENT_MAC = "AA-AA-AA-AA-00-01", "BB-BB-BB-BB-00-02"
TEST_NAS = "10.89.0.50"      # the tests container: nothing listens for Disconnect-Requests there
OTHER_IP = {"REMOTE_ADDR": "192.0.2.77"}


def token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, uid, password, **kwargs):
    return client.post("/login", data={"csrf_token": token(client), "uid": uid, "password": password}, **kwargs)


def radius_db():
    return psycopg.connect(host="postgres", dbname="radius", user="radius",
                           password=os.environ["POSTGRES_RADIUS_PASSWORD"], autocommit=True)


def nt_hash_present(uid):
    """Read as cn=radius, the only account allowed to see NT hashes (test service only)."""
    conn = portal.ldap_bind(f"cn=radius,ou=Services,{portal.BASE_DN}", os.environ["LDAP_RADIUS_PASSWORD"])
    try:
        conn.search(portal.BASE_DN, f"(uid={uid})", attributes=["sambaNTPassword"])
        return bool(portal.entries(conn)[0]["attributes"].get("sambaNTPassword"))
    finally:
        conn.unbind()


def ldap_binds(dn, password):
    try:
        portal.ldap_bind(dn, password).unbind()
        return True
    except portal.BAD_CREDENTIALS:
        return False


class PortalCase(unittest.TestCase):
    def setUp(self):
        for limiter in portal.LIMITERS:
            limiter.reset()
        self.client = portal.app.test_client()

    def logged_in(self):
        resp = login(self.client, UID, PASSWORD)
        self.assertEqual(resp.status_code, 302)
        return self.client


class LoginTests(PortalCase):
    def test_login_ok(self):
        resp = login(self.client, UID, PASSWORD, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("My devices", resp.get_data(as_text=True))
        with self.client.session_transaction() as s:
            self.assertEqual(s["uid"], UID)

    def test_wrong_and_unknown_user_get_the_same_answer(self):
        wrong = login(self.client, UID, "not-the-password")
        unknown = login(self.client, "nobody-" + secrets.token_hex(3), "not-the-password")
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        for resp in (wrong, unknown):
            self.assertIn(portal.GENERIC_LOGIN_ERROR, resp.get_data(as_text=True))
        # The two pages are identical apart from the echoed ID and the CSRF token (both are value="...")
        plain = lambda r: re.sub(r'value="[^"]*"', 'value=""', r.get_data(as_text=True))
        self.assertEqual(plain(wrong), plain(unknown))

    def test_empty_password_is_refused(self):
        self.assertEqual(login(self.client, UID, "").status_code, 401)
        self.assertIsNone(portal.authenticate(UID, ""))

    def test_disabled_user_is_refused(self):
        resp = login(self.client, DISABLED_UID, SEED_PASSWORD)
        self.assertEqual(resp.status_code, 401)
        self.assertIn(portal.GENERIC_LOGIN_ERROR, resp.get_data(as_text=True))
        with self.client.session_transaction() as s:
            self.assertNotIn("uid", s)

    def test_rate_limit_after_five_failures(self):
        for _ in range(5):
            self.assertEqual(login(self.client, UID, "wrong-password", environ_overrides=OTHER_IP).status_code, 401)
        # Even the right password is refused now, for this ID from this address
        resp = login(self.client, UID, PASSWORD, environ_overrides=OTHER_IP)
        self.assertEqual(resp.status_code, 429)
        self.assertIn(portal.GENERIC_LOGIN_ERROR, resp.get_data(as_text=True))
        # Another address is not affected
        self.assertEqual(login(self.client, UID, PASSWORD).status_code, 302)

    def test_uid_in_another_case_logs_in_with_the_stored_uid(self):
        typed = UID.upper()
        self.assertNotEqual(typed, UID)
        self.assertEqual(login(self.client, typed, PASSWORD).status_code, 302)
        with self.client.session_transaction() as s:
            self.assertEqual(s["uid"], UID)

    def test_post_without_csrf_token_is_rejected(self):
        resp = self.client.post("/login", data={"uid": UID, "password": PASSWORD})
        self.assertEqual(resp.status_code, 400)
        with self.client.session_transaction() as s:
            self.assertNotIn("uid", s)

    def test_logout(self):
        client = self.logged_in()
        resp = client.post("/logout", data={"csrf_token": token(client, "/devices")})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(client.get("/devices").status_code, 302)
        self.assertIn("/login", client.get("/devices").headers["Location"])

    def test_pages_need_a_login(self):
        for path in ("/devices", "/password"):
            self.assertIn("/login", self.client.get(path).headers["Location"], path)

    def test_security_headers_and_cookie(self):
        resp = login(self.client, UID, PASSWORD)
        cookie = resp.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        for path in ("/login", "/devices", "/password"):
            h = self.client.get(path).headers
            self.assertTrue(h["Content-Security-Policy"].startswith("default-src 'self'"), path)
            self.assertEqual(h["X-Frame-Options"], "DENY")
            self.assertEqual(h["X-Content-Type-Options"], "nosniff")
            self.assertEqual(h["Referrer-Policy"], "no-referrer")
            self.assertEqual(h["Cache-Control"], "no-store")
        self.assertNotIn("<style", self.client.get("/devices").get_data(as_text=True))
        self.assertNotIn("<script", self.client.get("/devices").get_data(as_text=True))

    def test_portal_account_cannot_read_password_hashes(self):
        # student001 was made while PEAP was allowed, so it HAS an NT hash: the check is not vacuous
        self.assertTrue(nt_hash_present("student001"))
        found = portal.portal_search(portal.BASE_DN, "(uid=student001)", ["cn", "userPassword", "sambaNTPassword"])
        attrs = found[0]["attributes"]
        self.assertTrue(attrs.get("cn"))
        self.assertFalse(attrs.get("userPassword"))
        self.assertFalse(attrs.get("sambaNTPassword"))

    def test_filter_metacharacters_in_the_id_never_reach_ldap(self):
        with mock.patch.object(portal, "portal_search") as search:
            for typed in ("*", "student*", "a)(uid=*", "x\\2a"):
                self.assertEqual(login(self.client, typed, "whatever").status_code, 401)
        search.assert_not_called()

    def test_junk_ids_do_not_create_per_user_entries(self):
        for i in range(10):
            login(self.client, f"!junk{i}", "whatever")
        self.assertEqual(len(portal.LOGIN_BY_USER.attempts), 0)

    def test_password_spraying_from_one_address_is_limited(self):
        for i in range(20):
            resp = login(self.client, f"nobody{i}x{secrets.token_hex(2)}", "Summer2026!", environ_overrides=OTHER_IP)
            self.assertEqual(resp.status_code, 401)
        self.assertEqual(login(self.client, UID, PASSWORD, environ_overrides=OTHER_IP).status_code, 429)

    def test_session_ends_30_minutes_after_login_even_when_used(self):
        client = self.logged_in()
        self.assertEqual(client.get("/devices").status_code, 200)
        with client.session_transaction() as s:
            s["login_at"] = time.time() - portal.SESSION_ABSOLUTE_SECONDS - 1
        self.assertIn("/login", client.get("/devices").headers["Location"])

    def test_forged_version_in_session_is_refused(self):
        client = self.logged_in()
        with client.session_transaction() as s:
            s["version"] = "19700101000000Z"
        self.assertIn("/login", client.get("/devices").headers["Location"])

    def test_csrf_needed_on_password_and_logout(self):
        client = self.logged_in()
        resp = client.post("/password", data={"old": PASSWORD, "new": secrets.token_hex(16), "confirm": "x"})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(client.post("/logout").status_code, 400)
        self.assertEqual(client.get("/devices").status_code, 200)       # still logged in

    def test_weak_secret_key_stops_the_portal(self):
        env = dict(os.environ, PORTAL_SECRET_KEY="change-me")
        run = subprocess.run([sys.executable, "-c", "import app"], env=env, capture_output=True, text=True,
                             cwd=os.path.dirname(os.path.abspath(portal.__file__)))
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("PORTAL_SECRET_KEY", run.stderr)


class PasswordTests(PortalCase):
    def post_change(self, client, old, new, confirm=None):
        return client.post("/password", data={"csrf_token": token(client, "/password"), "old": old,
                                              "new": new, "confirm": new if confirm is None else confirm})

    def test_change_ok_then_new_password_binds(self):
        client = self.logged_in()
        other = portal.app.test_client()       # a second session of the same user (or a stolen cookie)
        self.assertEqual(login(other, UID, PASSWORD).status_code, 302)
        new = secrets.token_hex(16)
        dn = portal.find_user(UID)[0]
        self.assertEqual(nt_hash_present(UID), portal.ALLOW_PEAP)
        try:
            resp = self.post_change(client, PASSWORD, new)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.headers["Location"])
            self.assertTrue(ldap_binds(dn, new))
            self.assertFalse(ldap_binds(dn, PASSWORD))
            # The old password must not keep working for PEAP: its NT hash is gone
            self.assertFalse(nt_hash_present(UID))
            # Every session of the user ended, including the other one
            for c in (client, other):
                self.assertIn("/login", c.get("/devices").headers["Location"])
        finally:
            if ldap_binds(dn, new):
                portal.change_password(dn, new, PASSWORD)     # restore for the other tests
        self.assertTrue(ldap_binds(dn, PASSWORD))

    def test_rules(self):
        client = self.logged_in()
        cases = [
            ("wrong old password", "wrong-old-password", secrets.token_hex(16), None, "current password is wrong"),
            ("too short", PASSWORD, "short-one", None, "at least 15"),
            ("contains the uid", PASSWORD, "xx" + UID.upper() + "-purple-tractor", None, "must not contain your user ID"),
            ("blocklisted", PASSWORD, "passwordpassword", None, "too common"),
            ("confirm mismatch", PASSWORD, secrets.token_hex(16), secrets.token_hex(16), "not the same"),
        ]
        for name, old, new, confirm, expected in cases:
            with self.subTest(name):
                resp = self.post_change(client, old, new, confirm)
                self.assertEqual(resp.status_code, 400)
                self.assertIn(expected, resp.get_data(as_text=True))
        self.assertTrue(ldap_binds(portal.find_user(UID)[0], PASSWORD))     # nothing changed

    def test_peap_warning_follows_the_setting(self):
        client = self.logged_in()
        page = client.get("/password").get_data(as_text=True)
        self.assertEqual("PEAP stops working" in page, portal.ALLOW_PEAP)


class DeviceTests(PortalCase):
    @classmethod
    def clean(cls):
        with radius_db() as conn:
            for table in ("radacct", "user_devices", "device_limit_events"):
                conn.execute(f"DELETE FROM {table} WHERE username = ANY(%s)", ([UID, OTHER_UID],))

    @classmethod
    def setUpClass(cls):
        cls.clean()
        with radius_db() as conn:
            for user, mac in ((UID, MY_MAC), (OTHER_UID, OTHER_MAC)):
                conn.execute(
                    """INSERT INTO radacct (acctsessionid, acctuniqueid, username, nasipaddress, acctstarttime,
                                            acctupdatetime, calledstationid, callingstationid, framedipaddress,
                                            acctinputoctets, acctoutputoctets)
                       VALUES (%s, %s, %s, %s, now(), now(), 'AP-TEST', %s, '10.99.0.5', 1024, 2048)""",
                    (secrets.token_hex(4), secrets.token_hex(8), user, TEST_NAS, mac))
            for user, mac in ((UID, MY_EVENT_MAC), (OTHER_UID, OTHER_EVENT_MAC)):
                conn.execute("INSERT INTO device_limit_events (username, callingstationid, live_devices, device_limit, mode) "
                             "VALUES (%s, %s, 3, 3, 'soft')", (user, mac))

    @classmethod
    def tearDownClass(cls):
        cls.clean()

    def test_devices_page_shows_only_own_rows(self):
        page = self.logged_in().get("/devices").get_data(as_text=True)
        self.assertIn(MY_MAC, page)
        self.assertIn(MY_EVENT_MAC, page)
        self.assertIn("AP-TEST", page)
        self.assertIn("10.99.0.5", page)
        self.assertIn("1.0 KB", page)
        self.assertIn(f"1 of {portal.DEVICE_LIMIT} devices online", page)
        for other in (OTHER_MAC, OTHER_EVENT_MAC, OTHER_UID):
            self.assertNotIn(other, page)

    def test_disconnect_of_a_mac_that_is_not_mine_is_refused(self):
        client = self.logged_in()
        with mock.patch.object(portal, "send_disconnect") as send:
            resp = client.post("/devices/disconnect", data={"csrf_token": token(client, "/devices"), "mac": OTHER_MAC},
                               follow_redirects=True)
        send.assert_not_called()
        self.assertIn("No active session of yours", resp.get_data(as_text=True))

    def test_disconnect_needs_a_csrf_token(self):
        client = self.logged_in()
        self.assertEqual(client.post("/devices/disconnect", data={"mac": MY_MAC}).status_code, 400)

    def test_disconnect_is_rate_limited(self):
        client = self.logged_in()
        with mock.patch.object(portal, "send_disconnect", return_value="none") as send:
            for _ in range(6):
                resp = client.post("/devices/disconnect", data={"csrf_token": token(client, "/devices"), "mac": MY_MAC},
                                   follow_redirects=True)
        self.assertEqual(send.call_count, 5)
        self.assertIn("Too many disconnect requests", resp.get_data(as_text=True))

    def test_send_disconnect_refuses_unsafe_values(self):
        good = {"nas": TEST_NAS, "acctsessionid": "abc", "callingstationid": MY_MAC}
        with mock.patch.object(portal.subprocess, "run") as run:
            for bad in ({"acctsessionid": 'a"b'}, {"acctsessionid": "a\\b"}, {"callingstationid": "x\ny"},
                        {"nas": "not-an-ip"}):
                self.assertEqual(portal.send_disconnect(UID, {**good, **bad}), "none")
            run.assert_not_called()

    def test_radclient_gets_the_secret_from_a_file(self):
        with mock.patch.object(portal.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "", "")
            portal.send_disconnect(UID, {"nas": TEST_NAS, "acctsessionid": "abc", "callingstationid": MY_MAC})
        argv = run.call_args.args[0]
        self.assertIn("-S", argv)
        self.assertNotIn(portal.RADIUS_SECRET_AP, argv)
        self.assertEqual(os.stat(portal.SECRET_FILE).st_mode & 0o777, 0o600)

    def test_portal_db_role_is_read_only(self):
        for sql in ("INSERT INTO user_devices VALUES ('x', 'y', now(), now())", "SELECT 1 FROM radpostauth LIMIT 1"):
            with self.subTest(sql), portal.db() as conn, conn.cursor() as cur:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    cur.execute(sql)

    def test_disconnect_of_my_mac_sends_the_request(self):
        client = self.logged_in()
        resp = client.post("/devices/disconnect", data={"csrf_token": token(client, "/devices"), "mac": MY_MAC},
                           follow_redirects=True)
        page = resp.get_data(as_text=True)
        self.assertIn("no reply from the access point", page)       # nothing answers at the test NAS
        self.assertIn("next re-check", page)


class LimiterTests(unittest.TestCase):
    def test_window_and_limit(self):
        limiter = portal.AttemptLimiter(limit=2, window=900)
        key = ("u", "1.2.3.4")
        self.assertTrue(limiter.attempt(key))
        self.assertTrue(limiter.attempt(key))
        self.assertFalse(limiter.attempt(key))
        limiter.succeeded(key, forget_all=True)
        self.assertTrue(limiter.attempt(key))

    def test_parallel_attempts_cannot_pass_the_limit(self):
        limiter = portal.AttemptLimiter(limit=5, window=900)
        allowed = []
        threads = [threading.Thread(target=lambda: allowed.append(limiter.attempt("k"))) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(allowed.count(True), 5)

    def test_flood_of_new_keys_cannot_evict_a_blocked_key(self):
        limiter = portal.AttemptLimiter(limit=2, window=900)
        limiter.MAX_KEYS = 10
        for _ in range(2):
            limiter.attempt("victim")
        for i in range(50):
            limiter.attempt(f"junk{i}")              # refused once the table is full
        self.assertLessEqual(len(limiter.attempts), 10)
        self.assertFalse(limiter.attempt("victim"))  # still blocked


if __name__ == "__main__":
    unittest.main()
