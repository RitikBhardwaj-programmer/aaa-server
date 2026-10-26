"""Live tests of the sign-in activity and new-device alerts (activity.py, migrations 004 and 005).

Run by scripts/test.ps1 in the portal-test container, with the same temporary user as test_portal.py.
Test rows in radpostauth, user_devices and device_reviews are written as role "radius" and deleted
again. The database tests run as role "portal", the role of the running portal.
"""
import secrets
import unittest

import psycopg

import app as portal     # first: app loads activity.py (register_features), which imports app
import activity

from .test_portal import PASSWORD, UID, login, radius_db, token

OTHER_UID = "activity-other-" + secrets.token_hex(3)
MY_MAC, MY_PRIVATE_MAC = "00-11-22-33-44-01", "DA-AD-BE-EF-44-02"
OTHER_MAC = "00-11-22-33-44-09"
AP = "AA-BB-CC-DD-EE-FF:NITS-Lab"
OTHER_AP = "11-22-33-44-55-66:Other-SSID"


def clean():
    with radius_db() as conn:
        for table in ("device_reviews", "user_devices", "radpostauth"):
            conn.execute(f"DELETE FROM {table} WHERE username = ANY(%s)", ([UID, OTHER_UID],))


def portal_rows(sql, params=()):
    with portal.db() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


class ActivityDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        clean()
        with radius_db() as conn:
            conn.execute("""INSERT INTO radpostauth (username, reply, calledstationid, callingstationid, authdate, class)
                            VALUES (%s, 'Access-Accept', %s, %s, now() - interval '1 hour', 'my-class'),
                                   (%s, 'Access-Reject', %s, %s, now() - interval '2 hours', 'my-class'),
                                   (%s, 'Access-Accept', %s, %s, now() - interval '40 days', 'my-class'),
                                   (%s, 'Access-Accept', %s, %s, now() - interval '1 hour', 'other-class')""",
                         (UID, AP, MY_MAC, UID, AP, MY_PRIVATE_MAC, UID, AP, MY_MAC, OTHER_UID, OTHER_AP, OTHER_MAC))
            # 150 more of the other user: the row cap is checked on them
            conn.execute("""INSERT INTO radpostauth (username, reply, calledstationid, callingstationid, authdate)
                            SELECT %s, 'Access-Accept', %s, %s, now() - make_interval(mins => i)
                            FROM generate_series(1, 150) i""", (OTHER_UID, OTHER_AP, OTHER_MAC))
            for user, mac in ((UID, MY_MAC), (OTHER_UID, OTHER_MAC)):
                conn.execute("INSERT INTO user_devices VALUES (%s, %s, now(), now())", (user, mac))

    @classmethod
    def tearDownClass(cls):
        clean()

    def assert_refused(self, sql, params=(), error=psycopg.errors.InsufficientPrivilege):
        with self.assertRaises(error):
            portal_rows(sql, params)

    def test_portal_cannot_read_radpostauth(self):
        for sql in ("SELECT * FROM radpostauth", "SELECT class FROM radpostauth LIMIT 1",
                    "SELECT * FROM radpostauth_default LIMIT 1"):
            with self.subTest(sql):
                self.assert_refused(sql)

    def test_portal_signins_is_a_pinned_security_definer_owned_by_radius(self):
        with radius_db() as conn:
            row = conn.execute("""SELECT prosecdef, proconfig, pg_get_userbyid(proowner),
                                         has_function_privilege('public', p.oid, 'EXECUTE')
                                  FROM pg_proc p WHERE proname = 'portal_signins'""").fetchone()
        self.assertEqual(row, (True, ["search_path=pg_catalog, public"], "radius", False))

    def test_portal_signins_returns_only_four_columns_of_one_user(self):
        with portal.db() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM portal_signins(%s, 30, 100)", (UID,))
            columns = [c.name for c in cur.description]
            rows = cur.fetchall()
        self.assertEqual(columns, ["authdate", "reply", "calledstationid", "callingstationid"])
        self.assertEqual(len(rows), 2)              # the 40-day-old row is outside 30 days
        self.assertEqual({r["callingstationid"] for r in rows}, {MY_MAC, MY_PRIVATE_MAC})
        self.assertEqual(rows[0]["reply"], "Access-Accept")       # newest first
        self.assertTrue(all(r["calledstationid"] == AP for r in rows))

    def test_portal_signins_caps_days_and_rows(self):
        self.assertEqual(len(portal_rows("SELECT * FROM portal_signins(%s, 999, 100)", (UID,))), 2)
        self.assertEqual(len(portal_rows("SELECT * FROM portal_signins(%s, 30, 9999)", (OTHER_UID,))), 100)
        self.assertEqual(len(portal_rows("SELECT * FROM portal_signins(%s, 30, 0)", (OTHER_UID,))), 1)

    def test_signins_core_reads_only_the_given_user(self):
        signins = activity.signins_core(UID, 30)
        self.assertEqual({s["mac"] for s in signins}, {MY_MAC, MY_PRIVATE_MAC})
        self.assertEqual({s["ssid"] for s in signins}, {"NITS-Lab"})
        self.assertEqual([s["private_mac"] for s in signins if s["mac"] == MY_PRIVATE_MAC], [True])

    def test_device_review_grants(self):
        upsert = """INSERT INTO device_reviews (username, callingstationid, verdict) VALUES (%s, %s, %s)
                    ON CONFLICT (username, callingstationid)
                    DO UPDATE SET verdict = EXCLUDED.verdict, reviewed_at = now() RETURNING verdict"""
        self.assertEqual(portal_rows(upsert, (UID, MY_MAC, "me")), [{"verdict": "me"}])
        self.assertEqual(portal_rows(upsert, (UID, MY_MAC, "not_me")), [{"verdict": "not_me"}])
        for sql in ("DELETE FROM device_reviews WHERE username = %s",
                    "UPDATE device_reviews SET username = 'x' WHERE username = %s",
                    "UPDATE device_reviews SET callingstationid = 'x' WHERE username = %s",
                    "TRUNCATE device_reviews"):
            with self.subTest(sql):
                self.assert_refused(sql, (UID,) if "%s" in sql else ())
        # Only "me" and "not_me", and only for a device the user has used
        self.assert_refused(upsert, (UID, MY_MAC, "maybe"), psycopg.errors.CheckViolation)
        self.assert_refused(upsert, (UID, OTHER_MAC, "me"), psycopg.errors.ForeignKeyViolation)


class ActivityPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        clean()
        with radius_db() as conn:
            conn.execute("""INSERT INTO radpostauth (username, reply, calledstationid, callingstationid)
                            VALUES (%s, 'Access-Accept', %s, %s), (%s, 'Access-Accept', %s, %s)""",
                         (UID, AP, MY_PRIVATE_MAC, OTHER_UID, OTHER_AP, OTHER_MAC))
            for user, mac in ((UID, MY_MAC), (UID, MY_PRIVATE_MAC), (OTHER_UID, OTHER_MAC)):
                conn.execute("INSERT INTO user_devices VALUES (%s, %s, now(), now())", (user, mac))

    @classmethod
    def tearDownClass(cls):
        clean()

    def setUp(self):
        for limiter in portal.LIMITERS:
            limiter.reset()
        self.client = portal.app.test_client()
        self.assertEqual(login(self.client, UID, PASSWORD).status_code, 302)

    def test_activity_page_shows_only_own_rows(self):
        html = self.client.get("/activity").get_data(as_text=True)
        self.assertIn(MY_PRIVATE_MAC, html)
        self.assertIn("NITS-Lab", html)
        self.assertIn("private address", html)
        for other in (OTHER_MAC, "Other-SSID", OTHER_UID):
            self.assertNotIn(other, html)

    def test_banner_review_and_api(self):
        html = self.client.get("/devices").get_data(as_text=True)
        self.assertIn("2 new devices signed in", html)
        self.assertNotIn(OTHER_MAC, html)
        resp = self.client.post("/activity/review", data={"csrf_token": token(self.client, "/devices"),
                                                          "mac": MY_MAC, "verdict": "me"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("1 new device signed in", self.client.get("/devices").get_data(as_text=True))
        # The API: the other user's device is not found, the token user's alert list is one device
        api = portal.app.test_client()
        tok = api.post("/api/v1/auth/token", json={"uid": UID, "password": PASSWORD}).get_json()["access_token"]
        headers = {"Authorization": "Bearer " + tok}
        alerts = api.get("/api/v1/alerts", headers=headers).get_json()
        self.assertEqual((alerts["count"], alerts["alerts"][0]["mac"]), (1, MY_PRIVATE_MAC))
        self.assertEqual(api.post(f"/api/v1/alerts/{OTHER_MAC}", json={"verdict": "me"}, headers=headers).status_code,
                         404)
        body = api.post(f"/api/v1/alerts/{MY_PRIVATE_MAC}", json={"verdict": "not_me"}, headers=headers).get_json()
        self.assertEqual(body, {"mac": MY_PRIVATE_MAC, "verdict": "not_me", "disconnect": [], "next": "password"})
        self.assertEqual(api.get("/api/v1/alerts", headers=headers).get_json()["count"], 0)
        with radius_db() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM device_reviews WHERE username = %s",
                                          (OTHER_UID,)).fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
