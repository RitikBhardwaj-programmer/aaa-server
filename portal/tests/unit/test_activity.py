"""Sign-in activity and new-device alerts (activity.py), with mocks only."""
import sys
import types
import unittest
from datetime import timedelta
from unittest import mock

import activity
import app as portal

from .helpers import MAC, NOW, UID, CoreCase, csrf_token, live_row

PRIVATE_MAC = "DA-AD-BE-EF-00-02"      # 0xDA: locally administered bit set
AP = "AA-BB-CC-DD-EE-FF:NITS-Lab"


def signin_row(mac=MAC, reply="Access-Accept", called=AP, hours_ago=1):
    return {"authdate": NOW - timedelta(hours=hours_ago), "reply": reply, "calledstationid": called,
            "callingstationid": mac}


def device_row(mac, days_ago=1):
    return {"callingstationid": mac, "first_seen": NOW - timedelta(days=days_ago), "last_seen": NOW}


class HelperTests(unittest.TestCase):
    def test_private_mac_is_the_locally_administered_bit(self):
        cases = {"DE-AD-BE-EF-00-01": True, "da:ad:be:ef:00:01": True, "02-00-00-00-00-00": True,
                 "00-11-22-33-44-55": False, "AC-DE-48-00-11-22": False, "dcad.beef.0001": False,
                 "dead.beef.0001": True, "not-a-mac": False, "": False, None: False}
        for mac, private in cases.items():
            with self.subTest(mac=mac):
                self.assertIs(activity.is_private_mac(mac), private)

    def test_called_station_id_is_split_into_ap_and_ssid(self):
        cases = {AP: ("AA-BB-CC-DD-EE-FF", "NITS-Lab"),
                 "aa:bb:cc:dd:ee:ff:NITS Lab": ("aa:bb:cc:dd:ee:ff", "NITS Lab"),
                 "AABBCCDDEEFF:x:y": ("AABBCCDDEEFF", "x:y"),
                 "AA-BB-CC-DD-EE-FF": ("AA-BB-CC-DD-EE-FF", None),
                 "AP-615": ("AP-615", None), "": (None, None), None: (None, None)}
        for called, parts in cases.items():
            with self.subTest(called=called):
                self.assertEqual(activity.split_station(called), parts)


class ActivityCase(CoreCase):
    """Keeps every fake connection, so a test can read the queries of all db() calls.
    pki.py (stage S5) is "not loaded" unless a test calls use_pki(): its functions are mocks here,
    so the fake database results of a test do not depend on whether pki.py is in the folder."""

    def setUp(self):
        self.connections = []
        super().setUp()
        p = mock.patch.object(activity, "pki_module", return_value=None)
        self.pki_module = p.start()
        self.addCleanup(p.stop)

    def use_pki(self, serials=(), revoke_error=None, list_error=None):
        pki = mock.Mock(spec=["certs_for_mac", "revoke_core"])
        pki.certs_for_mac.side_effect = list_error
        pki.certs_for_mac.return_value = list(serials)

        def revoke(uid, serial, reason, disconnect=True):
            if revoke_error and serial in revoke_error:
                raise revoke_error[serial]
            return {"serial": serial, "revoked_at": "2026-10-27T10:00:00+05:30", "disconnect": []}
        pki.revoke_core.side_effect = revoke
        self.pki_module.return_value = pki
        return pki

    def fake_db(self):
        conn = super().fake_db()
        self.connections.append(conn)
        return conn

    def queries(self):
        return [q for c in self.connections for q in c.cur.queries]


class ApiActivityTests(ActivityCase):
    def setUp(self):
        super().setUp()
        self.headers = self.bearer(self.api_token())

    def get(self, path):
        return self.client.get(path, headers=self.headers)

    def test_activity_shape_and_default_days(self):
        self.db_results = [[signin_row(), signin_row(PRIVATE_MAC, "Access-Reject", "AP-615", 2)]]
        resp = self.get("/api/v1/activity")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["days"], 7)
        self.assertEqual(body["signins"][0], {
            "time": (NOW - timedelta(hours=1)).isoformat(), "result": "accept", "access_point": AP,
            "ap_mac": "AA-BB-CC-DD-EE-FF", "ssid": "NITS-Lab", "mac": MAC, "private_mac": True})
        self.assertEqual(body["signins"][1]["result"], "reject")
        self.assertEqual((body["signins"][1]["ap_mac"], body["signins"][1]["ssid"]), ("AP-615", None))
        sql, params = self.queries()[-1]
        self.assertIn("FROM portal_signins(%s, %s, %s)", sql)
        self.assertNotIn("radpostauth", sql)
        self.assertEqual(params, (UID, 7, 100))

    def test_activity_days(self):
        self.db_results = [[]]
        self.assertEqual(self.get("/api/v1/activity?days=30").get_json(), {"days": 30, "signins": []})
        self.assertEqual(self.queries()[-1][1], (UID, 30, 100))
        for bad in ("0", "31", "-1", "abc", "7.5", "", "100", " 7"):
            with self.subTest(days=bad):
                resp = self.get("/api/v1/activity?days=" + bad)
                self.assertEqual(resp.status_code, 400)
                self.assertEqual(resp.get_json()["error"]["code"], "invalid_input")
        self.assertEqual(len(self.queries()), 1)

    def test_activity_database_down(self):
        self.db_error = True
        resp = self.get("/api/v1/activity")
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.get_json()["error"]["code"], "unavailable")

    def test_alerts_are_bundled_with_online_and_private_flags(self):
        self.db_results = [[device_row(PRIVATE_MAC, 1), device_row(MAC, 3)], [live_row(MAC)]]
        resp = self.get("/api/v1/alerts")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["alerts"][0], {"mac": PRIVATE_MAC, "first_seen": (NOW - timedelta(days=1)).isoformat(),
                                             "last_seen": NOW.isoformat(), "online": False, "private_mac": True})
        self.assertTrue(body["alerts"][1]["online"])
        sql, params = self.queries()[0]
        self.assertIn("NOT EXISTS (SELECT 1 FROM device_reviews", sql)
        self.assertEqual(params, (UID, 30))
        self.assertEqual(self.queries()[1][1][0], UID)       # live sessions of this user only

    def test_no_alerts(self):
        self.db_results = [[]]
        self.assertEqual(self.get("/api/v1/alerts").get_json(), {"count": 0, "alerts": []})

    def test_endpoints_need_a_token(self):
        api = portal.app.test_client()
        for method, path in (("get", "/api/v1/activity"), ("get", "/api/v1/alerts"), ("post", f"/api/v1/alerts/{MAC}")):
            with self.subTest(path=path):
                resp = getattr(api, method)(path, json={"verdict": "me"} if method == "post" else None)
                self.assertEqual(resp.status_code, 401)

    def review(self, mac, body):
        return self.client.post(f"/api/v1/alerts/{mac}", json=body, headers=self.headers)

    def test_review_me(self):
        self.db_results = [[{"verdict": "me"}]]
        resp = self.review(MAC, {"verdict": "me"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"mac": MAC, "verdict": "me", "disconnect": None, "next": None,
                                           "revoked": None, "revoke_failed": None})
        sql, params = self.queries()[0]
        self.assertIn("INSERT INTO device_reviews", sql)
        self.assertIn("FROM user_devices d WHERE d.username = %s AND d.callingstationid = %s", sql)
        self.assertEqual(params, ("me", UID, MAC))
        self.mocks["send_disconnect"].assert_not_called()

    def test_review_not_me_disconnects_an_online_device(self):
        self.db_results = [[{"verdict": "not_me"}], [live_row(MAC, nas="10.89.0.1")]]
        resp = self.review(MAC, {"verdict": "not_me"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"mac": MAC, "verdict": "not_me",
                                           "disconnect": [{"nas": "10.89.0.1", "result": "ACK"}], "next": "password",
                                           "revoked": None, "revoke_failed": None})
        self.assertEqual(self.mocks["send_disconnect"].call_args.args[0], UID)

    # ---- S6: "not_me" also revokes the device's certificates when pki.py is loaded ----

    def test_review_not_me_revokes_the_certificates_of_the_device(self):
        pki = self.use_pki(["4f1c0e", "a0b1c2"])
        self.db_results = [[{"verdict": "not_me"}], [live_row(MAC)]]
        resp = self.review(MAC, {"verdict": "not_me"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual((body["revoked"], body["revoke_failed"]), (["4f1c0e", "a0b1c2"], []))
        self.assertEqual(body["disconnect"], [{"nas": "10.89.0.1", "result": "ACK"}])
        pki.certs_for_mac.assert_called_once_with(UID, MAC)
        self.assertEqual(pki.revoke_core.call_args_list,
                         [mock.call(UID, "4f1c0e", "not_me", disconnect=False),
                          mock.call(UID, "a0b1c2", "not_me", disconnect=False)])
        self.mocks["send_disconnect"].assert_called_once()

    def test_review_not_me_without_certificates(self):
        pki = self.use_pki([])
        self.db_results = [[{"verdict": "not_me"}], []]
        body = self.review(MAC, {"verdict": "not_me"}).get_json()
        self.assertEqual((body["revoked"], body["revoke_failed"], body["next"]), ([], [], "password"))
        pki.revoke_core.assert_not_called()

    def test_review_me_does_not_revoke(self):
        pki = self.use_pki(["4f1c0e"])
        self.db_results = [[{"verdict": "me"}]]
        body = self.review(MAC, {"verdict": "me"}).get_json()
        self.assertEqual((body["revoked"], body["revoke_failed"]), (None, None))
        pki.certs_for_mac.assert_not_called()
        pki.revoke_core.assert_not_called()

    def test_review_of_a_device_that_is_not_mine_does_not_revoke(self):
        pki = self.use_pki(["4f1c0e"])
        self.db_results = [[]]
        self.assertEqual(self.review(MAC, {"verdict": "not_me"}).status_code, 404)
        pki.certs_for_mac.assert_not_called()

    def test_a_failed_revocation_does_not_stop_the_others_or_the_disconnect(self):
        self.use_pki(["4f1c0e", "a0b1c2"], revoke_error={"4f1c0e": portal.Unavailable("db down")})
        self.db_results = [[{"verdict": "not_me"}], [live_row(MAC)]]
        resp = self.review(MAC, {"verdict": "not_me"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual((body["revoked"], body["revoke_failed"]), (["a0b1c2"], ["4f1c0e"]))
        self.assertEqual((body["next"], len(body["disconnect"])), ("password", 1))
        self.assertIn("INSERT INTO device_reviews", self.queries()[0][0])     # the verdict is recorded

    def test_any_fault_of_pki_keeps_the_verdict_and_the_password_step(self):
        self.use_pki(list_error=RuntimeError("bug in pki"))
        self.db_results = [[{"verdict": "not_me"}], []]
        resp = self.review(MAC, {"verdict": "not_me"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual((body["revoked"], body["revoke_failed"], body["next"]), ([], ["*"], "password"))

    def test_revocation_runs_before_a_disconnect_that_is_refused(self):
        pki = self.use_pki(["4f1c0e"])
        self.db_results = [[{"verdict": "not_me"}], [live_row(MAC)]]
        portal.DISCONNECTS_RUNNING.add(UID)
        self.addCleanup(portal.DISCONNECTS_RUNNING.discard, UID)
        resp = self.review(MAC, {"verdict": "not_me"})
        self.assertEqual(resp.status_code, 409)
        pki.revoke_core.assert_called_once_with(UID, "4f1c0e", "not_me", disconnect=False)

    def test_a_disconnect_error_after_the_revocation_counts_as_revoked(self):
        # revoke_core raises Conflict / RateLimited only from its disconnect, after the revocation
        self.use_pki(["4f1c0e", "a0b1c2"], revoke_error={"4f1c0e": portal.Conflict("busy"),
                                                         "a0b1c2": portal.RateLimited("slow down")})
        self.db_results = [[{"verdict": "not_me"}], []]
        body = self.review(MAC, {"verdict": "not_me"}).get_json()
        self.assertEqual((body["revoked"], body["revoke_failed"]), (["4f1c0e", "a0b1c2"], []))

    def test_review_not_me_of_an_offline_device(self):
        self.db_results = [[{"verdict": "not_me"}], []]
        body = self.review(MAC, {"verdict": "not_me"}).get_json()
        self.assertEqual((body["disconnect"], body["next"]), ([], "password"))
        self.mocks["send_disconnect"].assert_not_called()

    def test_review_of_a_device_that_is_not_mine_is_404(self):
        self.db_results = [[]]                  # the INSERT ... SELECT FROM user_devices wrote nothing
        resp = self.review(MAC, {"verdict": "not_me"})
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.get_json()["error"]["code"], "not_found")
        self.mocks["send_disconnect"].assert_not_called()

    def test_review_input_is_checked_before_the_database(self):
        for mac, body in ((MAC, {"verdict": "maybe"}), (MAC, {"verdict": None}), (MAC, {}),
                          (MAC, ["me"]), ("x" * 41, {"verdict": "me"}), ("a%20b", {"verdict": "me"})):
            with self.subTest(mac=mac, body=body):
                resp = self.review(mac, body)
                self.assertEqual(resp.status_code, 400)
                self.assertEqual(resp.get_json()["error"]["code"], "invalid_input")
        self.assertEqual(self.queries(), [])

    def test_review_needs_json(self):
        resp = self.client.post(f"/api/v1/alerts/{MAC}", data="verdict=me", headers=self.headers,
                                content_type="application/x-www-form-urlencoded")
        self.assertEqual(resp.status_code, 415)

    def test_review_not_me_while_a_disconnect_runs_is_409(self):
        self.db_results = [[{"verdict": "not_me"}], [live_row(MAC)]]
        portal.DISCONNECTS_RUNNING.add(UID)
        self.addCleanup(portal.DISCONNECTS_RUNNING.discard, UID)
        resp = self.review(MAC, {"verdict": "not_me"})
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json()["error"]["code"], "disconnect_in_progress")


class WebActivityTests(ActivityCase):
    def setUp(self):
        super().setUp()
        self.web_login()

    def test_page_needs_a_login(self):
        resp = portal.app.test_client().get("/activity")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_activity_page(self):
        self.db_results = [[signin_row(PRIVATE_MAC), signin_row("00-11-22-33-44-55", "Access-Reject")]]
        resp = self.client.get("/activity")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        for text in ("Sign-in activity", "AA-BB-CC-DD-EE-FF", "NITS-Lab", PRIVATE_MAC, "Accepted", "Refused",
                     "activity.css"):
            self.assertIn(text, html)
        self.assertEqual(html.count('class="tag"'), 1)          # only the private MAC has the label
        self.assertNotIn("style=", html)
        self.assertNotIn("<script", html)
        self.assertIn('aria-current="page"', html)

    def test_activity_page_database_down(self):
        self.db_error = True
        resp = self.client.get("/activity")
        self.assertEqual(resp.status_code, 503)
        self.assertIn("temporarily unavailable", resp.get_data(as_text=True))

    def devices_page(self, alert_rows, live=()):
        # device_overview: live sessions, devices seen, limit events; then the banner: alerts, live
        self.db_results = [list(live), [], [], alert_rows] + ([list(live)] if alert_rows else [])
        resp = self.client.get("/devices")
        self.assertEqual(resp.status_code, 200)
        return resp.get_data(as_text=True)

    def test_banner_bundles_all_alerts(self):
        html = self.devices_page([device_row(PRIVATE_MAC), device_row(MAC)], live=[live_row(MAC)])
        self.assertIn("2 new devices signed in", html)
        self.assertEqual(html.count('name="verdict" value="me"'), 2)
        self.assertEqual(html.count('name="verdict" value="not_me"'), 2)
        self.assertIn("private address", html)
        self.assertIn("activity.css", html)
        self.assertNotIn("style=", html)

    def test_banner_for_one_device(self):
        self.assertIn("1 new device signed in", self.devices_page([device_row(MAC)]))

    def test_no_banner_without_alerts(self):
        html = self.devices_page([])
        self.assertNotIn("signed in</h2>", html)
        self.assertNotIn("activity.css", html)

    def post_review(self, mac, verdict):
        resp = self.client.post("/activity/review", data={"csrf_token": csrf_token(self.client, "/password"),
                                                          "mac": mac, "verdict": verdict})
        self.assertEqual(resp.status_code, 302)
        with self.client.session_transaction() as s:
            return resp.headers["Location"], "\n".join(text for _, text in s.pop("_flashes", []))

    def test_this_was_me(self):
        self.db_results = [[{"verdict": "me"}]]
        where, text = self.post_review(MAC, "me")
        self.assertTrue(where.endswith("/devices"))
        self.assertIn("marked as your device", text)
        self.mocks["send_disconnect"].assert_not_called()

    def test_not_me_disconnects_and_opens_the_password_page(self):
        self.db_results = [[{"verdict": "not_me"}], [live_row(MAC)]]
        where, text = self.post_review(MAC, "not_me")
        self.assertTrue(where.endswith("/password"))
        self.assertIn("disconnected the device (ACK)", text)
        self.assertIn("Change it now", text)
        self.mocks["send_disconnect"].assert_called_once()

    def test_not_me_goes_to_the_password_page_when_the_disconnect_is_limited(self):
        for _ in range(5):
            self.assertTrue(portal.DISCONNECTS.attempt(UID))
        self.db_results = [[{"verdict": "not_me"}], [live_row(MAC)]]
        where, text = self.post_review(MAC, "not_me")
        self.assertTrue(where.endswith("/password"))
        self.assertIn("Too many disconnect requests", text)

    def test_not_me_shows_the_revoked_certificates(self):
        self.use_pki(["4f1c0e"])
        self.db_results = [[{"verdict": "not_me"}], [live_row(MAC)]]
        where, text = self.post_review(MAC, "not_me")
        self.assertTrue(where.endswith("/password"))
        self.assertIn("1 device certificate revoked", text)
        self.assertIn("Change it now", text)

    def test_not_me_says_when_a_certificate_was_not_revoked(self):
        self.use_pki(["4f1c0e"], revoke_error={"4f1c0e": portal.Unavailable("db down")})
        self.db_results = [[{"verdict": "not_me"}], []]
        where, text = self.post_review(MAC, "not_me")
        self.assertTrue(where.endswith("/password"))
        self.assertIn("could not be revoked", text)

    def test_review_of_a_device_that_is_not_mine(self):
        self.db_results = [[]]
        where, text = self.post_review(MAC, "not_me")
        self.assertTrue(where.endswith("/devices"))
        self.assertIn("No device of yours", text)
        self.mocks["send_disconnect"].assert_not_called()

    def test_review_uses_the_session_uid_only(self):
        self.db_results = [[{"verdict": "me"}]]
        self.client.post("/activity/review", data={"csrf_token": csrf_token(self.client, "/password"),
                                                   "mac": MAC, "verdict": "me", "uid": "someone-else",
                                                   "username": "someone-else"})
        self.assertEqual(self.queries()[0][1], ("me", UID, MAC))

    def test_review_needs_a_csrf_token(self):
        resp = self.client.post("/activity/review", data={"mac": MAC, "verdict": "me"})
        self.assertEqual(resp.status_code, 400)

    def test_nav_link(self):
        self.db_results = [[], [], [], []]
        self.assertIn('href="/activity"', self.client.get("/devices").get_data(as_text=True))


class PkiModuleTests(unittest.TestCase):
    """activity.pki_module(): the pki functions are used only when the portal loaded pki.py."""

    def test_none_without_the_pki_blueprint(self):
        with mock.patch.dict(portal.app.blueprints), mock.patch.dict(sys.modules):
            portal.app.blueprints.pop("pki", None)
            sys.modules["pki"] = types.ModuleType("pki")      # a module alone is not enough
            self.assertIsNone(activity.pki_module())

    def test_the_loaded_module(self):
        fake = types.ModuleType("pki")
        with mock.patch.dict(portal.app.blueprints, {"pki": object()}), mock.patch.dict(sys.modules, {"pki": fake}):
            self.assertIs(activity.pki_module(), fake)


if __name__ == "__main__":
    unittest.main()
