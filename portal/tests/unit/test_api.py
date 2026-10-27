"""Devices and password API (api.py, docs/api/v1.md section 3), with mocks only."""
import unittest
from unittest import mock

import app as portal

from .helpers import DN, MAC, NOW, PASSWORD, UID, CoreCase, FakeConnection, csrf_token, live_row

OTHER_MAC = "DE-AD-BE-EF-00-02"
NEW = "a long new passphrase for wifi"
ROUTES = (("GET", "/api/v1/devices", None),
          ("POST", "/api/v1/devices/disconnect", {"mac": MAC}),
          ("POST", "/api/v1/password", {"old": PASSWORD, "new": NEW}))


class ApiCase(CoreCase):
    def setUp(self):
        super().setUp()
        self.token = self.api_token()
        # A change of the password changes the entry version in LDAP, as slapd does
        self.mocks["change_password"].side_effect = self.fake_change_password

    def fake_change_password(self, dn, old, new):
        if old != self.good_password:
            raise portal.WrongOldPassword("The current password is wrong.")
        self.good_password = new
        self.state["version"] = "csn-2"

    def get(self, path, token=None):
        return self.client.get(path, headers=self.bearer(token or self.token))

    def post(self, path, body, token=None, **kwargs):
        return self.client.post(path, json=body, headers=self.bearer(token or self.token), **kwargs)

    def assertError(self, resp, status, code):
        self.assertEqual(resp.status_code, status, resp.get_data(as_text=True))
        body = resp.get_json()
        self.assertEqual(set(body), {"error"})
        self.assertEqual(set(body["error"]), {"code", "message"})
        self.assertEqual(body["error"]["code"], code)
        return body["error"]["message"]

    def web_client(self):
        web = portal.app.test_client()
        self.assertEqual(self.web_login(web).status_code, 302)
        return web


class AuthTests(ApiCase):
    def call(self, method, path, body, headers):
        if method == "GET":
            return self.client.get(path, headers=headers)
        return self.client.post(path, json=body, headers=headers)

    def test_every_route_needs_a_token(self):
        for method, path, body in ROUTES:
            for headers in ({}, self.bearer("junk"), {"Authorization": "Basic " + self.token}):
                with self.subTest(path=path, headers=headers):
                    resp = self.call(method, path, body, headers)
                    self.assertError(resp, 401, "unauthorized")
                    self.assertIn("Bearer", resp.headers["WWW-Authenticate"])
        self.mocks["db"].assert_not_called()
        self.mocks["change_password"].assert_not_called()

    def test_web_session_cookie_alone_is_refused(self):
        self.web_login()                         # self.client now holds a web session
        for method, path, body in ROUTES:
            with self.subTest(path=path):
                self.assertError(self.call(method, path, body, {}), 401, "unauthorized")
        self.mocks["db"].assert_not_called()

    def test_changed_account_ends_the_token_on_every_route(self):
        self.state["version"] = "csn-9"
        for method, path, body in ROUTES:
            with self.subTest(path=path):
                self.assertError(self.call(method, path, body, self.bearer(self.token)), 401, "unauthorized")
        self.mocks["db"].assert_not_called()

    def test_writes_need_a_json_content_type(self):
        for path, form in (("/api/v1/devices/disconnect", {"mac": MAC}),
                           ("/api/v1/password", {"old": PASSWORD, "new": NEW})):
            for kwargs in (dict(data=form), dict(data='{"mac": "x"}', content_type="text/plain")):
                with self.subTest(path=path, kwargs=kwargs):
                    resp = self.client.post(path, headers=self.bearer(self.token), **kwargs)
                    self.assertError(resp, 415, "unsupported_media_type")
        self.mocks["db"].assert_not_called()
        self.mocks["change_password"].assert_not_called()

    def test_wrong_method_is_405(self):
        for method, path in (("POST", "/api/v1/devices"), ("GET", "/api/v1/devices/disconnect"),
                             ("GET", "/api/v1/password")):
            with self.subTest(path=path):
                resp = self.client.open(path, method=method, json={}, headers=self.bearer(self.token))
                self.assertError(resp, 405, "method_not_allowed")

    def test_module_is_registered(self):
        self.assertIn("api", portal.app.blueprints)
        for endpoint in ("api.devices", "api.disconnect", "api.password"):
            self.assertTrue(getattr(portal.app.view_functions[endpoint], "api_auth", False), endpoint)

    def test_no_cookie_and_security_headers(self):
        self.db_results = [[], [], []]
        resp = self.get("/api/v1/devices")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("Set-Cookie", resp.headers)
        self.assertEqual(resp.headers["Cache-Control"], "no-store")
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")


class DevicesTests(ApiCase):
    SLOT_KEYS = {"mac", "joined", "over_limit", "session"}
    SESSION_KEYS = {"access_point", "ip", "started", "updated", "bytes_up", "bytes_down"}

    def test_shape_matches_the_contract(self):
        newest, older = live_row(MAC, minutes_ago=5), live_row(OTHER_MAC, minutes_ago=20)
        self.db_results = [[newest, older],
                           [{"callingstationid": MAC, "first_seen": NOW, "last_seen": NOW},
                            {"callingstationid": "DE-AD-BE-EF-00-07", "first_seen": NOW, "last_seen": NOW}],
                           [{"eventtime": NOW, "callingstationid": "DE-AD-BE-EF-00-03", "live_devices": 3,
                             "device_limit": 3, "mode": "soft"}]]
        resp = self.get("/api/v1/devices")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "application/json")
        body = resp.get_json()
        self.assertEqual(set(body), {"online", "device_limit", "reauth_interval", "slots", "known", "limit_events"})
        self.assertEqual((body["online"], body["device_limit"], body["reauth_interval"]),
                         (2, portal.DEVICE_LIMIT, portal.REAUTH_INTERVAL))
        self.assertEqual([s["mac"] for s in body["slots"]], [OTHER_MAC, MAC])      # joining order
        for slot in body["slots"]:
            self.assertEqual(set(slot), self.SLOT_KEYS)
            self.assertEqual(set(slot["session"]), self.SESSION_KEYS)
            self.assertFalse(slot["over_limit"])
        self.assertEqual(body["slots"][1], {
            "mac": MAC, "joined": "2026-10-26T11:55:00+00:00", "over_limit": False,
            "session": {"access_point": "AP-615", "ip": "10.10.0.20", "started": "2026-10-26T11:55:00+00:00",
                        "updated": "2026-10-26T11:55:00+00:00", "bytes_up": 2048, "bytes_down": 4096}})
        self.assertEqual(body["known"], [
            {"mac": MAC, "first_seen": "2026-10-26T12:00:00+00:00", "last_seen": "2026-10-26T12:00:00+00:00",
             "online": True},
            {"mac": "DE-AD-BE-EF-00-07", "first_seen": "2026-10-26T12:00:00+00:00",
             "last_seen": "2026-10-26T12:00:00+00:00", "online": False}])
        self.assertEqual(body["limit_events"], [{"time": "2026-10-26T12:00:00+00:00", "mac": "DE-AD-BE-EF-00-03",
                                                 "live_devices": 3, "device_limit": 3, "mode": "soft"}])

    def test_rows_are_read_for_the_token_uid_only(self):
        conn = FakeConnection([[], [], []])
        with mock.patch.object(portal, "db", return_value=conn):
            self.assertEqual(self.get("/api/v1/devices").status_code, 200)
        self.assertEqual(len(conn.cur.queries), 3)
        for sql, params in conn.cur.queries:
            self.assertEqual(params[0], UID, sql)

    def test_one_slot_per_device_and_joined_is_the_first_session(self):
        roaming = [live_row(MAC, nas="10.89.0.1", minutes_ago=3), live_row(MAC, nas="10.89.0.2", minutes_ago=15)]
        roaming[0]["calledstationid"] = "AP-616"
        self.db_results = [roaming, [], []]
        body = self.get("/api/v1/devices").get_json()
        self.assertEqual(body["online"], 1)
        self.assertEqual(len(body["slots"]), 1)
        slot = body["slots"][0]
        self.assertEqual(slot["joined"], "2026-10-26T11:45:00+00:00")
        self.assertEqual(slot["session"]["access_point"], "AP-616")             # the newest session

    def test_slots_past_the_limit_are_over(self):
        macs = [f"DE-AD-BE-EF-00-1{i}" for i in range(portal.DEVICE_LIMIT + 1)]
        # newest first, as live_sessions() orders them; the last MAC joined last
        self.db_results = [[live_row(m, minutes_ago=50 - i) for i, m in reversed(list(enumerate(macs)))], [], []]
        body = self.get("/api/v1/devices").get_json()
        self.assertEqual([s["mac"] for s in body["slots"]], macs)
        self.assertEqual([s["over_limit"] for s in body["slots"]], [False] * portal.DEVICE_LIMIT + [True])

    def test_no_limit_for_faculty(self):
        self.state["groups"] = {"faculty"}
        self.token = self.api_token()
        self.db_results = [[live_row(f"DE-AD-BE-EF-00-1{i}", minutes_ago=10 + i) for i in range(5)], [], []]
        body = self.get("/api/v1/devices").get_json()
        self.assertIsNone(body["device_limit"])
        self.assertFalse(any(s["over_limit"] for s in body["slots"]))

    def test_empty_values_are_null(self):
        row = live_row(MAC)
        row.update(calledstationid=None, ip=None, acctupdatetime=None, acctinputoctets=None)
        self.db_results = [[row], [], []]
        session = self.get("/api/v1/devices").get_json()["slots"][0]["session"]
        self.assertEqual(set(session), self.SESSION_KEYS)
        for key in ("access_point", "ip", "updated", "bytes_up"):
            self.assertIsNone(session[key], key)

    def test_database_down_is_503(self):
        self.db_error = True
        message = self.assertError(self.get("/api/v1/devices"), 503, "unavailable")
        self.assertIn("temporarily unavailable", message)


class DisconnectTests(ApiCase):
    def disconnect(self, mac=MAC, **kwargs):
        return self.post("/api/v1/devices/disconnect", {"mac": mac}, **kwargs)

    def test_my_mac_gives_one_result_per_nas(self):
        self.mocks["send_disconnect"].side_effect = ["ACK", "NAK", "none"]
        self.db_results = [[live_row(MAC, nas="10.89.0.1"), live_row(MAC, nas="192.0.2.9"),
                            live_row(MAC, nas="192.0.2.10"), live_row(OTHER_MAC)]]
        resp = self.disconnect()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"mac": MAC, "results": [
            {"nas": "10.89.0.1", "result": "ACK"}, {"nas": "192.0.2.9", "result": "NAK"},
            {"nas": "192.0.2.10", "result": "none"}]})
        self.assertEqual(self.mocks["send_disconnect"].call_count, 3)
        self.assertEqual({c.args[0] for c in self.mocks["send_disconnect"].call_args_list}, {UID})

    def test_mac_without_a_live_session_of_mine_is_404(self):
        # The live sessions are read for the uid of the token; another user's MAC is not among them
        self.db_results = [[live_row(OTHER_MAC)]]
        self.assertError(self.disconnect(MAC), 404, "not_found")
        self.db_results = [[]]
        self.assertError(self.disconnect(MAC), 404, "not_found")
        self.mocks["send_disconnect"].assert_not_called()

    def test_sessions_are_read_for_the_token_uid_only(self):
        conn = FakeConnection([[live_row(MAC)]])
        with mock.patch.object(portal, "db", return_value=conn):
            self.assertEqual(self.disconnect().status_code, 200)
        self.assertEqual([params[0] for _, params in conn.cur.queries], [UID])

    def test_uid_in_the_body_is_ignored(self):
        self.db_results = [[live_row(MAC)]]
        with mock.patch.object(portal, "disconnect_core", wraps=portal.disconnect_core) as core:
            resp = self.post("/api/v1/devices/disconnect", {"mac": MAC, "uid": "someone-else"})
        self.assertEqual(resp.status_code, 200)
        core.assert_called_once_with(UID, MAC)

    def test_bad_input_is_400(self):
        for body in ({}, {"mac": None}, {"mac": 42}, {"mac": [MAC]}, [MAC]):
            with self.subTest(body=body):
                self.assertError(self.post("/api/v1/devices/disconnect", body), 400, "invalid_input")
        for mac in ("", "x" * 41, "DE AD BE EF", 'DE-AD"'):
            with self.subTest(mac=mac):
                self.assertError(self.disconnect(mac), 400, "invalid_input")
        self.mocks["db"].assert_not_called()
        self.mocks["send_disconnect"].assert_not_called()

    def test_one_disconnect_at_a_time(self):
        self.db_results = [[live_row(MAC)]]
        portal.DISCONNECTS_RUNNING.add(UID)
        self.addCleanup(portal.DISCONNECTS_RUNNING.discard, UID)
        self.assertError(self.disconnect(), 409, "disconnect_in_progress")
        self.mocks["send_disconnect"].assert_not_called()

    def test_rate_limit(self):
        for _ in range(5):
            self.db_results = [[live_row(MAC)]]
            self.assertEqual(self.disconnect().status_code, 200)
        self.db_results = [[live_row(MAC)]]
        self.assertError(self.disconnect(), 429, "rate_limited")
        self.assertEqual(self.mocks["send_disconnect"].call_count, 5)

    def web_disconnect(self, web):
        self.db_results = [[live_row(MAC)]]
        resp = web.post("/devices/disconnect", data={"csrf_token": csrf_token(web, "/password"), "mac": MAC})
        self.assertEqual(resp.status_code, 302)

    def test_web_disconnects_count_toward_the_api_limit(self):
        web = self.web_client()
        for _ in range(5):
            self.web_disconnect(web)
        self.db_results = [[live_row(MAC)]]
        self.assertError(self.disconnect(), 429, "rate_limited")
        self.assertEqual(self.mocks["send_disconnect"].call_count, 5)

    def test_api_disconnects_count_toward_the_web_limit(self):
        for _ in range(5):
            self.db_results = [[live_row(MAC)]]
            self.disconnect()
        web = self.web_client()
        self.web_disconnect(web)
        with web.session_transaction() as s:
            self.assertIn("Too many disconnect requests", " ".join(text for _, text in s["_flashes"]))
        self.assertEqual(self.mocks["send_disconnect"].call_count, 5)

    def test_database_down_is_503(self):
        self.db_error = True
        self.assertError(self.disconnect(), 503, "unavailable")


class PasswordTests(ApiCase):
    def change(self, old=PASSWORD, new=NEW, **kwargs):
        return self.post("/api/v1/password", {"old": old, "new": new}, **kwargs)

    def test_change_gives_204_and_no_body(self):
        resp = self.change()
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(resp.get_data(), b"")
        self.mocks["change_password"].assert_called_once_with(DN, PASSWORD, NEW)

    def test_change_ends_every_token_and_web_session(self):
        other_token = self.api_token()
        web = self.web_client()
        self.db_results = [[], [], [], []]       # the last one: new-device alerts (activity.py)
        self.assertEqual(web.get("/devices").status_code, 200)
        self.assertEqual(self.change().status_code, 204)
        for token in (self.token, other_token):
            self.assertError(self.get("/api/v1/me", token), 401, "unauthorized")
            self.assertError(self.change(token=token), 401, "unauthorized")
        self.assertIn("/login", web.get("/devices").headers["Location"])
        # A new login with the new password works
        resp = self.api_login(password=NEW)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.get("/api/v1/me", resp.get_json()["access_token"]).status_code, 200)
        self.assertEqual(self.api_login().status_code, 401)

    def test_rules_give_invalid_input_with_the_rule_text(self):
        cases = [("short", f"at least {portal.MIN_LENGTH}"),
                 ("x" * (portal.MAX_LENGTH + 1), f"at most {portal.MAX_LENGTH}"),
                 ("xx" + UID.upper() + "-purple-tractor", "must not contain your user ID"),
                 ("passwordpassword", "too common")]
        self.assertIn("passwordpassword", portal.BLOCKLIST)
        for new, text in cases:
            with self.subTest(text=text):
                self.assertIn(text, self.assertError(self.change(new=new), 400, "invalid_input"))
        self.mocks["change_password"].assert_not_called()
        self.assertEqual(portal.PASSWORD_BY_USER.attempts, {})       # a rule error is not a guess

    def test_new_is_also_the_confirmation(self):
        with mock.patch.object(portal, "password_core") as core:
            self.assertEqual(self.post("/api/v1/password", {"old": PASSWORD, "new": NEW, "confirm": "other"})
                             .status_code, 204)
        core.assert_called_once_with(UID, DN, PASSWORD, NEW, confirm=NEW)

    def test_bad_body_is_400(self):
        for body in ({}, {"old": PASSWORD}, {"new": NEW}, {"old": None, "new": NEW}, {"old": PASSWORD, "new": 5},
                     [PASSWORD, NEW]):
            with self.subTest(body=body):
                self.assertError(self.post("/api/v1/password", body), 400, "invalid_input")
        self.mocks["change_password"].assert_not_called()

    def test_wrong_old_password_is_403_and_counted(self):
        for _ in range(5):
            self.assertIn("current password is wrong", self.assertError(self.change(old="wrong"), 403, "wrong_password"))
        self.assertError(self.change(), 429, "rate_limited")          # even the right one, now
        self.assertEqual(self.state["version"], "csn-1")

    def test_directory_refusal_is_password_refused(self):
        self.mocks["change_password"].side_effect = portal.PasswordChangeError("The directory refused the new password.")
        for _ in range(6):
            message = self.assertError(self.change(), 400, "password_refused")
        self.assertEqual(message, "The directory refused the new password.")
        self.assertEqual(portal.PASSWORD_BY_USER.attempts, {})

    def test_ldap_down_is_503(self):
        self.mocks["change_password"].side_effect = portal.LDAPException("down")
        self.assertError(self.change(), 503, "unavailable")

    def web_change(self, web, old):
        return web.post("/password", data={"csrf_token": csrf_token(web, "/password"), "old": old,
                                           "new": NEW, "confirm": NEW})

    def test_web_failures_count_toward_the_api_limit(self):
        web = self.web_client()
        for _ in range(5):
            self.assertIn("current password is wrong", self.web_change(web, "wrong").get_data(as_text=True))
        self.assertError(self.change(), 429, "rate_limited")

    def test_api_failures_count_toward_the_web_limit(self):
        for _ in range(5):
            self.assertError(self.change(old="wrong"), 403, "wrong_password")
        web = self.web_client()
        self.assertIn("Too many wrong attempts", self.web_change(web, PASSWORD).get_data(as_text=True))
        self.mocks["change_password"].assert_called()
        self.assertEqual(self.state["version"], "csn-1")


class ApiCallLimitTests(ApiCase):
    def test_api_calls_limit_covers_the_new_routes(self):
        # The token request has no token, so it is not counted: 60 calls are left
        for _ in range(59):
            self.db_results = [[], [], []]
            self.assertEqual(self.get("/api/v1/devices").status_code, 200)
        self.db_results = [[]]
        self.assertEqual(self.post("/api/v1/devices/disconnect", {"mac": MAC}).status_code, 404)
        checks = self.mocks["account_state"].call_count
        self.assertError(self.post("/api/v1/password", {"old": PASSWORD, "new": NEW}), 429, "rate_limited")
        self.assertEqual(self.mocks["account_state"].call_count, checks)     # no LDAP work when limited
        self.mocks["change_password"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
