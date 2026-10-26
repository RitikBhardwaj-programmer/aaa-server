"""The web pages after the move to core functions: same answers, messages, limits and headers."""
import unittest

import app as portal

from .helpers import DN, MAC, NOW, PASSWORD, UID, CoreCase, csrf_token, live_row


class WebLoginTests(CoreCase):
    def test_login_ok_starts_a_session(self):
        resp = self.web_login()
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].endswith("/devices"))
        with self.client.session_transaction() as s:
            self.assertEqual((s["uid"], s["dn"], s["version"], s["student"]), (UID, DN, "csn-1", True))

    def test_failures_keep_status_and_message(self):
        resp = self.web_login(password="wrong")
        self.assertEqual(resp.status_code, 401)
        self.assertIn(portal.GENERIC_LOGIN_ERROR, resp.get_data(as_text=True))
        self.ldap_down = True
        resp = self.web_login()
        self.assertEqual(resp.status_code, 503)
        self.assertIn("temporarily unavailable", resp.get_data(as_text=True))

    def test_rate_limit_after_five_failures(self):
        for _ in range(5):
            self.web_login(password="wrong")
        resp = self.web_login()
        self.assertEqual(resp.status_code, 429)
        self.assertIn(portal.GENERIC_LOGIN_ERROR, resp.get_data(as_text=True))

    def test_junk_ids_count_against_the_address_only(self):
        self.web_login(uid="bad(uid)*")
        self.assertEqual(portal.LOGIN_BY_USER.attempts, {})
        self.assertEqual(len(portal.LOGIN_BY_IP.attempts), 1)

    def test_session_check_follows_the_account(self):
        self.web_login()
        self.db_results = [[], [], []]
        self.assertEqual(self.client.get("/devices").status_code, 200)
        self.state["version"] = "csn-2"
        resp = self.client.get("/devices")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_ldap_down_during_the_session_check(self):
        self.web_login()
        self.ldap_down = True
        self.assertEqual(self.client.get("/devices").status_code, 503)

    def test_headers_unchanged(self):
        self.web_login()
        self.db_results = [[], [], []]
        for path in ("/login", "/devices", "/password"):
            h = self.client.get(path).headers
            self.assertEqual(h["Content-Security-Policy"],
                             "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
            self.assertEqual(h["Cache-Control"], "no-store")
            self.assertEqual(h["X-Frame-Options"], "DENY")


class WebDeviceTests(CoreCase):
    def setUp(self):
        super().setUp()
        self.web_login()

    def test_devices_page_shows_slots_seen_devices_and_no_missing_features(self):
        other = "DE-AD-BE-EF-00-02"
        self.db_results = [[live_row(MAC, minutes_ago=5), live_row(other, minutes_ago=20)],
                           [{"callingstationid": MAC, "first_seen": NOW, "last_seen": NOW}],
                           []]
        html = self.client.get("/devices").get_data(as_text=True)
        self.assertIn("2 of 3 devices online", html)
        self.assertLess(html.index(other), html.index(MAC))      # slots in joining order
        self.assertIn("Devices seen", html)
        for missing in ("Sign-in activity", "Set up Wi-Fi", "Device certificates"):
            self.assertNotIn(missing, html)                    # their modules do not exist yet
        self.assertNotIn("<script", html)
        self.assertNotIn("<style", html)

    def test_devices_page_database_down(self):
        self.db_error = True
        resp = self.client.get("/devices")
        self.assertEqual(resp.status_code, 503)
        self.assertIn("The device list is temporarily unavailable", resp.get_data(as_text=True))

    def post_disconnect(self, mac):
        """The flashed messages, joined (the redirect to /devices is not followed)."""
        resp = self.client.post("/devices/disconnect", data={"csrf_token": csrf_token(self.client, "/password"),
                                                             "mac": mac})
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].endswith("/devices"))
        with self.client.session_transaction() as s:
            return "\n".join(text for _, text in s.pop("_flashes", []))

    def test_disconnect_of_my_mac(self):
        self.db_results = [[live_row(MAC)]]
        html = self.post_disconnect(MAC)
        self.assertIn(f"{MAC}: the access point disconnected the device (ACK).", html)
        self.mocks["send_disconnect"].assert_called_once()
        self.assertEqual(self.mocks["send_disconnect"].call_args.args[0], UID)

    def test_disconnect_messages(self):
        self.db_results = [[live_row("DE-AD-BE-EF-00-09")]]
        self.assertIn("No active session of yours was found for that device.",
                      self.post_disconnect(MAC))
        self.assertIn("That device is not valid.", self.post_disconnect("x" * 50))
        self.mocks["send_disconnect"].return_value = "none"
        self.db_results = [[live_row(MAC)]]
        self.assertIn("no reply from the access point", self.post_disconnect(MAC))

    def test_disconnect_rate_limit(self):
        for _ in range(5):
            self.db_results = [[live_row(MAC)]]
            self.post_disconnect(MAC)
        self.db_results = [[live_row(MAC)]]
        self.assertIn("Too many disconnect requests", self.post_disconnect(MAC))
        self.assertEqual(self.mocks["send_disconnect"].call_count, 5)

    def test_disconnect_core_refuses_a_second_one_in_progress(self):
        self.db_results = [[live_row(MAC)]]
        portal.DISCONNECTS_RUNNING.add(UID)
        self.addCleanup(portal.DISCONNECTS_RUNNING.discard, UID)
        with self.assertRaises(portal.Conflict) as cm:
            portal.disconnect_core(UID, MAC)
        self.assertEqual((cm.exception.status, cm.exception.code), (409, "disconnect_in_progress"))

    def test_disconnect_core_returns_one_result_per_session(self):
        self.db_results = [[live_row(MAC, nas="10.89.0.1"), live_row(MAC, nas="192.0.2.9")]]
        self.assertEqual(portal.disconnect_core(UID, MAC),
                         [{"nas": "10.89.0.1", "result": "ACK"}, {"nas": "192.0.2.9", "result": "ACK"}])


class WebPasswordTests(CoreCase):
    NEW = "a long new passphrase for wifi"

    def setUp(self):
        super().setUp()
        self.web_login()

    def post(self, old=PASSWORD, new=NEW, confirm=None):
        return self.client.post("/password", data={"csrf_token": csrf_token(self.client, "/password"),
                                                   "old": old, "new": new,
                                                   "confirm": new if confirm is None else confirm})

    def test_change_ok_ends_the_session(self):
        resp = self.post()
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])
        self.mocks["change_password"].assert_called_once_with(DN, PASSWORD, self.NEW)
        with self.client.session_transaction() as s:
            self.assertNotIn("uid", s)

    def test_rules_keep_their_messages(self):
        cases = [(dict(confirm="other"), "are not the same"), (dict(new="short"), "at least 15"),
                 (dict(new=UID + "-and-more-words"), "must not contain your user ID")]
        for kwargs, text in cases:
            with self.subTest(text=text):
                resp = self.post(**kwargs)
                self.assertEqual(resp.status_code, 400)
                self.assertIn(text, resp.get_data(as_text=True))
        self.mocks["change_password"].assert_not_called()

    def test_wrong_old_password_stays_counted(self):
        self.mocks["change_password"].side_effect = portal.WrongOldPassword("The current password is wrong.")
        for _ in range(5):
            self.assertIn("The current password is wrong.", self.post(old="x").get_data(as_text=True))
        resp = self.post(old="x")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Too many wrong attempts", resp.get_data(as_text=True))

    def test_directory_refusal_is_not_counted(self):
        self.mocks["change_password"].side_effect = portal.PasswordChangeError("The directory refused the new password.")
        for _ in range(6):
            self.assertIn("The directory refused the new password.", self.post().get_data(as_text=True))
        self.assertEqual(portal.PASSWORD_BY_USER.attempts, {})

    def test_ldap_down(self):
        self.mocks["change_password"].side_effect = portal.LDAPException("down")
        resp = self.post()
        self.assertEqual(resp.status_code, 400)
        self.assertIn("temporarily unavailable", resp.get_data(as_text=True))

    def test_password_core_error_types(self):
        with self.assertRaises(portal.InvalidInput):
            portal.password_core(UID, DN, PASSWORD, "short", "short")
        self.mocks["change_password"].side_effect = portal.WrongOldPassword("The current password is wrong.")
        with self.assertRaises(portal.WrongOldPassword) as cm:
            portal.password_core(UID, DN, "x", self.NEW, self.NEW)
        self.assertEqual((cm.exception.status, cm.exception.code), (403, "wrong_password"))


if __name__ == "__main__":
    unittest.main()
