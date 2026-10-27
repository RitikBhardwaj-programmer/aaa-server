"""Devices and password API (api.py) against the live LDAP and PostgreSQL, with Flask's test client.

Run by scripts/test.ps1 (service "portal-test") with the temporary user of test_portal.py. Only the
flows that the unit tests (tests/unit/test_api.py, mocks) cannot cover: real rows, real time zone,
real ownership in SQL, and a real wrong-password bind.

These tests do not change the password: the portal cannot write the NT hash back, and
test_portal.py (which runs after this file) checks it at its start. test_portal.py proves that a
real password change changes entryCSN and ends every session; the API uses the same check.
"""
import secrets
import unittest
from datetime import datetime

import app as portal

from tests.test_portal import PASSWORD, TEST_NAS, UID, radius_db

OTHER_UID = "api-other-" + secrets.token_hex(3)
MY_MAC, OTHER_MAC = "DE-AD-BE-EF-10-01", "DE-AD-BE-EF-10-02"


class ApiLiveCase(unittest.TestCase):
    def setUp(self):
        for limiter in portal.LIMITERS:
            limiter.reset()
        self.client = portal.app.test_client()
        resp = self.client.post("/api/v1/auth/token", json={"uid": UID, "password": PASSWORD})
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        self.headers = {"Authorization": "Bearer " + resp.get_json()["access_token"]}

    def error_code(self, resp):
        return resp.get_json()["error"]["code"]


class DeviceApiTests(ApiLiveCase):
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

    @classmethod
    def tearDownClass(cls):
        cls.clean()

    def test_devices_gives_only_own_rows_with_zoned_times(self):
        resp = self.client.get("/api/v1/devices", headers=self.headers)
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        body = resp.get_json()
        self.assertEqual(body["online"], 1)
        self.assertEqual([s["mac"] for s in body["slots"]], [MY_MAC])
        session = body["slots"][0]["session"]
        self.assertEqual((session["access_point"], session["ip"], session["bytes_up"], session["bytes_down"]),
                         ("AP-TEST", "10.99.0.5", 1024, 2048))
        for value in (body["slots"][0]["joined"], session["started"], session["updated"]):
            self.assertIsNotNone(datetime.fromisoformat(value).tzinfo, value)
        self.assertNotIn(OTHER_MAC, resp.get_data(as_text=True))

    def test_disconnect_of_a_mac_that_is_not_mine_is_404(self):
        resp = self.client.post("/api/v1/devices/disconnect", json={"mac": OTHER_MAC}, headers=self.headers)
        self.assertEqual((resp.status_code, self.error_code(resp)), (404, "not_found"))

    def test_disconnect_of_my_mac_sends_the_request(self):
        resp = self.client.post("/api/v1/devices/disconnect", json={"mac": MY_MAC}, headers=self.headers)
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        # Nothing answers at the test NAS
        self.assertEqual(resp.get_json(), {"mac": MY_MAC, "results": [{"nas": TEST_NAS, "result": "none"}]})


class PasswordApiTests(ApiLiveCase):
    def test_wrong_old_password_is_403_and_nothing_changes(self):
        new = secrets.token_hex(16)
        resp = self.client.post("/api/v1/password", json={"old": "wrong-old-password", "new": new},
                                headers=self.headers)
        self.assertEqual((resp.status_code, self.error_code(resp)), (403, "wrong_password"))
        # The token still works: the entry did not change
        self.assertEqual(self.client.get("/api/v1/me", headers=self.headers).status_code, 200)
        dn = portal.find_user(UID)[0]
        portal.ldap_bind(dn, PASSWORD).unbind()

    def test_rule_error_is_400_before_ldap(self):
        resp = self.client.post("/api/v1/password", json={"old": PASSWORD, "new": "xx" + UID + "-purple-tractor"},
                                headers=self.headers)
        self.assertEqual((resp.status_code, self.error_code(resp)), (400, "invalid_input"))
        self.assertIn("must not contain your user ID", resp.get_json()["error"]["message"])


if __name__ == "__main__":
    unittest.main()
