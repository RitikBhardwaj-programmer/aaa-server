"""Fakes for db() and the LDAP account lookup, and a base test case that installs them."""
import logging
import re
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import app as portal

UID, DN = "student042", "uid=student042,ou=People,dc=example,dc=test"
PASSWORD = "correct horse battery staple"
MAC = "DE-AD-BE-EF-00-01"
NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


class FakeCursor:
    """Gives the next prepared result to each fetchall(), in order."""

    def __init__(self, results):
        self.results = results
        self.queries = []

    def execute(self, sql, params=None):
        self.queries.append((sql, params))

    def fetchall(self):
        return self.results.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConnection:
    def __init__(self, results):
        self.cur = FakeCursor(results)

    def cursor(self):
        return self.cur

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def live_row(mac=MAC, nas="10.89.0.1", minutes_ago=5):
    start = NOW - timedelta(minutes=minutes_ago)
    return {"acctsessionid": "s-" + mac, "callingstationid": mac, "calledstationid": "AP-615",
            "nas": nas, "ip": "10.10.0.20", "acctstarttime": start, "acctupdatetime": start,
            "acctinputoctets": 2048, "acctoutputoctets": 4096}


def csrf_token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


class CoreCase(unittest.TestCase):
    """authenticate() and account_state() are mocks: self.good_password and self.state decide
    what LDAP "says". db() is a mock that gives self.db_results."""

    def setUp(self):
        logging.disable(logging.CRITICAL)        # the portal logs every failure; not useful here
        self.addCleanup(logging.disable, logging.NOTSET)
        for limiter in portal.LIMITERS:
            limiter.reset()
        self.state = {"version": "csn-1", "groups": {"students"}, "allowed": True}
        self.good_password = PASSWORD
        self.ldap_down = False
        self.db_results = []
        self.db_error = False
        patches = [
            mock.patch.object(portal, "authenticate", side_effect=self.fake_authenticate),
            mock.patch.object(portal, "account_state", side_effect=self.fake_account_state),
            mock.patch.object(portal, "db", side_effect=self.fake_db),
            mock.patch.object(portal, "send_disconnect", return_value="ACK"),
            mock.patch.object(portal, "change_password"),
        ]
        self.mocks = {}
        for p in patches:
            self.mocks[p.attribute] = p.start()
            self.addCleanup(p.stop)
        self.client = portal.app.test_client()

    def fake_authenticate(self, typed_uid, password):
        if self.ldap_down:
            raise portal.LDAPException("down")
        if typed_uid.lower() != UID or password != self.good_password or not self.state["allowed"]:
            return None
        return {"dn": DN, "uid": UID, "student": "students" in self.state["groups"],
                "version": self.state["version"]}

    def fake_account_state(self, dn):
        if self.ldap_down:
            raise portal.LDAPException("down")
        return dict(self.state) if dn == DN else None

    def fake_db(self):
        if self.db_error:
            raise portal.psycopg.OperationalError("down")
        return FakeConnection(self.db_results)

    # ---- helpers for the two front ends ----

    def web_login(self, client=None, uid=UID, password=PASSWORD, **kwargs):
        client = client or self.client
        return client.post("/login", data={"csrf_token": csrf_token(client), "uid": uid, "password": password},
                           **kwargs)

    def api_login(self, uid=UID, password=PASSWORD, **kwargs):
        return self.client.post("/api/v1/auth/token", json={"uid": uid, "password": password}, **kwargs)

    def api_token(self):
        resp = self.api_login()
        self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
        return resp.get_json()["access_token"]

    def bearer(self, token):
        return {"Authorization": "Bearer " + token}
