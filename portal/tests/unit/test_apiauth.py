"""API tokens and the /api rules (apiauth.py), with mocks only."""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from itsdangerous import URLSafeTimedSerializer

import apiauth
import app as portal

from .helpers import DN, PASSWORD, UID, CoreCase, csrf_token


class TokenTests(CoreCase):
    def test_token_issue_and_me(self):
        resp = self.api_login()
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["token_type"], "Bearer")
        self.assertEqual(body["expires_in"], apiauth.TOKEN_SECONDS)
        self.assertEqual(body["user"], {"uid": UID, "student": True, "device_limit": portal.DEVICE_LIMIT})
        me = self.client.get("/api/v1/me", headers=self.bearer(body["access_token"]))
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.get_json(), {"uid": UID, "student": True, "device_limit": portal.DEVICE_LIMIT})

    def test_token_carries_uid_dn_version_and_times(self):
        payload = apiauth.serializer.loads(self.api_token())
        self.assertEqual((payload["uid"], payload["dn"], payload["ver"]), (UID, DN, "csn-1"))
        self.assertEqual(payload["exp"] - payload["iat"], apiauth.TOKEN_SECONDS)

    def test_faculty_has_no_device_limit(self):
        self.state["groups"] = {"faculty"}
        self.assertIsNone(self.api_login().get_json()["user"]["device_limit"])

    def test_token_expires(self):
        token = self.api_token()
        later = time.time() + apiauth.TOKEN_SECONDS + 5
        with mock.patch("time.time", return_value=later):
            resp = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["error"]["code"], "unauthorized")
        self.assertIn("Bearer", resp.headers["WWW-Authenticate"])

    def test_absolute_limit_of_30_minutes(self):
        # A token that claims a later expiry is still refused 30 minutes after issue
        now = int(time.time())
        token = apiauth.serializer.dumps({"uid": UID, "dn": DN, "ver": "csn-1",
                                          "iat": now - 31 * 60, "exp": now + 600})
        self.assertEqual(self.client.get("/api/v1/me", headers=self.bearer(token)).status_code, 401)

    def test_tampered_tokens_are_refused(self):
        token = self.api_token()
        other_key = URLSafeTimedSerializer("another-secret-key-0123456789abcdef", salt=apiauth.TOKEN_SALT)
        claims = {"uid": "admin", "dn": DN, "ver": "csn-1", "iat": int(time.time()), "exp": int(time.time()) + 60}
        flipped = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
        for bad in (flipped, token + "x", other_key.dumps(claims), "junk", "a.b.c"):
            with self.subTest(bad=bad[:20]):
                self.assertEqual(self.client.get("/api/v1/me", headers=self.bearer(bad)).status_code, 401)

    def test_signed_but_unreadable_payload_is_401(self):
        # Right signature, payload not JSON: itsdangerous raises BadPayload (a BadData)
        signer = apiauth.serializer.make_signer(apiauth.TOKEN_SALT)
        token = signer.sign(b"not json").decode()
        self.assertEqual(self.client.get("/api/v1/me", headers=self.bearer(token)).status_code, 401)

    def test_real_web_secrets_are_not_tokens(self):
        # The real session cookie and a real CSRF token, both signed with PORTAL_SECRET_KEY
        self.assertEqual(self.web_login().status_code, 302)
        cookie = self.client.get_cookie("portal_session").value
        form_token = csrf_token(self.client, "/password")
        for value in (cookie, form_token):
            with self.subTest(value=value[:12]):
                api = portal.app.test_client()           # no cookie: only the header
                self.assertEqual(api.get("/api/v1/me", headers=self.bearer(value)).status_code, 401)

    def test_changed_entry_version_ends_the_token(self):
        token = self.api_token()
        self.state["version"] = "csn-2"          # e.g. a password change
        resp = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual(resp.status_code, 401)
        self.assertIn("changed", resp.get_json()["error"]["message"])

    def test_disabled_or_deleted_account_ends_the_token(self):
        token = self.api_token()
        self.state["allowed"] = False
        self.assertEqual(self.client.get("/api/v1/me", headers=self.bearer(token)).status_code, 401)
        self.state["allowed"] = True
        with mock.patch.object(portal, "account_state", return_value=None):
            self.assertEqual(self.client.get("/api/v1/me", headers=self.bearer(token)).status_code, 401)

    def test_ldap_down_during_the_token_check_is_503(self):
        token = self.api_token()
        self.ldap_down = True
        resp = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.get_json()["error"]["code"], "unavailable")

    def test_header_must_be_bearer(self):
        token = self.api_token()
        for value in ("", "Bearer", "Bearer   ", "Basic " + token, token):
            with self.subTest(value=value[:10]):
                resp = self.client.get("/api/v1/me", headers={"Authorization": value} if value else {})
                self.assertEqual(resp.status_code, 401)

    def test_token_lifetime_setting_is_checked(self):
        here = os.path.dirname(os.path.abspath(portal.__file__))
        for value in ("0", "31"):
            env = dict(os.environ, API_TOKEN_MINUTES=value, RADIUS_SECRET_AP="")
            run = subprocess.run([sys.executable, "-c", "import app"], env=env, capture_output=True,
                                 text=True, cwd=here)
            self.assertNotEqual(run.returncode, 0, value)
            self.assertIn("API_TOKEN_MINUTES", run.stderr)


class LoginErrorTests(CoreCase):
    def test_one_generic_message_for_every_credential_failure(self):
        answers = [self.api_login(uid=u, password=p) for u, p in
                   ((UID, "wrong"), ("nobody", PASSWORD), ("bad(uid)*", PASSWORD), (UID, ""))]
        for resp in answers:
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.get_json(), {"error": {"code": "login_failed",
                                                         "message": portal.GENERIC_LOGIN_ERROR}})

    def test_bad_body_is_400(self):
        for body in ([], {"uid": UID}, {"uid": 1, "password": PASSWORD}, {"uid": UID, "password": None}):
            with self.subTest(body=body):
                resp = self.client.post("/api/v1/auth/token", json=body)
                self.assertEqual(resp.status_code, 400)
                self.assertEqual(resp.get_json()["error"]["code"], "invalid_input")
        self.mocks["authenticate"].assert_not_called()

    def test_ldap_down_is_503(self):
        self.ldap_down = True
        resp = self.api_login()
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.get_json()["error"]["code"], "unavailable")


class SharedLimiterTests(CoreCase):
    """The API login uses the same limiter objects and login slots as the web login."""

    def test_api_failures_count_toward_the_web_limit(self):
        for _ in range(5):
            self.assertEqual(self.api_login(password="wrong").status_code, 401)
        self.assertEqual(self.web_login().status_code, 429)        # right password, but blocked

    def test_web_failures_count_toward_the_api_limit(self):
        for _ in range(5):
            self.assertEqual(self.web_login(password="wrong").status_code, 401)
        resp = self.api_login()
        self.assertEqual(resp.status_code, 429)
        self.assertEqual(resp.get_json(), {"error": {"code": "rate_limited", "message": portal.GENERIC_LOGIN_ERROR}})

    def test_spraying_over_both_front_ends_hits_the_address_limit(self):
        for i in range(10):
            self.api_login(uid=f"user{i}", password="wrong")
            self.web_login(uid=f"other{i}", password="wrong")
        self.assertEqual(self.api_login().status_code, 429)

    def test_login_slots_are_shared(self):
        taken = 0
        while portal.LOGIN_SLOTS.acquire(blocking=False):
            taken += 1
        try:
            resp = self.api_login()
            self.assertEqual(resp.status_code, 503)
            self.assertEqual(resp.get_json()["error"]["code"], "busy")
            self.assertEqual(self.web_login().status_code, 503)
        finally:
            for _ in range(taken):
                portal.LOGIN_SLOTS.release()
        self.assertEqual(self.api_login().status_code, 200)

    def test_uid_case_does_not_split_the_limit(self):
        for _ in range(5):
            self.api_login(uid=UID.upper(), password="wrong")
        self.assertEqual(self.web_login(uid=UID.lower()).status_code, 429)

    def test_success_takes_the_attempts_back(self):
        for _ in range(4):
            self.api_login(password="wrong")
        self.assertEqual(self.api_login().status_code, 200)
        for _ in range(4):
            self.assertEqual(self.web_login(password="wrong").status_code, 401)


class ApiRuleTests(CoreCase):
    def test_cookie_alone_is_refused(self):
        self.assertEqual(self.web_login().status_code, 302)      # the client now holds a web session
        self.db_results = [[], [], [], []]       # the last one: new-device alerts (activity.py)
        self.assertEqual(self.client.get("/devices").status_code, 200)
        resp = self.client.get("/api/v1/me")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["error"]["code"], "unauthorized")

    def test_api_never_sets_a_cookie(self):
        self.web_login()
        token = self.api_token()
        for resp in (self.client.get("/api/v1/me", headers=self.bearer(token)), self.client.get("/api/v1/me"),
                     self.api_login(password="wrong")):
            self.assertNotIn("Set-Cookie", resp.headers)

    def test_writes_need_a_json_content_type(self):
        cases = [dict(data={"uid": UID, "password": PASSWORD}),                  # a form
                 dict(data='{"uid": "x", "password": "y"}', content_type="text/plain"),
                 dict(data='{"uid": "x", "password": "y"}')]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                resp = self.client.post("/api/v1/auth/token", **kwargs)
                self.assertEqual(resp.status_code, 415)
                self.assertEqual(resp.get_json()["error"]["code"], "unsupported_media_type")
        self.mocks["authenticate"].assert_not_called()
        resp = self.client.post("/api/v1/auth/token", data='{"uid": "%s", "password": "%s"}' % (UID, PASSWORD),
                                content_type="application/json; charset=utf-8")
        self.assertEqual(resp.status_code, 200)

    def test_no_csrf_token_needed_on_the_api_but_still_on_the_web(self):
        self.assertEqual(self.api_login().status_code, 200)
        resp = self.client.post("/login", data={"uid": UID, "password": PASSWORD})
        self.assertEqual(resp.status_code, 400)

    def test_no_cors_headers(self):
        token = self.api_token()
        origin = {"Origin": "https://evil.example"}
        responses = [self.client.get("/api/v1/me", headers={**origin, **self.bearer(token)}),
                     self.client.options("/api/v1/me", headers={**origin, "Access-Control-Request-Method": "GET"}),
                     self.client.options("/api/v1/auth/token", headers=origin),
                     self.client.post("/api/v1/auth/token", json={"uid": UID, "password": PASSWORD}, headers=origin)]
        for resp in responses:
            self.assertFalse([h for h in resp.headers.keys() if h.lower().startswith("access-control-")])

    def test_security_headers_on_api_responses(self):
        for resp in (self.client.get("/api/v1/me"), self.api_login(), self.client.get("/api/v1/nothing")):
            self.assertEqual(resp.headers["Cache-Control"], "no-store")
            self.assertTrue(resp.headers["Content-Security-Policy"].startswith("default-src 'self'"))
            self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")

    def test_errors_under_api_are_json_and_web_errors_are_not(self):
        resp = self.client.get("/api/v1/nothing")
        self.assertEqual((resp.status_code, resp.get_json()["error"]["code"]), (404, "not_found"))
        resp = self.client.get("/api/v1/auth/token")
        self.assertEqual((resp.status_code, resp.get_json()["error"]["code"]), (405, "method_not_allowed"))
        resp = self.client.post("/api/v1/auth/token", data="x" * (32 * 1024), content_type="application/json")
        self.assertEqual((resp.status_code, resp.get_json()["error"]["code"]), (413, "too_large"))
        web = self.client.get("/nothing")
        self.assertEqual(web.status_code, 404)
        self.assertIn("text/html", web.content_type)

    def test_an_unprotected_api_view_is_refused(self):
        # A later stage that forgets api_auth_required gets 401, not an open endpoint
        def forgot_the_decorator():
            return {"secret": True}
        with mock.patch.dict(portal.app.view_functions, {"apiauth.me": forgot_the_decorator}):
            resp = self.client.get("/api/v1/me")
        self.assertEqual(resp.status_code, 401)

    def test_an_unprotected_api_post_is_401_not_a_csrf_error(self):
        def forgot_the_decorator():
            return {"secret": True}
        with mock.patch.dict(portal.app.view_functions, {"apiauth.token": forgot_the_decorator}):
            resp = self.client.post("/api/v1/auth/token", json={"uid": UID, "password": PASSWORD})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["error"]["code"], "unauthorized")

    def test_web_forms_still_need_a_csrf_token(self):
        self.web_login()
        for path, data in (("/logout", {}), ("/password", {"old": PASSWORD, "new": "x" * 20, "confirm": "x" * 20}),
                           ("/devices/disconnect", {"mac": "DE-AD-BE-EF-00-01"}), ("/login", {"uid": UID})):
            with self.subTest(path=path):
                resp = self.client.post(path, data=data)
                self.assertEqual(resp.status_code, 400)
                self.assertIn("The form has expired or is invalid", resp.get_data(as_text=True))
        self.mocks["change_password"].assert_not_called()
        self.mocks["send_disconnect"].assert_not_called()

    def test_api_decorators_refuse_views_outside_api(self):
        # A later stage that mounts an API view on a web path must not get a CSRF-free web form
        token = self.api_token()
        public = apiauth.api_public(lambda: "served")
        protected = apiauth.api_auth_required(lambda: "served")
        self.web_login()
        form = {"csrf_token": csrf_token(self.client, "/password")}
        with mock.patch.dict(portal.app.view_functions, {"logout": public}):
            resp = self.client.post("/logout", data=form)
        self.assertEqual((resp.status_code, resp.get_json()["error"]["code"]), (500, "server_error"))
        with mock.patch.dict(portal.app.view_functions, {"devices": protected}):
            resp = self.client.get("/devices", headers=self.bearer(token))
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("served", resp.get_data(as_text=True))

    def test_api_calls_are_limited_per_user(self):
        token = self.api_token()
        for _ in range(60):
            self.assertEqual(self.client.get("/api/v1/me", headers=self.bearer(token)).status_code, 200)
        checks = self.mocks["account_state"].call_count
        resp = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual((resp.status_code, resp.get_json()["error"]["code"]), (429, "rate_limited"))
        self.assertEqual(self.mocks["account_state"].call_count, checks)     # no LDAP work when limited

    def test_feature_files_load_from_the_portal_folder_only(self):
        # A module of the same name earlier on sys.path must not load instead of portal/apiauth.py
        here = os.path.dirname(os.path.abspath(portal.__file__))
        with tempfile.TemporaryDirectory() as other:
            with open(os.path.join(other, "apiauth.py"), "w") as f:
                f.write("raise RuntimeError('impostor module loaded')\n")
            code = ("import sys; sys.path.append(%r); import app; print(sys.modules['apiauth'].__file__)" % here)
            run = subprocess.run([sys.executable, "-c", code], env=dict(os.environ, RADIUS_SECRET_AP=""),
                                 capture_output=True, text=True, cwd=other)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), os.path.join(here, "apiauth.py"))

    def test_feature_hook_registered_apiauth(self):
        self.assertIn("apiauth", portal.app.blueprints)
        self.assertIn("apiauth.token", portal.app.view_functions)


if __name__ == "__main__":
    unittest.main()
