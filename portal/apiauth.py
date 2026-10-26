"""JSON API, version 1: Bearer tokens and the rules for every /api request (docs/api/v1.md).

- POST /api/v1/auth/token changes {uid, password} into a Bearer token. It calls app.login_core, so
  the API and the web login share the same rate limits and login slots.
- A token is signed with PORTAL_SECRET_KEY (itsdangerous, salt "api-v1", so a session cookie is
  never a valid token). It carries uid, dn, the entry version (entryCSN) and the issue time. It ends
  API_TOKEN_MINUTES after issue (default 15), and never later than 30 minutes after issue.
- api_auth_required checks the account in LDAP on every call, like login_required: a password
  change, a disabled account or a lost Wi-Fi group ends every token of that user.
- /api accepts only the Authorization header. A session cookie alone gets 401, so a web page on
  another site cannot use the browser's login (no CSRF token is needed for that reason).
- Writes (POST, PUT, PATCH) need Content-Type: application/json. No CORS headers are sent.
"""
import functools
import os
import time

from flask import Blueprint, current_app, g, jsonify, request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from ldap3.core.exceptions import LDAPException
from werkzeug.exceptions import HTTPException

import app as core     # app.py imports this module at its end (register_features)

TOKEN_SALT = "api-v1"
TOKEN_ABSOLUTE_SECONDS = 30 * 60
TOKEN_MINUTES = int(os.environ.get("API_TOKEN_MINUTES") or "15")
if not 1 <= TOKEN_MINUTES <= TOKEN_ABSOLUTE_SECONDS // 60:
    raise RuntimeError("API_TOKEN_MINUTES must be between 1 and 30")
TOKEN_SECONDS = TOKEN_MINUTES * 60
WRITE_METHODS = {"POST", "PUT", "PATCH"}

bp = Blueprint("apiauth", __name__, url_prefix="/api/v1")
serializer = URLSafeTimedSerializer(core.SECRET_KEY, salt=TOKEN_SALT)


def api_error(status, code, message, headers=None):
    """The one error shape of the API: {"error": {"code", "message"}}."""
    resp = jsonify(error={"code": code, "message": message})
    resp.status_code = status
    for name, value in (headers or {}).items():
        resp.headers[name] = value
    return resp


def portal_error(exc):
    """API response for a PortalError of the core functions."""
    return api_error(exc.status, exc.code, exc.message)


def unauthorized(message="Log in again."):
    return api_error(401, "unauthorized", message, {"WWW-Authenticate": 'Bearer realm="api"'})


def issue_token(user):
    now = int(time.time())
    return serializer.dumps({"uid": user["uid"], "dn": user["dn"], "ver": user["version"],
                             "iat": now, "exp": now + TOKEN_SECONDS})


def read_token(token):
    """The token's payload, or None when it is forged, changed or expired."""
    try:
        payload = serializer.loads(token, max_age=TOKEN_SECONDS)
    except BadSignature:                # includes SignatureExpired
        return None
    if not isinstance(payload, dict) or not all(isinstance(payload.get(k), str) for k in ("uid", "dn", "ver")):
        return None
    now = time.time()
    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int):
        return None
    if now > exp or now - iat > TOKEN_ABSOLUTE_SECONDS or iat > now + 60:
        return None
    return payload


def bearer_token():
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def device_limit(student):
    return core.DEVICE_LIMIT if student and core.DEVICE_LIMIT > 0 else None


def api_public(view):
    """An /api view that needs no token (only the token endpoint). Exempt from CSRF."""
    view.api_public = True
    return core.csrf.exempt(view)


def api_auth_required(view):
    """A valid Bearer token whose account is unchanged since the token was issued (same check as
    login_required, on every call). Sets g.api_user = {"uid", "dn", "version", "student"}."""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        token = bearer_token()
        if token is None:
            return unauthorized("A Bearer token is needed.")
        payload = read_token(token)
        if payload is None:
            return unauthorized()
        try:
            state = core.current_account(payload["dn"], payload["ver"])
        except LDAPException:
            core.log.exception("LDAP unavailable during the token check")
            return api_error(503, "unavailable", "The login service is temporarily unavailable. Try again later.")
        if state is None:
            return unauthorized("Your account has changed. Log in again.")
        g.api_user = {"uid": payload["uid"], "dn": payload["dn"], "version": payload["ver"],
                      "student": "students" in state["groups"]}
        return view(*args, **kwargs)
    wrapper.api_auth = True
    # No CSRF token: the browser never sends the Authorization header by itself
    return core.csrf.exempt(wrapper)


def json_body():
    """The request body as a dict, or None."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


# ---- Rules for every /api request ---------------------------------------------------------------

@bp.before_app_request
def api_rules():
    if not core.is_api_request():
        return None
    view = current_app.view_functions.get(request.endpoint)
    if view is None:
        return None                     # unknown path: the JSON 404 below
    if not (getattr(view, "api_auth", False) or getattr(view, "api_public", False)):
        # Safety net: an /api view that a later stage forgot to protect is refused (fail closed)
        core.log.error("unprotected API view refused: %s", request.endpoint)
        return unauthorized()
    if request.method in WRITE_METHODS and request.mimetype != "application/json":
        return api_error(415, "unsupported_media_type", "Send the request body as application/json.")
    return None


@bp.app_errorhandler(HTTPException)
def api_http_error(exc):
    """JSON errors for /api (unknown path, wrong method, body too large); web pages are unchanged."""
    if not core.is_api_request():
        return exc
    codes = {400: "invalid_input", 404: "not_found", 405: "method_not_allowed", 413: "too_large"}
    return api_error(exc.code or 500, codes.get(exc.code, "server_error"), exc.name)


# ---- Endpoints ----------------------------------------------------------------------------------

@bp.route("/auth/token", methods=["POST"])
@api_public
def token():
    body = json_body()
    if body is None or not isinstance(body.get("uid"), str) or not isinstance(body.get("password"), str):
        return api_error(400, "invalid_input", "Send uid and password as strings.")
    try:
        user = core.login_core(body["uid"], body["password"], core.client_ip())
    except core.PortalError as exc:
        return portal_error(exc)
    core.log.info("api token issued: uid=%s ip=%s", user["uid"], core.client_ip())
    return jsonify(access_token=issue_token(user), token_type="Bearer", expires_in=TOKEN_SECONDS,
                   user={"uid": user["uid"], "student": user["student"],
                         "device_limit": device_limit(user["student"])})


@bp.route("/me")
@api_auth_required
def me():
    u = g.api_user
    return jsonify(uid=u["uid"], student=u["student"], device_limit=device_limit(u["student"]))
