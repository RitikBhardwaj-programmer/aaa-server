"""Self-service portal for Wi-Fi users: log in, change password, see and disconnect own devices.

Lab limits (see README, "Self-service portal"):
- Flask's built-in server. Production needs a real WSGI server (a new dependency: needs approval).
- The rate limits are kept in this process's memory. Several portal processes would each count
  alone, so they would need a shared store.
- The session is a signed cookie: 15 minutes idle, 30 minutes at most after login. Every request
  re-checks the account in LDAP, so a password change, a disabled account or a lost Wi-Fi group
  ends every session of that user, including stolen copies of the cookie.

The route logic is in core functions (login_core, device_overview, disconnect_core, password_core).
They return data or raise a PortalError. The web pages below and the JSON API (apiauth.py and the
feature modules registered at the end of this file) call the same functions, so both get the same
checks and the same rate limits.
"""
import importlib.util
import ipaddress
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timedelta

import psycopg
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask.sessions import SecureCookieSessionInterface
from flask_wtf.csrf import CSRFError, CSRFProtect
from ldap3 import MODIFY_DELETE, NONE, SIMPLE, Connection, Server
from ldap3.core.exceptions import (LDAPBindError, LDAPException, LDAPInvalidCredentialsResult,
                                   LDAPNoSuchAttributeResult)
from ldap3.utils.conv import escape_filter_chars
from psycopg.rows import dict_row


def need(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not set")
    return value


BASE_DN = need("LDAP_BASE_DN")
PORTAL_DN = f"cn=portal,ou=Services,{BASE_DN}"
PORTAL_PASSWORD = need("LDAP_PORTAL_PASSWORD")
PG_PASSWORD = need("POSTGRES_PORTAL_PASSWORD")
ALLOW_PEAP = os.environ.get("ALLOW_PEAP", "yes") == "yes"
STALE_MINUTES = int(os.environ.get("STALE_SESSION_MINUTES", "25"))
DEVICE_LIMIT = int(os.environ.get("DEVICE_LIMIT_STUDENTS", "3"))
REAUTH_INTERVAL = int(os.environ.get("REAUTH_INTERVAL", "300"))
RADIUS_SECRET_AP = os.environ.get("RADIUS_SECRET_AP", "")
AP_IP = os.environ.get("AP_IP", "")

# Docker Desktop shows every access point as this address (see README 6.4); the real target is AP_IP
DOCKER_GATEWAY = "10.89.0.1"
DAS_PORT = 3799
WIFI_GROUPS = {"students", "faculty", "staff", "guests"}
UID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")        # same rule as ldap/add-user.sh
MAC_RE = re.compile(r"[0-9A-Za-z:.-]{1,40}")
GENERIC_LOGIN_ERROR = "Login failed. Check your ID and password, then try again."
MIN_LENGTH, MAX_LENGTH = 15, 128                    # NIST SP 800-63B-4

SESSION_ABSOLUTE_SECONDS = 30 * 60   # a session ends this long after login, even while in use
API_PREFIX = "/api/"                 # JSON API (apiauth.py): Bearer token only, no cookie, no CSRF

SECRET_KEY = need("PORTAL_SECRET_KEY")
if len(SECRET_KEY) < 32 or SECRET_KEY == "change-me":
    # Whoever knows the key can forge a session for any user
    raise RuntimeError("PORTAL_SECRET_KEY must be a random value of at least 32 characters (scripts/init.ps1 makes one)")


class PortalSessionInterface(SecureCookieSessionInterface):
    def should_set_cookie(self, app, session):
        # The API uses Bearer tokens only: an /api response never sets or refreshes the web session
        return not is_api_request() and super().should_set_cookie(app, session)


app = Flask(__name__)
app.session_interface = PortalSessionInterface()
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_NAME="portal_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    # false in the lab (http on localhost); true behind https
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in ("1", "true", "yes"),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    WTF_CSRF_TIME_LIMIT=900,
    # CSRF follows the path, not the view: csrf_for_web() checks every request outside /api
    WTF_CSRF_CHECK_DEFAULT=False,
    MAX_CONTENT_LENGTH=16 * 1024,
)
csrf = CSRFProtect(app)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = app.logger

with open(os.path.join(os.path.dirname(__file__), "blocklist.txt"), encoding="utf-8") as f:
    BLOCKLIST = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


# ---- Errors of the core functions -------------------------------------------------------------

class PortalError(Exception):
    """A request that the core functions refuse. The message is safe to show to the user.
    status is the HTTP status, code is the stable name the API sends (docs/api/v1.md)."""

    status, code = 400, "invalid_input"

    def __init__(self, message, code=None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code


class InvalidInput(PortalError):
    status, code = 400, "invalid_input"


class LoginFailed(PortalError):
    status, code = 401, "login_failed"


class NotFound(PortalError):
    status, code = 404, "not_found"


class Conflict(PortalError):
    status, code = 409, "conflict"


class RateLimited(PortalError):
    status, code = 429, "rate_limited"


class Unavailable(PortalError):
    status, code = 503, "unavailable"


# ---- Rate limits ------------------------------------------------------------------------------

class AttemptLimiter:
    """At most `limit` attempts per key in `window` seconds, in memory (one process only).

    attempt() counts BEFORE the work is done, inside the lock, so parallel requests cannot all
    pass the check before any failure is recorded. succeeded() takes the attempt back.
    Memory is bounded without ever dropping a key that still holds attempts: when the table is
    full, expired keys are removed and, if it is still full, new keys are refused (fail closed),
    so a flood of junk names cannot push out a real user's count.
    """

    MAX_KEYS = 10000

    def __init__(self, limit, window):
        self.limit, self.window = limit, window
        self.attempts = {}
        self.lock = threading.Lock()

    def _recent(self, key, now):
        q = self.attempts.get(key)
        if q is None:
            return 0
        while q and now - q[0] > self.window:
            q.popleft()
        if not q:
            del self.attempts[key]
            return 0
        return len(q)

    def attempt(self, key):
        """True and counted when allowed; False when the key is over its limit or the table is full."""
        with self.lock:
            now = time.monotonic()
            if self._recent(key, now) >= self.limit:
                return False
            if key not in self.attempts and len(self.attempts) >= self.MAX_KEYS:
                for k in list(self.attempts):
                    self._recent(k, now)
                if len(self.attempts) >= self.MAX_KEYS:
                    return False
            self.attempts.setdefault(key, deque()).append(now)
            return True

    def succeeded(self, key, forget_all=False):
        """Takes back the last attempt (or all of them) after a success."""
        with self.lock:
            q = self.attempts.get(key)
            if q and not forget_all:
                q.pop()
            if not q or forget_all:
                self.attempts.pop(key, None)

    def reset(self):
        with self.lock:
            self.attempts.clear()


# Separate instances, so one kind of attempt can never fill another's count
LOGIN_BY_USER = AttemptLimiter(5, 15 * 60)      # key (uid, client IP)
LOGIN_BY_IP = AttemptLimiter(20, 15 * 60)       # key client IP: stops spraying one password over many IDs
PASSWORD_BY_USER = AttemptLimiter(5, 15 * 60)   # key uid: wrong "current password" on the password page
DISCONNECTS = AttemptLimiter(5, 5 * 60)         # key uid: Disconnect-Requests sent
# key uid: API calls with a valid token. Each call costs two LDAP searches on the one shared portal
# connection, which logins also need
API_CALLS = AttemptLimiter(60, 60)
LIMITERS = (LOGIN_BY_USER, LOGIN_BY_IP, PASSWORD_BY_USER, DISCONNECTS, API_CALLS)
# At most this many logins at once: every login costs slapd up to three Argon2 checks, and the same
# slapd checks Wi-Fi passwords for the whole campus
LOGIN_SLOTS = threading.BoundedSemaphore(4)
DISCONNECTS_RUNNING = set()                     # uids with a Disconnect-Request in progress
DISCONNECTS_LOCK = threading.Lock()


def client_ip():
    return request.remote_addr or "?"


# ---- LDAP -------------------------------------------------------------------------------------

SERVER = Server("ldap", port=389, get_info=NONE, connect_timeout=5)
BAD_CREDENTIALS = (LDAPInvalidCredentialsResult, LDAPBindError)


def ldap_bind(dn, password):
    """Opens a simple-bind connection. Raises BAD_CREDENTIALS for a wrong password."""
    if not password:
        # An empty password would be an anonymous bind, which always "succeeds"
        raise LDAPBindError("empty password")
    conn = Connection(SERVER, user=dn, password=password, authentication=SIMPLE,
                      raise_exceptions=True, receive_timeout=10)
    try:
        if not conn.bind():
            raise LDAPBindError("bind refused")
    except Exception:
        # Close the socket at once: a failed bind would otherwise keep a connection to slapd open
        # until garbage collection, which a flood of wrong passwords could pile up
        conn.unbind()
        raise
    return conn


def entries(conn):
    return [e for e in conn.response if e.get("type") == "searchResEntry"]


# One long-lived connection bound as the read-only portal account, shared by all requests (under a
# lock: ldap3 connections are not thread-safe). A new bind per search would cost slapd an Argon2
# check each time, which a flood of login attempts could turn against Wi-Fi logins.
_portal_conn = None
_portal_lock = threading.Lock()


def portal_search(base, filt, attributes, scope="SUBTREE"):
    global _portal_conn
    with _portal_lock:
        for try_no in (1, 2):
            try:
                if _portal_conn is None or not _portal_conn.bound:
                    _portal_conn = ldap_bind(PORTAL_DN, PORTAL_PASSWORD)
                _portal_conn.search(base, filt, search_scope=scope, attributes=attributes)
                return entries(_portal_conn)
            except LDAPException:
                # Stale connection (slapd restarted, idle timeout): bind again once
                try:
                    _portal_conn.unbind()
                except Exception:
                    pass
                _portal_conn = None
                if try_no == 2:
                    raise


def first_value(attrs, name):
    value = attrs.get(name)
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value) if value is not None else None


def find_user(typed_uid):
    """(dn, uid as stored in LDAP) of the user, or None. Uses the read-only portal account."""
    found = portal_search(BASE_DN, f"(&(objectClass=inetOrgPerson)(uid={escape_filter_chars(typed_uid)}))",
                          ["uid"])
    if len(found) != 1:
        return None
    for stored in found[0]["attributes"].get("uid", []):
        # LDAP matches uid case-insensitively; accounting and the device limit use the stored form
        if stored.lower() == typed_uid.lower():
            return found[0]["dn"], stored
    return None


def user_groups(dn):
    names = set()
    for e in portal_search(f"ou=Groups,{BASE_DN}",
                           f"(&(objectClass=groupOfNames)(member={escape_filter_chars(dn)}))", ["cn"]):
        names.update(c.lower() for c in e["attributes"].get("cn", []))
    return names


def account_state(dn):
    """Current state of the account: {"version", "groups", "allowed"}, or None if the entry is gone.
    version is the entry's entryCSN, which changes with every modification (microsecond resolution,
    unlike modifyTimestamp), including every password change."""
    found = portal_search(dn, "(objectClass=inetOrgPerson)", ["entryCSN"], scope="BASE")
    if len(found) != 1:
        return None
    version = first_value(found[0]["attributes"], "entryCSN")
    groups = user_groups(dn)
    # No readable version = no way to notice a password change, so no session (fail closed)
    return {"version": version, "groups": groups,
            "allowed": version is not None and "disabled" not in groups and bool(groups & WIFI_GROUPS)}


def authenticate(typed_uid, password):
    """User dict on success, None for any failure. Raises LDAPException if LDAP is unreachable."""
    if not UID_RE.fullmatch(typed_uid) or not password or len(password) > 256:
        return None
    found = find_user(typed_uid)
    if found is None:
        return None
    dn, uid = found
    try:
        ldap_bind(dn, password).unbind()
    except BAD_CREDENTIALS:
        return None
    state = account_state(dn)
    if state is None or not state["allowed"]:
        return None
    return {"dn": dn, "uid": uid, "student": "students" in state["groups"], "version": state["version"]}


# ---- Password change (LDAP Password Modify; docs/decisions/0002) -----

class PasswordChangeError(PortalError):
    """Message is safe to show to the user."""

    status, code = 400, "password_refused"


class WrongOldPassword(PasswordChangeError):
    status, code = 403, "wrong_password"


def change_password(dn, old, new):
    """RFC 3062 Password Modify as the user. slapd checks the old password and hashes the new one
    ({ARGON2}). userPassword is never written directly.

    First the user's NT hash (PEAP-MSCHAPv2) is deleted: Password Modify does not update it, so the
    OLD password would otherwise keep working for PEAP. Deleting it first is the safe order: if the
    password change then fails, the user only loses PEAP, never keeps a password they replaced."""
    try:
        conn = ldap_bind(dn, old)
    except BAD_CREDENTIALS:
        raise WrongOldPassword("The current password is wrong.") from None
    try:
        try:
            conn.modify(dn, {"sambaNTPassword": [(MODIFY_DELETE, [])]})
        except LDAPNoSuchAttributeResult:
            pass                        # no NT hash (PEAP was off when the user was made)
        except LDAPException:
            log.exception("could not delete the NT hash of %s", dn)
            raise PasswordChangeError("The password was not changed: the old PEAP login could not be "
                                      "removed. Contact the network office.") from None
        if not conn.extend.standard.modify_password(user=dn, old_password=old, new_password=new):
            raise PasswordChangeError("The directory refused the new password.")
    except LDAPException:
        log.exception("password modify failed for %s", dn)
        raise PasswordChangeError("The directory refused the new password.") from None
    finally:
        conn.unbind()


def check_new_password(uid, new, confirm):
    """Error text, or None when the password is acceptable (no composition rules)."""
    if new != confirm:
        return "The new password and the confirmation are not the same."
    if len(new) < MIN_LENGTH:
        return f"The new password must have at least {MIN_LENGTH} characters."
    if len(new) > MAX_LENGTH:
        return f"The new password must have at most {MAX_LENGTH} characters."
    if uid.lower() in new.lower():
        return "The new password must not contain your user ID."
    if new.lower() in BLOCKLIST:
        return "That password is too common. Choose another one."
    return None


# ---- PostgreSQL (role "portal": SELECT only) ----------------------------------------------------

def db():
    return psycopg.connect(host="postgres", dbname="radius", user="portal", password=PG_PASSWORD,
                           connect_timeout=5, autocommit=True, row_factory=dict_row)


def live_sessions(cur, uid):
    """Open sessions of this user with an accounting update within STALE_SESSION_MINUTES."""
    cur.execute(
        """SELECT acctsessionid, callingstationid, calledstationid, host(nasipaddress) AS nas,
                  host(framedipaddress) AS ip, acctstarttime, acctupdatetime,
                  acctinputoctets, acctoutputoctets
           FROM radacct
           WHERE username = %s AND acctstoptime IS NULL
             AND COALESCE(acctupdatetime, acctstarttime) > now() - make_interval(mins => %s)
           ORDER BY acctstarttime DESC""", (uid, STALE_MINUTES))
    return cur.fetchall()


def _write_secret_file():
    """The AP's RADIUS secret in a private file for radclient -S, so it is not on a command line
    (visible in /proc and `docker top` while radclient runs). mkstemp creates it with mode 0600."""
    if not RADIUS_SECRET_AP:
        return None
    fd, path = tempfile.mkstemp(prefix="das-secret-")
    with os.fdopen(fd, "w") as f:
        f.write(RADIUS_SECRET_AP + "\n")
    return path


SECRET_FILE = _write_secret_file()


def send_disconnect(uid, s):
    """RFC 5176 Disconnect-Request for one session. Returns "ACK", "NAK" or "none" (no reply)."""
    target = AP_IP if s["nas"] == DOCKER_GATEWAY else s["nas"]
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return "none"
    if SECRET_FILE is None:
        return "none"
    values = (uid, s["acctsessionid"], s["callingstationid"])
    if any(re.search(r'["\\\r\n]', v) for v in values):
        return "none"           # would break out of the attribute list; never send it
    attrs = ('User-Name = "%s", Acct-Session-Id = "%s", Calling-Station-Id = "%s", '
             'Message-Authenticator = 0x00\n' % values)
    try:
        # Argument list, no shell. The attributes go in on stdin.
        out = subprocess.run(["radclient", "-r", "2", "-t", "3", "-S", SECRET_FILE,
                              f"{target}:{DAS_PORT}", "disconnect"],
                             input=attrs, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "none"
    answers = re.findall(r"Disconnect-(ACK|NAK)", out.stdout + out.stderr)
    return answers[-1] if answers else "none"


# ---- Core functions (used by the web pages and by the API) -------------------------------------

def current_account(dn, version):
    """The account state when the account is unchanged since login (same entry version, not
    disabled, still in a Wi-Fi group); None otherwise. Raises LDAPException if LDAP is unreachable.
    login_required and apiauth.api_auth_required call it on every request."""
    state = account_state(dn)
    if state is None or not state["allowed"] or version is None or state["version"] != version:
        return None
    return state


def login_core(typed_uid, password, ip):
    """User dict ({"dn", "uid", "student", "version"}) on success. Raises Unavailable (busy or LDAP
    down), RateLimited or LoginFailed. All failures of the credentials give the same message."""
    typed = typed_uid.strip()
    valid = bool(UID_RE.fullmatch(typed))
    shown = typed if valid else "(invalid format)"      # never log a pasted password
    if not LOGIN_SLOTS.acquire(blocking=False):
        raise Unavailable("The login service is busy. Try again in a moment.", code="busy")
    try:
        # Every attempt is counted before the password is checked and taken back only on success,
        # so parallel requests cannot slip past the limit. A malformed ID counts against the
        # address only: it never creates a per-user entry.
        user_key = (typed.lower(), ip)
        if not LOGIN_BY_IP.attempt(ip) or (valid and not LOGIN_BY_USER.attempt(user_key)):
            log.warning("login blocked by rate limit: uid=%s ip=%s", shown, ip)
            raise RateLimited(GENERIC_LOGIN_ERROR)
        try:
            user = authenticate(typed, password) if valid else None
        except LDAPException:
            log.exception("LDAP unavailable during login")      # the attempt stays counted
            raise Unavailable("The login service is temporarily unavailable. Try again later.") from None
        if user is None:
            log.warning("login failed: uid=%s ip=%s", shown, ip)
            raise LoginFailed(GENERIC_LOGIN_ERROR)
        LOGIN_BY_USER.succeeded(user_key, forget_all=True)
        LOGIN_BY_IP.succeeded(ip)
    finally:
        LOGIN_SLOTS.release()
    log.info("login ok: uid=%s ip=%s", user["uid"], ip)
    return user


def device_overview(uid):
    """{"slots", "known", "events", "online"} for the user. Raises Unavailable."""
    try:
        with db() as conn, conn.cursor() as cur:
            live = live_sessions(cur, uid)
            cur.execute("SELECT callingstationid, first_seen, last_seen FROM user_devices "
                        "WHERE username = %s ORDER BY last_seen DESC", (uid,))
            known = cur.fetchall()
            cur.execute("SELECT eventtime, callingstationid, live_devices, device_limit, mode "
                        "FROM device_limit_events WHERE username = %s ORDER BY eventtime DESC LIMIT 10", (uid,))
            events = cur.fetchall()
    except psycopg.Error:
        log.exception("database error on the devices page")
        raise Unavailable("The device list is temporarily unavailable. Try again later.") from None
    online = {s["callingstationid"] for s in live}
    # One slot per device (a phone roaming between APs has several sessions), showing its newest
    # session, in the order the devices joined: past the limit, the latest joiner is the one "over"
    slots = {}
    for s in live:                                   # newest session first
        slot = slots.setdefault(s["callingstationid"], {"mac": s["callingstationid"], "session": s,
                                                        "joined": s["acctstarttime"]})
        slot["joined"] = min(slot["joined"], s["acctstarttime"])
    slots = sorted(slots.values(), key=lambda d: d["joined"])
    return {"slots": slots, "known": known, "events": events, "online": online}


def disconnect_core(uid, mac):
    """Sends a Disconnect-Request for each live session of this user's device. Returns a list of
    {"nas", "result"} (result "ACK", "NAK" or "none"). Raises InvalidInput, Unavailable, NotFound,
    Conflict (a disconnect of this user is in progress) or RateLimited."""
    if not MAC_RE.fullmatch(mac):
        raise InvalidInput("That device is not valid.")
    try:
        with db() as conn, conn.cursor() as cur:
            # The request is not trusted: only sessions of the logged-in user can match
            mine = [s for s in live_sessions(cur, uid) if s["callingstationid"] == mac]
    except psycopg.Error:
        log.exception("database error on disconnect")
        raise Unavailable("The device list is temporarily unavailable. Try again later.") from None
    if not mine:
        raise NotFound("No active session of yours was found for that device.")
    # Each request starts radclient (up to ~9 s): one at a time per user, and a few per 5 minutes
    with DISCONNECTS_LOCK:
        busy = uid in DISCONNECTS_RUNNING
        if not busy:
            DISCONNECTS_RUNNING.add(uid)
    if busy:
        raise Conflict("A disconnect is already in progress. Wait for it to finish.", code="disconnect_in_progress")
    try:
        if not DISCONNECTS.attempt(uid):
            raise RateLimited("Too many disconnect requests. Wait 5 minutes and try again.")
        results = [(s, send_disconnect(uid, s)) for s in mine]
    finally:
        with DISCONNECTS_LOCK:
            DISCONNECTS_RUNNING.discard(uid)
    for s, result in results:
        log.info("disconnect: uid=%s mac=%s nas=%s result=%s", uid, mac, s["nas"], result)
    return [{"nas": s["nas"], "result": result} for s, result in results]


def password_core(uid, dn, old, new, confirm):
    """Changes the password. Returns None on success: the account version then changes, which ends
    every web session and API token of the user. Raises InvalidInput (rules), RateLimited,
    WrongOldPassword, PasswordChangeError or Unavailable."""
    error = check_new_password(uid, new, confirm)
    if error:
        raise InvalidInput(error)
    # Counted before the old password is checked, so a stolen session cannot guess it, even in parallel
    if not PASSWORD_BY_USER.attempt(uid):
        raise RateLimited("Too many wrong attempts. Wait 15 minutes and try again.")
    try:
        change_password(dn, old, new)
    except WrongOldPassword:
        raise                                # stays counted
    except PasswordChangeError:
        PASSWORD_BY_USER.succeeded(uid)      # not a guess: take the attempt back
        raise
    except LDAPException:
        log.exception("password change failed")
        raise Unavailable("The login service is temporarily unavailable. Try again later.") from None
    PASSWORD_BY_USER.succeeded(uid, forget_all=True)
    log.info("password changed: uid=%s", uid)
    # A device certificate must not outlive the password that got it (pki.py, stage S5)
    if "pki" in app.blueprints:
        try:
            sys.modules["pki"].revoke_all_core(uid, "password")
        except Exception:               # the password is already changed: never turn that into an error
            log.exception("password changed, but the certificates of uid=%s could not be revoked", uid)


# ---- Pages ------------------------------------------------------------------------------------

def login_required(view):
    """A valid session is at most SESSION_ABSOLUTE_SECONDS old, and its account is unchanged since
    login: same entry version (a password change changes it), not disabled, still in a Wi-Fi group.
    Checked on every request, so the user's password change or an administrator's disable ends all
    sessions of that user, including a stolen copy of the cookie."""
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("login"))
        if time.time() - session.get("login_at", 0) > SESSION_ABSOLUTE_SECONDS:
            session.clear()
            flash("Your session has ended. Log in again.", "info")
            return redirect(url_for("login"))
        try:
            state = current_account(session["dn"], session.get("version"))
        except LDAPException:
            log.exception("LDAP unavailable during the session check")
            return render_template("message.html", title="Unavailable",
                                   text="The login service is temporarily unavailable. Try again later."), 503
        if state is None:
            session.clear()
            flash("Your account has changed. Log in again.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapper.__name__ = view.__name__
    return wrapper


@app.template_filter("when")
def when(value):
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "-"


@app.template_filter("clock")
def clock(value):
    """Short time for the device slots: "23:11" today, else "11 Oct 23:11" (database time zone)."""
    if not value:
        return "-"
    if value.date() == datetime.now(value.tzinfo).date():
        return value.strftime("%H:%M")
    return value.strftime("%d %b %H:%M")


@app.template_filter("size")
def size(value):
    n = float(value or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def page_helpers():
    # base.html shows a nav link only when the feature module that serves it is installed
    return {"has_endpoint": lambda endpoint: endpoint in app.view_functions}


def is_api_request():
    return request.path.startswith(API_PREFIX)


@app.before_request
def csrf_for_web():
    """Every form outside /api needs a CSRF token, whatever its view. /api needs none: apiauth
    accepts only the Authorization header there, which a browser never sends by itself."""
    if app.config["WTF_CSRF_ENABLED"] and request.endpoint and not is_api_request():
        csrf.protect()


@app.errorhandler(CSRFError)
def csrf_error(error):
    return render_template("message.html", title="Request refused",
                           text="The form has expired or is invalid. Go back, reload the page and try again."), 400


@app.route("/")
def index():
    return redirect(url_for("devices"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    typed = request.form.get("uid", "").strip()
    try:
        user = login_core(typed, request.form.get("password", ""), client_ip())
    except PortalError as exc:
        return render_template("login.html", error=exc.message, uid=typed), exc.status
    session.clear()                      # new session after login (no fixation)
    session.permanent = True
    session.update(uid=user["uid"], dn=user["dn"], student=user["student"], version=user["version"],
                   login_at=time.time())
    return redirect(url_for("devices"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/devices")
@login_required
def devices():
    uid = session["uid"]
    try:
        view = device_overview(uid)
    except PortalError as exc:
        return render_template("message.html", title="Devices", text=exc.message), exc.status
    return render_template("devices.html", uid=uid, **view,
                           show_limit=session.get("student") and DEVICE_LIMIT > 0, limit=DEVICE_LIMIT,
                           reauth=REAUTH_INTERVAL)


@app.route("/devices/disconnect", methods=["POST"])
@login_required
def disconnect():
    mac = request.form.get("mac", "")
    try:
        results = disconnect_core(session["uid"], mac)
    except PortalError as exc:
        flash(exc.message, "error")
        return redirect(url_for("devices"))
    for r in results:
        if r["result"] == "ACK":
            flash(f"{mac}: the access point disconnected the device (ACK).", "ok")
        elif r["result"] == "NAK":
            flash(f"{mac}: the access point refused the request (NAK). The device is dropped at the next "
                  f"re-check, within {REAUTH_INTERVAL} seconds.", "error")
        else:
            flash(f"{mac}: no reply from the access point. It ignores Disconnect-Requests, so the device is "
                  f"dropped at the next re-check, within {REAUTH_INTERVAL} seconds.", "info")
    return redirect(url_for("devices"))


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "GET":
        return render_template("password.html", peap=ALLOW_PEAP, min_length=MIN_LENGTH, max_length=MAX_LENGTH)
    try:
        password_core(session["uid"], session["dn"], request.form.get("old", ""),
                      request.form.get("new", ""), request.form.get("confirm", ""))
    except PortalError as exc:
        return render_template("password.html", error=exc.message, peap=ALLOW_PEAP,
                               min_length=MIN_LENGTH, max_length=MAX_LENGTH), 400
    # The account version changed, which ends every session of this user (including this one)
    session.clear()
    flash("Your password was changed. Log in with the new password.", "ok")
    if ALLOW_PEAP:
        flash("PEAP no longer works for your account. Set up your devices as EAP-TTLS with PAP.", "info")
    return redirect(url_for("login"))


# ---- Feature modules ------------------------------------------------------------------------------
# Each later stage adds its own module with a Blueprint named `bp` (docs/api/v1.md, "Feature modules").
# Only the modules that exist are loaded; an error inside one stops the portal (fail loud).

FEATURE_MODULES = ("apiauth", "api", "activity", "downloads", "pki")


def register_features():
    """Loads each feature file from this folder by its path, so a module of the same name elsewhere
    on sys.path can never load instead. The module is in sys.modules before it runs, because it
    imports app, and app may be imported from it."""
    here = os.path.dirname(os.path.abspath(__file__))
    for name in FEATURE_MODULES:
        path = os.path.join(here, f"{name}.py")
        if not os.path.isfile(path):
            continue                    # feature not installed
        module = sys.modules.get(name)
        if module is None or os.path.abspath(getattr(module, "__file__", "")) != path:
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
            except BaseException:
                del sys.modules[name]
                raise
        app.register_blueprint(module.bp)


register_features()
