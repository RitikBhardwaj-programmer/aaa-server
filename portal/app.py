"""Self-service portal for Wi-Fi users: log in, change password, see and disconnect own devices.

Lab limits (see README, "Self-service portal"):
- Flask's built-in server. Production needs a real WSGI server (a new dependency: needs approval).
- The rate limits are kept in this process's memory. Several portal processes would each count
  alone, so they would need a shared store.
- The session is a signed cookie: 15 minutes idle, 30 minutes at most after login. Every request
  re-checks the account in LDAP, so a password change, a disabled account or a lost Wi-Fi group
  ends every session of that user, including stolen copies of the cookie.
"""
import ipaddress
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timedelta

import psycopg
from flask import Flask, flash, redirect, render_template, request, session, url_for
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
PASSWORD_BACKEND = os.environ.get("PASSWORD_BACKEND", "ldap")
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

SECRET_KEY = need("PORTAL_SECRET_KEY")
if len(SECRET_KEY) < 32 or SECRET_KEY == "change-me":
    # Whoever knows the key can forge a session for any user
    raise RuntimeError("PORTAL_SECRET_KEY must be a random value of at least 32 characters (scripts/init.ps1 makes one)")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_NAME="portal_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    # false in the lab (http on localhost); true behind https
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in ("1", "true", "yes"),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    WTF_CSRF_TIME_LIMIT=900,
    MAX_CONTENT_LENGTH=16 * 1024,
)
CSRFProtect(app)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = app.logger

with open(os.path.join(os.path.dirname(__file__), "blocklist.txt"), encoding="utf-8") as f:
    BLOCKLIST = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


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
LIMITERS = (LOGIN_BY_USER, LOGIN_BY_IP, PASSWORD_BY_USER, DISCONNECTS)
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


# ---- Password change: one backend function (LDAP now, Kerberos later; docs/decisions/0001) -----

class PasswordChangeError(Exception):
    """Message is safe to show to the user."""


class WrongOldPassword(PasswordChangeError):
    pass


def change_password_ldap(dn, old, new):
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


def change_password_krb5(dn, old, new):
    raise PasswordChangeError(
        "Password change through Kerberos is not set up yet (PASSWORD_BACKEND=krb5 is reserved; "
        "see docs/decisions/0001-ldap-now-kerberos-later.md).")


PASSWORD_BACKENDS = {"ldap": change_password_ldap, "krb5": change_password_krb5}
if PASSWORD_BACKEND not in PASSWORD_BACKENDS:
    raise RuntimeError(f"PASSWORD_BACKEND must be one of {sorted(PASSWORD_BACKENDS)}")


def change_password(dn, old, new):
    PASSWORD_BACKENDS[PASSWORD_BACKEND](dn, old, new)


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
            state = account_state(session["dn"])
        except LDAPException:
            log.exception("LDAP unavailable during the session check")
            return render_template("message.html", title="Unavailable",
                                   text="The login service is temporarily unavailable. Try again later."), 503
        if state is None or not state["allowed"] or state["version"] != session.get("version"):
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
    password = request.form.get("password", "")
    ip = client_ip()
    valid = bool(UID_RE.fullmatch(typed))
    shown = typed if valid else "(invalid format)"      # never log a pasted password
    if not LOGIN_SLOTS.acquire(blocking=False):
        return render_template("login.html", error="The login service is busy. Try again in a moment.",
                               uid=typed), 503
    try:
        # Every attempt is counted before the password is checked and taken back only on success,
        # so parallel requests cannot slip past the limit. A malformed ID counts against the
        # address only: it never creates a per-user entry.
        user_key = (typed.lower(), ip)
        if not LOGIN_BY_IP.attempt(ip) or (valid and not LOGIN_BY_USER.attempt(user_key)):
            log.warning("login blocked by rate limit: uid=%s ip=%s", shown, ip)
            return render_template("login.html", error=GENERIC_LOGIN_ERROR, uid=typed), 429
        try:
            user = authenticate(typed, password) if valid else None
        except LDAPException:
            log.exception("LDAP unavailable during login")      # the attempt stays counted
            return render_template("login.html", error="The login service is temporarily unavailable. "
                                   "Try again later.", uid=typed), 503
        if user is None:
            log.warning("login failed: uid=%s ip=%s", shown, ip)
            return render_template("login.html", error=GENERIC_LOGIN_ERROR, uid=typed), 401
        LOGIN_BY_USER.succeeded(user_key, forget_all=True)
        LOGIN_BY_IP.succeeded(ip)
    finally:
        LOGIN_SLOTS.release()
    session.clear()                      # new session after login (no fixation)
    session.permanent = True
    session.update(uid=user["uid"], dn=user["dn"], student=user["student"], version=user["version"],
                   login_at=time.time())
    log.info("login ok: uid=%s ip=%s", user["uid"], ip)
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
        return render_template("message.html", title="Devices",
                               text="The device list is temporarily unavailable. Try again later."), 503
    online = {s["callingstationid"] for s in live}
    # One slot per device (a phone roaming between APs has several sessions), showing its newest
    # session, in the order the devices joined: past the limit, the latest joiner is the one "over"
    slots = {}
    for s in live:                                   # newest session first
        slot = slots.setdefault(s["callingstationid"], {"mac": s["callingstationid"], "session": s,
                                                        "joined": s["acctstarttime"]})
        slot["joined"] = min(slot["joined"], s["acctstarttime"])
    slots = sorted(slots.values(), key=lambda d: d["joined"])
    return render_template("devices.html", uid=uid, slots=slots, known=known, events=events, online=online,
                           show_limit=session.get("student") and DEVICE_LIMIT > 0, limit=DEVICE_LIMIT,
                           reauth=REAUTH_INTERVAL)


@app.route("/devices/disconnect", methods=["POST"])
@login_required
def disconnect():
    uid = session["uid"]
    mac = request.form.get("mac", "")
    if not MAC_RE.fullmatch(mac):
        flash("That device is not valid.", "error")
        return redirect(url_for("devices"))
    try:
        with db() as conn, conn.cursor() as cur:
            # The form is not trusted: only sessions of the logged-in user can match
            mine = [s for s in live_sessions(cur, uid) if s["callingstationid"] == mac]
    except psycopg.Error:
        log.exception("database error on disconnect")
        flash("The device list is temporarily unavailable. Try again later.", "error")
        return redirect(url_for("devices"))
    if not mine:
        flash("No active session of yours was found for that device.", "error")
        return redirect(url_for("devices"))
    # Each request starts radclient (up to ~9 s): one at a time per user, and a few per 5 minutes
    with DISCONNECTS_LOCK:
        busy = uid in DISCONNECTS_RUNNING
        if not busy:
            DISCONNECTS_RUNNING.add(uid)
    if busy:
        flash("A disconnect is already in progress. Wait for it to finish.", "error")
        return redirect(url_for("devices"))
    try:
        if not DISCONNECTS.attempt(uid):
            flash("Too many disconnect requests. Wait 5 minutes and try again.", "error")
            return redirect(url_for("devices"))
        results = [(s, send_disconnect(uid, s)) for s in mine]
    finally:
        with DISCONNECTS_LOCK:
            DISCONNECTS_RUNNING.discard(uid)
    for s, result in results:
        log.info("disconnect: uid=%s mac=%s nas=%s result=%s", uid, mac, s["nas"], result)
        if result == "ACK":
            flash(f"{mac}: the access point disconnected the device (ACK).", "ok")
        elif result == "NAK":
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
    uid = session["uid"]
    old = request.form.get("old", "")
    new = request.form.get("new", "")
    confirm = request.form.get("confirm", "")
    error = check_new_password(uid, new, confirm)
    # Counted before the old password is checked, so a stolen session cannot guess it, even in parallel
    if error is None and not PASSWORD_BY_USER.attempt(uid):
        error = "Too many wrong attempts. Wait 15 minutes and try again."
    elif error is None:
        try:
            change_password(session["dn"], old, new)
        except WrongOldPassword as exc:
            error = str(exc)                # stays counted
        except PasswordChangeError as exc:
            PASSWORD_BY_USER.succeeded(uid)  # not a guess: take the attempt back
            error = str(exc)
        except LDAPException:
            log.exception("password change failed")
            error = "The login service is temporarily unavailable. Try again later."
    if error:
        return render_template("password.html", error=error, peap=ALLOW_PEAP,
                               min_length=MIN_LENGTH, max_length=MAX_LENGTH), 400
    PASSWORD_BY_USER.succeeded(uid, forget_all=True)
    log.info("password changed: uid=%s", uid)
    # The account version changed, which ends every session of this user (including this one)
    session.clear()
    flash("Your password was changed. Log in with the new password.", "ok")
    if ALLOW_PEAP:
        flash("PEAP no longer works for your account. Set up your devices as EAP-TTLS with PAP.", "info")
    return redirect(url_for("login"))
