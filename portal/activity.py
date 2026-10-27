"""Sign-in activity and new-device alerts (stage S2; docs/api/v1.md section 4).

- Sign-in activity: the user's own logins of the last 30 days (time, result, access point, device).
  The role "portal" cannot read radpostauth. It calls the SQL function portal_signins (migration
  004), which returns only four columns of one user's rows, and this module gives it only the uid
  of the logged-in user. The access point tells where the user was: it is personal data.
- An alert is a device of this user (user_devices) first seen in the last ALERT_DAYS days with no
  review (device_reviews, migration 005). The devices page shows all alerts in one banner.
- "This was me" records the verdict "me". "Not me" records "not_me", disconnects the device if it is
  online (core.disconnect_core: same checks and limits as Disconnect), and sends the user to the
  password page.

The web pages and the API call the same core functions (signins_core, alerts_core, review_core).
"""
import re

import psycopg
from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, session, url_for

import apiauth
import app as core     # app.py loads this module at its end (register_features)

bp = Blueprint("activity", __name__)

ALERT_DAYS = 30
MAX_DAYS = 30           # also capped inside portal_signins
MAX_SIGNINS = 100       # also capped inside portal_signins
API_DEFAULT_DAYS = 7
VERDICTS = ("me", "not_me")

# Called-Station-Id is "<AP MAC>:<SSID>" (RFC 3580 3.20). The AP MAC itself can use ":" as separator.
STATION_RE = re.compile(r"((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"
                        r"|[0-9A-Fa-f]{12})(?::(.*))?")


# ---- Helpers ------------------------------------------------------------------------------------

def is_private_mac(mac):
    """True when the locally administered bit (0x02 of the first octet) is set: a random ("private")
    Wi-Fi address of a phone or laptop, not the address of its hardware."""
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(digits) != 12:
        return False
    return bool(int(digits[:2], 16) & 0x02)


def split_station(called):
    """(AP MAC, SSID) from a Called-Station-Id. A value that does not start with a MAC (for example
    "AP-615") is returned as the AP with no SSID."""
    if not called:
        return None, None
    m = STATION_RE.fullmatch(called)
    if m is None:
        return called, None
    return m.group(1), m.group(2) or None


def iso(value):
    return value.isoformat() if value else None


def signin_view(row):
    ap_mac, ssid = split_station(row["calledstationid"])
    return {"time": row["authdate"], "result": "accept" if row["reply"] == "Access-Accept" else "reject",
            "access_point": row["calledstationid"] or None, "ap_mac": ap_mac, "ssid": ssid,
            "mac": row["callingstationid"] or None, "private_mac": is_private_mac(row["callingstationid"])}


# ---- Core functions -------------------------------------------------------------------------------

def signins_core(uid, days=MAX_DAYS):
    """The user's sign-ins of the last `days` days (1..30), newest first, at most 100.
    Raises InvalidInput or Unavailable."""
    if not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        raise core.InvalidInput(f"days must be a whole number from 1 to {MAX_DAYS}.")
    try:
        with core.db() as conn, conn.cursor() as cur:
            cur.execute("SELECT authdate, reply, calledstationid, callingstationid "
                        "FROM portal_signins(%s, %s, %s)", (uid, days, MAX_SIGNINS))
            rows = cur.fetchall()
    except psycopg.Error:
        core.log.exception("database error on the sign-in activity")
        raise core.Unavailable("The sign-in activity is temporarily unavailable. Try again later.") from None
    return [signin_view(r) for r in rows]


def alerts_core(uid):
    """Devices of the user first seen in the last ALERT_DAYS days with no review, newest first:
    [{"mac", "first_seen", "last_seen", "online", "private_mac"}]. Raises Unavailable."""
    try:
        with core.db() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT d.callingstationid, d.first_seen, d.last_seen
                   FROM user_devices d
                   WHERE d.username = %s AND d.first_seen > now() - make_interval(days => %s)
                     AND NOT EXISTS (SELECT 1 FROM device_reviews r
                                     WHERE r.username = d.username AND r.callingstationid = d.callingstationid)
                   ORDER BY d.first_seen DESC""", (uid, ALERT_DAYS))
            rows = cur.fetchall()
            online = {s["callingstationid"] for s in core.live_sessions(cur, uid)} if rows else set()
    except psycopg.Error:
        core.log.exception("database error on the device alerts")
        raise core.Unavailable("The device alerts are temporarily unavailable. Try again later.") from None
    return [{"mac": r["callingstationid"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
             "online": r["callingstationid"] in online, "private_mac": is_private_mac(r["callingstationid"])}
            for r in rows]


def review_core(uid, mac, verdict):
    """Records the user's answer for one of their devices. A second answer replaces the first.
    For "not_me" it then disconnects the device if it is online.
    Returns {"mac", "verdict", "disconnect", "next"}. Raises InvalidInput, NotFound, Unavailable,
    and for "not_me" also Conflict or RateLimited from the disconnect (the verdict stays recorded)."""
    if verdict not in VERDICTS:
        raise core.InvalidInput('verdict must be "me" or "not_me".')
    if not isinstance(mac, str) or not core.MAC_RE.fullmatch(mac):
        raise core.InvalidInput("That device is not valid.")
    try:
        with core.db() as conn, conn.cursor() as cur:
            # Only a device of this user can match: the row is written only when user_devices has
            # (uid, mac). The foreign key of device_reviews checks the same again.
            cur.execute(
                """INSERT INTO device_reviews (username, callingstationid, verdict, reviewed_at)
                   SELECT d.username, d.callingstationid, %s, now()
                   FROM user_devices d WHERE d.username = %s AND d.callingstationid = %s
                   ON CONFLICT (username, callingstationid)
                   DO UPDATE SET verdict = EXCLUDED.verdict, reviewed_at = EXCLUDED.reviewed_at
                   RETURNING verdict""", (verdict, uid, mac))
            recorded = cur.fetchall()
    except psycopg.errors.ForeignKeyViolation:
        recorded = []                   # the device expired at the same moment
    except psycopg.Error:
        core.log.exception("database error on a device review")
        raise core.Unavailable("The device alerts are temporarily unavailable. Try again later.") from None
    if not recorded:
        raise core.NotFound("No device of yours was found with that address.")
    core.log.info("device review: uid=%s mac=%s verdict=%s", uid, mac, verdict)
    if verdict == "me":
        return {"mac": mac, "verdict": verdict, "disconnect": None, "next": None}
    try:
        results = core.disconnect_core(uid, mac)
    except core.NotFound:
        results = []                    # not online now
    return {"mac": mac, "verdict": verdict, "disconnect": results, "next": "password"}


# ---- Web pages ------------------------------------------------------------------------------------

@bp.app_context_processor
def alert_helpers():
    """_alerts.html (included by devices.html) calls new_device_alerts(). It reads the database only
    when a page asks for it, and only for the logged-in user."""
    def new_device_alerts():
        uid = session.get("uid")
        if not uid:
            return []
        try:
            return alerts_core(uid)
        except core.PortalError:
            return None                 # the banner says that the alerts are not available
    return {"new_device_alerts": new_device_alerts}


@bp.route("/activity")
@core.login_required
def page():
    try:
        signins = signins_core(session["uid"], MAX_DAYS)
    except core.PortalError as exc:
        return render_template("message.html", title="Sign-in activity", text=exc.message), exc.status
    return render_template("activity.html", signins=signins, days=MAX_DAYS, limit=MAX_SIGNINS)


def flash_disconnect(mac, results):
    for r in results:
        if r["result"] == "ACK":
            flash(f"{mac}: the access point disconnected the device (ACK).", "ok")
        else:
            flash(f"{mac}: the access point did not confirm the disconnect. The device is dropped at the "
                  f"next re-check, within {core.REAUTH_INTERVAL} seconds.", "info")


@bp.route("/activity/review", methods=["POST"])
@core.login_required
def review():
    mac, verdict = request.form.get("mac", ""), request.form.get("verdict", "")
    try:
        result = review_core(session["uid"], mac, verdict)
    except (core.Conflict, core.RateLimited) as exc:
        # Only "not_me" disconnects, and its verdict is already recorded: go on to the password
        flash(exc.message, "error")
        flash("Change your password now, so that the device cannot sign in again.", "error")
        return redirect(url_for("password"))
    except core.PortalError as exc:
        flash(exc.message, "error")
        return redirect(url_for("devices"))
    if verdict == "me":
        flash(f"{mac}: marked as your device.", "ok")
        return redirect(url_for("devices"))
    flash_disconnect(mac, result["disconnect"])
    flash("Someone else may know your password. Change it now, so that the device cannot sign in again.",
          "error")
    return redirect(url_for("password"))


# ---- API (docs/api/v1.md section 4) -----------------------------------------------------------------

def api_signin(s):
    return {**s, "time": iso(s["time"])}


@bp.route("/api/v1/activity")
@apiauth.api_auth_required
def api_activity():
    raw = request.args.get("days", str(API_DEFAULT_DAYS))
    if not re.fullmatch(r"[0-9]{1,2}", raw):
        return apiauth.api_error(400, "invalid_input", f"days must be a whole number from 1 to {MAX_DAYS}.")
    try:
        signins = signins_core(g.api_user["uid"], int(raw))
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
    return jsonify(days=int(raw), signins=[api_signin(s) for s in signins])


@bp.route("/api/v1/alerts")
@apiauth.api_auth_required
def api_alerts():
    try:
        alerts = alerts_core(g.api_user["uid"])
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
    return jsonify(count=len(alerts),
                   alerts=[{**a, "first_seen": iso(a["first_seen"]), "last_seen": iso(a["last_seen"])}
                           for a in alerts])


@bp.route("/api/v1/alerts/<mac>", methods=["POST"])
@apiauth.api_auth_required
def api_review(mac):
    body = apiauth.json_body()
    if body is None or not isinstance(body.get("verdict"), str):
        return apiauth.api_error(400, "invalid_input", 'Send verdict as "me" or "not_me".')
    try:
        return jsonify(review_core(g.api_user["uid"], mac, body["verdict"]))
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
