"""JSON API, version 1: devices and password (docs/api/v1.md, section 3).

- The views call the same core functions as the web pages (device_overview, disconnect_core,
  password_core), so both front ends get the same checks, messages and rate limits
  (PASSWORD_BY_USER, DISCONNECTS, one disconnect at a time per user).
- Every view has apiauth.api_auth_required: the account is checked in LDAP on every call. A
  password change changes the entry version (entryCSN), so after POST /password this token and
  every other token and web session of the user get 401.
- The request is not trusted: the uid comes from the token only, and disconnect_core matches the
  MAC only against live sessions of that uid.
"""
from flask import Blueprint, g, jsonify

import apiauth
import app as core     # app.py imports this module at its end (register_features)

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def iso(value):
    """ISO 8601 with the UTC offset of the database time zone, or None."""
    return value.isoformat(timespec="seconds") if value is not None else None


def session_json(s):
    return {"access_point": s["calledstationid"], "ip": s["ip"],
            "started": iso(s["acctstarttime"]), "updated": iso(s["acctupdatetime"]),
            "bytes_up": s["acctinputoctets"], "bytes_down": s["acctoutputoctets"]}


@bp.route("/devices")
@apiauth.api_auth_required
def devices():
    u = g.api_user
    try:
        view = core.device_overview(u["uid"])
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
    limit = apiauth.device_limit(u["student"])
    # Slots are in joining order: past the limit, the latest joiners are the ones "over" (as on the web page)
    slots = [{"mac": slot["mac"], "joined": iso(slot["joined"]),
              "over_limit": limit is not None and number > limit,
              "session": session_json(slot["session"])}
             for number, slot in enumerate(view["slots"], start=1)]
    known = [{"mac": d["callingstationid"], "first_seen": iso(d["first_seen"]), "last_seen": iso(d["last_seen"]),
              "online": d["callingstationid"] in view["online"]} for d in view["known"]]
    events = [{"time": iso(e["eventtime"]), "mac": e["callingstationid"], "live_devices": e["live_devices"],
               "device_limit": e["device_limit"], "mode": e["mode"]} for e in view["events"]]
    return jsonify(online=len(view["online"]), device_limit=limit, reauth_interval=core.REAUTH_INTERVAL,
                   slots=slots, known=known, limit_events=events)


@bp.route("/devices/disconnect", methods=["POST"])
@apiauth.api_auth_required
def disconnect():
    body = apiauth.json_body()
    if body is None or not isinstance(body.get("mac"), str):
        return apiauth.api_error(400, "invalid_input", "Send mac as a string.")
    try:
        results = core.disconnect_core(g.api_user["uid"], body["mac"])
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
    return jsonify(mac=body["mac"], results=results)


@bp.route("/password", methods=["POST"])
@apiauth.api_auth_required
def password():
    body = apiauth.json_body()
    if body is None or not isinstance(body.get("old"), str) or not isinstance(body.get("new"), str):
        return apiauth.api_error(400, "invalid_input", "Send old and new as strings.")
    u = g.api_user
    try:
        core.password_core(u["uid"], u["dn"], body["old"], body["new"], confirm=body["new"])
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
    # The account version changed, which ends this token and every other token and web session
    return "", 204
