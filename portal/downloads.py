"""Wi-Fi setup downloads (stage S3, docs/api/v1.md section 5; EAP-TLS: stage S6, section 7).

- /setup (web, login required) detects the OS from the User-Agent and offers the right file first,
  then the files for all other platforms.
- /setup/<file> gives one profile with the uid filled in and never a password (profiles.py).
- GET /api/v1/profiles/android gives the Android app the same settings as JSON, for EAP-TTLS or
  (?method=tls) for EAP-TLS.
- tls_profile() and tls_download() make the EAP-TLS profiles from a PKCS#12 file. They have no
  route here: the /certs page of pki.py (stage S5) calls them with the file that it just made, so
  this module does not need pki.py and works without it.

The lab root CA comes from PROFILE_CA_FILE (compose mounts certs/ca.pem read-only). Apple profiles
are CMS-signed with the profile-signing key when PROFILE_SIGNING=yes. If a needed file cannot be
read, the answer is 503: the portal never gives an unsigned profile in place of a signed one.
"""
import os
import re

from flask import Blueprint, Response, g, jsonify, render_template, request, session

import apiauth
import app as core     # app.py imports this module at its end (register_features)
import profiles

SERVER_NAME = "radius.nitsrinagar.lab"     # CN and DNS name of the RADIUS server certificate
ANONYMOUS_IDENTITY = "anonymous"           # outer identity: the uid travels only inside the tunnel
SSID = os.environ.get("WIFI_SSID") or "NITS-Lab"
if not profiles.SSID_RE.fullmatch(SSID):
    raise RuntimeError("WIFI_SSID must be 1 to 32 characters: letters, digits, space, '.', '_', '-'")
PROFILE_SIGNING = os.environ.get("PROFILE_SIGNING") or "yes"
if PROFILE_SIGNING not in ("yes", "no"):
    raise RuntimeError("PROFILE_SIGNING must be yes or no")
SIGN_PROFILES = PROFILE_SIGNING == "yes"
CA_FILE = os.environ.get("PROFILE_CA_FILE") or "/certs/ca.pem"
SIGNING_CERT_FILE = os.environ.get("PROFILE_SIGNING_CERT") or "/certs/profile-sign.pem"
SIGNING_KEY_FILE = os.environ.get("PROFILE_SIGNING_KEY") or "/certs/profile-sign.key"

UNAVAILABLE = "Wi-Fi setup is temporarily unavailable. Try again later."

bp = Blueprint("downloads", __name__)

# kind -> (path below /setup/, file name for the user, MIME type)
FILES = {
    "apple": ("apple.mobileconfig", "nits-wifi.mobileconfig", "application/x-apple-aspen-config"),
    "windows_ps1": ("windows.ps1", "nits-wifi-setup.ps1", "text/plain"),     # Flask adds the charset
    "windows_xml": ("windows.xml", "nits-wifi.xml", "application/xml"),
    "linux": ("linux.sh", "nits-wifi-setup.sh", "application/x-sh"),
    "chromeos": ("chromeos.onc", "nits-wifi.onc", "application/json"),
}


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def settings(uid):
    """profiles.WifiSettings for uid. Raises core.Unavailable if the CA cannot be read."""
    try:
        return profiles.WifiSettings(SSID, read_file(CA_FILE), SERVER_NAME, ANONYMOUS_IDENTITY, uid)
    except (OSError, profiles.ProfileError):
        core.log.exception("cannot read the lab CA for Wi-Fi profiles: %s", CA_FILE)
        raise core.Unavailable(UNAVAILABLE) from None


def apple_profile(s):
    return sign_apple(s, profiles.apple_mobileconfig(s))


def sign_apple(s, data):
    if not SIGN_PROFILES:
        return data
    try:
        return profiles.sign_mobileconfig(data, read_file(SIGNING_CERT_FILE), read_file(SIGNING_KEY_FILE),
                                          chain_pem=s.ca_pem.encode("ascii"))
    except (OSError, profiles.ProfileError):
        core.log.exception("cannot sign the Apple profile (PROFILE_SIGNING=yes)")
        raise core.Unavailable(UNAVAILABLE) from None


BUILDERS = {
    "apple": apple_profile,
    "windows_ps1": profiles.windows_ps1,
    "windows_xml": profiles.windows_wlan_xml,
    "linux": profiles.linux_nmcli,
    "chromeos": profiles.chromeos_onc,
}


# EAP-TLS: kind -> (file name for the user, MIME type). The file holds the PKCS#12 file of pki.py,
# encrypted with its passphrase; the device asks for the passphrase.
TLS_FILES = {
    "apple": ("nits-wifi-tls.mobileconfig", "application/x-apple-aspen-config"),
    "windows": ("nits-wifi-tls-setup.ps1", "text/plain"),
    "linux": ("nits-wifi-tls-setup.sh", "application/x-sh"),
}

TLS_BUILDERS = {
    "apple": lambda s, p12: sign_apple(s, profiles.apple_tls_mobileconfig(s, p12)),
    "windows": profiles.windows_tls_ps1,
    "linux": profiles.linux_tls_nmcli,
}


def tls_profile(uid, kind, p12):
    """The EAP-TLS profile of `kind` ("apple", "windows" or "linux") for uid, with the PKCS#12 file
    p12 (DER bytes, made by pki.py; never the passphrase). Returns (body, file name, MIME type).
    Raises core.InvalidInput (unknown kind, or p12 is not a PKCS#12 file) or core.Unavailable (the
    CA or, with PROFILE_SIGNING=yes, the signing files cannot be read). Logs uid and kind, never
    the content."""
    if kind not in TLS_FILES:
        raise core.InvalidInput("Unknown platform for the certificate profile.")
    try:
        profiles.check_p12(p12)
    except profiles.ProfileError:
        raise core.InvalidInput("The certificate file is not valid.") from None
    body = TLS_BUILDERS[kind](settings(uid), p12)
    filename, mimetype = TLS_FILES[kind]
    core.log.info("profile download: uid=%s kind=tls-%s", uid, kind)     # never the content
    return body, filename, mimetype


def tls_download(uid, kind, p12):
    """tls_profile() as a download response (Content-Disposition: attachment, Cache-Control:
    no-store from the portal). Raises the same errors as tls_profile()."""
    body, filename, mimetype = tls_profile(uid, kind, p12)
    resp = Response(body, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


def detect_os(user_agent):
    """Rough OS guess from the User-Agent, only to put one platform first. iPadOS reports a Mac."""
    ua = (user_agent or "").lower()
    if "iphone" in ua or "ipad" in ua or "ipod" in ua or "macintosh" in ua or "mac os x" in ua:
        return "apple"
    if "android" in ua:
        return "android"
    if re.search(r"\bcros\b", ua):                   # not the "cros" inside "microsoft"
        return "chromeos"
    if "windows" in ua:
        return "windows"
    if "linux" in ua or "x11" in ua:
        return "linux"
    return None


def unavailable_page(exc):
    return render_template("message.html", title="Unavailable", text=exc.message), exc.status


@bp.route("/setup")
@core.login_required
def setup():
    try:
        s = settings(session["uid"])
    except core.PortalError as exc:
        return unavailable_page(exc)
    platforms = ["apple", "windows", "linux", "chromeos", "android"]
    detected = detect_os(request.headers.get("User-Agent"))
    if detected:
        platforms.remove(detected)
        platforms.insert(0, detected)
    return render_template("setup.html", s=s, platforms=platforms, detected=detected,
                           signed=SIGN_PROFILES, sha1=profiles.sha1_thumbprint(s),
                           sha256=profiles.sha256_fingerprint(s))


def download(kind):
    uid = session["uid"]
    try:
        body = BUILDERS[kind](settings(uid))
    except core.PortalError as exc:
        return unavailable_page(exc)
    _, filename, mimetype = FILES[kind]
    core.log.info("profile download: uid=%s kind=%s", uid, kind)       # never the content
    resp = Response(body, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


def add_download_route(kind):
    def view():
        return download(kind)
    view.__name__ = kind
    bp.add_url_rule(f"/setup/{FILES[kind][0]}", kind, core.login_required(view))


for _kind in FILES:
    add_download_route(_kind)


ANDROID_METHODS = {"ttls": profiles.android_settings, "tls": profiles.android_tls_settings}


@bp.route("/api/v1/profiles/android")
@apiauth.api_auth_required
def android():
    method = request.args.get("method", "ttls")
    if method not in ANDROID_METHODS:
        return apiauth.api_error(400, "invalid_input", 'method must be "ttls" or "tls".')
    uid = g.api_user["uid"]
    try:
        s = settings(uid)
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
    core.log.info("profile download: uid=%s kind=%s", uid, "android" if method == "ttls" else "android-tls")
    return jsonify(ANDROID_METHODS[method](s))
