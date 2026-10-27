"""EAP-TLS device certificates (stage S5; docs/api/v1.md section 6).

- The portal holds the Device CA (certs/make-certs.sh: an intermediate under the lab root, pathlen 0)
  and never the root key. Each certificate has CN = uid, Extended Key Usage clientAuth only, a random
  serial and 1 year of validity. The subject of a CSR is ignored: only its public key is used.
- A user has at most CERT_LIMIT active certificates (not revoked, not expired). The count and the
  INSERT run in one transaction under a per-user PostgreSQL advisory lock, so parallel requests
  cannot pass the limit together. Web certificates count in the same limit as app certificates.
- FreeRADIUS (sites-available/check-eap-tls) accepts a certificate only while its row in
  device_certs (migration 006) is active for the same user. Revoking is that UPDATE, followed by a
  Disconnect-Request for the devices that signed in with the certificate (core.disconnect_core:
  same checks and limits as the Disconnect button). There is no CRL or OCSP service.
- The Android app makes its key on the phone and sends a CSR (POST /api/v1/certs). For Apple,
  Windows and Linux the web page /certs makes the key on the server and gives a PKCS#12 file once,
  with a random passphrase shown on that page once. The key and the passphrase exist only in memory
  for that one response: they are never stored, logged or sent again.

Core functions for the web pages, the API and other modules: issue_core, list_core, revoke_core
(S6 calls it for "Not me") and certs_for_mac.
"""
import base64
import hashlib
import os
import re
import secrets
import sys
import unicodedata
from datetime import datetime, timedelta, timezone

import psycopg
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, session, url_for

import apiauth
import app as core     # app.py loads this module at its end (register_features)

bp = Blueprint("pki", __name__)

CERT_LIMIT = 3          # active certificates per user (same number as the 3-device rule)
VALID_DAYS = 365
SEEN_DAYS = 30          # certs_for_mac and the revoke disconnect look this far back
LABEL_MAX = 40
REASONS = ("user", "not_me", "admin", "password")
RSA_MIN_BITS, RSA_MAX_BITS = 2048, 8192
EC_CURVES = (ec.SECP256R1, ec.SECP384R1)
WEB_KEY_BITS = 3072     # key made on the server for the PKCS#12 download
# pg_advisory_xact_lock(namespace, hashtext(uid)): the namespace keeps these locks apart from any
# other advisory lock. Two uids with the same hash only wait for each other, never pass the limit.
LOCK_NAMESPACE = 0x5005
SERIAL_RE = re.compile(r"(?:[0-9a-f]{2}){1,20}")
# Passphrase of the PKCS#12 download: easy to type on a phone (no 0/o, 1/l/i), 20 characters of 31
# (about 99 bits), in groups of 4. The dashes are part of it, so the user types what the page shows.
PASSPHRASE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"

CA_CERT_FILE = os.environ.get("PKI_CA_CERT", "/certs/device-ca.pem")
CA_KEY_FILE = os.environ.get("PKI_CA_KEY", "/certs/device-ca.key")
ROOT_CA_FILE = os.environ.get("PROFILE_CA_FILE", "/certs/ca.pem")

# key uid: certificates issued. Each costs a signature (and, for the web, an RSA key), and a
# revoke-and-issue loop would otherwise add rows without end.
ISSUES = core.AttemptLimiter(10, 60 * 60)


class BadCsr(core.PortalError):
    status, code = 400, "bad_csr"


class CertLimit(core.Conflict):
    code = "cert_limit"


# ---- Checks -----------------------------------------------------------------------------------

def check_label(label):
    """The label, stripped. 1 to 40 characters, no control or format characters (it is shown on
    the pages and becomes the PKCS#12 friendly name)."""
    if not isinstance(label, str):
        raise core.InvalidInput(f"The name must be 1 to {LABEL_MAX} characters.")
    label = label.strip()
    if not 1 <= len(label) <= LABEL_MAX or any(unicodedata.category(c).startswith("C") for c in label):
        raise core.InvalidInput(f"The name must be 1 to {LABEL_MAX} characters, without control characters.")
    return label


def check_key(key):
    """Refuses a weak or unknown public key: RSA below 2048 bits (or above 8192, or a small
    exponent), EC on a curve other than P-256 or P-384, and every other key type."""
    if isinstance(key, rsa.RSAPublicKey):
        if not RSA_MIN_BITS <= key.key_size <= RSA_MAX_BITS or key.public_numbers().e < 65537:
            raise BadCsr(f"The key is too weak: use RSA with {RSA_MIN_BITS} bits or more, or EC P-256.")
        return
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, EC_CURVES):
        return
    raise BadCsr("This key type is not accepted: use RSA with 2048 bits or more, or EC P-256 or P-384.")


def check_csr(csr_pem):
    """The public key of a valid PKCS#10 request. Raises BadCsr. The subject and every other part
    of the request are ignored."""
    if not isinstance(csr_pem, str) or not csr_pem.isascii():
        raise BadCsr("Send csr_pem as a PEM certificate request.")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        signed = csr.is_signature_valid
        key = csr.public_key()
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise BadCsr("This is not a valid certificate request.") from None
    if not signed:
        # Proves that the sender holds the private key of the public key in the request
        raise BadCsr("The signature of the certificate request is not valid.")
    check_key(key)
    return key


def new_serial():
    """159 random bits with the top one set: always 20 bytes, positive, and written as 40 lower-case
    hex digits, the same form FreeRADIUS gives in TLS-Client-Cert-Serial."""
    return secrets.randbits(159) | (1 << 158)


def serial_hex(number):
    return format(number, "040x")


def new_passphrase():
    chars = "".join(secrets.choice(PASSPHRASE_ALPHABET) for _ in range(20))
    return "-".join(chars[i:i + 4] for i in range(0, 20, 4))


# ---- Device CA ----------------------------------------------------------------------------------

def load_ca():
    """(Device CA certificate, its key, root CA certificate). Raises Unavailable. Read on every
    issue, not at import: without the files (unit tests, CI) only issuing fails, with 503."""
    try:
        with open(CA_CERT_FILE, "rb") as f:
            ca = x509.load_pem_x509_certificate(f.read())
        with open(CA_KEY_FILE, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(ROOT_CA_FILE, "rb") as f:
            root = x509.load_pem_x509_certificate(f.read())
        is_ca = ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm, x509.ExtensionNotFound) as exc:
        # The type only: the text of a key error must never reach the log
        core.log.error("device CA not readable (%s): see certs/make-certs.sh", type(exc).__name__)
        raise core.Unavailable("Certificates cannot be issued now. Try again later.") from None
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    if not is_ca or ca.public_key().public_bytes(serialization.Encoding.DER, spki) != \
            key.public_key().public_bytes(serialization.Encoding.DER, spki):
        core.log.error("device CA certificate and key do not match, or it is not a CA")
        raise core.Unavailable("Certificates cannot be issued now. Try again later.")
    return ca, key, root


def build_cert(uid, public_key, ca, ca_key, serial, now):
    """CN = uid (as stored in LDAP), clientAuth only, valid from now for VALID_DAYS."""
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, uid)]))
            .issuer_name(ca.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


# ---- Core functions -------------------------------------------------------------------------------

ACTIVE = "revoked_at IS NULL AND not_after > now()"


def issue_core(uid, label, via, public_key=None):
    """Issues a certificate for public_key, or for a new RSA key made here when public_key is None
    (the PKCS#12 download). Returns {"row", "cert", "chain", "private_key"}: row is the device_certs
    row, chain is [Device CA, root CA], private_key is None for a given public key.
    Raises InvalidInput (label), BadCsr (key), RateLimited, CertLimit or Unavailable."""
    label = check_label(label)
    if public_key is not None:
        check_key(public_key)
    ca, ca_key, root = load_ca()
    if not ISSUES.attempt(uid):
        raise core.RateLimited("Too many certificates were issued. Wait an hour and try again.")
    private_key = None
    if public_key is None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=WEB_KEY_BITS)
        public_key = private_key.public_key()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    serial = new_serial()
    cert = build_cert(uid, public_key, ca, ca_key, serial, now)
    spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        with core.db() as conn, conn.transaction(), conn.cursor() as cur:
            # Held until the transaction ends: the next request of this user counts after this INSERT
            cur.execute("SELECT pg_advisory_xact_lock(%s, hashtext(%s))", (LOCK_NAMESPACE, uid))
            cur.execute(f"SELECT count(*) AS active FROM device_certs WHERE username = %s AND {ACTIVE}", (uid,))
            if cur.fetchall()[0]["active"] >= CERT_LIMIT:
                raise CertLimit(f"You already have {CERT_LIMIT} active certificates. Revoke one first.")
            cur.execute(
                """INSERT INTO device_certs (serial, username, label, pubkey_sha256, issued_at, not_after, via)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   RETURNING serial, label, issued_at, not_after, revoked_at, revoke_reason, via""",
                (serial_hex(serial), uid, label, hashlib.sha256(spki).hexdigest(), now,
                 now + timedelta(days=VALID_DAYS), via))
            row = cur.fetchall()[0]
    except CertLimit:
        ISSUES.succeeded(uid)           # nothing was issued: not counted
        raise
    except psycopg.Error:
        ISSUES.succeeded(uid)
        core.log.exception("database error while issuing a certificate")
        raise core.Unavailable("Certificates cannot be issued now. Try again later.") from None
    core.log.info("certificate issued: uid=%s serial=%s via=%s", uid, row["serial"], via)
    return {"row": {**row, "active": True}, "cert": cert, "chain": [ca, root], "private_key": private_key}


def list_core(uid):
    """The user's certificates, newest first, revoked and expired ones included. Raises Unavailable."""
    try:
        with core.db() as conn, conn.cursor() as cur:
            cur.execute(f"""SELECT serial, label, issued_at, not_after, revoked_at, revoke_reason, via,
                                   ({ACTIVE}) AS active
                            FROM device_certs WHERE username = %s ORDER BY issued_at DESC, serial""", (uid,))
            return cur.fetchall()
    except psycopg.Error:
        core.log.exception("database error on the certificate list")
        raise core.Unavailable("The certificate list is temporarily unavailable. Try again later.") from None


def revoke_core(uid, serial, reason, disconnect=True):
    """Revokes one certificate of this user, then (disconnect=True) sends a Disconnect-Request for
    each live session of the devices that signed in with it in the last SEEN_DAYS days.
    Returns {"serial", "revoked_at" (datetime), "disconnect": [{"nas", "result"}]}. A second call
    returns the first revoked_at (and reason) and tries the disconnect again.
    Raises InvalidInput (reason), NotFound (no such certificate of this user), Unavailable, and from
    the disconnect Conflict or RateLimited: the certificate then stays revoked. With
    disconnect=False ("Not me", which disconnects the device itself) it never raises those two."""
    if reason not in REASONS:
        raise core.InvalidInput('reason must be "user", "not_me", "admin" or "password".')
    if not isinstance(serial, str) or not SERIAL_RE.fullmatch(serial):
        raise core.NotFound("No certificate of yours has that serial number.")
    try:
        with core.db() as conn, conn.cursor() as cur:
            # The request is not trusted: only a certificate of this uid can match
            cur.execute("""UPDATE device_certs SET revoked_at = now(), revoke_reason = %s
                           WHERE serial = %s AND username = %s AND revoked_at IS NULL
                           RETURNING revoked_at""", (reason, serial, uid))
            rows = cur.fetchall()
            newly = bool(rows)
            if not rows:
                cur.execute("SELECT revoked_at FROM device_certs WHERE serial = %s AND username = %s",
                            (serial, uid))
                rows = cur.fetchall()
            macs = []
            if rows and disconnect:
                cur.execute("""SELECT callingstationid FROM device_cert_seen
                               WHERE serial = %s AND username = %s AND last_seen > now() - make_interval(days => %s)
                               ORDER BY last_seen DESC""", (serial, uid, SEEN_DAYS))
                macs = [r["callingstationid"] for r in cur.fetchall()]
    except psycopg.Error:
        core.log.exception("database error while revoking a certificate")
        raise core.Unavailable("Certificates cannot be revoked now. Try again later.") from None
    if not rows:
        raise core.NotFound("No certificate of yours has that serial number.")
    if newly:
        core.log.info("certificate revoked: uid=%s serial=%s reason=%s", uid, serial, reason)
    results = []
    for mac in macs:
        try:
            results += core.disconnect_core(uid, mac)
        except (core.NotFound, core.InvalidInput):
            pass                        # that device is not online now
    return {"serial": serial, "revoked_at": rows[0]["revoked_at"], "disconnect": results}


def revoke_all_core(uid, reason):
    """Revokes every active certificate of this user (password change: a stolen password must not
    leave a certificate behind that outlives it), then tries to disconnect the devices that used
    them. Returns the revoked serials. Raises InvalidInput (reason) or Unavailable; a failed
    disconnect is logged and never raised, because the revocation already holds."""
    if reason not in REASONS:
        raise core.InvalidInput('reason must be "user", "not_me", "admin" or "password".')
    try:
        with core.db() as conn, conn.cursor() as cur:
            cur.execute("""UPDATE device_certs SET revoked_at = now(), revoke_reason = %s
                           WHERE username = %s AND revoked_at IS NULL AND not_after > now()
                           RETURNING serial""", (reason, uid))
            serials = [r["serial"] for r in cur.fetchall()]
            macs = []
            if serials:
                cur.execute("""SELECT DISTINCT callingstationid FROM device_cert_seen
                               WHERE serial = ANY(%s) AND username = %s
                                 AND last_seen > now() - make_interval(days => %s)""",
                            (serials, uid, SEEN_DAYS))
                macs = [r["callingstationid"] for r in cur.fetchall()]
    except psycopg.Error:
        core.log.exception("database error while revoking all certificates")
        raise core.Unavailable("Certificates cannot be revoked now. Try again later.") from None
    for serial in serials:
        core.log.info("certificate revoked: uid=%s serial=%s reason=%s", uid, serial, reason)
    for mac in macs:
        try:
            core.disconnect_core(uid, mac)
        except core.PortalError as exc:
            core.log.warning("revoke all: no disconnect for uid=%s mac=%s (%s)", uid, mac, exc.code)
    return serials


def certs_for_mac(uid, mac):
    """Serials of this user's active certificates that the device (Calling-Station-Id) used to sign
    in during the last SEEN_DAYS days, most recent first. Raises Unavailable."""
    if not isinstance(mac, str) or not core.MAC_RE.fullmatch(mac):
        return []
    try:
        with core.db() as conn, conn.cursor() as cur:
            cur.execute("""SELECT c.serial FROM device_cert_seen s
                            JOIN device_certs c ON c.serial = s.serial AND c.username = s.username
                            WHERE s.username = %s AND s.callingstationid = %s
                              AND s.last_seen > now() - make_interval(days => %s)
                              AND c.revoked_at IS NULL AND c.not_after > now()
                            ORDER BY s.last_seen DESC""", (uid, mac, SEEN_DAYS))
            return [r["serial"] for r in cur.fetchall()]
    except psycopg.Error:
        core.log.exception("database error on the certificates of a device")
        raise core.Unavailable("The certificate list is temporarily unavailable. Try again later.") from None


# ---- Web pages ------------------------------------------------------------------------------------

def page(certs, **extra):
    return render_template("certs.html", certs=certs, limit=CERT_LIMIT, label_max=LABEL_MAX,
                           active=sum(1 for c in certs or () if c["active"]), **extra)


@bp.route("/certs")
@core.login_required
def certs():
    try:
        certs = list_core(session["uid"])
    except core.PortalError as exc:
        return render_template("message.html", title="Device certificates", text=exc.message), exc.status
    return page(certs)


@bp.route("/certs/new", methods=["POST"])
@core.login_required
def new():
    """The one response that holds the PKCS#12 file and its passphrase. Both are made here, put
    into this page (the file as a data: link) and then dropped: nothing is stored or logged."""
    uid = session["uid"]
    try:
        issued = issue_core(uid, request.form.get("label", ""), "web")
    except core.PortalError as exc:
        flash(exc.message, "error")
        return redirect(url_for("pki.certs"))
    passphrase = new_passphrase()
    ca = issued["chain"][0]
    # Triple-DES and SHA-1 MAC: the PKCS#12 form that Windows 10, macOS and iOS all import (they
    # refuse the AES form of OpenSSL 3). The passphrase has about 99 random bits, so the weak
    # key derivation is not the weak point.
    encryption = (serialization.PrivateFormat.PKCS12.encryption_builder()
                  .kdf_rounds(50000)
                  .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                  .hmac_hash(hashes.SHA1())
                  .build(passphrase.encode("ascii")))
    blob = pkcs12.serialize_key_and_certificates(issued["row"]["label"].encode("utf-8"), issued["private_key"],
                                                 issued["cert"], [ca], encryption)
    try:
        certs = list_core(uid)
    except core.PortalError:
        certs = None                    # the file must still be shown: it cannot be made again
    return page(certs, issued=issued["row"], passphrase=passphrase,
                p12_b64=base64.b64encode(blob).decode("ascii"), filename=f"nits-wifi-{uid}.p12",
                tls_profiles=tls_profiles(uid, blob))


TLS_PROFILE_NAMES = (("apple", "iPhone, iPad or Mac"), ("windows", "Windows"), ("linux", "Linux"))


def tls_profiles(uid, blob):
    """The EAP-TLS setup files of downloads.py (stage S6) for this PKCS#12 file, as data: links:
    [{"title", "filename", "mimetype", "b64"}]. They hold the file but never the passphrase. Empty
    without downloads.py; a profile that cannot be made is left out, never an error on this page."""
    if "downloads" not in core.app.blueprints:
        return []
    downloads = sys.modules["downloads"]
    files = []
    for kind, title in TLS_PROFILE_NAMES:
        try:
            body, filename, mimetype = downloads.tls_profile(uid, kind, blob)
        except Exception:
            core.log.exception("no EAP-TLS %s profile for uid=%s", kind, uid)
            continue
        data = body.encode("utf-8") if isinstance(body, str) else body
        files.append({"title": title, "filename": filename, "mimetype": mimetype.split(";")[0],
                      "b64": base64.b64encode(data).decode("ascii")})
    return files


@bp.route("/certs/revoke", methods=["POST"])
@core.login_required
def revoke():
    serial = request.form.get("serial", "")
    try:
        result = revoke_core(session["uid"], serial, "user")
    except (core.Conflict, core.RateLimited):
        # Raised by the disconnect, after the revocation: the certificate is revoked
        flash("The certificate was revoked. Devices that use it can no longer join the Wi-Fi.", "ok")
        flash(f"A disconnect could not be sent now. A device that uses it is dropped at the next "
              f"re-check, within {core.REAUTH_INTERVAL} seconds.", "info")
        return redirect(url_for("pki.certs"))
    except core.PortalError as exc:
        flash(exc.message, "error")
        return redirect(url_for("pki.certs"))
    flash("The certificate was revoked. Devices that use it can no longer join the Wi-Fi.", "ok")
    for r in result["disconnect"]:
        if r["result"] == "ACK":
            flash("The access point disconnected a device that used it (ACK).", "ok")
        else:
            flash(f"The access point did not confirm the disconnect. The device is dropped at the next "
                  f"re-check, within {core.REAUTH_INTERVAL} seconds.", "info")
    return redirect(url_for("pki.certs"))


# ---- API (docs/api/v1.md section 6) ---------------------------------------------------------------

def iso(value):
    return value.isoformat() if value is not None else None


def cert_json(row):
    return {"serial": row["serial"], "label": row["label"], "issued_at": iso(row["issued_at"]),
            "not_after": iso(row["not_after"]), "revoked_at": iso(row["revoked_at"]),
            "revoke_reason": row["revoke_reason"], "via": row["via"], "active": row["active"]}


@bp.route("/api/v1/certs", methods=["POST"])
@apiauth.api_auth_required
def api_issue():
    body = apiauth.json_body()
    if body is None or not isinstance(body.get("csr_pem"), str) or not isinstance(body.get("label"), str):
        return apiauth.api_error(400, "invalid_input", "Send csr_pem and label as strings.")
    uid = g.api_user["uid"]
    try:
        label = check_label(body["label"])
        public_key = check_csr(body["csr_pem"])
        issued = issue_core(uid, label, "app", public_key)
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
    row = issued["row"]
    resp = jsonify(serial=row["serial"], label=row["label"], issued_at=iso(row["issued_at"]),
                   not_after=iso(row["not_after"]), cert_pem=pem(issued["cert"]),
                   chain_pem="".join(pem(c) for c in issued["chain"]))
    resp.status_code = 201
    return resp


@bp.route("/api/v1/certs")
@apiauth.api_auth_required
def api_list():
    try:
        rows = list_core(g.api_user["uid"])
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
    return jsonify(limit=CERT_LIMIT, certs=[cert_json(r) for r in rows])


@bp.route("/api/v1/certs/<serial>", methods=["DELETE"])
@apiauth.api_auth_required
def api_revoke(serial):
    try:
        result = revoke_core(g.api_user["uid"], serial, "user")
    except core.PortalError as exc:
        return apiauth.portal_error(exc)
    return jsonify(serial=result["serial"], revoked_at=iso(result["revoked_at"]), disconnect=result["disconnect"])
