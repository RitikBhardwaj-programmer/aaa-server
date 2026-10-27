"""Wi-Fi setup profiles (profiles.py) and the downloads (downloads.py), with a throwaway CA.

certs/ is gitignored, so each run makes its own root CA and profile-signing certificate here.
"""
import base64
import datetime
import hashlib
import json
import logging
import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import app as portal
import downloads
import profiles

from .helpers import PASSWORD, UID, CoreCase

SSID, SERVER, ANON = "NITS-Lab", "radius.nitsrinagar.lab", "anonymous"
TTLS_NS = "{http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1}"


def make_cert(cn, key, issuer_cert=None, issuer_key=None, ca=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder()
               .subject_name(name)
               .issuer_name(issuer_cert.subject if issuer_cert else name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
    else:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
                                         critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


CA_KEY = ec.generate_private_key(ec.SECP256R1())
CA = make_cert("NIT Srinagar Lab CA (unit test)", CA_KEY, ca=True)
SIGN_KEY = ec.generate_private_key(ec.SECP256R1())
SIGN_CERT = make_cert("Profile Signing (unit test)", SIGN_KEY, CA, CA_KEY)
SIGN_KEY_PEM = SIGN_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
CA_DER = CA.public_bytes(serialization.Encoding.DER)
CA_SHA1 = hashlib.sha1(CA_DER).hexdigest()


def settings(uid=UID, ssid=SSID):
    return profiles.WifiSettings(ssid, pem(CA), SERVER, ANON, uid)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.s = settings()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return path

    # ---- inputs ----

    def test_inputs_are_checked(self):
        bad = [dict(ssid="a'b"), dict(ssid=""), dict(ssid=" lead"), dict(ssid="x" * 33), dict(ssid="a\nb"),
               dict(uid="$(reboot)"), dict(uid="a b"), dict(uid=""), dict(server_name="bad name"),
               dict(server_name="a;b"), dict(anonymous_identity="a'b")]
        for change in bad:
            args = {"ssid": SSID, "ca_pem": pem(CA), "server_name": SERVER, "anonymous_identity": ANON, "uid": UID}
            args.update(change)
            with self.subTest(change=change), self.assertRaises(profiles.ProfileError):
                profiles.WifiSettings(**args)
        self.assertEqual(settings(ssid="Campus Wi-Fi 5").ssid, "Campus Wi-Fi 5")

    def test_ca_must_be_one_certificate(self):
        for ca in (b"", b"junk", pem(CA) + pem(SIGN_CERT)):
            with self.subTest(ca=ca[:10]), self.assertRaises(profiles.ProfileError):
                profiles.WifiSettings(SSID, ca, SERVER, ANON, UID)

    # ---- Apple ----

    def test_mobileconfig_round_trip_and_keys(self):
        data = profiles.apple_mobileconfig(self.s)
        top = plistlib.loads(data)
        self.assertEqual(top["PayloadType"], "Configuration")
        ca, wifi = top["PayloadContent"]
        self.assertEqual(ca["PayloadType"], "com.apple.security.root")
        self.assertEqual(ca["PayloadContent"], CA_DER)
        self.assertEqual(wifi["PayloadType"], "com.apple.wifi.managed")
        self.assertEqual(wifi["SSID_STR"], SSID)
        self.assertEqual(wifi["EncryptionType"], "WPA2")
        eap = wifi["EAPClientConfiguration"]
        self.assertEqual(eap["AcceptEAPTypes"], [21])
        self.assertEqual(eap["TTLSInnerAuthentication"], "PAP")
        self.assertEqual(eap["OuterIdentity"], "anonymous")
        self.assertEqual(eap["UserName"], UID)
        self.assertEqual(eap["TLSTrustedServerNames"], [SERVER])
        self.assertEqual(eap["PayloadCertificateAnchorUUID"], [ca["PayloadUUID"]])
        self.assertNotIn("UserPassword", eap)
        uuids = [top["PayloadUUID"], ca["PayloadUUID"], wifi["PayloadUUID"]]
        self.assertEqual(len(set(uuids)), 3)
        # Deterministic per user: a new download replaces the installed profile
        self.assertEqual(data, profiles.apple_mobileconfig(settings()))
        self.assertNotEqual(top["PayloadUUID"], plistlib.loads(profiles.apple_mobileconfig(settings("other")))["PayloadUUID"])

    def signed(self):
        data = profiles.apple_mobileconfig(self.s)
        return data, profiles.sign_mobileconfig(data, pem(SIGN_CERT), SIGN_KEY_PEM, chain_pem=pem(CA))

    def test_signed_profile_holds_content_and_certificates(self):
        data, der = self.signed()
        self.assertEqual(der[0], 0x30)                       # DER SEQUENCE
        self.assertIn(data, der)                             # not detached: the plist is inside
        certs = pkcs7.load_der_pkcs7_certificates(der)
        self.assertEqual({c.subject for c in certs}, {SIGN_CERT.subject, CA.subject})

    def test_bad_signing_key_is_an_error(self):
        with self.assertRaises(profiles.ProfileError):
            profiles.sign_mobileconfig(b"x", pem(SIGN_CERT), b"not a key")

    @unittest.skipUnless(shutil.which("openssl"), "openssl is not installed")
    def test_openssl_cms_verify(self):
        data, der = self.signed()
        signed = self.write("p.mobileconfig", der)
        ca = self.write("ca.pem", pem(CA))
        out = os.path.join(self.tmp, "out.plist")
        for extra in (["-noverify"], ["-CAfile", ca]):
            with self.subTest(extra=extra):
                run = subprocess.run(["openssl", "cms", "-verify", "-inform", "DER", "-in", signed, "-out", out]
                                     + extra, capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                with open(out, "rb") as f:
                    self.assertEqual(f.read(), data)
        # A changed byte in the content breaks the signature
        i = der.index(b"<string>PAP</string>")
        tampered = self.write("bad.mobileconfig", der[:i + 8] + b"CHAP" + der[i + 11:])
        run = subprocess.run(["openssl", "cms", "-verify", "-inform", "DER", "-in", tampered, "-noverify",
                              "-out", out], capture_output=True)
        self.assertNotEqual(run.returncode, 0)

    # ---- Windows ----

    def test_wlan_xml(self):
        xml = profiles.windows_wlan_xml(self.s)
        root = ET.fromstring(xml)
        self.assertEqual(root.tag, "{http://www.microsoft.com/networking/WLAN/profile/v1}WLANProfile")
        ns = "{http://www.microsoft.com/networking/WLAN/profile/v1}"
        self.assertEqual(root.find(f"{ns}name").text, SSID)
        self.assertEqual(root.find(f"{ns}SSIDConfig/{ns}SSID/{ns}hex").text, SSID.encode().hex().upper())
        self.assertEqual(root.find(f".//{ns}authentication").text, "WPA2")
        self.assertEqual(root.find(".//{http://www.microsoft.com/provisioning/EapCommon}Type").text, "21")
        self.assertEqual(root.find(".//{http://www.microsoft.com/provisioning/EapCommon}AuthorId").text, "311")
        self.assertEqual(root.find(f".//{TTLS_NS}ServerNames").text, SERVER)
        thumb = root.find(f".//{TTLS_NS}TrustedRootCAHash").text
        self.assertEqual(thumb.replace(" ", ""), CA_SHA1)
        self.assertEqual(profiles.sha1_thumbprint(self.s).replace(" ", ""), CA_SHA1)
        self.assertIsNotNone(root.find(f".//{TTLS_NS}Phase2Authentication/{TTLS_NS}PAPAuthentication"))
        self.assertEqual(root.find(f".//{TTLS_NS}AnonymousIdentity").text, ANON)

    def test_ps1(self):
        ps1 = profiles.windows_ps1(self.s)
        self.assertIn("certutil -user -addstore Root $CaFile", ps1)
        self.assertIn('netsh wlan add profile filename="$XmlFile" user=current', ps1)
        self.assertIn(profiles.windows_wlan_xml(self.s).rstrip("\n"), ps1.replace("\r\n", "\n"))
        self.assertIn(self.s.ca_pem.rstrip("\n"), ps1.replace("\r\n", "\n"))
        self.assertTrue(ps1.isascii())                       # Windows PowerShell 5.1 reads a file without BOM as ANSI
        self.assertNotIn("\n", ps1.replace("\r\n", ""))     # CRLF line ends only

    # ---- Linux ----

    def test_nmcli_script_syntax_and_settings(self):
        sh = profiles.linux_nmcli(self.s)
        path = self.write("setup.sh", sh)
        run = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        for want in ("802-1x.eap ttls", "802-1x.phase2-auth pap", f"802-1x.anonymous-identity {ANON}",
                     f"802-1x.domain-suffix-match {SERVER}", "802-1x.password-flags 2",
                     f"802-1x.identity {UID}", 'CA_DIR="$HOME/.local/share/nits-wifi"'):
            self.assertIn(want, sh)

    def test_nmcli_script_runs_with_a_fake_nmcli(self):
        home, bin_dir = os.path.join(self.tmp, "home"), os.path.join(self.tmp, "bin")
        os.makedirs(home)
        os.makedirs(bin_dir)
        log = os.path.join(self.tmp, "nmcli.log")
        fake = self.write("bin/nmcli", f'#!/bin/bash\nprintf "%s\\n" "$*" >> {log}\n')
        os.chmod(fake, 0o755)
        script = self.write("setup.sh", profiles.linux_nmcli(self.s))
        env = {"HOME": home, "PATH": bin_dir + os.pathsep + os.environ["PATH"]}
        run = subprocess.run(["bash", script], capture_output=True, text=True, env=env)
        self.assertEqual(run.returncode, 0, run.stderr)
        with open(os.path.join(home, ".local/share/nits-wifi/ca.pem"), "rb") as f:
            self.assertEqual(x509.load_pem_x509_certificate(f.read()), CA)
        with open(log) as f:
            calls = f.read().splitlines()
        add = calls[-1]
        self.assertTrue(add.startswith(f"connection add type wifi con-name {SSID} ssid {SSID} "), add)
        self.assertIn(f"802-1x.ca-cert {home}/.local/share/nits-wifi/ca.pem", add)

    # ---- ChromeOS ----

    def test_onc(self):
        onc = json.loads(profiles.chromeos_onc(self.s))
        self.assertEqual(onc["Type"], "UnencryptedConfiguration")
        (cert,) = onc["Certificates"]
        self.assertEqual(cert["Type"], "Authority")
        self.assertEqual(base64.b64decode(cert["X509"]), CA_DER)
        (net,) = onc["NetworkConfigurations"]
        self.assertEqual((net["Type"], net["Name"]), ("WiFi", SSID))
        wifi = net["WiFi"]
        self.assertEqual((wifi["SSID"], wifi["Security"]), (SSID, "WPA-EAP"))
        eap = wifi["EAP"]
        self.assertEqual((eap["Outer"], eap["Inner"]), ("EAP-TTLS", "PAP"))
        self.assertEqual((eap["Identity"], eap["AnonymousIdentity"]), (UID, ANON))
        self.assertEqual(eap["ServerCARefs"], [cert["GUID"]])
        self.assertEqual(eap["DomainSuffixMatch"], [SERVER])
        self.assertFalse(eap["UseSystemCAs"])
        self.assertNotIn("Password", eap)

    # ---- all ----

    def test_no_password_in_any_output(self):
        outputs = {
            "apple": profiles.apple_mobileconfig(self.s).decode(),
            "signed": self.signed()[1].decode("latin-1"),
            "xml": profiles.windows_wlan_xml(self.s),
            "ps1": profiles.windows_ps1(self.s),
            "linux": profiles.linux_nmcli(self.s),
            "onc": profiles.chromeos_onc(self.s),
            "android": json.dumps(profiles.android_settings(self.s)),
        }
        for kind, text in outputs.items():
            with self.subTest(kind=kind):
                self.assertNotIn(PASSWORD, text)
                for key in ("UserPassword", '"Password"', "802-1x.password ", "<Password", "<password"):
                    self.assertNotIn(key, text)


class DownloadTests(CoreCase):
    """The routes of downloads.py with a temporary CA and signing files."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        files = {"CA_FILE": ("ca.pem", pem(CA)), "SIGNING_CERT_FILE": ("sign.pem", pem(SIGN_CERT)),
                 "SIGNING_KEY_FILE": ("sign.key", SIGN_KEY_PEM)}
        for attr, (name, data) in files.items():
            path = os.path.join(tmp, name)
            with open(path, "wb") as f:
                f.write(data)
            p = mock.patch.object(downloads, attr, path)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(downloads, "SIGN_PROFILES", True)
        p.start()
        self.addCleanup(p.stop)
        self.paths = ["/setup"] + [f"/setup/{path}" for path, _, _ in downloads.FILES.values()]

    def test_blueprint_is_loaded_with_its_endpoints(self):
        for endpoint in ("downloads.setup", "downloads.apple", "downloads.windows_ps1", "downloads.windows_xml",
                         "downloads.linux", "downloads.chromeos", "downloads.android"):
            self.assertIn(endpoint, portal.app.view_functions)

    def test_login_required(self):
        for path in self.paths:
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 302)
                self.assertTrue(resp.headers["Location"].endswith("/login"))

    def test_setup_page_puts_the_detected_os_first(self):
        self.web_login()
        agents = {
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)": "apple",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)": "windows",
            "Mozilla/5.0 (X11; Linux x86_64)": "linux",
            "Mozilla/5.0 (X11; CrOS x86_64 16000.0.0)": "chromeos",
            "Mozilla/5.0 (Linux; Android 15; SM-S911B)": "android",
        }
        for agent, first in agents.items():
            with self.subTest(first=first):
                resp = self.client.get("/setup", headers={"User-Agent": agent})
                self.assertEqual(resp.status_code, 200)
                html = resp.get_data(as_text=True)
                self.assertIn("setup.css", html)
                self.assertIn("For this device", html)
                sections = [html.index(f'aria-labelledby="p-{k}"') for k in ("apple", "windows", "linux", "chromeos", "android")]
                self.assertEqual(min(sections), html.index(f'aria-labelledby="p-{first}"'))
                self.assertIn(UID, html)
                self.assertNotIn("<script", html)
                self.assertNotIn("style=", html)
        self.assertEqual(downloads.detect_os("Mozilla/5.0 (Windows NT 10.0) Microsoft Outlook"), "windows")
        resp = self.client.get("/setup", headers={"User-Agent": "curl/8"})
        self.assertNotIn("For this device", resp.get_data(as_text=True))

    def test_downloads_types_names_and_log(self):
        self.web_login()
        logging.disable(logging.NOTSET)
        for kind, (path, filename, mimetype) in downloads.FILES.items():
            with self.subTest(kind=kind), self.assertLogs(portal.log, "INFO") as logs:
                resp = self.client.get(f"/setup/{path}")
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(resp.headers["Content-Type"].split(";")[0], mimetype.split(";")[0])
                self.assertEqual(resp.headers["Content-Disposition"], f'attachment; filename="{filename}"')
                self.assertEqual(resp.headers["Cache-Control"], "no-store")
                self.assertNotIn(PASSWORD.encode(), resp.data)
                lines = [r.getMessage() for r in logs.records]
                self.assertIn(f"profile download: uid={UID} kind={kind}", lines)
                self.assertTrue(all("BEGIN CERTIFICATE" not in line for line in lines))

    def test_apple_download_is_signed_or_not(self):
        self.web_login()
        der = self.client.get("/setup/apple.mobileconfig").data
        self.assertEqual(der[0], 0x30)
        self.assertEqual(len(pkcs7.load_der_pkcs7_certificates(der)), 2)
        with mock.patch.object(downloads, "SIGN_PROFILES", False):
            plain = self.client.get("/setup/apple.mobileconfig").data
        self.assertEqual(plistlib.loads(plain)["PayloadContent"][1]["EAPClientConfiguration"]["UserName"], UID)

    def test_missing_signing_key_is_503_not_unsigned(self):
        self.web_login()
        with mock.patch.object(downloads, "SIGNING_KEY_FILE", "/nonexistent/sign.key"):
            resp = self.client.get("/setup/apple.mobileconfig")
        self.assertEqual(resp.status_code, 503)
        self.assertNotIn(b"<plist", resp.data)

    def test_missing_ca_is_503(self):
        self.web_login()
        with mock.patch.object(downloads, "CA_FILE", "/nonexistent/ca.pem"):
            for path in self.paths:
                with self.subTest(path=path):
                    self.assertEqual(self.client.get(path).status_code, 503)

    # ---- API ----

    def test_android_api_shape(self):
        resp = self.client.get("/api/v1/profiles/android", headers=self.bearer(self.api_token()))
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(set(body), {"ssid", "eap", "phase2", "identity", "anonymous_identity",
                                     "domain_suffix_match", "alt_subject_match", "ca_pem"})
        self.assertEqual(body["ssid"], downloads.SSID)
        self.assertEqual((body["eap"], body["phase2"]), ("TTLS", "PAP"))
        self.assertEqual((body["identity"], body["anonymous_identity"]), (UID, "anonymous"))
        self.assertEqual(body["domain_suffix_match"], "radius.nitsrinagar.lab")
        self.assertEqual(body["alt_subject_match"], "DNS:radius.nitsrinagar.lab")
        self.assertEqual(x509.load_pem_x509_certificate(body["ca_pem"].encode()), CA)
        self.assertNotIn(PASSWORD, resp.get_data(as_text=True))

    def test_android_api_needs_a_token(self):
        self.web_login()                                     # a session cookie is not enough
        resp = self.client.get("/api/v1/profiles/android")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["error"]["code"], "unauthorized")

    def test_android_api_ca_missing_is_503(self):
        token = self.api_token()
        with mock.patch.object(downloads, "CA_FILE", "/nonexistent/ca.pem"):
            resp = self.client.get("/api/v1/profiles/android", headers=self.bearer(token))
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.get_json()["error"]["code"], "unavailable")


if __name__ == "__main__":
    unittest.main()
