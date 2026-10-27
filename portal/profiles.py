"""Wi-Fi setup profiles for EAP-TTLS with inner PAP (stage S3, docs/api/v1.md section 5) and for
EAP-TLS with a device certificate (stage S6, section 7).

Pure functions: no Flask, no files, no environment. downloads.py reads the settings and the CA
and calls these functions. The inputs are the SSID, the lab root CA (PEM), the RADIUS server
name, the anonymous outer identity and the uid of the user. The EAP-TLS profiles also take the
PKCS#12 file (DER) that the /certs page of pki.py makes.

Rules for every profile:
- The uid is filled in. A password is never put in a profile: the device asks the user for it.
- The device trusts only the lab root CA, and only a server certificate with the server name.
  "Do not validate" is never set, because a fake access point could then read the password.
- EAP-TLS: the PKCS#12 file goes into the profile as it is, encrypted with its passphrase. The
  passphrase is never put in a profile: the device asks the user for it when it installs the file.
- The text inputs are checked against strict patterns before they go into XML, plist, JSON,
  PowerShell or bash, so no input can change the structure of a file.
"""
import base64
import hashlib
import json
import plistlib
import re
import shlex
import uuid
from xml.sax.saxutils import escape

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

# Strict patterns. The SSID pattern is narrower than 802.11 allows (1 to 32 bytes of anything),
# so that the SSID is safe in every file format without special quoting rules.
SSID_RE = re.compile(r"[A-Za-z0-9._-](?:[A-Za-z0-9 ._-]{0,30}[A-Za-z0-9._-])?")
UID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")          # same rule as app.UID_RE
HOST_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
ANON_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}")

ORGANIZATION = "NIT Srinagar"
PROFILE_ID = "lab.nitsrinagar.wifi"
UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "wifi-profiles.nitsrinagar.lab")
EAP_TTLS = 21                                         # IANA EAP method type of EAP-TTLS
EAP_TLS = 13                                          # IANA EAP method type of EAP-TLS
P12_MAX_BYTES = 16 * 1024                             # one key, its certificate and the chain


class ProfileError(ValueError):
    """An input is not valid (bad SSID, uid, server name or CA)."""


class WifiSettings:
    """The checked inputs of all profiles. ca_pem must hold exactly one certificate."""

    def __init__(self, ssid, ca_pem, server_name, anonymous_identity, uid):
        for name, value, pattern in (("ssid", ssid, SSID_RE), ("uid", uid, UID_RE),
                                     ("server_name", server_name, HOST_RE),
                                     ("anonymous_identity", anonymous_identity, ANON_RE)):
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise ProfileError(f"{name} is not valid")
        self.ssid, self.server_name, self.anonymous_identity, self.uid = ssid, server_name, anonymous_identity, uid
        self.ca = load_ca(ca_pem)
        self.ca_der = self.ca.public_bytes(serialization.Encoding.DER)
        self.ca_pem = self.ca.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def uuid(self, kind):
        """Deterministic UUID per user, SSID and payload: a new download replaces the old profile."""
        return str(uuid.uuid5(UUID_NAMESPACE, f"{kind}|{self.ssid}|{self.uid}")).upper()


def load_ca(ca_pem):
    if isinstance(ca_pem, str):
        ca_pem = ca_pem.encode("ascii", "replace")
    try:
        certs = x509.load_pem_x509_certificates(ca_pem)
    except ValueError:
        raise ProfileError("the CA file is not a PEM certificate") from None
    if len(certs) != 1:
        raise ProfileError("the CA file must hold exactly one certificate")
    return certs[0]


def check_p12(p12):
    """The PKCS#12 file as bytes. Without the passphrase only its outer form can be checked: a DER
    SEQUENCE of a sane size. The device checks the rest when the user types the passphrase."""
    if not isinstance(p12, (bytes, bytearray)) or not 4 <= len(p12) <= P12_MAX_BYTES or p12[0] != 0x30:
        raise ProfileError("the PKCS#12 file is not valid")
    return bytes(p12)


def sha1_thumbprint(s):
    """SHA-1 of the DER certificate, as hex bytes with spaces ("ab 12 ..."), the Windows format."""
    return " ".join(f"{b:02x}" for b in hashlib.sha1(s.ca_der).digest())


def sha256_fingerprint(s):
    """SHA-256 of the DER certificate, as "AB:12:...", for users who check the CA by hand."""
    return ":".join(f"{b:02X}" for b in hashlib.sha256(s.ca_der).digest())


# ---- Apple: iOS, iPadOS, macOS ----------------------------------------------------------------

def _apple_ca_payload(s, ca_uuid):
    return {
        "PayloadType": "com.apple.security.root",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{PROFILE_ID}.ca",
        "PayloadUUID": ca_uuid,
        "PayloadDisplayName": "NIT Srinagar Lab CA",
        "PayloadCertificateFileName": "nits-lab-ca.cer",
        "PayloadContent": s.ca_der,
    }


def _apple_wifi_payload(s, wifi_uuid, eap):
    return {
        "PayloadType": "com.apple.wifi.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{PROFILE_ID}.network",
        "PayloadUUID": wifi_uuid,
        "PayloadDisplayName": f"Wi-Fi {s.ssid}",
        "SSID_STR": s.ssid,
        "HIDDEN_NETWORK": False,
        "AutoJoin": True,
        "EncryptionType": "WPA2",
        "IsHotspot": False,
        "EAPClientConfiguration": eap,
    }


def _apple_profile(s, kind, description, payloads):
    # The same PayloadIdentifier for TTLS and TLS: installing one profile replaces the other.
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": PROFILE_ID,
        "PayloadUUID": s.uuid(kind),
        "PayloadDisplayName": f"{s.ssid} Wi-Fi",
        "PayloadDescription": description,
        "PayloadOrganization": ORGANIZATION,
        "PayloadRemovalDisallowed": False,
        "PayloadContent": payloads,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True)


def apple_mobileconfig(s):
    """An unsigned .mobileconfig (XML plist): the root CA payload and a Wi-Fi payload that trusts
    only that CA and the server name. UserName is filled in; there is no UserPassword, so the
    device asks for the password when it joins."""
    ca_uuid, wifi_uuid = s.uuid("apple-ca"), s.uuid("apple-wifi")
    eap = {
        "AcceptEAPTypes": [EAP_TTLS],
        "TTLSInnerAuthentication": "PAP",
        "OuterIdentity": s.anonymous_identity,
        "UserName": s.uid,
        "TLSTrustedServerNames": [s.server_name],
        "PayloadCertificateAnchorUUID": [ca_uuid],
        "TLSAllowTrustExceptions": False,
    }
    return _apple_profile(s, "apple-profile",
                          f"Connects to {s.ssid} (WPA2-Enterprise, EAP-TTLS) as {s.uid}. "
                          "The device asks for your password when it joins.",
                          [_apple_ca_payload(s, ca_uuid), _apple_wifi_payload(s, wifi_uuid, eap)])


def apple_tls_mobileconfig(s, p12):
    """An unsigned .mobileconfig for EAP-TLS: the root CA, the device certificate and its key
    (com.apple.security.pkcs12, with no Password key, so the device asks for the passphrase when
    the profile is installed), and a Wi-Fi payload that signs in with that certificate
    (PayloadCertificateUUID) and trusts only the root CA and the server name."""
    p12 = check_p12(p12)
    ca_uuid, p12_uuid, wifi_uuid = s.uuid("apple-ca"), s.uuid("apple-tls-p12"), s.uuid("apple-tls-wifi")
    p12_payload = {
        "PayloadType": "com.apple.security.pkcs12",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{PROFILE_ID}.device-cert",
        "PayloadUUID": p12_uuid,
        "PayloadDisplayName": f"Wi-Fi certificate of {s.uid}",
        "PayloadCertificateFileName": "nits-wifi-device.p12",
        "PayloadContent": p12,
    }
    eap = {
        "AcceptEAPTypes": [EAP_TLS],
        "UserName": s.uid,
        "TLSTrustedServerNames": [s.server_name],
        "PayloadCertificateAnchorUUID": [ca_uuid],
        "TLSAllowTrustExceptions": False,
    }
    wifi = _apple_wifi_payload(s, wifi_uuid, eap)
    wifi["PayloadCertificateUUID"] = p12_uuid
    return _apple_profile(s, "apple-tls-profile",
                          f"Connects to {s.ssid} (WPA2-Enterprise, EAP-TLS) as {s.uid} with a device "
                          "certificate. The device asks for the passphrase of the certificate when you "
                          "install the profile.",
                          [_apple_ca_payload(s, ca_uuid), p12_payload, wifi])


def sign_mobileconfig(data, cert_pem, key_pem, chain_pem=None):
    """CMS SignedData (DER) with the content inside (not detached), as Apple devices expect.
    The signer certificate, and the chain certificates if given, go into the signature."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError):
        raise ProfileError("the profile signing certificate or key is not valid") from None
    builder = pkcs7.PKCS7SignatureBuilder().set_data(data).add_signer(cert, key, hashes.SHA256())
    for extra in x509.load_pem_x509_certificates(chain_pem) if chain_pem else ():
        builder = builder.add_certificate(extra)
    # Binary: sign the bytes as they are (no change of line ends to CRLF, as for S/MIME text)
    return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])


# ---- Windows 10 and 11 ------------------------------------------------------------------------

WLAN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid}</name>
  <SSIDConfig>
    <SSID>
      <hex>{ssid_hex}</hex>
      <name>{ssid}</name>
    </SSID>
    <nonBroadcast>false</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2</authentication>
        <encryption>AES</encryption>
        <useOneX>true</useOneX>
      </authEncryption>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <authMode>user</authMode>
        <EAPConfig>
          <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
            <EapMethod>
              <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">21</Type>
              <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
              <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
              <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">311</AuthorId>
            </EapMethod>
            <Config>
              <EapTtls xmlns="http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1">
                <ServerValidation>
                  <ServerNames>{server_name}</ServerNames>
                  <TrustedRootCAHash>{ca_hash}</TrustedRootCAHash>
                  <DisablePrompt>true</DisablePrompt>
                </ServerValidation>
                <Phase2Authentication>
                  <PAPAuthentication/>
                </Phase2Authentication>
                <Phase1Identity>
                  <IdentityPrivacy>true</IdentityPrivacy>
                  <AnonymousIdentity>{anonymous_identity}</AnonymousIdentity>
                </Phase1Identity>
              </EapTtls>
            </Config>
          </EapHostConfig>
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</WLANProfile>
"""


def windows_wlan_xml(s):
    """WLANProfile for `netsh wlan add profile`: WPA2-Enterprise, the Windows EAP-TTLS method
    (type 21, author 311), inner PAP, anonymous outer identity, server name and root CA hash.
    DisablePrompt: Windows refuses an unknown server and does not ask "connect anyway?".

    Not verified on a real laptop yet: Windows documents TrustedRootCAHash as the certificate
    thumbprint, and the thumbprint that Windows shows is SHA-1. This profile uses the SHA-1 hash.
    If Windows refuses the server, check if this field needs the SHA-256 hash instead."""
    return WLAN_XML.format(ssid=escape(s.ssid), ssid_hex=s.ssid.encode("ascii").hex().upper(),
                           server_name=escape(s.server_name), ca_hash=sha1_thumbprint(s),
                           anonymous_identity=escape(s.anonymous_identity))


def _ps_here_string(text):
    """A PowerShell literal here-string (@' ... '@): no variables or escapes are expanded inside."""
    if "\n'@" in "\n" + text:
        raise ProfileError("the text cannot go into a PowerShell here-string")
    return "@'\n" + text.rstrip("\n") + "\n'@"


def windows_ps1(s):
    """PowerShell script: adds the root CA to the user's trusted roots (certutil -user, so Windows
    shows one confirmation dialog), then adds the WLAN profile for the current user."""
    lines = [
        f"# {s.ssid} Wi-Fi setup for {s.uid} (EAP-TTLS, inner PAP). Made by the NIT Srinagar Wi-Fi portal.",
        "# This script does not contain or store your password. Windows asks for it when you connect.",
        "# Run: right-click > Run with PowerShell, or: powershell -ExecutionPolicy Bypass -File <this file>",
        "Set-StrictMode -Version 2",
        "$ErrorActionPreference = 'Stop'",
        f"$Ssid = '{s.ssid}'",
        f"$CaPem = {_ps_here_string(s.ca_pem)}",
        f"$WlanXml = {_ps_here_string(windows_wlan_xml(s))}",
        "$Dir = Join-Path $env:TEMP ('nits-wifi-' + [guid]::NewGuid())",
        "New-Item -ItemType Directory -Path $Dir | Out-Null",
        "try {",
        "    $CaFile = Join-Path $Dir 'nits-lab-ca.pem'",
        "    $XmlFile = Join-Path $Dir 'nits-wifi.xml'",
        "    [IO.File]::WriteAllText($CaFile, $CaPem)",
        "    [IO.File]::WriteAllText($XmlFile, $WlanXml)",
        "    Write-Host 'Step 1: add the NIT Srinagar Lab CA to your trusted root certificates.'",
        "    Write-Host 'Windows shows a security warning. Check the thumbprint, then click Yes.'",
        f"    Write-Host 'SHA-1 thumbprint: {sha1_thumbprint(s)}'",
        "    certutil -user -addstore Root $CaFile",
        "    if ($LASTEXITCODE -ne 0) { throw 'certutil could not add the CA certificate.' }",
        "    Write-Host \"Step 2: add the Wi-Fi network $Ssid.\"",
        "    netsh wlan add profile filename=\"$XmlFile\" user=current",
        "    if ($LASTEXITCODE -ne 0) { throw 'netsh could not add the Wi-Fi profile.' }",
        f"    Write-Host \"Done. Connect to $Ssid. User name: {s.uid}. Then type your password.\"",
        "} finally {",
        "    Remove-Item -Recurse -Force $Dir",
        "}",
    ]
    return "\r\n".join("\n".join(lines).split("\n")) + "\r\n"     # CRLF everywhere, also in the here-strings


WLAN_TLS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid}</name>
  <SSIDConfig>
    <SSID>
      <hex>{ssid_hex}</hex>
      <name>{ssid}</name>
    </SSID>
    <nonBroadcast>false</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2</authentication>
        <encryption>AES</encryption>
        <useOneX>true</useOneX>
      </authEncryption>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <authMode>user</authMode>
        <EAPConfig>
          <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
            <EapMethod>
              <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
              <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
              <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
              <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
            </EapMethod>
            <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
              <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                <Type>13</Type>
                <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
                  <CredentialsSource>
                    <CertificateStore>
                      <SimpleCertSelection>true</SimpleCertSelection>
                    </CertificateStore>
                  </CredentialsSource>
                  <ServerValidation>
                    <DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
                    <ServerNames>{server_name}</ServerNames>
                    <TrustedRootCA>{ca_hash}</TrustedRootCA>
                  </ServerValidation>
                  <DifferentUsername>false</DifferentUsername>
                  <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>
                  <AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</AcceptServerName>
                </EapType>
              </Eap>
            </Config>
          </EapHostConfig>
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</WLANProfile>
"""


def windows_tls_wlan_xml(s):
    """WLANProfile for EAP-TLS (type 13, the Windows built-in method, author 0): the user
    certificate from the user's personal store (SimpleCertSelection), the server name and the root
    CA hash (TrustedRootCA, the SHA-1 thumbprint as for TTLS). DisableUserPromptForServerValidation:
    Windows refuses an unknown server and does not ask "connect anyway?". Not verified on a real
    laptop yet."""
    return WLAN_TLS_XML.format(ssid=escape(s.ssid), ssid_hex=s.ssid.encode("ascii").hex().upper(),
                               server_name=escape(s.server_name), ca_hash=sha1_thumbprint(s))


def _base64_lines(data):
    text = base64.b64encode(data).decode("ascii")
    return "\n".join(text[i:i + 76] for i in range(0, len(text), 76))


def windows_tls_ps1(s, p12):
    """PowerShell script for EAP-TLS: imports the PKCS#12 file into the user's personal store
    (Import-PfxCertificate asks for the passphrase with Read-Host -AsSecureString; the key is not
    marked exportable), adds the root CA to the user's trusted roots, then the WLAN profile."""
    p12 = check_p12(p12)
    lines = [
        f"# {s.ssid} Wi-Fi setup for {s.uid} (EAP-TLS, device certificate). Made by the NIT Srinagar Wi-Fi portal.",
        "# This script holds your device certificate and its key, encrypted with the passphrase that the",
        "# portal showed you. It does not contain the passphrase. Delete this file after the setup.",
        "# Run: right-click > Run with PowerShell, or: powershell -ExecutionPolicy Bypass -File <this file>",
        "Set-StrictMode -Version 2",
        "$ErrorActionPreference = 'Stop'",
        f"$Ssid = '{s.ssid}'",
        f"$CaPem = {_ps_here_string(s.ca_pem)}",
        f"$P12Base64 = {_ps_here_string(_base64_lines(p12))}",
        f"$WlanXml = {_ps_here_string(windows_tls_wlan_xml(s))}",
        "$Dir = Join-Path $env:TEMP ('nits-wifi-' + [guid]::NewGuid())",
        "New-Item -ItemType Directory -Path $Dir | Out-Null",
        "try {",
        "    $CaFile = Join-Path $Dir 'nits-lab-ca.pem'",
        "    $P12File = Join-Path $Dir 'nits-wifi-device.p12'",
        "    $XmlFile = Join-Path $Dir 'nits-wifi.xml'",
        "    [IO.File]::WriteAllText($CaFile, $CaPem)",
        "    [IO.File]::WriteAllBytes($P12File, [Convert]::FromBase64String(($P12Base64 -replace '\\s', '')))",
        "    [IO.File]::WriteAllText($XmlFile, $WlanXml)",
        "    Write-Host 'Step 1: add your device certificate.'",
        "    $Passphrase = Read-Host -AsSecureString 'Type the passphrase that the portal showed you'",
        "    Import-PfxCertificate -FilePath $P12File -CertStoreLocation Cert:\\CurrentUser\\My -Password $Passphrase | Out-Null",
        "    Write-Host 'Step 2: add the NIT Srinagar Lab CA to your trusted root certificates.'",
        "    Write-Host 'Windows shows a security warning. Check the thumbprint, then click Yes.'",
        f"    Write-Host 'SHA-1 thumbprint: {sha1_thumbprint(s)}'",
        "    certutil -user -addstore Root $CaFile",
        "    if ($LASTEXITCODE -ne 0) { throw 'certutil could not add the CA certificate.' }",
        "    Write-Host \"Step 3: add the Wi-Fi network $Ssid.\"",
        "    netsh wlan add profile filename=\"$XmlFile\" user=current",
        "    if ($LASTEXITCODE -ne 0) { throw 'netsh could not add the Wi-Fi profile.' }",
        "    Write-Host \"Done. Connect to $Ssid. Windows signs in with your device certificate.\"",
        "} finally {",
        "    Remove-Item -Recurse -Force $Dir",
        "}",
    ]
    return "\r\n".join("\n".join(lines).split("\n")) + "\r\n"     # CRLF everywhere, also in the here-strings


# ---- Linux (NetworkManager) -------------------------------------------------------------------

def linux_nmcli(s):
    """bash script for NetworkManager: writes the CA to ~/.local/share/nits-wifi/ca.pem and adds
    a connection. password-flags 2 (agent-owned, not saved by NetworkManager in its system file):
    the desktop asks for the password and keeps it in the user's keyring."""
    q = shlex.quote
    return "\n".join([
        "#!/bin/bash",
        f"# {s.ssid} Wi-Fi setup for {s.uid} (EAP-TTLS, inner PAP). Made by the NIT Srinagar Wi-Fi portal.",
        "# This script does not contain or store your password. NetworkManager asks for it.",
        "# Run: bash nits-wifi-setup.sh",
        "set -euo pipefail",
        f"SSID={q(s.ssid)}",
        'CA_DIR="$HOME/.local/share/nits-wifi"',
        'CA_FILE="$CA_DIR/ca.pem"',
        "command -v nmcli >/dev/null || { echo 'nmcli not found: this script needs NetworkManager.' >&2; exit 1; }",
        'mkdir -p "$CA_DIR"',
        "cat > \"$CA_FILE\" <<'NITS_CA_END'",
        s.ca_pem.rstrip("\n"),
        "NITS_CA_END",
        'chmod 644 "$CA_FILE"',
        f"echo 'CA SHA-256 fingerprint: {sha256_fingerprint(s)}'",
        "# Replace an older connection of the same name",
        'if nmcli -t -f NAME connection show | grep -Fxq -- "$SSID"; then',
        '    nmcli connection delete id "$SSID"',
        "fi",
        'nmcli connection add type wifi con-name "$SSID" ssid "$SSID" \\',
        "    wifi-sec.key-mgmt wpa-eap \\",
        "    802-1x.eap ttls \\",
        "    802-1x.phase2-auth pap \\",
        f"    802-1x.identity {q(s.uid)} \\",
        f"    802-1x.anonymous-identity {q(s.anonymous_identity)} \\",
        '    802-1x.ca-cert "$CA_FILE" \\',
        f"    802-1x.domain-suffix-match {q(s.server_name)} \\",
        "    802-1x.password-flags 2",
        f'echo "Done. Connect to $SSID. User name: {s.uid}. NetworkManager asks for your password."',
        "",
    ])


def linux_tls_nmcli(s, p12):
    """bash script for NetworkManager and EAP-TLS: writes the CA and the PKCS#12 file (mode 600) to
    ~/.local/share/nits-wifi/ and adds a connection that uses the file as client-cert and
    private-key. private-key-password-flags 2 (agent-owned): the desktop asks for the passphrase
    and keeps it in the user's keyring; NetworkManager does not save it in its system file."""
    p12 = check_p12(p12)
    q = shlex.quote
    return "\n".join([
        "#!/bin/bash",
        f"# {s.ssid} Wi-Fi setup for {s.uid} (EAP-TLS, device certificate). Made by the NIT Srinagar Wi-Fi portal.",
        "# This script holds your device certificate and its key, encrypted with the passphrase that the",
        "# portal showed you. It does not contain the passphrase. NetworkManager asks for it.",
        "# Run: bash nits-wifi-tls-setup.sh, then delete this file.",
        "set -euo pipefail",
        f"SSID={q(s.ssid)}",
        'CA_DIR="$HOME/.local/share/nits-wifi"',
        'CA_FILE="$CA_DIR/ca.pem"',
        'P12_FILE="$CA_DIR/device.p12"',
        "command -v nmcli >/dev/null || { echo 'nmcli not found: this script needs NetworkManager.' >&2; exit 1; }",
        "command -v base64 >/dev/null || { echo 'base64 not found.' >&2; exit 1; }",
        'mkdir -p "$CA_DIR"',
        'chmod 700 "$CA_DIR"',
        "cat > \"$CA_FILE\" <<'NITS_CA_END'",
        s.ca_pem.rstrip("\n"),
        "NITS_CA_END",
        'chmod 644 "$CA_FILE"',
        "(umask 077; base64 -d > \"$P12_FILE\" <<'NITS_P12_END'",
        _base64_lines(p12),
        "NITS_P12_END",
        ")",
        'chmod 600 "$P12_FILE"',
        f"echo 'CA SHA-256 fingerprint: {sha256_fingerprint(s)}'",
        "# Replace an older connection of the same name",
        'if nmcli -t -f NAME connection show | grep -Fxq -- "$SSID"; then',
        '    nmcli connection delete id "$SSID"',
        "fi",
        'nmcli connection add type wifi con-name "$SSID" ssid "$SSID" \\',
        "    wifi-sec.key-mgmt wpa-eap \\",
        "    802-1x.eap tls \\",
        f"    802-1x.identity {q(s.uid)} \\",
        '    802-1x.ca-cert "$CA_FILE" \\',
        '    802-1x.client-cert "$P12_FILE" \\',
        '    802-1x.private-key "$P12_FILE" \\',
        "    802-1x.private-key-password-flags 2 \\",
        f"    802-1x.domain-suffix-match {q(s.server_name)}",
        'echo "Done. Connect to $SSID. NetworkManager asks for the passphrase of your device certificate."',
        "",
    ])


# ---- ChromeOS ---------------------------------------------------------------------------------

def chromeos_onc(s):
    """Open Network Configuration (ONC) file: the root CA as an Authority certificate and a Wi-Fi
    network that uses it (ServerCARefs) with the server name (DomainSuffixMatch). No Password."""
    ca_guid = "{" + s.uuid("onc-ca").lower() + "}"
    onc = {
        "Type": "UnencryptedConfiguration",
        "Certificates": [{
            "GUID": ca_guid,
            "Type": "Authority",
            "X509": base64.b64encode(s.ca_der).decode("ascii"),
        }],
        "NetworkConfigurations": [{
            "GUID": "{" + s.uuid("onc-wifi").lower() + "}",
            "Name": s.ssid,
            "Type": "WiFi",
            "WiFi": {
                "SSID": s.ssid,
                "Security": "WPA-EAP",
                "AutoConnect": True,
                "EAP": {
                    "Outer": "EAP-TTLS",
                    "Inner": "PAP",
                    "Identity": s.uid,
                    "AnonymousIdentity": s.anonymous_identity,
                    "ServerCARefs": [ca_guid],
                    "UseSystemCAs": False,
                    "DomainSuffixMatch": [s.server_name],
                    "SubjectAlternativeNameMatch": [{"Type": "DNS", "Value": s.server_name}],
                    "SaveCredentials": True,
                },
            },
        }],
    }
    return json.dumps(onc, indent=2) + "\n"


# ---- Android app (GET /api/v1/profiles/android) -----------------------------------------------

def android_settings(s):
    """The fields of docs/api/v1.md section 5 (EAP-TTLS), for a WifiEnterpriseConfig in the app."""
    return {
        "ssid": s.ssid,
        "eap": "TTLS",
        "phase2": "PAP",
        "identity": s.uid,
        "anonymous_identity": s.anonymous_identity,
        "domain_suffix_match": s.server_name,
        "alt_subject_match": f"DNS:{s.server_name}",
        "ca_pem": s.ca_pem,
    }


def android_tls_settings(s):
    """The fields of docs/api/v1.md section 7 (EAP-TLS). The app makes its own key and gets its
    certificate from POST /api/v1/certs; the identity is the uid, the CN of that certificate."""
    return {
        "ssid": s.ssid,
        "eap": "TLS",
        "phase2": None,
        "identity": s.uid,
        "anonymous_identity": None,
        "domain_suffix_match": s.server_name,
        "alt_subject_match": f"DNS:{s.server_name}",
        "ca_pem": s.ca_pem,
    }
