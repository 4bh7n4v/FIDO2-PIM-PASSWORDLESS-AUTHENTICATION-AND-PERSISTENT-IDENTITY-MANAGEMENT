"""Reads this PC's TPM identity (the Endorsement Key) for the PIM client agent.

REAL mode      : asks Windows for the TPM 2.0 Endorsement Key through PowerShell
                 (Get-TpmEndorsementKeyInfo). This needs an elevated (Administrator) shell.
SIMULATED mode : creates and remembers a fake "TPM" per name, so the whole system
                 can be tried on a machine without a TPM and in automated tests.
"""
import base64
import datetime
import json
import os
import re
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SIMULATED_TPM_DIR = Path(os.environ.get("PIM_SIMULATED_TPM_DIR", Path(__file__).resolve().parent / "SIMULATED_TPM"))

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$isAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) { throw 'Administrator privilege is required to read the TPM endorsement key.' }
$info = Get-TpmEndorsementKeyInfo -HashAlgorithm sha256
if (-not $info -or -not $info.IsPresent) { throw 'No TPM 2.0 endorsement key is present on this PC (is the TPM enabled?).' }
$publicKey = $info.PublicKey
if ($publicKey.EncodedKeyValue -ne $null) { $raw = $publicKey.EncodedKeyValue.RawData } else { $raw = $publicKey.RawData }
$certificates = @()
foreach ($certificate in @($info.ManufacturerCertificates) + @($info.AdditionalCertificates)) {
    if ($certificate -ne $null) { $certificates += [Convert]::ToBase64String($certificate.RawData) }
}
$result = [ordered]@{
    public_key  = if ($raw) { [Convert]::ToBase64String($raw) } else { $null }
    public_hash = $info.PublicKeyHash
    certificate = if ($certificates.Count -gt 0) { $certificates[0] } else { $null }
}
$result | ConvertTo-Json -Compress
"""


class TpmUnavailable(Exception):
    pass


def _powershell_executable() -> str:
    return "powershell.exe"


def read_real_tpm() -> dict:
    try:
        completed = subprocess.run(
            [_powershell_executable(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", POWERSHELL_SCRIPT],
            capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise TpmUnavailable("PowerShell was not found. The real TPM reader only works on Windows.")
    except subprocess.TimeoutExpired:
        raise TpmUnavailable("PowerShell took too long to read the TPM.")
    output = (completed.stdout or "").strip()
    if completed.returncode != 0 or not output:
        problem = (completed.stderr or output or "unknown error").strip().splitlines()
        hint = ""
        text = " ".join(problem).lower()
        if "administrator" in text or "access" in text or "denied" in text or "privilege" in text:
            hint = " Start the client from an elevated (Run as administrator) PowerShell."
        raise TpmUnavailable("Could not read the TPM endorsement key: " + (problem[0] if problem else "") + hint)
    try:
        data = json.loads(output.splitlines()[-1])
    except json.JSONDecodeError:
        raise TpmUnavailable("Unexpected PowerShell output while reading the TPM.")
    public_key, public_hash = data.get("public_key"), data.get("public_hash")
    if not public_key:
        if not public_hash:
            raise TpmUnavailable("The TPM did not return an endorsement key.")
        # Windows only gave us its own hash of the key: use that as the stable identity.
        public_key = base64.b64encode(("ek-hash:" + str(public_hash).lower()).encode()).decode()
    return {"mode": "REAL", "ek_public_key": public_key, "ek_certificate": data.get("certificate"),
            "label": "Windows TPM 2.0"}


def read_simulated_tpm(name: str) -> dict:
    """A stable fake TPM: the key is created once and then reused for this name."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name or "PC")
    SIMULATED_TPM_DIR.mkdir(parents=True, exist_ok=True)
    path = SIMULATED_TPM_DIR / f"{safe}.json"
    if path.exists():
        stored = json.loads(path.read_text(encoding="utf-8"))
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Simulated TPM {safe}")])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PIM Simulated TPM CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - datetime.timedelta(days=1))
                       .not_valid_after(now + datetime.timedelta(days=3650))
                       .sign(key, hashes.SHA256()))
        stored = {
            "ek_public_key": base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.PKCS1)).decode(),
            "ek_certificate": base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode(),
        }
        path.write_text(json.dumps(stored), encoding="utf-8")
    return {"mode": "SIMULATED", "ek_public_key": stored["ek_public_key"],
            "ek_certificate": stored["ek_certificate"], "label": f"Simulated TPM '{safe}'"}


def device_header_value(info: dict) -> str:
    """The value the agent puts in the X-Device-Info header of every request."""
    payload = {"mode": info["mode"], "ek_public_key": info["ek_public_key"],
               "ek_certificate": info.get("ek_certificate")}
    return base64.b64encode(json.dumps(payload).encode()).decode()
