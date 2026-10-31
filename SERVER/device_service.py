"""Devices = physical PCs, identified by the hash of their TPM Endorsement Key.

The client agent reads the Endorsement Key (EK) public key from the TPM and
sends it with every request. The server hashes it itself, so the device id is
never taken on trust from the client, and it also checks that the EK
certificate (when one was sent) really contains that public key.

LIMITATION (documented in the threat model): the EK public key is not a secret,
and this MVP does not run the TPM2 MakeCredential / ActivateCredential
challenge that would prove the sender physically holds the TPM.
"""
import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

import clock
import settings
from errors import PimError

DEVICE_HEADER = "x-device-info"


@dataclass
class DeviceClaim:
    mode: str                      # REAL or SIMULATED
    ek_public_key: bytes
    ek_certificate: Optional[bytes]

    @property
    def ek_hash(self) -> str:
        return hashlib.sha256(self.ek_public_key).hexdigest()


def parse_device_header(header_value: Optional[str]) -> DeviceClaim:
    if not header_value:
        raise PimError(400, "TPM device information is missing. Start the PIM client agent on this PC.")
    try:
        payload = json.loads(base64.b64decode(header_value))
        mode = str(payload["mode"]).upper()
        public_key = base64.b64decode(payload["ek_public_key"])
        certificate = base64.b64decode(payload["ek_certificate"]) if payload.get("ek_certificate") else None
    except Exception:
        raise PimError(400, "TPM device information is malformed.")
    if mode not in ("REAL", "SIMULATED") or len(public_key) < 16:
        raise PimError(400, "TPM device information is malformed.")
    return DeviceClaim(mode=mode, ek_public_key=public_key, ek_certificate=certificate)


def _check_certificate(claim: DeviceClaim):
    """Returns (matches_public_key, issuer_name). The RSA modulus of the EK
    certificate must appear inside the submitted public key bytes, which holds
    for both raw PKCS#1 and SubjectPublicKeyInfo encodings."""
    if not claim.ek_certificate:
        return False, None
    try:
        certificate = x509.load_der_x509_certificate(claim.ek_certificate)
        key = certificate.public_key()
        issuer = certificate.issuer.rfc4514_string() or None
        if isinstance(key, rsa.RSAPublicKey):
            modulus = key.public_numbers().n
            modulus_bytes = modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")
            return modulus_bytes in claim.ek_public_key, issuer
        return False, issuer
    except Exception:
        return False, None


def ensure_device(db, claim: DeviceClaim) -> int:
    """Finds or creates the device row for this claim and returns its id."""
    if claim.mode == "SIMULATED" and not settings.ALLOW_SIMULATED_TPM:
        raise PimError(400, "This server only accepts real TPM devices.")
    existing = db.one("SELECT id FROM devices WHERE ek_hash = ?", (claim.ek_hash,))
    if existing:
        return existing["id"]
    certificate_ok, issuer = _check_certificate(claim)
    return db.insert(
        "INSERT INTO devices (ek_hash, ek_issuer, tpm_mode, cert_checked, first_seen) VALUES (?, ?, ?, ?, ?)",
        (claim.ek_hash, issuer, claim.mode, 1 if certificate_ok else 0, clock.now()),
    )


def find_device(db, claim: DeviceClaim):
    return db.one("SELECT * FROM devices WHERE ek_hash = ?", (claim.ek_hash,))


def link_account(db, account_id: int, device_id: int, source: str) -> None:
    """Attaches the device to the account. The moment a second account is linked
    to the same device, that device counts as shared from then on."""
    now = clock.now()
    db.execute(
        "INSERT OR IGNORE INTO account_devices (account_id, device_id, linked_at, link_source) VALUES (?, ?, ?, ?)",
        (account_id, device_id, now, source),
    )
    count = db.one("SELECT COUNT(*) AS n FROM account_devices WHERE device_id = ?", (device_id,))["n"]
    if count >= 2:
        db.execute("UPDATE devices SET shared_since = ? WHERE id = ? AND shared_since IS NULL", (now, device_id))


def device_ids_of(db, account_id: int) -> list:
    return [r["device_id"] for r in db.all("SELECT device_id FROM account_devices WHERE account_id = ?", (account_id,))]


def account_ids_on(db, device_id: int) -> list:
    return [r["account_id"] for r in db.all("SELECT account_id FROM account_devices WHERE device_id = ?", (device_id,))]


def shared_since(db, device_id: int, exclude_account_id: Optional[int] = None) -> Optional[float]:
    """When did this device first have two accounts, ignoring one account?
    The policy engine needs 'was it already shared before the newcomer?'."""
    rows = db.all(
        "SELECT linked_at FROM account_devices WHERE device_id = ? AND account_id != ? ORDER BY linked_at ASC",
        (device_id, exclude_account_id if exclude_account_id is not None else -1),
    )
    return rows[1]["linked_at"] if len(rows) >= 2 else None


def is_linked(db, account_id: int, device_id: int) -> bool:
    return db.one(
        "SELECT 1 FROM account_devices WHERE account_id = ? AND device_id = ?", (account_id, device_id)
    ) is not None
