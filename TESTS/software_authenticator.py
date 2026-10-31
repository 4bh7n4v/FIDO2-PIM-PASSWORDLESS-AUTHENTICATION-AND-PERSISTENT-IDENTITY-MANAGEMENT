"""A software FIDO2 authenticator (like Windows Hello, but in Python) so the real
WebAuthn verification of the server can be exercised without a browser."""
import hashlib
import json
import os
from base64 import urlsafe_b64decode, urlsafe_b64encode

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ORIGIN = "http://localhost:8765"


def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftwareAuthenticator:
    def __init__(self):
        self.credentials = {}   # credential id -> [private key, sign count, user handle]

    def create(self, options: dict, origin: str = ORIGIN) -> dict:
        key = ec.generate_private_key(ec.SECP256R1())
        credential_id = os.urandom(32)
        numbers = key.public_key().public_numbers()
        cose_key = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        auth_data = (hashlib.sha256(options["rp"]["id"].encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big")
                     + bytes(16) + len(credential_id).to_bytes(2, "big") + credential_id + cbor2.dumps(cose_key))
        client_data = json.dumps({"type": "webauthn.create", "challenge": options["challenge"],
                                  "origin": origin, "crossOrigin": False}).encode()
        self.credentials[credential_id] = [key, 0, unb64url(options["user"]["id"])]
        return {
            "id": b64url(credential_id), "rawId": b64url(credential_id), "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})),
                "transports": ["internal"],
            },
        }

    def get(self, options: dict, origin: str = ORIGIN) -> dict:
        allowed = [unb64url(c["id"]) for c in options.get("allowCredentials", [])]
        credential_id = next((c for c in allowed if c in self.credentials), None)
        if credential_id is None:
            raise LookupError("this authenticator holds none of the allowed credentials")
        entry = self.credentials[credential_id]
        entry[1] += 1
        auth_data = hashlib.sha256(options["rpId"].encode()).digest() + bytes([0x05]) + entry[1].to_bytes(4, "big")
        client_data = json.dumps({"type": "webauthn.get", "challenge": options["challenge"],
                                  "origin": origin, "crossOrigin": False}).encode()
        signature = entry[0].sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": b64url(credential_id), "rawId": b64url(credential_id), "type": "public-key",
            "clientExtensionResults": {},
            "response": {"clientDataJSON": b64url(client_data), "authenticatorData": b64url(auth_data),
                         "signature": b64url(signature), "userHandle": b64url(entry[2])},
        }
