"""Thin wrapper around the `webauthn` library (FIDO2 / WebAuthn ceremonies).

Attestation is "none": the server only needs the public key. The TPM identity
comes from the separate device channel, not from WebAuthn, because WebAuthn is
deliberately unlinkable across accounts."""
import json
import os

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

import settings
from errors import PimError

# platform = Windows Hello on this PC; cross-platform = USB security key; any = let the browser offer both
_ATTACHMENT = {
    "platform": AuthenticatorAttachment.PLATFORM,
    "cross-platform": AuthenticatorAttachment.CROSS_PLATFORM,
    "any": None,
}[os.environ.get("PIM_AUTHENTICATOR_ATTACHMENT", "platform")]


def registration_options(username: str, user_id: bytes, existing_credential_ids=()):
    options = generate_registration_options(
        rp_id=settings.RELYING_PARTY_ID,
        rp_name=settings.RELYING_PARTY_NAME,
        user_id=user_id,
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=_ATTACHMENT,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c) for c in existing_credential_ids],
    )
    return json.loads(options_to_json(options)), options.challenge


def verify_registration(credential: dict, challenge: bytes):
    try:
        return verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.RELYING_PARTY_ID,
            expected_origin=settings.ALLOWED_ORIGINS,
            require_user_verification=True,
        )
    except Exception as error:
        raise PimError(400, f"Windows Hello / security key registration could not be verified ({error}).")


def authentication_options(credential_ids):
    options = generate_authentication_options(
        rp_id=settings.RELYING_PARTY_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c) for c in credential_ids],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options)), options.challenge


def credential_raw_id(credential: dict) -> bytes:
    try:
        return base64url_to_bytes(credential["rawId"])
    except Exception:
        raise PimError(400, "The credential response is malformed.")


def verify_authentication(credential: dict, challenge: bytes, public_key: bytes, sign_count: int):
    try:
        return verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.RELYING_PARTY_ID,
            expected_origin=settings.ALLOWED_ORIGINS,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
    except Exception as error:
        raise PimError(401, f"Windows Hello / security key verification failed ({error}).")
