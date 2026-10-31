"""Mock one-time codes for e-mail and phone verification.

Nothing is actually sent: the codes are printed on the server console, which is
what you show during the demo ("the SMS and the Gmail message"). The hashes are
stored in the ceremony state so the codes are never kept in clear text."""
import hashlib
import hmac
import secrets
import time

import settings
from errors import PimError


def _digest(salt: str, code: str) -> str:
    return hashlib.sha256((salt + code).encode()).hexdigest()


class OtpService:
    def __init__(self, show_in_response: bool = False):
        self.show_in_response = show_in_response

    def issue(self, flow: dict, email: str, phone_display: str, purpose: str) -> dict:
        salt = secrets.token_hex(8)
        email_code = f"{secrets.randbelow(10**6):06d}"
        phone_code = f"{secrets.randbelow(10**6):06d}"
        flow["otp"] = {
            "salt": salt,
            "email": _digest(salt, email_code),
            "phone": _digest(salt, phone_code),
            "attempts": 0,
            "expires_at": time.time() + settings.OTP_LIFETIME_SECONDS,
        }
        print(
            "\n+----------------------- MOCK OTP DELIVERY -----------------------+\n"
            f"  purpose : {purpose}\n"
            f"  e-mail  : {email:<32} code {email_code}\n"
            f"  SMS     : {phone_display:<32} code {phone_code}\n"
            "+-----------------------------------------------------------------+",
            flush=True,
        )
        return {"email_code": email_code, "phone_code": phone_code}

    def check(self, flow: dict, email_code: str, phone_code: str) -> None:
        otp = flow.get("otp")
        if not otp or otp["expires_at"] < time.time():
            raise PimError(400, "The verification codes have expired. Please start again.")
        otp["attempts"] += 1
        if otp["attempts"] > settings.OTP_MAX_ATTEMPTS:
            raise PimError(429, "Too many wrong codes. Please start again.")
        email_ok = hmac.compare_digest(otp["email"], _digest(otp["salt"], (email_code or "").strip()))
        phone_ok = hmac.compare_digest(otp["phone"], _digest(otp["salt"], (phone_code or "").strip()))
        if not (email_ok and phone_ok):
            raise PimError(400, "The e-mail or phone code is wrong.")
