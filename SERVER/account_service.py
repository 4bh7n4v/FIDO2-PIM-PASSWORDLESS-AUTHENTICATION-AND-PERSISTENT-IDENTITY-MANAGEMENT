"""Registration (UC-01), login (UC-02), new-device login (UC-06) and sessions."""
import hashlib
import hmac
import secrets
import threading
import time

import audit_log
import clock
import device_service
import settings
import webauthn_service
from errors import PimError
from flow_store import FlowStore
from identity_normalizer import normalize_email, normalize_phone, validate_username
from otp_service import OtpService
from policy_engine import PolicyEngine

_SCRYPT = dict(n=2**14, r=8, p=1, dklen=32)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **_SCRYPT)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


_DUMMY_HASH = hash_password("timing-equaliser")


class AccountService:
    def __init__(self, db, engine: PolicyEngine, otp: OtpService):
        self.db = db
        self.engine = engine
        self.otp = otp
        self.flows = FlowStore(settings.FLOW_LIFETIME_SECONDS)
        self._failures = {}
        self._failure_lock = threading.Lock()

    # ------------------------------------------------------------- sessions
    def create_session(self, account_id: int, device_id: int) -> str:
        token = secrets.token_urlsafe(32)
        now = clock.now()
        self.db.execute(
            "INSERT INTO sessions (token_hash, account_id, device_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (hashlib.sha256(token.encode()).hexdigest(), account_id, device_id, now,
             now + settings.SESSION_LIFETIME_SECONDS))
        return token

    def session_account(self, token: str):
        if not token:
            raise PimError(401, "Please log in.")
        row = self.db.one(
            """SELECT a.id, a.username, s.device_id, s.expires_at FROM sessions s
               JOIN accounts a ON a.id = s.account_id WHERE s.token_hash = ?""",
            (hashlib.sha256(token.encode()).hexdigest(),))
        if not row or row["expires_at"] < time.time():
            raise PimError(401, "Your session has expired. Please log in again.")
        return {"id": row["id"], "username": row["username"], "device_id": row["device_id"]}

    def end_session(self, token: str):
        self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256((token or "").encode()).hexdigest(),))

    def profile(self, account: dict) -> dict:
        device = self.db.one("SELECT * FROM devices WHERE id = ?", (account["device_id"],))
        return {
            "username": account["username"],
            "device": None if not device else {
                "ek_hash_short": device["ek_hash"][:8] + "…" + device["ek_hash"][-6:],
                "tpm_mode": device["tpm_mode"],
                "shared_pc": device["shared_since"] is not None,
            },
        }

    # ------------------------------------------------------------- UC-01
    def start_registration(self, username, password, email, phone) -> dict:
        username = validate_username(username)
        email_key = normalize_email(email)
        phone_key = normalize_phone(phone)
        if len(password or "") < settings.PASSWORD_MIN_LENGTH:
            raise PimError(400, f"Password must have at least {settings.PASSWORD_MIN_LENGTH} characters.")
        if self.db.one("SELECT 1 FROM accounts WHERE username = ?", (username,)):
            raise PimError(409, "That username is already taken.")
        taken = self.db.one("SELECT id FROM accounts WHERE email_normalized = ?", (email_key,))
        if taken:
            # Gmail signal: an alias of an existing address ("ra.vi+2@gmail.com"). Refused, and if
            # the owner is blocked by somebody the attempt is recorded as a likely block-evasion.
            blocked = self.db.one(
                "SELECT 1 FROM blocks WHERE target_id = ? AND mode = 'BLOCK' AND status = 'ACTIVE'", (taken["id"],))
            if blocked:
                audit_log.record(self.db, "EMAIL_ALIAS_EVASION_ATTEMPT", subject_id=taken["id"],
                                 attempted_username=username, attempted_email=email)
            raise PimError(409, "That e-mail address is already registered.")
        flow_id, flow = self.flows.create(
            "register", username=username, password_hash=hash_password(password), email=email.strip(),
            email_key=email_key, phone_key=phone_key, phone_display=phone.strip(), verified=False)
        codes = self.otp.issue(flow, email.strip(), phone.strip(), f"registration of '{username}'")
        response = {"flow_id": flow_id, "message": "Verification codes were sent to your e-mail and phone."}
        if self.otp.show_in_response:
            response["demo_codes"] = codes
        return response

    def verify_registration_codes(self, flow_id, email_code, phone_code) -> dict:
        flow = self.flows.get(flow_id, "register")
        self.otp.check(flow, email_code, phone_code)
        flow["verified"] = True
        flow["user_handle"] = secrets.token_bytes(16)
        options, challenge = webauthn_service.registration_options(flow["username"], flow["user_handle"])
        flow["challenge"] = challenge
        return {"webauthn_options": options}

    def complete_registration(self, flow_id, credential, claim) -> dict:
        flow = self.flows.get(flow_id, "register")
        if not flow.get("verified") or "challenge" not in flow:
            raise PimError(400, "Verify the e-mail and phone codes first.")
        verified = webauthn_service.verify_registration(credential, flow["challenge"])
        with self.db.transaction():
            if self.db.one("SELECT 1 FROM accounts WHERE username = ? OR email_normalized = ?",
                           (flow["username"], flow["email_key"])):
                raise PimError(409, "That username or e-mail was just registered by someone else.")
            device_id = device_service.ensure_device(self.db, claim)
            account_id = self.db.insert(
                """INSERT INTO accounts (username, password_hash, email, email_normalized, phone_normalized,
                                         webauthn_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (flow["username"], flow["password_hash"], flow["email"], flow["email_key"], flow["phone_key"],
                 flow["user_handle"], clock.now()))
            self.db.insert(
                """INSERT INTO credentials (account_id, credential_id, public_key, sign_count, device_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (account_id, verified.credential_id, verified.credential_public_key, verified.sign_count,
                 device_id, clock.now()))
            device_service.link_account(self.db, account_id, device_id, "REGISTRATION")
            audit_log.record(self.db, "ACCOUNT_REGISTERED", subject_id=account_id,
                             device=claim.ek_hash[:12], tpm_mode=claim.mode)
            self.engine.evaluate_new_account(account_id)   # UC-04, same transaction
            token = self.create_session(account_id, device_id)
        self.flows.delete(flow_id)
        return {"token": token, "username": flow["username"]}

    # ------------------------------------------------------------- UC-02 / UC-06
    def _check_lockout(self, username: str):
        key = username.lower()
        with self._failure_lock:
            recent = [t for t in self._failures.get(key, []) if t > time.time() - settings.LOGIN_LOCKOUT_SECONDS]
            self._failures[key] = recent
            if len(recent) >= settings.LOGIN_MAX_FAILURES:
                raise PimError(429, "Too many failed attempts. Try again in a few minutes.")

    def _record_failure(self, username: str):
        with self._failure_lock:
            self._failures.setdefault(username.lower(), []).append(time.time())

    def login_with_password(self, username, password, claim) -> dict:
        username = (username or "").strip()
        self._check_lockout(username)
        account = self.db.one("SELECT * FROM accounts WHERE username = ?", (username,))
        password_ok = verify_password(password or "", account["password_hash"] if account else _DUMMY_HASH)
        if not account or not password_ok:
            self._record_failure(username)
            audit_log.record(self.db, "LOGIN_FAILED", subject_id=account["id"] if account else None, username=username)
            raise PimError(401, "Invalid username or password.")

        device = device_service.find_device(self.db, claim)
        if device and device_service.is_linked(self.db, account["id"], device["id"]):
            credentials = self.db.all(
                "SELECT credential_id FROM credentials WHERE account_id = ? AND device_id = ?",
                (account["id"], device["id"])) or self.db.all(
                "SELECT credential_id FROM credentials WHERE account_id = ?", (account["id"],))
            options, challenge = webauthn_service.authentication_options([c["credential_id"] for c in credentials])
            flow_id, _ = self.flows.create("login", account_id=account["id"], challenge=challenge,
                                           device_hash=claim.ek_hash)
            return {"step": "WEBAUTHN", "flow_id": flow_id, "webauthn_options": options}

        # UC-06: password is right, but this PC is not known for the account
        flow_id, flow = self.flows.create("new_device", account_id=account["id"], device_hash=claim.ek_hash,
                                          verified=False)
        codes = self.otp.issue(flow, account["email"], account["phone_normalized"],
                               f"new PC for '{account['username']}'")
        response = {"step": "NEW_DEVICE", "flow_id": flow_id,
                    "message": "This PC is new for your account. Verification codes were sent to your e-mail and phone."}
        if self.otp.show_in_response:
            response["demo_codes"] = codes
        return response

    def complete_login(self, flow_id, credential, claim) -> dict:
        flow = self.flows.get(flow_id, "login")
        if flow["device_hash"] != claim.ek_hash:
            raise PimError(400, "Login must finish on the same PC where it started.")
        raw_id = webauthn_service.credential_raw_id(credential)
        row = self.db.one("SELECT * FROM credentials WHERE credential_id = ? AND account_id = ?",
                          (raw_id, flow["account_id"]))
        if not row:
            raise PimError(401, "This security credential does not belong to the account.")
        verified = webauthn_service.verify_authentication(credential, flow["challenge"], row["public_key"],
                                                          row["sign_count"])
        with self.db.transaction():
            self.db.execute("UPDATE credentials SET sign_count = ? WHERE id = ?", (verified.new_sign_count, row["id"]))
            device = device_service.find_device(self.db, claim)
            token = self.create_session(flow["account_id"], device["id"])
            audit_log.record(self.db, "LOGIN_OK", subject_id=flow["account_id"], device=claim.ek_hash[:12])
        self.flows.delete(flow_id)
        return {"token": token}

    def verify_new_device_codes(self, flow_id, email_code, phone_code, claim) -> dict:
        flow = self.flows.get(flow_id, "new_device")
        if flow["device_hash"] != claim.ek_hash:
            raise PimError(400, "Enrolment must finish on the same PC where it started.")
        self.otp.check(flow, email_code, phone_code)
        account = self.db.one("SELECT * FROM accounts WHERE id = ?", (flow["account_id"],))
        existing = [c["credential_id"] for c in self.db.all(
            "SELECT credential_id FROM credentials WHERE account_id = ?", (account["id"],))]
        options, challenge = webauthn_service.registration_options(account["username"], account["webauthn_user_id"], existing)
        flow["verified"] = True
        flow["challenge"] = challenge
        return {"webauthn_options": options}

    def complete_new_device(self, flow_id, credential, claim) -> dict:
        flow = self.flows.get(flow_id, "new_device")
        if not flow.get("verified") or flow["device_hash"] != claim.ek_hash:
            raise PimError(400, "Verify the e-mail and phone codes first, on the same PC.")
        verified = webauthn_service.verify_registration(credential, flow["challenge"])
        with self.db.transaction():
            device_id = device_service.ensure_device(self.db, claim)
            self.db.insert(
                """INSERT INTO credentials (account_id, credential_id, public_key, sign_count, device_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (flow["account_id"], verified.credential_id, verified.credential_public_key, verified.sign_count,
                 device_id, clock.now()))
            device_service.link_account(self.db, flow["account_id"], device_id, "NEW_DEVICE")
            audit_log.record(self.db, "NEW_DEVICE_LINKED", subject_id=flow["account_id"], device=claim.ek_hash[:12])
            self.engine.evaluate_new_account(flow["account_id"], device_ids=[device_id], check_phone=False)
        self.flows.delete(flow_id)
        # UC-06 steps 12-14: now prove the freshly registered credential with a normal login
        options, challenge = webauthn_service.authentication_options([verified.credential_id])
        login_id, _ = self.flows.create("login", account_id=flow["account_id"], challenge=challenge,
                                        device_hash=claim.ek_hash)
        return {"step": "WEBAUTHN", "flow_id": login_id, "webauthn_options": options}
