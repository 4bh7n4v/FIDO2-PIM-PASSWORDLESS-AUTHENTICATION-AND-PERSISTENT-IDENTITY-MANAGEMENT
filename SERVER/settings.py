"""Central configuration for the PIM server.

Everything can be overridden with environment variables so the same code runs
on the demo server PC and inside the automated tests.
"""
import os
import secrets
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# --- storage -----------------------------------------------------------------
DATABASE_PATH = Path(os.environ.get("PIM_DATABASE_PATH", Path(__file__).resolve().parent / "DATA" / "pim_chat.sqlite3"))

# --- WebAuthn / FIDO2 --------------------------------------------------------
# The browser talks to a local client agent on http://localhost:<port>, so the
# relying-party id is "localhost". Windows Hello works on localhost over http.
RELYING_PARTY_ID = os.environ.get("PIM_RP_ID", "localhost")
RELYING_PARTY_NAME = "FIDO2 PIM Chat"
_default_origins = ",".join(f"http://localhost:{port}" for port in range(8765, 8781))
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("PIM_ALLOWED_ORIGINS", _default_origins).split(",") if o.strip()]

# --- TPM ---------------------------------------------------------------------
# Simulated TPMs let the project be demonstrated on a machine without a TPM
# (and let the automated tests run). Turn this off for the real demo.
ALLOW_SIMULATED_TPM = os.environ.get("PIM_ALLOW_SIMULATED_TPM", "1") == "1"

# --- OTP (mock) --------------------------------------------------------------
# Codes are printed on the server console. Setting this to 1 also returns them
# in the API response so a single-person test does not need two windows.
DEMO_SHOW_OTP_IN_RESPONSE = os.environ.get("PIM_DEMO_SHOW_OTP", "0") == "1"
OTP_LIFETIME_SECONDS = 600
OTP_MAX_ATTEMPTS = 5

# --- sessions / login --------------------------------------------------------
SESSION_LIFETIME_SECONDS = 8 * 3600
FLOW_LIFETIME_SECONDS = 600          # registration / login ceremonies
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 300
PASSWORD_MIN_LENGTH = 8

# --- admin page --------------------------------------------------------------
ADMIN_TOKEN = os.environ.get("PIM_ADMIN_TOKEN") or secrets.token_urlsafe(12)
