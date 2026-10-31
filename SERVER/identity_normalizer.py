"""Turns e-mail addresses and phone numbers into comparable keys.

Gmail ignores dots and "+tag" suffixes, so ra.vi+x@gmail.com and ravi@gmail.com
are the same inbox. Phone numbers are compared on their last 10 digits so that
"+91 98765 43210" and "09876543210" match.
"""
import re

from errors import PimError

_EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_USERNAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{2,23}$")
_GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}


def normalize_email(email: str) -> str:
    email = (email or "").strip()
    if not _EMAIL_PATTERN.match(email):
        raise PimError(400, "Enter a valid e-mail address.")
    local, domain = email.lower().rsplit("@", 1)
    local = local.split("+", 1)[0]
    if domain in _GMAIL_DOMAINS:
        local = local.replace(".", "")
        domain = "gmail.com"
    return f"{local}@{domain}"


def normalize_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    if not 8 <= len(digits) <= 15:
        raise PimError(400, "Enter a valid phone number (8 to 15 digits).")
    return digits[-10:]


def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not _USERNAME_PATTERN.match(username):
        raise PimError(400, "Username must be 3-24 characters, start with a letter and use only letters, digits, . _ -")
    return username
