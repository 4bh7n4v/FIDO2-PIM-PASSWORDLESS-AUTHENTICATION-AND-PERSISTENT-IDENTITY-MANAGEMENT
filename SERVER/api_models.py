"""Request bodies for the JSON API."""
from typing import Any, Dict, Optional

from pydantic import BaseModel


class RegistrationStart(BaseModel):
    username: str
    password: str
    email: str
    phone: str


class CodesBody(BaseModel):
    flow_id: str
    email_code: str
    phone_code: str


class CredentialBody(BaseModel):
    flow_id: str
    credential: Dict[str, Any]


class PasswordLogin(BaseModel):
    username: str
    password: str


class SendMessage(BaseModel):
    to: str
    body: str


class BlockRequest(BaseModel):
    username: str
