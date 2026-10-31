"""All HTTP endpoints of the PIM server."""
from fastapi import APIRouter, Depends, Header, Request

import api_models as models
import audit_log
import device_service
from errors import PimError


def build_router(services) -> APIRouter:
    router = APIRouter(prefix="/api")
    accounts, chat, blocks = services.accounts, services.chat, services.blocks

    def device_claim(request: Request):
        return device_service.parse_device_header(request.headers.get(device_service.DEVICE_HEADER))

    def current_account(authorization: str = Header(default="")):
        token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
        return accounts.session_account(token)

    # ------------------------------------------------------------ registration
    @router.post("/register/start")
    def register_start(body: models.RegistrationStart, claim=Depends(device_claim)):
        return accounts.start_registration(body.username, body.password, body.email, body.phone)

    @router.post("/register/verify")
    def register_verify(body: models.CodesBody, claim=Depends(device_claim)):
        return accounts.verify_registration_codes(body.flow_id, body.email_code, body.phone_code)

    @router.post("/register/complete")
    def register_complete(body: models.CredentialBody, claim=Depends(device_claim)):
        return accounts.complete_registration(body.flow_id, body.credential, claim)

    # ------------------------------------------------------------------- login
    @router.post("/login/password")
    def login_password(body: models.PasswordLogin, claim=Depends(device_claim)):
        return accounts.login_with_password(body.username, body.password, claim)

    @router.post("/login/webauthn")
    def login_webauthn(body: models.CredentialBody, claim=Depends(device_claim)):
        return accounts.complete_login(body.flow_id, body.credential, claim)

    @router.post("/login/new-device/verify")
    def new_device_verify(body: models.CodesBody, claim=Depends(device_claim)):
        return accounts.verify_new_device_codes(body.flow_id, body.email_code, body.phone_code, claim)

    @router.post("/login/new-device/complete")
    def new_device_complete(body: models.CredentialBody, claim=Depends(device_claim)):
        return accounts.complete_new_device(body.flow_id, body.credential, claim)

    @router.post("/logout")
    def logout(authorization: str = Header(default="")):
        accounts.end_session(authorization[7:] if authorization.lower().startswith("bearer ") else "")
        return {"ok": True}

    @router.get("/me")
    def me(account=Depends(current_account)):
        return accounts.profile(account)

    # -------------------------------------------------------------------- chat
    @router.get("/users/search")
    def search(q: str = "", account=Depends(current_account)):
        return {"users": chat.search_users(account["id"], q)}

    @router.get("/conversations")
    def conversations(account=Depends(current_account)):
        return {"conversations": chat.conversations(account["id"])}

    @router.get("/messages/{peer}")
    def thread(peer: str, after: int = 0, account=Depends(current_account)):
        return chat.thread(account["id"], peer, after)

    @router.post("/messages")
    def send(body: models.SendMessage, account=Depends(current_account)):
        return chat.send_message(account["id"], body.to, body.body)

    @router.get("/requests")
    def requests_list(account=Depends(current_account)):
        return {"senders": chat.request_senders(account["id"])}

    @router.get("/requests/{sender}")
    def requests_thread(sender: str, account=Depends(current_account)):
        return chat.request_thread(account["id"], sender)

    # ------------------------------------------------------------------ blocks
    @router.get("/blocks")
    def blocks_overview(account=Depends(current_account)):
        return blocks.overview(account["id"])

    @router.post("/blocks")
    def blocks_create(body: models.BlockRequest, account=Depends(current_account)):
        return blocks.block_user(account["id"], body.username)

    @router.delete("/blocks/{block_id}")
    def blocks_unblock(block_id: int, account=Depends(current_account)):
        blocks.unblock(account["id"], block_id)
        return {"ok": True}

    @router.post("/blocks/{block_id}/confirm")
    def blocks_confirm(block_id: int, account=Depends(current_account)):
        blocks.confirm_block(account["id"], block_id)
        return {"ok": True}

    @router.post("/blocks/{block_id}/allow")
    def blocks_allow(block_id: int, account=Depends(current_account)):
        blocks.allow(account["id"], block_id)
        return {"ok": True}

    return router
