"""Builds the FastAPI application and wires the services together."""
from types import SimpleNamespace

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import settings
from account_service import AccountService
from admin_page import build_admin_router
from api_routes import build_router
from block_service import BlockService
from chat_service import ChatService
from database import Database
from errors import PimError
from otp_service import OtpService
from policy_engine import PolicyEngine


def create_app(database: Database = None, show_otp: bool = None) -> FastAPI:
    db = database or Database(settings.DATABASE_PATH)
    engine = PolicyEngine(db)
    otp = OtpService(settings.DEMO_SHOW_OTP_IN_RESPONSE if show_otp is None else show_otp)
    services = SimpleNamespace(
        db=db,
        engine=engine,
        accounts=AccountService(db, engine, otp),
        chat=ChatService(db, engine),
        blocks=BlockService(db, engine),
    )
    app = FastAPI(title="FIDO2 PIM Chat server", docs_url=None, redoc_url=None)
    app.state.services = services

    @app.exception_handler(PimError)
    async def pim_error_handler(request: Request, error: PimError):
        return JSONResponse({"detail": error.message}, status_code=error.status_code)

    app.include_router(build_router(services))
    app.include_router(build_admin_router(db))

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
