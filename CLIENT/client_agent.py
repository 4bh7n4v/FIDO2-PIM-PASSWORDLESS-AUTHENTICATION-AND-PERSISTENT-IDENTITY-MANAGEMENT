"""The local client agent. It runs on each user PC and does two jobs:

1. serves the chat web page on http://localhost:<port>  (localhost counts as a secure
   origin, so Windows Hello / WebAuthn works without HTTPS certificates)
2. forwards every API call to the PIM server and attaches this PC's TPM identity
   in the X-Device-Info header
"""
import hashlib
import base64
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from tpm_reader import device_header_value

WEB_DIR = Path(__file__).resolve().parent / "WEB"
FORWARDED_HEADERS = ("authorization", "content-type")


def create_agent_app(server_url: str, device_info: dict, http_client: httpx.Client = None) -> FastAPI:
    server_url = server_url.rstrip("/")
    header_value = device_header_value(device_info)
    ek_hash = hashlib.sha256(base64.b64decode(device_info["ek_public_key"])).hexdigest()
    client = http_client or httpx.Client(timeout=30)
    app = FastAPI(docs_url=None, redoc_url=None)

    @app.get("/agent/status")
    def status():
        try:
            reachable = client.get(f"{server_url}/health", timeout=3).status_code == 200
        except Exception:
            reachable = False
        return {"tpm_mode": device_info["mode"], "tpm_label": device_info["label"],
                "ek_hash_short": ek_hash[:8] + "…" + ek_hash[-6:], "server_url": server_url,
                "server_reachable": reachable}

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "DELETE"])
    async def forward(path: str, request: Request):
        headers = {name: value for name, value in request.headers.items() if name.lower() in FORWARDED_HEADERS}
        headers["x-device-info"] = header_value
        body = await request.body()
        try:
            upstream = client.request(request.method, f"{server_url}/api/{path}", params=request.query_params,
                                      content=body, headers=headers)
        except httpx.HTTPError:
            return JSONResponse({"detail": f"The PIM server at {server_url} is not reachable."}, status_code=502)
        return Response(content=upstream.content, status_code=upstream.status_code,
                        media_type=upstream.headers.get("content-type", "application/json"))

    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
    return app
