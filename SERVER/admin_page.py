"""A read-only admin view for the demo: devices, blocks and the policy decisions.
Protected by the admin token that is printed when the server starts."""
import html
import time

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse

import audit_log
import settings
from errors import PimError


def _ts(value):
    return time.strftime("%H:%M:%S", time.localtime(value)) if value else "-"


def _table(headers, rows):
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def build_admin_router(db) -> APIRouter:
    router = APIRouter()

    @router.get("/admin", response_class=HTMLResponse)
    def admin(token: str = Query(default="")):
        if token != settings.ADMIN_TOKEN:
            raise PimError(403, "Admin token required: /admin?token=...")
        devices = db.all(
            """SELECT d.id, d.ek_hash, d.tpm_mode, d.cert_checked, d.shared_since,
                      (SELECT group_concat(a.username, ', ') FROM account_devices ad
                         JOIN accounts a ON a.id = ad.account_id WHERE ad.device_id = d.id) AS accounts
               FROM devices d ORDER BY d.id""")
        blocks = db.all(
            """SELECT b.id, bl.username AS blocker, t.username AS target, b.mode, b.origin, b.status,
                      b.root_block_id, b.reason FROM blocks b
               JOIN accounts bl ON bl.id = b.blocker_id JOIN accounts t ON t.id = b.target_id ORDER BY b.id""")
        accounts = db.all("SELECT username, email, phone_normalized FROM accounts ORDER BY id")
        events = audit_log.recent(db, 80)
        page = f"""<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="4">
<title>PIM admin</title><style>
body{{font:14px system-ui,Segoe UI,sans-serif;margin:24px;background:#0f172a;color:#e2e8f0}}
h1{{font-size:20px}} h2{{font-size:15px;margin:22px 0 6px;color:#7dd3fc}}
table{{border-collapse:collapse;width:100%;background:#1e293b}} th,td{{padding:5px 9px;border-bottom:1px solid #334155;text-align:left;font-size:13px;vertical-align:top}}
th{{color:#94a3b8;font-weight:600}}</style></head><body>
<h1>FIDO2 PIM &ndash; policy engine view <small style="color:#64748b">(refreshes every 4 s)</small></h1>
<h2>Devices (TPM identity)</h2>
{_table(["id", "EK hash", "TPM", "cert matches key", "shared since", "accounts"],
        [(d["id"], d["ek_hash"][:16] + "…", d["tpm_mode"], "yes" if d["cert_checked"] else "no", _ts(d["shared_since"]), d["accounts"]) for d in devices])}
<h2>Blocks</h2>
{_table(["id", "blocker", "target", "mode", "origin", "status", "root", "reason"],
        [(b["id"], b["blocker"], b["target"], b["mode"], b["origin"], b["status"], b["root_block_id"] or "", b["reason"]) for b in blocks])}
<h2>Accounts</h2>
{_table(["username", "e-mail", "phone key"], [(a["username"], a["email"], a["phone_normalized"]) for a in accounts])}
<h2>Audit log (newest first)</h2>
{_table(["time", "event", "actor", "subject", "detail"], [(_ts(e["ts"]), e["event"], e["actor"] or "", e["subject"] or "", e["detail"]) for e in events])}
</body></html>"""
        return HTMLResponse(page)

    return router
