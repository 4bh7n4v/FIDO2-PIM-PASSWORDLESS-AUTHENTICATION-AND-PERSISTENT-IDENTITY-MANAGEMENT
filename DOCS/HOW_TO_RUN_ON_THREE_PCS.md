# Running FIDO2 PIM Chat on three Windows PCs

| | PC-1 | PC-2 | PC-3 |
|---|---|---|---|
| Role | USER1 | USER2 | **Server** (identity provider + Policy Engine + database) |
| Needs | TPM 2.0, Windows Hello | TPM 2.0, Windows Hello | Python only |

All three PCs must reach each other (same Wi-Fi, or better a **phone hotspot**: university Wi-Fi often blocks PC-to-PC traffic).

## 1. What to send where

| PC | Folder to copy | Only needs |
|---|---|---|
| PC-3 (server) | `SERVER\` | Python 3.10+ |
| PC-1, PC-2 (clients) | `CLIENT\` | Python 3.10+, TPM 2.0, a Windows Hello PIN (*Settings > Accounts > Sign-in options*) |

Each folder is self-contained: it has its own requirements file and a "from scratch" script that creates its own
virtual environment. (If PowerShell blocks scripts: `Set-ExecutionPolicy -Scope Process Bypass`.)

## 2. Start the server (PC-3) - the Policy Engine

```
cd SERVER
.\start_policy_engine_from_scratch.ps1
```
It installs what it needs, opens TCP 8000 in the firewall (when run as Administrator) and prints the exact command for the
clients, e.g. `.\start_client_from_scratch.ps1 -Server http://192.168.43.10:8000`. It also prints an admin link
`http://localhost:8000/admin?token=...` that shows devices, blocks and every Policy Engine decision live - keep it open on the projector.
**Keep this window visible: the mock OTP "SMS" and "Gmail" codes are printed here.**

Options: `-RealTpmOnly` (refuse simulated TPMs for the real demo), `-Reset` (empty database), `-ShowOtpInPages` (codes also shown in the web page), `-Port 9000`.

## 3. Start each client (PC-1 and PC-2)

```
cd CLIENT
.\check_tpm.ps1                  # once, as Administrator: must end with "OK"
.\start_client_from_scratch.ps1 -Server http://192.168.43.10:8000
```
The script installs what it needs, **re-opens itself as Administrator** (Windows only lets administrators read the TPM Endorsement Key),
checks that the server is reachable, reads the TPM and opens **http://localhost:8765**. Always use exactly that address
(with `localhost`, not an IP): Windows Hello only works for it.
Without a TPM: add `-Simulated -TpmName PC-2` (demo only; the server accepts it unless started with `-RealTpmOnly`).

## 4. Demo script

| Step | Where | What you show |
|---|---|---|
| 1 | PC-1 | Register **alice**. Codes for the mock e-mail and SMS appear in the **server window** (PC-3). Windows Hello creates the credential. |
| 2 | PC-2 | Register **bob**. Chat: bob finds alice and writes; alice answers. |
| 3 | PC-1 | alice presses **Block user** on bob. |
| 4 | PC-2 | bob can no longer find alice, and writing gives *User not found*. |
| 5 | PC-2 | bob logs out and registers **bob_again** with a new Gmail and new phone → he still cannot find alice. |
| 6 | PC-1 | **Review** tab: *bob_again* is in **Blocked automatically** — same TPM-verified PC. Admin page shows the decision. |
| 7 | PC-1 | Press **Not the same person – unblock** (bob_again is free; bob stays blocked). |
| 8 | PC-2 | **Soft block / family PC**: register **ravi** and **priya** on PC-2 first, then have alice (PC-1) block ravi: priya appears under **Needs your decision**; her messages are held (count shown) until alice presses **Allow** or **Block**. |
| 9 | PC-2 | Log in as alice on PC-2 (unknown PC) → OTP + new Windows Hello credential (**UC-06**). |
| 10 | – | Phone only: register **carol** on PC-3's client or a third browser profile with bob's phone number → her messages appear as a **message request**. |

To start again from an empty database run the server script with `-Reset`.

## Troubleshooting

| Problem | Fix |
|---|---|
| `TPM ERROR: Administrator privilege is required` | Start the client from PowerShell *Run as administrator*. |
| `No TPM 2.0 endorsement key is present` | Enable the TPM in the BIOS (fTPM on AMD, PTT on Intel). `Get-Tpm` must show `TpmPresent: True`. |
| Page says *server NOT REACHABLE* | Wrong IP, different networks, or firewall on PC-3 (TCP 8000). |
| Windows Hello does not appear / `SecurityError` | The page must be opened as `http://localhost:8765`, and a Windows Hello PIN must exist. |
| *Windows Hello … could not be verified (origin)* | The client port must be in 8765–8780 (or set `PIM_ALLOWED_ORIGINS` on the server). |
| *TPM … malformed* | The agent was not started through `run_client.py`. |
| Real TPM not available at all | Use `--tpm simulated --tpm-name PC-1` (see README); the server must allow it (default). |
