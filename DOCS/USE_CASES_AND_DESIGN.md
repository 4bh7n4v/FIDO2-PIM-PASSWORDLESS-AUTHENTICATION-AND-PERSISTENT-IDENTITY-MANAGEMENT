# FIDO2-PIM — FIDO2 Persistent Identity Management

**Course:** 20CYS401 Secure Software Engineering, Amrita School of Computing
**Team:** B. Hemanth Kumar (Security Engineer) · P. Abhinav (Project Lead & Backend) · P. Jashwanth (Frontend / Client)

---

## 1. Overview

FIDO2-PIM is a messaging system where a block follows the **person or device**, not just the account.
Users authenticate with **password + Windows Hello (FIDO2)**. Every client PC proves its identity with its
**TPM 2.0 Endorsement Key (EK)**. When User A blocks User B and B returns with a new account, the
Policy Engine checks the signals in priority order — **TPM > phone > Gmail** — and applies the block
automatically, softly, or not at all.

### Demo setup

| Machine | Role | Runs |
|---|---|---|
| PC-1 (Windows 11, TPM 2.0) | USER1 | `client/pim_client.py` (CLI) |
| PC-2 (Windows 11, TPM 2.0) | USER2 | `client/pim_client.py` (CLI) |
| PC-3 (Windows) | Server: IdP + Policy Engine + DB | `server/` (FastAPI + SQLite) |

All on one network (phone hotspot recommended). Because the client is a native script, not a browser,
no HTTPS domain/certificate setup is required for WebAuthn (TLS is still recommended for the API).

### Stack

- **Client:** Python, `fido2` (Yubico) → Windows WebAuthn API (Windows Hello), TPM access via Windows TBS / PowerShell
- **Server:** Python, FastAPI, SQLite, `fido2`/`webauthn` for ceremony verification
- **Verification:** mock OTP (printed on server console) for Gmail and phone

### Actors

Registered User · New User · Blocker (User A) · Blocked User (User B) · Identity Provider (IdP) ·
Policy Engine · FIDO2 Authenticator (Windows Hello) · TPM Agent

---

## 2. Use cases

### UC-01 Register a new account
**Actor:** New User · **Supporting:** IdP, Windows Hello, TPM Agent

1. User enters username, password, Gmail, phone.
2. Server sends mock OTPs for Gmail and phone; user enters both.
3. TPM Agent reads the EK + EK certificate; server checks the certificate chains to a known TPM manufacturer.
4. **TPM challenge:** server encrypts a secret to the EK (`MakeCredential`); the agent returns it via `ActivateCredential`.
5. Windows Hello creates a FIDO2 credential; server verifies and stores the public key.
6. Server records the `Device` (verified EK hash) and runs **UC-04** before activating the account.

**Exceptions:** wrong OTP · EK certificate unknown (VM / virtual TPM) · TPM challenge fails · Windows Hello cancelled.

### UC-02 Login
**Actor:** Registered User

1. User enters username + password → server verifies (hashed with Argon2/bcrypt).
2. Server issues a WebAuthn challenge → Windows Hello signs it → server verifies the signature and sign counter.
3. Server confirms the device's EK hash matches a device linked to the account (else → UC-06).
4. Session token issued.

### UC-03 Block a user
**Actor:** Blocker (User A)

1. A selects the target account and confirms.
2. Server records `Block(source_identity, target_identity)` with timestamp.
3. Block is resolved at query time from then on (no copying of rows).

### UC-04 Evaluate a new account against existing blocks (TPM-first)
**Actor:** Policy Engine

| Order | Condition | Result |
|---|---|---|
| 1 | TPM matches a blocked identity, device **SINGLE_USER** (or became shared *after* the block) | **AUTO_BLOCK** — treated as the same person |
| 2 | TPM matches a blocked identity, device was **SHARED before** the block | **SOFT_BLOCK** — hidden from blocker, blocker asked to confirm (UC-07) |
| 3 | Phone matches a blocked identity | **MESSAGE_REQUEST** — messages to blocker land in a requests folder |
| 4 | Normalized Gmail matches a blocked identity | **FLAG** — logged, rate-limited |
| 5 | No match | **ALLOW** |

A device becomes **SHARED** when ≥2 verified distinct users (different Gmail + phone + Windows Hello
credential) have registered on it. Gmail is normalized (dots and `+tag` removed) before comparison.

### UC-05 Enforce blocks on every interaction
**Actor:** Policy Engine

1. Every search, profile view and message passes through `evaluateInteraction(actor, target, action)`.
2. Blocks are checked in both directions via identity links.
3. Denied → the target appears as **"user not found"** (never reveals the block).
4. If the Policy Engine cannot decide (error/timeout) → **deny** (fail closed).

### UC-06 Login from a new PC (new device registration)
**Actor:** Registered User

1. User logs in on a new PC with password.
2. No credential/device found for this PC → TPM challenge + Windows Hello registration.
3. New credential and device linked to the **existing identity** (authenticated link).
4. Login completes.

### UC-07 Review soft blocks and auto-blocked accounts
**Actor:** Blocker (User A)

1. A sees: "A new account shares a device with someone you blocked — block it too?"
2. A chooses **Block** or **Allow**.
3. A can also view the list of auto-blocked accounts and **unblock** any wrongly linked one.

### UC-08 Unblock
**Actor:** Blocker

Removes the block; because blocks are resolved at query time, all linked accounts are unblocked instantly.

---

## 3. What is actually possible

| Feature | Status | Notes |
|---|---|---|
| Password + Windows Hello (FIDO2) login | ✅ Possible | `fido2` WindowsClient on Windows 10/11 |
| Read TPM EK + EK certificate | ✅ Possible | `Get-TpmEndorsementKeyInfo`; may need admin. Some firmware TPMs (Intel PTT / AMD fTPM) do not store the EK cert locally — Windows fetches it online |
| EK certificate chain check | ✅ Possible | Needs manufacturer root CAs (Intel, AMD, Infineon, STMicro, Nuvoton) bundled with the server |
| `MakeCredential` / `ActivateCredential` challenge | ⚠️ Possible, **highest risk** | Requires creating an attestation key and calling TPM2 commands from Python on Windows (TBS / TSS.MSR / Platform Crypto Provider). Prototype this in week 1; fallback = EK-hash-only with spoofing documented in STRIDE |
| TPM-first block decision (UC-04) | ✅ Possible | Pure server logic |
| Shared-device detection | ✅ Possible | Based on verified distinct users per EK |
| Query-time block enforcement (UC-05) | ✅ Possible | One SQL `EXISTS` query per interaction |
| Mock Gmail/phone OTP | ✅ Possible | Printed to server console |
| CLI messaging between PC-1 and PC-2 | ✅ Possible | Polling the server for new messages |
| Detect same person from **biometrics** | ❌ Not possible | Windows Hello never releases biometric data |
| Link accounts from **FIDO2 credential alone** | ❌ Not possible | Each registration is a new, unlinkable key pair |
| Stop a user with a **new PC + new SIM + new Gmail** | ❌ Not possible | Accepted, documented limitation |
| Support Mac / Linux / phones | ❌ Out of scope | Windows + TPM 2.0 only |

**Conclusion:** the project is feasible on 3 Windows PCs. The only part with real technical risk is the
full TPM credential-activation challenge; for the 1-day MVP it is deferred and the EK-hash-only
fallback is used (see §5).

---

## 4. Project tree (estimated)

```
fido2-pim/
├── README.md
├── requirements.txt
├── docs/
│   ├── USE_CASES.md               # this document
│   ├── STRIDE.md                  # threat model (next lab)
│   └── diagrams/                  # use case, class, sequence, DFD exports
├── server/
│   ├── main.py                    # FastAPI app entry point
│   ├── config.py                  # RP ID, DB path, OTP settings
│   ├── db/
│   │   ├── database.py            # SQLite connection
│   │   ├── models.py              # Identity, Account, Credential, Device, IdentityLink,
│   │   │                          # Block, Interaction, Otp, Session, AuditLog, ReviewItem
│   │   └── schema.sql
│   ├── api/
│   │   ├── auth.py                # /register, /login (UC-01, UC-02)
│   │   ├── devices.py             # /devices/attest, new device (UC-06)
│   │   ├── blocks.py              # /block, /unblock (UC-03, UC-08)
│   │   ├── interactions.py        # /search, /profile, /message (UC-05)
│   │   └── review.py              # soft-block review, auto-blocked list (UC-07)
│   ├── services/
│   │   ├── webauthn_service.py    # FIDO2 registration/assertion verification
│   │   ├── tpm_attestation.py     # EK cert chain + MakeCredential challenge
│   │   ├── otp_service.py         # mock OTP (console)
│   │   ├── linkage_service.py     # identity links, shared-device status
│   │   ├── policy_engine.py       # evaluate_new_account (UC-04), evaluate_interaction (UC-05)
│   │   └── audit.py               # audit logging
│   ├── certs/tpm_roots/           # TPM manufacturer root CAs
│   └── tests/
│       ├── test_policy_engine.py  # decision table incl. family / shared-device cases
│       ├── test_auth.py
│       └── test_tpm_attestation.py
├── client/
│   ├── pim_client.py              # CLI menu: register, login, search, message, block, review
│   ├── api_client.py              # HTTP calls to server
│   ├── webauthn_win.py            # Windows Hello via fido2 WindowsClient
│   ├── tpm_agent.py               # read EK, ActivateCredential
│   └── session_store.py           # local session token
└── scripts/
    ├── run_server.ps1
    ├── reset_db.py
    └── seed_demo.py               # demo users / shared-device scenario
```

---

## 5. One-day plan (MVP)

**Deadline: 1 day.** Scope is cut to what proves the core idea; everything else is documented as future work.

### In scope (MVP)

- UC-01 / UC-02: password + Windows Hello registration and login
- TPM: **EK hash only** (read via PowerShell as admin), sent with registration
- Mock OTP for Gmail and phone
- UC-03, UC-04, UC-05, UC-07, UC-08: blocks, TPM-first decision table, shared-device rule, "user not found" on deny, review/unblock
- CLI client with simple messaging (polling)
- Unit tests for the Policy Engine decision table (incl. family / shared-device cases)

### Deferred (future work, listed in STRIDE)

- EK certificate chain check and `MakeCredential` / `ActivateCredential` challenge → **EK-hash spoofing is a known, documented threat**
- UC-06 new-device flow (keep in design docs; demo only if time remains)
- TLS on the API, rate limiting, full audit trail (simple log table only)

### Schedule

| Time | Abhinav (Server) | Jashwanth (Client) | Hemanth (Security / QA) |
|---|---|---|---|
| Hour 0–1 | **All:** on all 3 PCs check Python 3.11+, Windows Hello PIN set up, `Get-TpmEndorsementKeyInfo` works as admin, PCs can reach the server (phone hotspot, firewall port open) | | |
| Hour 1–4 | DB schema, register/login API, WebAuthn verification, mock OTP | CLI menus, API client, Windows Hello (`webauthn_win.py`), TPM agent | Policy Engine decision-table unit tests, demo seed data |
| Hour 4–7 | Policy Engine (UC-04, UC-05), blocks, review/unblock API | Search, messaging, block, review screens | STRIDE draft, update use case / class diagrams |
| Hour 7–9 | **All:** integration on 3 PCs, fix bugs | | |
| Hour 9–10 | **All:** demo rehearsal (script below) | | |

### Demo script

1. PC-1: USER1 registers and logs in.
2. PC-2: USER2 registers, messages USER1 → delivered.
3. PC-1: USER1 blocks USER2 → USER2 now sees USER1 as "user not found".
4. PC-2: USER2 creates a new account (new Gmail + new phone) → **TPM match → AUTO_BLOCK**.
5. Seeded shared-device case: account on a device that was SHARED before the block → **SOFT_BLOCK**, USER1 reviews it (UC-07).
6. USER1 unblocks (UC-08) → all linked accounts unblocked instantly.
7. Show the server log / Policy Engine decisions.

---

## 6. Risks to carry into the STRIDE lab

- **Spoofing:** faked EK hash (mitigated by the TPM challenge); stolen password without Windows Hello.
- **Tampering:** modified client script; tampered DB rows for links/blocks.
- **Repudiation:** auto-block and link decisions must be audit-logged.
- **Information disclosure:** block existence leaked to the blocked user; EK hash is a permanent hardware ID (privacy).
- **Denial of service:** Policy Engine on every request; fail-closed turns outages into total denial.
- **Elevation of privilege:** abuse of unblock/review paths; family member auto-blocked after the block (bounded harm, undoable by blocker).

---

## 7. As built (differences from the plan above)

The implementation in this repository follows sections 2–3 with these decisions:

* **Web GUI instead of a pure CLI:** each client PC runs a small agent that serves the chat page on `http://localhost:<port>`
  (a secure origin, so Windows Hello works without certificates) and adds the TPM identity to every request.
* **Account = persistent identity.** There is no separate identity table: an account owns its FIDO2 credentials and the
  TPM-verified devices linked to it, and blocks are stored per (blocker, account) with a pointer to the block they came from.
* **Gmail tier:** because e-mail addresses are unique after normalisation, an alias of an existing address
  (`ra.vi+2@gmail.com`) is refused at registration and logged as `EMAIL_ALIAS_EVASION_ATTEMPT`, rather than creating a flagged account.
* **UC-06 is implemented** and additionally requires the e-mail and phone codes before a new PC may be enrolled.
* **TPM depth:** the EK public key is read and hashed by the server and its certificate is checked against the key;
  the `MakeCredential/ActivateCredential` proof-of-possession is **not** implemented (listed as a STRIDE threat).
* Screenshots of the working system: `DOCS/SCREENSHOTS/`.
