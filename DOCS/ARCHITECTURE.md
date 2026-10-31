# Architecture

```
 USER PC (x2)                                                         SERVER PC
┌────────────────────────────────────────────┐                  ┌────────────────────────────────┐
│ Browser  http://localhost:8765             │                  │  FastAPI  (SERVER/)            │
│   chat GUI + Windows Hello (WebAuthn)      │                  │   account_service  UC-01/02/06 │
│        │                                   │   HTTP + header  │   webauthn_service (FIDO2)     │
│        ▼                                   │   X-Device-Info  │   device_service   TPM devices │
│ Client agent (CLIENT/client_agent.py)  ────┼─────────────────►│   policy_engine    UC-03..05   │
│   · serves the GUI                         │                  │   block_service    UC-07/08    │
│   · reads the TPM Endorsement Key          │                  │   chat_service     messaging   │
│     (CLIENT/tpm_reader.py → PowerShell)    │                  │   SQLite (DATA/)               │
└────────────────────────────────────────────┘                  └────────────────────────────────┘
```

**Why a local agent?** A browser cannot read a TPM, and WebAuthn needs a secure origin. `http://localhost` is a secure
origin, so Windows Hello works without certificates, and the agent adds the TPM identity to every request.

**WebAuthn and the TPM are separate channels on purpose.** WebAuthn is *designed* to be unlinkable across accounts
(every registration gets a fresh key pair), so it can never say "this is the same PC". The TPM Endorsement Key is the
stable hardware identity; the server hashes it itself (`device_service.py`) and never trusts a hash from the client.

## Identity model

* **Account** = the persistent identity (`UserCredentialIdentity` in the class diagram): it owns its FIDO2 credentials and
  the TPM-verified devices linked to it (`account_devices`).
* **Device** = one physical PC, keyed by the SHA-256 of its TPM Endorsement Key. A device becomes **shared** at the moment
  a second account is linked to it (`device_service.link_account`).
* **Block** = one row per (blocker, account). Rows that the Policy Engine derives point to the manual block they came
  from (`root_block_id`), so unblocking the original block removes them all.

## What the Policy Engine decides (TPM > phone > Gmail)

| Situation | Result | Who is told |
|---|---|---|
| New account / newly linked PC matches a blocked account's **TPM**, and the PC was **not shared before the block** | `BLOCK` (origin TPM) — treated as the same person | blocker sees it under *Blocked automatically* and can free it |
| …but the PC was **already shared by 2+ accounts before the block** | `SOFT` — hidden from the blocker, messages held, blocker decides | blocker: *Needs your decision* |
| Same **phone number**, no TPM match | `REQUEST` — messages go to the blocker's message requests | blocker: *Message requests* |
| E-mail normalises to an existing one (`ra.vi+x@gmail.com`) | registration refused (*already registered*), logged as `EMAIL_ALIAS_EVASION_ATTEMPT` | admin audit log |
| Nothing matches | normal chat | – |

When the blocker blocks someone who already has other accounts on the same PC, those accounts become `SOFT`
(the PC is shared since before this block); accounts sharing the phone become `REQUEST`.

Enforcement on every interaction (UC-05) — `PolicyEngine.evaluate_interaction`:
* target blocked the actor → **404 "User not found"** (indistinguishable from a missing user; search results and
  conversations disappear too)
* target soft-blocked the actor → message accepted (sender sees "sent"), but held back (`QUARANTINE`)
* target requested → message filed as a request (`REQUESTS`)
* any internal error → **fail closed** (deny)

Rows for a new account are written **in the same database transaction that creates the account**, so there is no window
between "account exists" and "block applied".

## Data tables (`SERVER/database_schema.sql`)

`accounts`, `credentials`, `devices`, `account_devices`, `blocks`, `messages`, `sessions`, `audit_log`.

## Starting points for the STRIDE lab

| | Threat in this system | Where / mitigation today |
|---|---|---|
| **S**poofing | Fake client sends a victim's EK public key (the EK is not secret) → framing, or random keys → evasion | **Open:** needs TPM2 `MakeCredential/ActivateCredential` (proof the sender holds the TPM) and EK-certificate chain validation to TPM vendor roots. Today: server hashes the key itself and checks the certificate matches the key. |
| | Password stolen | Second factor: Windows Hello assertion; unknown PCs additionally need e-mail + phone codes (UC-06). Login lockout after 5 failures. |
| | Phishing / wrong site | WebAuthn is bound to the RP id `localhost` and the allowed origins (`ALLOWED_ORIGINS`); wrong origin test included. |
| **T**ampering | Edited `blocks` / `account_devices` rows; modified client script | DB is server-only; client script is untrusted for everything except the EK claim. |
| **R**epudiation | "I never blocked/unblocked/was blocked" | `audit_log` records every policy decision, block, unblock, login, device link (view: `/admin`). |
| **I**nformation disclosure | Blocked user learns about the block | Block looks like *User not found*; soft/request deliveries look like normal "sent". |
| | Blocker learns about the blocked person's other accounts (Review tab shows linked usernames) | Accepted: needed for the decision; document as privacy trade-off. |
| | EK hash is a permanent hardware identifier (GDPR-relevant) | Only the hash is stored; disclose and obtain consent. |
| **D**enial of service | Policy Engine is on the path of every interaction; failing closed turns an outage into total denial | One indexed query per interaction; fail-closed is deliberate. |
| | Attacker registers accounts on a victim's PC to get the victim auto-blocked | Bounded: only blockers of the attacker are affected, and each can free the victim (UC-07). |
| **E**levation of privilege | Using the new-PC flow to add an attacker's PC to a victim's account | Needs password **and** e-mail/phone codes **and** a new Windows Hello credential. |
| | Family member auto-blocked after the block | Soft/auto-block distinction + per-account release that is remembered. |

**Accepted limitation:** a user with a new PC **and** new phone **and** new Gmail evades the block. Every platform has this
limit; this design raises the cost of evasion from "make an e-mail" to "buy a PC and a SIM".
