# TEAM CONTRIBUTION: FIDO2-PIM Chat

Course: 20CYS401 Secure Software Engineering, Amrita School of Computing

| Member | Role | ID |
|---|---|---|
| P. Abhinav | Project Lead & Backend Developer | AM.SC.U4CYS23033 |
| B. Hemanth Kumar | Security Engineer | AM.SC.U4CYS23016 |
| P. Jashwanth | Frontend Developer | AM.SC.U4CYS23034 |

---

## 1. P. Abhinav: Project Lead & Backend Developer

I led the project and built the accounts, the sign-in, the database and the API. I also built the whole FIDO2 / Windows Hello part.

### What I did
- I built **Windows Hello registration** for new accounts (UC-01).
- I built **sign-in with Windows Hello** after the password check (UC-02).
- I built **adding a new PC** to an existing account, with a new Windows Hello for that PC (UC-06).
- I wrote the server-side checks of the Windows Hello response, and the browser-side code that asks Windows Hello to create and use the key.
- I made a software stand-in for Windows Hello so the automated tests can run without a real device.
- I built account registration and login: passwords, sessions and login lockout.
- I designed the database and the API.
- As project lead, I wrote the use cases, merged everyone's work, and planned the demo.

### My files
| Area | Files |
|---|---|
| FIDO2 | `SERVER/webauthn_service.py`, `CLIENT/WEB/webauthn_helpers.js`, `TESTS/software_authenticator.py`, FIDO2 settings in `SERVER/settings.py` |
| Accounts | `SERVER/account_service.py`, `SERVER/flow_store.py` |
| Server core | `SERVER/app.py`, `SERVER/api_routes.py`, `SERVER/api_models.py`, `SERVER/errors.py`, `SERVER/clock.py`, `SERVER/run_server.py` |
| Database | `SERVER/database.py`, `SERVER/database_schema.sql`, `SCRIPTS/reset_database.py` |
| Tests | `TESTS/test_registration_and_login.py`, `TESTS/conftest.py` |
| Docs | `DOCS/USE_CASES_AND_DESIGN.md`, `README.md` |

---

## 2. B. Hemanth Kumar: Security Engineer

I built the Policy Engine, the checks that identify a PC and a user, and the safety features of the system.

### What I did
- I built the **Policy Engine**, which decides whether a new account is blocked, held for review, or allowed (UC-04).
- I built **blocking and unblocking**, including the review actions (UC-03, UC-05, UC-07, UC-08).
- I built the **PC identification**: it reads the PC's TPM and turns it into a device ID, so a block follows the PC.
- I cleaned up Gmail addresses and phone numbers so the same person can't slip through with `a.b@gmail.com` instead of `ab@gmail.com`.
- I built the **OTP checks** (e-mail and phone codes) for registration and for new PCs.
- I built the **audit log and admin page**, so every important event (blocks, unblocks, failed logins) is recorded and can be viewed.
- I made the system **fail safely**: if anything goes wrong, it refuses instead of allowing.
- I wrote the **threat model (STRIDE)** and did the security review of the finished project.

### My files
| Area | Files |
|---|---|
| Policy Engine and blocks | `SERVER/policy_engine.py`, `SERVER/block_service.py` |
| PC identification | `SERVER/device_service.py`, `CLIENT/tpm_reader.py`, `CLIENT/check_tpm.ps1` |
| Matching signals | `SERVER/identity_normalizer.py` |
| OTP | `SERVER/otp_service.py` |
| Audit and admin | `SERVER/audit_log.py`, `SERVER/admin_page.py` |
| Security docs | STRIDE section of `DOCS/ARCHITECTURE.md` |
| Tests | `TESTS/test_policy_engine.py`, `TESTS/simulated_pc.py` |

---

## 3. P. Jashwanth: Frontend Developer

I built everything the user sees and clicks, and the chat itself.

### What I did
- I built the **chat web page** that opens in the browser at `http://localhost:8765`.
- I built the **sign-in, sign-up and OTP screens**, including the Windows Hello button.
- I built the **chat screens**: user search, conversation list, messages, and "user not found" for blocked users.
- I built the **chat backend**: sending messages, conversations, and holding messages for soft blocks.
- I built the **Review tab and Blocked tab**, where the user decides on automatic and soft blocks and unblocks people.
- I built the **local client program** that serves the page and connects it to the server, and its start script.
- I took the **screenshots** and wrote the **end-to-end browser test** that shows the whole demo working.

### My files
| Area | Files |
|---|---|
| Web page | `CLIENT/WEB/index.html`, `CLIENT/WEB/chat_style.css`, `CLIENT/WEB/chat_app.js` |
| Chat backend | `SERVER/chat_service.py` |
| Client program | `CLIENT/client_agent.py`, `CLIENT/run_client.py`, `CLIENT/start_client_from_scratch.ps1` |
| Tests | `TESTS/test_client_agent.py`, `TESTS/browser_end_to_end_check.py` |
| Docs | `DOCS/SCREENSHOTS/`, `DOCS/HOW_TO_RUN_ON_THREE_PCS.md` |

---

## 4. Work we did together

| Item | Who |
|---|---|
| Worksheets 2, 3 and 4 (use cases, class and sequence diagrams, DFD) | All three of us |
| Final integration and the live demo on 3 PCs | All three of us |
| Server start script `SERVER/start_policy_engine_from_scratch.ps1` | Abhinav and Hemanth |
| Project report and presentation | All three of us |

## 5. Summary

| Member | Main deliverable | Approx. share |
|---|---|---|
| P. Abhinav | Accounts and login, database and API, all FIDO2 / Windows Hello, project lead | 33% |
| B. Hemanth Kumar | Policy Engine, blocking, PC identification, OTP, audit log, threat model | 34% |
| P. Jashwanth | Chat web page and chat backend, client program, end-to-end test, screenshots | 33% |
