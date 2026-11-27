# PhishTrace — Findings Register, Test Matrix & Evidence Index

## 1. Findings Register (F-01 to F-05)

| Finding ID | Vulnerability / Threat | Baseline Behavior (Before) | Remediation / Control (After) | Mapped Test ID | Before Evidence | After Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F-01** | No brute-force lockout / credential stuffing protection | `POST /api/login` accepted 7+ consecutive invalid attempts (`"Invalid. Fails: 7"`) without blocking the account | `POST /events/login` increments `fails` in Floci Firestore and enforces `403 Forbidden` (`QUARANTINED`) on the 5th failed attempt | `T02` | `F-01 & F-04.png` | `Screenshot 2026-11-27 001646.png`, `Screenshot 2026-11-27 001710.png` |
| **F-02** | Broken authentication (client-controlled login bypass) | Sending `"password": "wrong_password"` with `"success": true` bypassed authentication and returned `200 OK` | Server-side PBKDF2 password hash verification in `seed.py` and `main.py`; invalid credentials strictly return `401 Unauthorized` | `T01` | `F02 &F-03.png` | `Screenshot 2026-11-27 003600.png`, `Screenshot 2026-11-27 001710.png` |
| **F-03** | Plaintext password storage & leakage in responses/logs | `200 OK` response directly leaked `"plaintext_password": "demo_password_123"` in JSON | Passwords hashed via PBKDF2 (`seed.py`); `audit.log.jsonl` logs only metadata (`corr_id`, `outcome`, `risk`) with zero password leaks | `T05`, `T07` | `F02 &F-03.png` | `Screenshot 2026-11-27 002934.png`, `Screenshot 2026-11-27 003041.png` |
| **F-04** | Verbose error disclosure & missing SOC alerting | Internal failure count exposed in `401` errors; unhandled crashes exposed stack details; no SOC alerts emitted | Safe `500` handler returns generic `"Internal processing error"` with `correlation_id`; Pub/Sub alert (`event=ALERT_PUBLISH`) emitted on quarantine | `T03`, `T06` | `F-01 & F-04.png` | `Screenshot 2026-11-27 001710.png`, `Screenshot 2026-11-27 002751.png` |
| **F-05** | Unauthenticated admin unlock & lack of account isolation | `POST /api/unquarantine/{username}` allowed any caller without authentication to reset accounts (`"Account reset by anyone"`) | Admin recovery gated behind `ADMIN_TOKEN` (`.env`), rejecting bad keys (`DENIED_BAD_KEY`) while isolating locked accounts from healthy users | `T04`, `T08` | `F-05.png` | `Screenshot 2026-11-27 003404.png`, `Screenshot 2026-11-27 003506.png` |

---

## 2. Verification Test Matrix (T01–T08)

| ID | Test Scenario | Expected Result | Baseline Result (Before) | After-Fix Result (After) | Pass/Fail | Evidence Filename |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T01** | Normal valid student login | `200 OK`, `outcome=SUCCESS`, failure counter reset to `0`, profile accessible | Accepted spoofed `"success": true` with wrong password (`200 OK`) | Valid login succeeds (`corr_id=req-2950b3`), `fails_reset=True`, UI shows *"Signed in as synthetic_student_01"* | **PASS** | `Screenshot 2026-11-27 001710.png`, `Screenshot 2026-11-27 003600.png` |
| **T02** | Brute-force lockout threshold (5 failed logins) | Attempts 1–4 return `401`; 5th attempt triggers `QUARANTINED` (`risk=85`) and `403 Forbidden` | Allowed 7+ failed logins (`"Invalid. Fails: 7"`) with `401` and no lockout | 5th failed attempt (`corr_id=req-347dad`) returned `403 Forbidden`; UI flashed red: *"Too many failed attempts. Account quarantined."* | **PASS** | `F-01 & F-04.png` (Before), `Screenshot 2026-11-27 001646.png`, `Screenshot 2026-11-27 001710.png` (After) |
| **T03** | Asynchronous SOC Pub/Sub alert publishing | Quarantining an account publishes an alert message (`alert_id`) to Floci Pub/Sub | No SOC alert published on repeated login failures | `event=ALERT_PUBLISH outcome=PUBLISHED alert_id=alrt-b8522e msg_id=3` logged on 5th failure | **PASS** | `Screenshot 2026-11-27 001710.png`, `Screenshot 2026-11-27 002934.png` |
| **T04** | Tenant/account isolation & unauthorised unlock protection | Quarantining `synthetic_student_01` does not lock `synthetic_student_02`; invalid admin keys are denied | Any unauthenticated caller could unlock any user via `/api/unquarantine/{username}` | `synthetic_student_02` logged in normally (`200_ACTIVE`); invalid admin keys logged `outcome=DENIED_BAD_KEY` | **PASS** | `F-05.png` (Before), `Screenshot 2026-11-27 003404.png`, `Screenshot 2026-11-27 002934.png` (After) |
| **T05** | Zero plaintext password leaks in structured audit logs | `audit.log.jsonl` records security events without plaintext passwords or tokens | Plaintext password (`demo_password_123`) exposed in API output | Verified 24 entries in `audit.log.jsonl` contain only `ts`, `corr_id`, `event`, `outcome`, `user_id`, `ip`, `risk`—zero secrets | **PASS** | `F02 &F-03.png` (Before), `Screenshot 2026-11-27 002934.png` (After) |
| **T06** | Safe internal error handling (`500` disclosure check) | Unhandled server exceptions return generic `500` JSON with `correlation_id`, hiding stack traces | Raw error/counter details exposed in API responses | `GET /api/crash` returned `{"detail": "Internal processing error", "correlation_id": "req-e161ce"}` and logged `SAFE_HANDLED` | **PASS** | `Screenshot 2026-11-27 002751.png`, `Screenshot 2026-11-27 002934.png` |
| **T07** | Repository secret & canary leak scan | Plaintext test password (`demo_password_123`) exists only inside `seed.py` hash setup, never in logs/UI/env leaks | Plaintext password returned directly in login response | Repo-wide search confirmed `demo_password_123` appears only once (`seed.py` PBKDF2 generator), zero leaks elsewhere | **PASS** | `Screenshot 2026-11-27 003041.png` |
| **T08** | Authorized admin recovery & full end-to-end regression | Valid `ADMIN_TOKEN` restores `QUARANTINED` account to `ACTIVE`, allowing normal sign-in afterward | Unauthenticated reset endpoint exposed without key verification | Valid Admin key restored `synthetic_student_01` (`Reference: req-952cf8`, `RESTORED_ACTIVE`), followed by successful login | **PASS** | `Screenshot 2026-11-27 003506.png`, `Screenshot 2026-11-27 003600.png` |

---

## 3. Evidence Index (`evidence/`)

1. `F-01 & F-04.png` — Baseline `POST /api/login` accepting 7 failed attempts (`401`) without lockout.
2. `F02 &F-03.png` — Baseline `POST /api/login` bypassing auth via `"success": true` and leaking `"plaintext_password"`.
3. `F-05.png` — Baseline unauthenticated `POST /api/unquarantine/synthetic_student_01` returning `200 OK`.
4. `Screenshot 2026-11-27 001646.png` — Hardened UI displaying red quarantine banner (`Reference: req-347dad`) after 5 failed attempts.
5. `Screenshot 2026-11-27 001710.png` — Uvicorn terminal log showing progressive risk scores (`20` → `85`), `403 Forbidden`, and `ALERT_PUBLISH` (`alert_id=alrt-b8522e`).
6. `Screenshot 2026-11-27 002751.png` — Safe `500` error response on `/api/crash` returning only generic detail and `correlation_id: req-e161ce`.
7. `Screenshot 2026-11-27 002934.png` — Structured `audit.log.jsonl` proving append-only logging (`DENIED_BAD_KEY`, `RESTORED_ACTIVE`, `SAFE_HANDLED`) with zero password leakage.
8. `Screenshot 2026-11-27 003041.png` — VS Code repo-wide search confirming `demo_password_123` is isolated to `seed.py`.
9. `Screenshot 2026-11-27 003404.png` — Account isolation proof showing `synthetic_student_02` signed in normally while `synthetic_student_01` is quarantined.
10. `Screenshot 2026-11-27 003506.png` — Security desk admin recovery restoring `synthetic_student_01` to `ACTIVE` (`Reference: req-952cf8`) with masked Admin key.
11. `Screenshot 2026-11-27 003600.png` — Post-recovery login verification confirming `synthetic_student_01` signs in normally after admin reset.

---

## 4. Documented Environment Limitations

* **Local Emulator Scope:** All tests ran locally on `localhost:8000` using the **Floci GCP emulator** for Firestore and Pub/Sub rather than live cloud infrastructure.
* **Cloud Logging Simulation:** Native GCP Cloud Logging was simulated via a local append-only JSONL adapter (`audit.log.jsonl`), preserving structured correlation IDs (`corr_id`) and schema parity for audit verification.
* **Synthetic Identities Only:** Testing used synthetic accounts (`synthetic_student_01`, `synthetic_student_02`) and test credentials (`demo_password_123`) in compliance with project privacy rules.
