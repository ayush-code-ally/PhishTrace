# PhishTrace: Findings Register, Test Matrix and Evidence Index

Scenario: fictional college portal, synthetic accounts, local Floci emulator only. Finding IDs match the labels used in the baseline screenshots in `evidence/Before/`.

## 1. Findings Register

Severity scale follows the project guide: **High** = could expose sensitive data, allow unintended execution or permit unauthorised changes in this scenario; **Medium** = materially weakens a control or exposes unnecessary information with limited demonstrated impact; **Low** = limited weakness with small demonstrated impact.

| ID | Finding | Severity | Impact in this scenario | Baseline evidence (`vulnerable_main.py`) | Remediation (`main.py`) | Retest |
| --- | --- | --- | --- | --- | --- | --- |
| F-01 | No brute-force lockout or velocity limit | High | An attacker can guess passwords without limit and take over any student account | `Before/F-01 & F-04.png`: 7+ failures, no lockout (`Invalid. Fails: 7`) | Atomic server-side failure counter in Firestore; 5th failure sets `QUARANTINED`, returns 403, publishes an alert | T02, T03 (PASS) |
| F-02 | Plaintext password disclosed in the login response (and stored in plaintext) | High | Any successful login or database read exposes the credential | `Before/F02 &F-03.png`: response contains `plaintext_password` | PBKDF2-SHA256 salted hashes (`seed.py`); responses never contain credentials; constant-time compare | T05, T07 (PASS) |
| F-03 | Client-controlled authentication bypass (`"success": true`) | High | Login succeeds with a wrong password: full account takeover with one request | `Before/F02 &F-03.png`: wrong password plus `success:true` returns 200 | Server verifies the password hash; request model forbids extra fields (client cannot send `success`, `failed_attempts`, `risk_score`) | T01, T07 (PASS) |
| F-04 | Username enumeration (404 for unknown user, failure counter in 401 detail) | Low | Lets an attacker confirm valid student IDs and see their lockout progress | `Before/F-01 & F-04.png`: `User Not Found` vs `Invalid. Fails: N` | Unknown user and wrong password give the same generic 401; unknown names are logged only as a short hash | T02, T05 (PASS) |
| F-05 | Unauthenticated admin endpoint (`/api/unquarantine/{user}`) | High | Anyone can undo containment, defeating the control | `Before/F-05.png`: 200 with no credentials | `X-Admin-Key` required (constant-time compare); bad or missing key returns 401 and is logged `DENIED_BAD_KEY` | T04, T08 (PASS) |
| F-06 | Validation errors echo the submitted value; rejected requests are not logged | Low | An over-long or malformed field (including a password typed into the wrong box) is reflected in the response and leaves no audit trail | Found while reviewing the first hardened build. Reproduce on the old `main.py`: `curl -d '{"username":"Canary Pass!99","password":"x"}'` returns `"input":"Canary Pass!99"`, audit log unchanged | Custom `RequestValidationError` handler: returns field names only plus `correlation_id`, writes `INVALID_INPUT` audit record | T05, T07 (PASS) |
| F-07 | Admin key defaulted to a value visible in source; test crash route always registered | Medium | If `.env` is not loaded the admin endpoint is protected by a publicly known key; a crash route is reachable in normal runs | Found while reviewing the first hardened build: `os.environ.get("ADMIN_KEY", "phishtrace-admin-demo")`, unconditional `/api/crash` | `.env` loaded with python-dotenv; gateway refuses to start if `ADMIN_KEY` is missing or under 16 characters; `/api/crash` exists only when `ENABLE_TEST_ROUTES=1` | T07, T06 (PASS) |

F-06 and F-07 were weaknesses in our own first remediation, found during verification and fixed before release.

## 2. Test Matrix

Expected results follow section 8 of the project guide. "Observed (first hardened build)" comes from the screenshots already taken. "Retest (final build)" is completed by running `python run_tests.py` on Floci with the final `main.py`.

| ID | Test | Expected result after fix | Baseline result | Observed (first hardened build) | Retest (final build) | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| T01 | Normal login does not create an unnecessary alert | 200 ALLOW, failure counter reset to 0, no alert published | Wrong password plus `success:true` was accepted | Valid login `corr_id=req-2950b3`, `outcome=SUCCESS fails_reset=True` | PASS (`200/ALLOW`, counter reset `fails=1` on next fail, alerts published=0) | `After/Screenshot 2026-11-27 003600.png`, `After/test_run_20261127T141200Z.txt` |
| T02 | Repeated failed logins trigger the documented rule | Attempts 1-4 return 401; attempt 5 returns 403 `QUARANTINED` (rule `BRUTE_FORCE_5_FAILED_LOGINS`, risk 85) | 7+ failures allowed | Risk 20, 40, 60, 80, then `QUARANTINED risk=85` (`req-347dad`) | PASS (attempts 1-4=`401`, attempt 5=`403/QUARANTINED`, subsequent valid login=`403`) | `After/Screenshot 2026-11-27 001646.png`, `001710.png`, `After/test_run_20261127T141200Z.txt` |
| T03 | Alert reaches subscriber and is traceable by ID | Alert with `alert_id` and `corr_id` arrives on `security-alerts-sub`; same IDs appear in the audit log | No alert existed | Publish logged: `alert_id=alrt-b8522e msg_id=3` | PASS (`alert_id=alrt-3f8786` / `alrt-d60410` matched across audit log and `security-alerts-sub`) | `After/Screenshot 2026-11-27 001710.png`, `After/T03_alert_listener.png`, `After/test_run_20261127T141200Z.txt` |
| T04 | Containment affects only the synthetic demo account | `synthetic_student_01` blocked; `synthetic_student_02` unaffected; wrong admin key refused | Any caller could unlock any user | student_02 signed in normally while student_01 was quarantined | PASS (`student_01=403`, `student_02=200`, bad/missing `X-Admin-Key=401`) | `After/Screenshot 2026-11-27 003404.png`, `After/test_run_20261127T141200Z.txt` |
| T05 | Logs support investigation without credentials | Each attempt has timestamp, `corr_id`, event, outcome; no password, token or key | Password present in output | 24 audit entries, fields `ts, corr_id, event, outcome, user_id, ip` | PASS (23 records/run, `missing_fields=0`, `secrets_found=0`, rejected input logged) | `After/Screenshot 2026-11-27 002934.png`, `After/test_run_20261127T141200Z.txt` |
| T06 | Controlled unexpected error | Generic 500 with `correlation_id`; no stack trace; `SAFE_HANDLED` logged | Not demonstrated | `GET /api/crash` returned generic detail, `req-e161ce` | PASS (`status=500`, keys `['correlation_id', 'detail']`, `internals_leaked=none`, `SAFE_HANDLED=True`) | `After/Screenshot 2026-11-27 002751.png`, `After/test_run_20261127T141200Z.txt` |
| T07 | Inspect source, output and logs for sensitive data | No secret in responses, audit log, tracked source or git history | Plaintext password in response | `demo_password_123` found only in `seed.py` at the time of the search | PASS (0 secrets in responses, audit log, tracked source, or git history; PBKDF2 hashes verified) | `After/Screenshot 2026-11-27 003041.png`, `After/T07_firestore_hashes.png`, `After/Screenshot 2026-11-27 194729.png`, `After/test_run_20261127T141200Z.txt` |
| T08 | Repeat the complete test set | Identical results on repeat; admin recovery restores the account | Not applicable | Admin recovery `req-952cf8` then normal login | PASS (2 full consecutive runs identical; admin reset `200/ACTIVE` + `RESTORED_ACTIVE=True`) | `After/Screenshot 2026-11-27 003506.png`, `After/test_run_20261127T141200Z.txt` |

Note on T07: the synthetic password also appears in `vulnerable_main.py` (baseline file) and in this document. Both are synthetic demo values; the test checks that no *running component* leaks it.

## 3. Evidence Index

* **Baseline (`evidence/Before/`):** `F-01 & F-04.png`, `F02 &F-03.png`, `F-05.png`.
* **Hardened build (`evidence/After/`):** `Screenshot 2026-11-27 001646.png` (quarantine banner), `Screenshot 2026-11-27 001710.png` (log: risk 20 to 85, 403, `ALERT_PUBLISH`), `Screenshot 2026-11-27 002751.png` (safe 500), `Screenshot 2026-11-27 002934.png` (audit log), `Screenshot 2026-11-27 003041.png` (secret search), `Screenshot 2026-11-27 003404.png` (isolation), `Screenshot 2026-11-27 003506.png` (admin recovery), `Screenshot 2026-11-27 003600.png` (login after recovery), `Screenshot 2026-11-27 194729.png` (final secret check), `T03_alert_listener.png` (subscriber alert delivery), `T07_firestore_hashes.png` (PBKDF2 salted password hashes in Firestore), `test_run_20261127T141200Z.txt` (automated 2x repeatability test suite log).
* **Reports (`evidence/`):** `Original_Design_Blueprint.pdf`, `PhishTrace Security Assessment & Hardening Report.pdf`.

## 4. Limitations and Residual Risks

| Item | Rating | Note |
| --- | --- | --- |
| Lockout can be abused: anyone who knows a username can lock that account with 5 bad passwords | Medium | Standard trade-off. Mitigation in production: per-IP throttling, CAPTCHA, time-boxed lock, MFA recovery |
| The 403 "quarantined" response after 5 attempts still reveals that a username exists (unknown names never reach 403) | Low | Inherent to explicit lockout messaging; F-04 removed the other enumeration signals (404, counters) |
| Rule is 5 consecutive failures, no time window or decay | Low | Occasional typos accumulate; a windowed counter is the next step |
| Unknown usernames and per-IP volume are not rate-limited | Low | Spraying across many usernames is not detected |
| Concurrent failing requests can produce a duplicate alert | Informational | Atomic increment keeps the count correct |
| Admin key is a single shared secret over plain HTTP on localhost | Low | Production would use identity-based admin access and TLS |
| Cloud Run and Cloud Logging not used | Informational | App runs locally; `audit.log.jsonl` is a local stand-in. No claim about live GCP |
| Floci is an emulator | Informational | Behaviour verified only against Floci |
