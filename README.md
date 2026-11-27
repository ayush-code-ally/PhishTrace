# PhishTrace: Account Takeover (ATO) Security Gateway
 
Defensive demo for MindMatrix Project 02. A FastAPI gateway receives **only** `{username, password}` from a portal login page and does all security work server-side: password verification (PBKDF2), failure counting, quarantine, Pub/Sub alerting and audit logging. State lives in Firestore and alerts in Pub/Sub, both served by the **Floci** local GCP emulator on `localhost:4588`. No real GCP credentials are used.
 
> Synthetic accounts only. Never use real student data or credentials.
 
## Files
 
| File | Purpose |
| --- | --- |
| `main.py` | Gateway: `/events/login`, `/users/{id}/profile`, `/users/{id}/unquarantine`, portal at `/` |
| `seed.py` | Creates the synthetic users (hashed passwords) and the `security-alerts` topic/subscription |
| `index.html` | Student-portal login page plus a "Security desk" admin recovery panel |
| `alert_listener.py` | SOC monitor: prints alerts arriving on the subscription |
| `run_tests.py` | Automated verification of T01-T08, writes `evidence/After/test_run_*.txt` |
| `vulnerable_main.py` | **Baseline only** (intentionally insecure). Used for the "before" evidence. Never deploy |
| `FINDINGS_AND_TEST_MATRIX.md` | Findings register, test matrix, evidence index, limitations |
 
## Setup
 
```bash
python -m venv .venv
source .venv/Scripts/activate        # Git Bash on Windows; Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                 # then edit .env: set ADMIN_KEY (16+ chars). .env is git-ignored
```
 
`ADMIN_KEY` is required. The gateway refuses to start without it (there is no default). Set `ENABLE_TEST_ROUTES=1` only while running test T06.
 
## Run
 
1. **Floci** (WSL terminal): `floci gcp start` (port 4588)
2. **Seed** (also resets the demo): `python seed.py`
3. **Gateway**: `uvicorn main:app --port 8000`
4. **SOC monitor** (second terminal): `python alert_listener.py`
5. **Portal**: open <http://localhost:8000/>
Demo accounts: `synthetic_student_01` / `synthetic_student_02`. Their passwords are in `seed.py` (synthetic).
 
## Verify
 
With Floci, the gateway and `.env` (`ENABLE_TEST_ROUTES=1`) in place:
 
```bash
python run_tests.py          # whole suite twice; T08 = identical results on repeat
python run_tests.py --pull   # also pulls the alert from the subscription (stop alert_listener.py first)
```
 
Manual demo: enter 5 wrong passwords for `synthetic_student_01` (red banner, HTTP 403, alert in the listener window), then use "Security desk" with the admin key to restore the account.
 
## What is verified and what is not
 
* Verified locally against the Floci emulator: Firestore reads/updates (including atomic increment), Pub/Sub publish and pull.
* **Not verified / simulated:** Cloud Run (the app runs locally under uvicorn) and Cloud Logging (`audit.log.jsonl` is a local stand-in with the same structured fields). No claim is made about live GCP behaviour.
* Known limits: the lockout rule is "5 consecutive failures", not time-windowed. An attacker who knows a username can lock that account (a standard lockout trade-off). Unknown usernames are not rate-limited. See section 4 of `FINDINGS_AND_TEST_MATRIX.md`.
 