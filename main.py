"""PhishTrace - self-defending login gateway (FastAPI + Floci Firestore/PubSub).

The client sends ONLY {username, password}. Everything else (failure counting,
quarantine, alerting, audit logging) is decided server-side.
"""
import os

# Route ALL traffic to the Floci emulator. Must be set before importing GCP libs.
os.environ["FIRESTORE_EMULATOR_HOST"] = "localhost:4588"
os.environ["PUBSUB_EMULATOR_HOST"] = "localhost:4588"

import datetime
import hashlib
import hmac
import json
import re
import secrets
import uuid
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from google.cloud import firestore, pubsub_v1
from pydantic import BaseModel, ConfigDict, Field

# Secrets come from .env (git-ignored), never from source code.
load_dotenv(Path(__file__).parent / ".env")

PROJECT_ID = "phishtrace-sandbox-team2"
TOPIC_ID = "security-alerts"
MAX_FAILS = 5
PBKDF2_ROUNDS = 200_000  # keep identical to seed.py

# F-07 fix: fail CLOSED. No default key exists, so a missing .env can never
# leave the admin endpoint protected by a value that is visible in the repo.
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
if len(ADMIN_KEY) < 16:
    raise RuntimeError("ADMIN_KEY missing or shorter than 16 chars. Copy .env.example to .env and set it.")
ENABLE_TEST_ROUTES = os.environ.get("ENABLE_TEST_ROUTES") == "1"
AUDIT_FILE = Path(__file__).parent / "audit.log.jsonl"
INDEX_FILE = Path(__file__).parent / "index.html"

app = FastAPI(title="PhishTrace Security Gateway (Floci GCP)")

# Allow the portal when opened via file:// (origin "null") or a local static server.
# Serving it from this app at http://localhost:8000/ needs no CORS at all.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "null",
        "http://localhost:8000", "http://127.0.0.1:8000",
        "http://localhost:8080", "http://127.0.0.1:8080",
        "http://localhost:5500", "http://127.0.0.1:5500",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Key"],
)

db = firestore.Client(project=PROJECT_ID)
publisher = pubsub_v1.PublisherClient()
TOPIC_PATH = publisher.topic_path(PROJECT_ID, TOPIC_ID)


# ---------------------------------------------------------------- helpers
def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def new_corr_id() -> str:
    return f"req-{uuid.uuid4().hex[:6]}"


def safe(value: Optional[str]) -> str:
    """Strip control chars / spaces so attacker input cannot forge log lines."""
    return re.sub(r"[^A-Za-z0-9_.@-]", "?", (value or "")[:64])


def audit(corr_id: str, event: str, outcome: str, user_id: Optional[str] = None,
          ip: Optional[str] = None, **extra) -> None:
    """Terminal + JSONL audit trail. Passwords are never passed in here."""
    ts = now_iso()
    parts = [f"[{ts}]", f"corr_id={corr_id}"]
    if user_id is not None:
        parts.append(f"user_id={safe(user_id)}")
    if ip:
        parts.append(f"ip={ip}")
    parts += [f"event={event}", f"outcome={outcome}"]
    parts += [f"{k}={v}" for k, v in extra.items()]
    print(" ".join(parts))
    record = {"ts": ts, "corr_id": corr_id, "event": event, "outcome": outcome,
              "user_id": safe(user_id) if user_id is not None else None, "ip": ip, **extra}
    try:
        with AUDIT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS).hex()


def verify_password(password: str, user: dict) -> bool:
    salt = bytes.fromhex(user.get("password_salt", ""))
    return hmac.compare_digest(hash_password(password, salt), user.get("password_hash", ""))


_DUMMY_SALT = secrets.token_bytes(16)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------- models
class LoginRequest(BaseModel):
    # extra="forbid": a client sending pre-computed fields (failed_attempts,
    # risk_score, success...) is rejected with 422 - no trusting the frontend.
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=1, max_length=128)


# ---------------------------------------------------------------- errors
@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    """F-06 fix: FastAPI's default 422 echoes the submitted value ("input") back
    and nothing is logged. Return only WHICH fields failed, never their values,
    and write an audit record with a correlation ID (T05)."""
    corr_id = new_corr_id()
    fields = sorted({safe(".".join(str(p) for p in e["loc"][1:]) or "body") for e in exc.errors()})
    audit(corr_id, "REQUEST_VALIDATION", "INVALID_INPUT", ip=client_ip(request),
          path=request.url.path, fields=",".join(fields))
    return JSONResponse(status_code=422, content={
        "detail": "Invalid request", "fields": fields, "correlation_id": corr_id})


@app.exception_handler(Exception)
async def safe_exception_handler(request: Request, exc: Exception):
    corr_id = new_corr_id()
    # Log only the exception TYPE; never the request body or message.
    audit(corr_id, "UNEXPECTED_ERROR", "SAFE_HANDLED", path=request.url.path,
          error=type(exc).__name__)
    return JSONResponse(status_code=500,
                        content={"detail": "Internal processing error", "correlation_id": corr_id})


# ---------------------------------------------------------------- alerting
def publish_alert(corr_id: str, uid: str, risk_score: int, fails: int) -> str:
    alert_id = f"alrt-{uuid.uuid4().hex[:6]}"
    payload = json.dumps({
        "alert_id": alert_id,
        "corr_id": corr_id,
        "user_id": uid,
        "triggered_rule": "BRUTE_FORCE_5_FAILED_LOGINS",
        "failed_attempts": fails,
        "risk_score": risk_score,
        "action": "ACCOUNT_QUARANTINED",
        "timestamp": now_iso(),
    }).encode("utf-8")

    future = publisher.publish(TOPIC_PATH, payload)  # non-blocking

    def _done(f):
        try:
            msg_id = f.result()
            audit(corr_id, "ALERT_PUBLISH", "PUBLISHED", user_id=uid, alert_id=alert_id, msg_id=msg_id)
        except Exception as exc:  # noqa: BLE001
            audit(corr_id, "ALERT_PUBLISH", "FAILED", user_id=uid, alert_id=alert_id,
                  error=type(exc).__name__)

    future.add_done_callback(_done)
    return alert_id


# ---------------------------------------------------------------- routes
@app.get("/", include_in_schema=False)
def portal():
    return FileResponse(INDEX_FILE)


# Plain `def` routes run in FastAPI's threadpool, so blocking Firestore calls
# don't stall the event loop.
@app.post("/events/login")
def login(body: LoginRequest, request: Request):
    corr_id = new_corr_id()
    ip = client_ip(request)
    uid = body.username.strip()
    ref = db.collection("users").document(uid)
    doc = ref.get()

    # Unknown user: same generic response as a wrong password (no user enumeration),
    # plus a dummy hash so response timing is similar.
    if not doc.exists:
        hash_password(body.password, _DUMMY_SALT)
        # Log a short hash, not the raw string: users sometimes type their
        # password into the username box, and that must never reach the log.
        masked = "unknown-" + hashlib.sha256(uid.encode()).hexdigest()[:8]
        audit(corr_id, "LOGIN", "USER_NOT_FOUND", user_id=masked, ip=ip)
        return JSONResponse(status_code=401, content={
            "decision": "DENY", "detail": "Invalid username or password",
            "correlation_id": corr_id})

    user = doc.to_dict()

    # Already quarantined: refuse even a correct password.
    if user.get("account_status") == "QUARANTINED":
        audit(corr_id, "LOGIN", "DENY_QUARANTINED", user_id=uid, ip=ip)
        return JSONResponse(status_code=403, content={
            "decision": "BLOCK_AND_QUARANTINE", "account_status": "QUARANTINED",
            "detail": "Account is quarantined. Contact the security desk.",
            "correlation_id": corr_id})

    # ---- T01: success
    if verify_password(body.password, user):
        token = secrets.token_urlsafe(32)
        ref.update({
            "fail_count": 0,
            "risk_score": 5,
            "account_status": "ACTIVE",
            "session_token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "last_login_at": now_iso(),
        })
        audit(corr_id, "LOGIN", "SUCCESS", user_id=uid, ip=ip, fails_reset=True)
        return {"decision": "ALLOW", "account_status": "ACTIVE", "user_id": uid,
                "session_token": token, "correlation_id": corr_id}

    # ---- T02: failure -> atomic server-side increment, then re-read the stored value
    ref.update({"fail_count": firestore.Increment(1), "last_failed_at": now_iso()})
    fails = int(ref.get().to_dict().get("fail_count", 0))
    risk = min(100, fails * 20)

    if fails >= MAX_FAILS:
        risk = 85
        ref.update({
            "account_status": "QUARANTINED",
            "risk_score": risk,
            "session_token_hash": None,  # revoke any live session
            "quarantined_at": now_iso(),
        })
        # ---- T03: alert on quarantine
        alert_id = publish_alert(corr_id, uid, risk, fails)
        audit(corr_id, "LOGIN", "QUARANTINED", user_id=uid, ip=ip, fails=fails,
              risk=risk, alert_id=alert_id)
        return JSONResponse(status_code=403, content={
            "decision": "BLOCK_AND_QUARANTINE", "account_status": "QUARANTINED",
            "risk_score": risk, "triggered_rules": ["BRUTE_FORCE_5_FAILED_LOGINS"],
            "detail": "Too many failed attempts. Account quarantined.",
            "correlation_id": corr_id})

    ref.update({"risk_score": risk})
    audit(corr_id, "LOGIN", "FAIL_AUTH", user_id=uid, ip=ip, fails=fails, risk=risk)
    return JSONResponse(status_code=401, content={
        "decision": "DENY", "account_status": "ACTIVE",
        "detail": "Invalid username or password",
        "correlation_id": corr_id})


@app.get("/users/{user_id}/profile")
def get_profile(user_id: str, request: Request, authorization: Optional[str] = Header(None)):
    corr_id = new_corr_id()
    ip = client_ip(request)
    doc = db.collection("users").document(safe(user_id)).get()

    if not doc.exists:
        audit(corr_id, "PROFILE_CHECK", "401_UNKNOWN", user_id=user_id, ip=ip)
        return JSONResponse(status_code=401, content={"detail": "Not authenticated",
                                                       "correlation_id": corr_id})
    user = doc.to_dict()

    if user.get("account_status") == "QUARANTINED":
        audit(corr_id, "PROFILE_CHECK", "403_QUARANTINED", user_id=user_id, ip=ip)
        return JSONResponse(status_code=403, content={
            "account_status": "QUARANTINED",
            "detail": "Account quarantined due to suspicious login activity.",
            "correlation_id": corr_id})

    token = (authorization or "").removeprefix("Bearer ").strip()
    stored = user.get("session_token_hash")
    if not token or not stored or not hmac.compare_digest(
            hashlib.sha256(token.encode()).hexdigest(), stored):
        audit(corr_id, "PROFILE_CHECK", "401_NO_SESSION", user_id=user_id, ip=ip)
        return JSONResponse(status_code=401, content={"detail": "Not authenticated",
                                                       "correlation_id": corr_id})

    audit(corr_id, "PROFILE_CHECK", "200_ACTIVE", user_id=user_id, ip=ip)
    return {"user_id": user_id, "account_status": user.get("account_status", "ACTIVE"),
            "risk_score": user.get("risk_score", 0), "correlation_id": corr_id}


@app.post("/users/{user_id}/unquarantine")
def unquarantine(user_id: str, request: Request, x_admin_key: Optional[str] = Header(None)):
    corr_id = new_corr_id()
    ip = client_ip(request)

    # bytes comparison: a non-ASCII header must not raise TypeError
    if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), ADMIN_KEY.encode()):
        audit(corr_id, "ADMIN_RECOVERY", "DENIED_BAD_KEY", user_id=user_id, ip=ip)
        return JSONResponse(status_code=401, content={"detail": "Invalid admin key",
                                                       "correlation_id": corr_id})

    ref = db.collection("users").document(safe(user_id))
    if not ref.get().exists:
        audit(corr_id, "ADMIN_RECOVERY", "NOT_FOUND", user_id=user_id, ip=ip)
        return JSONResponse(status_code=404, content={"detail": "User not found",
                                                       "correlation_id": corr_id})

    ref.update({"account_status": "ACTIVE", "fail_count": 0, "risk_score": 0,
                "session_token_hash": None})
    audit(corr_id, "ADMIN_RECOVERY", "RESTORED_ACTIVE", user_id=user_id, ip=ip)
    return {"user_id": user_id, "account_status": "ACTIVE", "correlation_id": corr_id}


# T06 test-only trigger. NOT registered unless ENABLE_TEST_ROUTES=1 in .env,
# so a normal deployment has no route that can be used to crash the service.
if ENABLE_TEST_ROUTES:
    @app.get("/api/crash")
    async def force_crash():
        raise ValueError("Simulated unexpected database failure.")