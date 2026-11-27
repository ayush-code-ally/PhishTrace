"""PhishTrace - automated verification of the MindMatrix test matrix T01-T08.

Prerequisites: Floci running, `python seed.py` done, gateway running
(`uvicorn main:app --port 8000`), and .env containing ADMIN_KEY
(+ ENABLE_TEST_ROUTES=1 for T06).

    python run_tests.py              # runs the whole suite twice (T08 = repeatable)
    python run_tests.py --runs 3
    python run_tests.py --pull       # also pull the alert from the Pub/Sub
                                     # subscription (stop alert_listener.py first,
                                     # otherwise it consumes the message)

Output is printed AND saved to evidence/After/test_run_<UTC>.txt. The file holds
only results (no passwords, no keys) so it can be committed as evidence.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from dotenv import load_dotenv

HERE = Path(__file__).parent
load_dotenv(HERE / ".env")

BASE = os.environ.get("BASE_URL", "http://localhost:8000")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
AUDIT = HERE / "audit.log.jsonl"
PROJECT_ID = "phishtrace-sandbox-team2"
U1, U2 = "synthetic_student_01", "synthetic_student_02"
GOOD = {U1: "demo_password_123", U2: "safe_password_456"}
CANARY_WRONG = "WrongPass-Canary-7731!"
CANARY_LONG = "L" * 200            # > 128 chars -> fails validation
CANARY_USERNAME = "Canary Pass 8842!"  # not a legal username

RESPONSES: list = []   # every response body (scanned in T07)
CORRS: list = []       # every correlation_id returned (traced in T05)


# ---------------------------------------------------------------- helpers
def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    text = raw.decode("utf-8", "replace")
    RESPONSES.append(text)
    try:
        js = json.loads(text)
    except ValueError:
        js = {}
    if isinstance(js, dict) and js.get("correlation_id"):
        CORRS.append(js["correlation_id"])
    return status, js


def login(user, password):
    return call("POST", "/events/login", {"username": user, "password": password})


def admin_reset(user, key=None):
    return call("POST", f"/users/{user}/unquarantine",
                headers={"X-Admin-Key": ADMIN_KEY if key is None else key})


def reset_all():
    for u in (U1, U2):
        s, _ = admin_reset(u)
        if s != 200:
            raise RuntimeError(f"admin reset of {u} returned {s}; check ADMIN_KEY in .env matches the server")


def audit_records(since=0):
    if not AUDIT.exists():
        return []
    lines = AUDIT.read_text(encoding="utf-8").splitlines()[since:]
    return [json.loads(x) for x in lines if x.strip()]


def audit_len():
    return len(AUDIT.read_text(encoding="utf-8").splitlines()) if AUDIT.exists() else 0


def wait_for(pred, seconds=8):
    end = time.time() + seconds
    while time.time() < end:
        hit = pred(audit_records())
        if hit:
            return hit
        time.sleep(0.4)
    return None


def pull_alerts():
    os.environ["PUBSUB_EMULATOR_HOST"] = "localhost:4588"
    from google.cloud import pubsub_v1
    sub = pubsub_v1.SubscriberClient()
    path = sub.subscription_path(PROJECT_ID, "security-alerts-sub")
    resp = sub.pull(request={"subscription": path, "max_messages": 50}, timeout=15)
    msgs = [json.loads(m.message.data) for m in resp.received_messages]
    if resp.received_messages:
        sub.acknowledge(request={"subscription": path,
                                 "ack_ids": [m.ack_id for m in resp.received_messages]})
    return msgs


# ---------------------------------------------------------------- tests
def t01(ctx):
    reset_all()
    alerts_before = sum(1 for r in audit_records() if r.get("event") == "ALERT_PUBLISH")
    login(U1, "WrongPass-A"); login(U1, "WrongPass-B")                 # fails = 2
    s, js = login(U1, GOOD[U1])                                         # success -> reset
    ok = s == 200 and js.get("decision") == "ALLOW" and js.get("session_token")
    ctx["token1"] = js.get("session_token")
    s2, js2 = login(U1, "WrongPass-C")                                  # fails must restart at 1
    rec = wait_for(lambda rs: next((r for r in rs if r.get("corr_id") == js2.get("correlation_id")
                                    and r.get("outcome") == "FAIL_AUTH"), None)) or {}
    ok = ok and s2 == 401 and rec.get("fails") == 1                     # counter was reset by the success
    sp, _ = call("GET", f"/users/{U1}/profile", headers={"Authorization": f"Bearer {ctx['token1']}"})
    ok = ok and sp == 200
    time.sleep(1)
    alerts_after = sum(1 for r in audit_records() if r.get("event") == "ALERT_PUBLISH")
    ok = ok and alerts_after == alerts_before
    return ok, (f"success={s}/{js.get('decision')}, profile with session token={sp}, next failure counted as "
                f"fails={rec.get('fails')} (counter was reset), alerts published during T01={alerts_after - alerts_before}")


def t02(ctx):
    reset_all()
    seen, corrs = [], []
    for i in range(4):
        s, js = login(U1, CANARY_WRONG)
        seen.append(s)
        corrs.append(js.get("correlation_id"))
    s5, js5 = login(U1, CANARY_WRONG)
    ctx["corr5"], ctx["alert_hint"] = js5.get("correlation_id"), js5
    s6, js6 = login(U1, GOOD[U1])                                       # right password, still locked
    fails = []
    for c in corrs:
        rec = wait_for(lambda rs, c=c: next((r for r in rs if r.get("corr_id") == c
                                             and r.get("outcome") == "FAIL_AUTH"), None)) or {}
        fails.append(rec.get("fails"))
    ok = (seen == [401] * 4 and fails == [1, 2, 3, 4] and s5 == 403
          and js5.get("account_status") == "QUARANTINED"
          and js5.get("decision") == "BLOCK_AND_QUARANTINE" and s6 == 403)
    return ok, (f"attempts 1-4 status={seen} (server-side fail_count in log={fails}), "
                f"attempt 5={s5}/{js5.get('account_status')}, correct password afterwards={s6}")


def t03(ctx, pull=False):
    corr = ctx.get("corr5")
    rec = wait_for(lambda rs: next((r for r in rs if r.get("event") == "ALERT_PUBLISH"
                                    and r.get("corr_id") == corr and r.get("outcome") == "PUBLISHED"), None))
    if not rec:
        return False, f"no ALERT_PUBLISH/PUBLISHED audit record for corr_id={corr}"
    q = next((r for r in audit_records() if r.get("corr_id") == corr and r.get("outcome") == "QUARANTINED"), {})
    ok = q.get("alert_id") == rec.get("alert_id") and bool(rec.get("alert_id"))
    detail = f"alert_id={rec.get('alert_id')} msg_id={rec.get('msg_id')} corr_id={corr} (QUARANTINED record links same alert_id: {ok})"
    if pull:
        msgs = pull_alerts()
        hit = next((m for m in msgs if m.get("corr_id") == corr), None)
        need = {"alert_id", "corr_id", "user_id", "triggered_rule"}
        ok = ok and bool(hit) and need <= set(hit)
        detail += f"; pulled from subscription: {'FOUND ' + hit['alert_id'] if hit else 'NOT FOUND'}"
    return ok, detail


def t04(ctx):
    s1, _ = login(U1, GOOD[U1])                                         # U1 quarantined (from T02)
    s2, js2 = login(U2, GOOD[U2])
    p1, _ = call("GET", f"/users/{U1}/profile")
    p2, _ = call("GET", f"/users/{U2}/profile",
                 headers={"Authorization": f"Bearer {js2.get('session_token', '')}"})
    bad, _ = admin_reset(U1, key="not-the-admin-key")
    none, _ = call("POST", f"/users/{U1}/unquarantine")
    ok = (s1 == 403 and s2 == 200 and p1 == 403 and p2 == 200 and bad == 401 and none == 401)
    return ok, (f"student_01 login={s1} profile={p1}; student_02 login={s2} profile={p2}; "
                f"wrong admin key={bad}, no admin key={none}")


def t05(ctx):
    required = {"ts", "corr_id", "event", "outcome"}
    # a REJECTED request must also leave a traceable record
    sv, jv = call("POST", "/events/login", {"username": U1, "password": "x", "success": True})
    rejected_ok = sv == 422 and bool(jv.get("correlation_id")) and bool(wait_for(
        lambda rs: next((r for r in rs if r.get("corr_id") == jv.get("correlation_id")
                         and r.get("outcome") == "INVALID_INPUT"), None)))
    recs = audit_records(ctx["audit_start"])
    missing_fields = [r for r in recs if not required <= set(r)]
    logged = {r.get("corr_id") for r in recs}
    untraced = [c for c in set(CORRS) if c not in logged]
    text = AUDIT.read_text(encoding="utf-8")
    leaks = [s for s in [*GOOD.values(), CANARY_WRONG, CANARY_LONG[:20], ADMIN_KEY, "WrongPass-A"] if s and s in text]
    ok = recs and not missing_fields and not untraced and not leaks and rejected_ok
    return bool(ok), (f"{len(recs)} new audit records; rejected request logged={rejected_ok}; missing required fields={len(missing_fields)}; "
                      f"response corr_ids not found in log={len(untraced)}; secrets found in log={len(leaks)}")


def t06(ctx):
    s, js = call("GET", "/api/crash")
    if s == 404:
        return None, "SKIPPED - /api/crash not registered. Set ENABLE_TEST_ROUTES=1 in .env and restart the gateway"
    body = json.dumps(js)
    leaked = [w for w in ("ValueError", "Simulated", "Traceback", "File \"") if w in body]
    corr = js.get("correlation_id")
    rec = wait_for(lambda rs: next((r for r in rs if r.get("corr_id") == corr
                                    and r.get("event") == "UNEXPECTED_ERROR"
                                    and r.get("outcome") == "SAFE_HANDLED"), None))
    ok = s == 500 and js.get("detail") == "Internal processing error" and not leaked and bool(rec)
    return ok, f"status={s}, body keys={sorted(js)}, internals leaked={leaked or 'none'}, logged SAFE_HANDLED={bool(rec)}"


def t07(ctx):
    findings = []
    # (a) invalid requests must not echo submitted values back
    probes = [
        ("extra field", {"username": U1, "password": CANARY_WRONG, "success": True}),
        ("illegal username", {"username": CANARY_USERNAME, "password": "x"}),
        ("over-long password", {"username": U1, "password": CANARY_LONG}),
    ]
    for name, body in probes:
        s, js = call("POST", "/events/login", body)
        txt = json.dumps(js)
        if s != 422 or CANARY_WRONG in txt or CANARY_USERNAME in txt or CANARY_LONG[:20] in txt or "input" in js:
            findings.append(f"{name}: status={s}, echoed value")
    # (b) no response ever contained a password or the admin key
    for t in RESPONSES:
        for secret in (*GOOD.values(), CANARY_WRONG, ADMIN_KEY):
            if secret and secret in t:
                findings.append("a response body contained a secret")
                break
    # (c) source files must not contain the admin key or the demo passwords
    for name in ("main.py", "index.html", "alert_listener.py", "README.md", "run_tests.py"):
        p = HERE / name
        if not p.exists():
            continue
        src = p.read_text(encoding="utf-8", errors="replace")
        for secret in (ADMIN_KEY, GOOD[U1], GOOD[U2]):
            if name == "run_tests.py" and secret in GOOD.values():
                continue  # the test script legitimately logs in with the synthetic passwords
            if secret and secret in src:
                findings.append(f"{name} contains a secret")
    # (d) .env must not be tracked by git
    try:
        tracked = subprocess.run(["git", "ls-files", ".env"], cwd=HERE, capture_output=True, text=True).stdout.strip()
        if tracked:
            findings.append(".env is tracked by git")
    except OSError:
        pass
    return not findings, "no secret found in responses, audit log, tracked source or git" if not findings else "; ".join(sorted(set(findings)))


def t08a(ctx):
    s, js = admin_reset(U1)
    s2, js2 = login(U1, GOOD[U1])
    rec = wait_for(lambda rs: next((r for r in rs if r.get("corr_id") == js.get("correlation_id")
                                    and r.get("outcome") == "RESTORED_ACTIVE"), None))
    ok = s == 200 and js.get("account_status") == "ACTIVE" and s2 == 200 and bool(rec)
    return ok, f"admin reset={s}/{js.get('account_status')}, login afterwards={s2}, audit RESTORED_ACTIVE={bool(rec)}"


TESTS = [("T01", "Normal login: no alert, failure counter reset", t01),
         ("T02", "5 wrong passwords -> 4x 401 then 403 QUARANTINED", t02),
         ("T03", "Alert published, traceable by alert_id/corr_id", t03),
         ("T04", "Only synthetic_student_01 contained; bad admin key refused", t04),
         ("T05", "Audit log supports investigation without credentials", t05),
         ("T06", "Controlled error -> safe 500 + logged correlation ID", t06),
         ("T07", "No secret in responses, logs, source or git", t07),
         ("T08a", "Admin recovery restores account; login works again", t08a)]


def run_suite(n, pull):
    CORRS.clear()  # T05 traces only this run's correlation IDs
    ctx = {"audit_start": audit_len()}
    out = {}
    for tid, title, fn in TESTS:
        try:
            ok, detail = fn(ctx, pull) if tid == "T03" else fn(ctx)
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        out[tid] = (ok, title, detail)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument("--pull", action="store_true")
    args = ap.parse_args()
    if len(ADMIN_KEY) < 16:
        sys.exit("ADMIN_KEY missing from .env (needed to reset accounts between tests)")

    lines = [f"PhishTrace test run - {datetime.datetime.now(datetime.timezone.utc).isoformat()} - target {BASE}", ""]
    runs = []
    for n in range(1, args.runs + 1):
        res = run_suite(n, args.pull)
        runs.append(res)
        lines.append(f"=== RUN {n} ===")
        for tid, (ok, title, detail) in res.items():
            word = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
            lines.append(f"{tid:5} {word:4}  {title}\n        {detail}")
        lines.append("")
    vectors = [{k: v[0] for k, v in r.items()} for r in runs]
    same = all(v == vectors[0] for v in vectors)
    allpass = all(ok is not False for v in vectors for ok in v.values())
    t08 = same and allpass and args.runs >= 2 and all(r["T08a"][0] for r in runs)
    lines.append(f"T08   {'PASS' if t08 else 'FAIL'}  Full test set repeated {args.runs}x: identical results={same}, no failures={allpass}, admin recovery ok every run")
    skipped = [k for k, v in vectors[0].items() if v is None]
    if skipped:
        lines.append(f"NOTE: skipped {skipped} - enable the test route and rerun for a complete matrix")
    report = "\n".join(lines)
    print(report)

    out_dir = HERE / "evidence" / "After"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out_dir / f"test_run_{stamp}.txt").write_text(report + "\n", encoding="utf-8")
    print(f"\nSaved evidence/After/test_run_{stamp}.txt")
    sys.exit(0 if t08 and not skipped else 1)


if __name__ == "__main__":
    main()
