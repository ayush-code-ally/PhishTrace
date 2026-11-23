from fastapi import FastAPI, HTTPException, Request
import datetime
import uuid

app = FastAPI(title="PhishTrace API - Baseline")

# Mock database for our synthetic testing (Task A & B)
MOCK_DB = {
    "synthetic_student_01": {"password": "demo_password_123", "is_locked": False, "fail_count": 0}
}

@app.post("/api/login")
async def login(request: Request):
    payload = await request.json()
    
    # Generate Correlation ID for tracking (Task D)
    corr_id = f"req-{uuid.uuid4().hex[:6]}"
    timestamp = datetime.datetime.utcnow().isoformat()
    
    username = payload.get("username")
    password = payload.get("password")
    
    # Basic Validation
    if username not in MOCK_DB:
        print(f"[{timestamp}] corr_id={corr_id} event=LOGIN outcome=USER_NOT_FOUND")
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    user_record = MOCK_DB[username]
    
    # Check Password
    if password != user_record["password"]:
        user_record["fail_count"] += 1
        print(f"[{timestamp}] corr_id={corr_id} event=LOGIN outcome=FAIL_BAD_PASSWORD fails={user_record['fail_count']}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    print(f"[{timestamp}] corr_id={corr_id} event=LOGIN outcome=SUCCESS")
    return {"message": "Login successful", "correlation_id": corr_id}
