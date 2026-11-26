from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="PhishTrace VULNERABLE Baseline")

class WeakLogin(BaseModel):
    username: str
    password: str = None
    success: bool = False # F-03: Logic flaw bypass

# Simulated vulnerable database
mock_db = {
    "synthetic_student_01": {"password": "demo_password_123", "fail_count": 0}
}

@app.post("/api/login")
async def vulnerable_login(req: WeakLogin):
    if req.username not in mock_db:
        raise HTTPException(status_code=404, detail="User Not Found") # F-04: Username Enumeration
    
    # F-03: Frontend trust bypass
    if req.success or req.password == mock_db[req.username]["password"]:
        return {"message": "Login successful", "plaintext_password": mock_db[req.username]["password"]} # F-02: Secret Leakage
    
    # F-01: No velocity limits or quarantine
    mock_db[req.username]["fail_count"] += 1
    raise HTTPException(status_code=401, detail=f"Invalid. Fails: {mock_db[req.username]['fail_count']}")

@app.post("/api/unquarantine/{username}")
async def weak_unquarantine(username: str):
    # F-05: Unauthenticated Admin Endpoint
    mock_db[username]["fail_count"] = 0
    return {"message": "Account reset by anyone"}