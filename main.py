from fastapi import FastAPI, HTTPException, Request
from google.cloud import firestore, pubsub_v1
import datetime
import uuid
import json

app = FastAPI(title="PhishTrace API - Hardened")

db = firestore.Client(project="phishtrace-sandbox-team2")
publisher = pubsub_v1.PublisherClient()
TOPIC_PATH = publisher.topic_path("phishtrace-sandbox-team2", "security-alerts")

@app.post("/api/login")
async def login(request: Request):
    payload = await request.json()
    corr_id = f"req-{uuid.uuid4().hex[:6]}"
    timestamp = datetime.datetime.utcnow().isoformat()
    username = payload.get("username")
    password = payload.get("password")
    
    user_ref = db.collection("users").document(username)
    user_doc = user_ref.get()
    
    if not user_doc.exists:
        print(f"[{timestamp}] corr_id={corr_id} event=LOGIN outcome=USER_NOT_FOUND")
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    data = user_doc.to_dict()
    
    if data.get("is_locked", False):
        print(f"[{timestamp}] corr_id={corr_id} event=LOGIN outcome=DENY_LOCKED")
        raise HTTPException(status_code=403, detail="Account contained.")
        
    if password != data.get("password"):
        new_fail_count = data.get("fail_count", 0) + 1
        if new_fail_count >= 5:
            user_ref.update({"is_locked": True, "fail_count": new_fail_count})
            alert_msg = json.dumps({
                "alert_id": f"alrt-{uuid.uuid4().hex[:4]}", 
                "corr_id": corr_id, 
                "user": username, 
                "rule_triggered": "5_FAILS_IN_60S"
            })
            publisher.publish(TOPIC_PATH, alert_msg.encode("utf-8"))
            print(f"[{timestamp}] corr_id={corr_id} event=LOGIN outcome=ACCOUNT_LOCKED fails={new_fail_count}")
            raise HTTPException(status_code=403, detail="Account contained due to suspicious activity.")
        else:
            user_ref.update({"fail_count": new_fail_count})
            print(f"[{timestamp}] corr_id={corr_id} event=LOGIN outcome=FAIL_BAD_PASSWORD fails={new_fail_count}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
            
    print(f"[{timestamp}] corr_id={corr_id} event=LOGIN outcome=SUCCESS")
    user_ref.update({"fail_count": 0})
    return {"message": "Login successful", "correlation_id": corr_id}