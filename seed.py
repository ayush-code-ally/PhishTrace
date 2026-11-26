"""Seed Floci (local GCP emulator) with test users and the Pub/Sub topic.

Run once (safe to re-run; it also acts as a full demo reset):
    python seed.py
"""
import os

# Route ALL traffic to the Floci emulator. Must be set before importing GCP libs.
os.environ["FIRESTORE_EMULATOR_HOST"] = "localhost:4588"
os.environ["PUBSUB_EMULATOR_HOST"] = "localhost:4588"

import hashlib
import secrets

from google.api_core.exceptions import AlreadyExists
from google.cloud import firestore, pubsub_v1

PROJECT_ID = "phishtrace-sandbox-team2"
TOPIC_ID = "security-alerts"
SUB_ID = "security-alerts-sub"
PBKDF2_ROUNDS = 200_000  # keep identical to main.py


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS).hex()


def make_user(password: str) -> dict:
    salt = secrets.token_bytes(16)
    return {
        "password_salt": salt.hex(),
        "password_hash": hash_password(password, salt),  # no plaintext passwords stored
        "account_status": "ACTIVE",
        "fail_count": 0,
        "risk_score": 0,
        "session_token_hash": None,
    }


db = firestore.Client(project=PROJECT_ID)

# Primary target (T01-T03) and control account (T04 isolation check).
users = {
    "synthetic_student_01": make_user("demo_password_123"),
    "synthetic_student_02": make_user("safe_password_456"),
}
for uid, profile in users.items():
    db.collection("users").document(uid).set(profile)  # set() fully overwrites -> reset
print("[OK] Seeded synthetic_student_01 and synthetic_student_02 in Floci Firestore.")

publisher = pubsub_v1.PublisherClient()
subscriber = pubsub_v1.SubscriberClient()
topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID)
sub_path = subscriber.subscription_path(PROJECT_ID, SUB_ID)

try:
    publisher.create_topic(request={"name": topic_path})
except AlreadyExists:
    pass

try:
    subscriber.create_subscription(request={"name": sub_path, "topic": topic_path})
except AlreadyExists:
    pass

print(f"[OK] Pub/Sub topic '{TOPIC_ID}' and subscription '{SUB_ID}' ready.")
