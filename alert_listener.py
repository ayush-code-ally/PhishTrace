"""Shows T03 evidence: pulls and prints alerts from the security-alerts subscription.

    python alert_listener.py
"""
import os

os.environ["PUBSUB_EMULATOR_HOST"] = "localhost:4588"

from google.cloud import pubsub_v1

PROJECT_ID = "phishtrace-sandbox-team2"
SUB_ID = "security-alerts-sub"

subscriber = pubsub_v1.SubscriberClient()
sub_path = subscriber.subscription_path(PROJECT_ID, SUB_ID)


def callback(message):
    print("[ALERT RECEIVED]", message.data.decode("utf-8"))
    message.ack()


print(f"Listening on {sub_path} (Ctrl+C to stop)...")
future = subscriber.subscribe(sub_path, callback=callback)
try:
    future.result()
except KeyboardInterrupt:
    future.cancel()
