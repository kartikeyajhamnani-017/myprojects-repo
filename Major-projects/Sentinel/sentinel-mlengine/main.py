import redis
import json
import time
import sys
from rules import RuleBasedDetector
from model import MLModel

# Setup
REDIS_HOST = 'localhost'
QUEUE_NAME = 'traffic_queue'

# Initialize Components
r = redis.Redis(host=REDIS_HOST, port=6379, db=0)
rules_engine = RuleBasedDetector()
ml_engine = MLModel()

print("🧠 Sentinel Brain Active (Hybrid Mode: Rules + ML)")

def analyze_packet(data):
    try:
        log = json.loads(data)
        payload = log.get("payload", "")
        ip = log.get("source_ip", "Unknown")

        # --- LAYER 1: RULES (Fast) ---
        is_threat, keyword = rules_engine.check(payload)
        if is_threat:
            print(f"🚨 [LAYER 1] KNOWN THREAT: IP {ip} | Keyword: {keyword}")
            return

        # --- LAYER 2: ML MODEL (Deep) ---
        # Returns -1 for Anomaly, 1 for Normal
        prediction = ml_engine.predict(payload)
        
        if prediction == -1:
            print(f"⚠️  [LAYER 2] ANOMALY DETECTED: IP {ip} | Payload: {payload}")
        else:
            # print(f"✅ Clean: {payload}") # Commented out for noise
            pass

    except Exception as e:
        print(f"❌ Error: {e}")

def start():
    while True:
        _, data = r.blpop(QUEUE_NAME)
        analyze_packet(data)

if __name__ == "__main__":
    start()