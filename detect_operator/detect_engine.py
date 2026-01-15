import json
import datetime
import os

ALERT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "alert.log"
)

def is_suspicious(event: dict) -> bool:
    if event.get("event_type") == "NETWORK_CONNECT":
        if "unknown" in event.get("detail", ""):
            return True
    return False

@staticmethod
def write_alert(event: dict):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} ALERT {event}\n")


