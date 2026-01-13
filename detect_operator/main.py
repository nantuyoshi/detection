import time
import csv
from datetime import datetime

LOG_PATH = "mock_log.csv"
ALERT_LOG = "alert.log"
INTERVAL = 10  # 秒

def collect_logs():
    with open(LOG_PATH, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def detect(logs):
    alerts = []
    for log in logs:
        if log["event_type"] == "NETWORK_CONNECT":
            alerts.append(log)
    return alerts

def alert_output(alerts):
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        for a in alerts:
            msg = f"{datetime.now()} ALERT {a}\n"
            f.write(msg)
            print(msg.strip())

def main():
    print("[INFO] 自動ログ収集・検知 開始")
    while True:
        logs = collect_logs()
        print(f"[INFO] 収集ログ件数: {len(logs)}")

        alerts = detect(logs)
        if alerts:
            alert_output(alerts)
        else:
            print("[INFO] 異常なし")

        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
