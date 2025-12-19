import csv
from datetime import datetime

class LogCollector:

    def load_proxy(self, path: str):
        logs = []
        try:
            with open(path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    logs.append({
                        "type": "proxy",
                        "timestamp": row["timestamp"],
                        "client_ip": row["src_ip"],
                        "dst_ip": row["dest_ip"],
                        "method": row.get("method", "POST"),
                        "body_bytes": int(row.get("bytes", 0)),
                        "body": row.get("body", "")
                    })
        except FileNotFoundError:
            print(f"[WARN] Proxyログファイルが見つかりません: {path}")
        return logs

    def load_firewall(self, path: str):
        logs = []
        try:
            with open(path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    logs.append({
                        "type": "firewall",
                        "timestamp": row["timestamp"],
                        "client_ip": row["src_ip"],
                        "dst_ip": row["dest_ip"],
                        "action": row["action"]
                    })
        except FileNotFoundError:
            print(f"[WARN] Firewallログファイルが見つかりません: {path}")
        return logs
