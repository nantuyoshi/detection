# detect_operator/log_collector.py

import csv
import json
from datetime import datetime

class LogCollector:
    def load_proxy_logs(self, path: str):
        logs = []
        try:
            with open(path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    logs.append({
                        "type": "proxy",
                        "timestamp": row.get("timestamp", str(datetime.now())),
                        "src_ip": row.get("src_ip"),
                        "dest_ip": row.get("dest_ip"),
                        "url": row.get("url"),
                        "action": row.get("action")
                    })
        except FileNotFoundError:
            print(f"[WARN] Proxyログファイルが見つかりません: {path}")
        return logs

    def load_firewall_logs(self, path: str):
        logs = []
        try:
            with open(path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    logs.append({
                        "type": "firewall",
                        "timestamp": row.get("timestamp", str(datetime.now())),
                        "src_ip": row.get("src_ip"),
                        "dest_ip": row.get("dest_ip"),
                        "port": row.get("port"),
                        "action": row.get("action")
                    })
        except FileNotFoundError:
            print(f"[WARN] Firewallログファイルが見つかりません: {path}")
        return logs
