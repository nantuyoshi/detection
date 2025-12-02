import json
import xmltodict
import csv
from datetime import datetime

class LogCollector:

    # --- Sysmon (XML/JSON) ---
    def load_sysmon(self, path: str) -> list:
        if path.endswith(".xml"):
            with open(path, "r", encoding="utf-8") as f:
                data = xmltodict.parse(f.read())
            return self._parse_sysmon_dict(data)

        if path.endswith(".json"):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return self._parse_sysmon_dict(data)

    def _parse_sysmon_dict(self, data):
        events = data.get("Events", {}).get("Event", [])
        parsed = []

        for e in events:
            parsed.append({
                "timestamp": e.get("System", {}).get("TimeCreated", {}).get("@SystemTime"),
                "event_id": e.get("System", {}).get("EventID"),
                "process": e.get("EventData", {}).get("Data", [{}])[0].get("#text"),
                "action": "process_event"
            })

        return parsed

    # --- Proxy Log (CSV) ---
    def load_proxy(self, path: str) -> list:
        logs = []
        with open(path, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                logs.append({
                    "timestamp": row.get("timestamp"),
                    "src_ip": row.get("src_ip"),
                    "dst_domain": row.get("domain"),
                    "dst_ip": row.get("dst_ip"),
                    "method": row.get("method"),
                    "body_size": int(row.get("body_size", 0))
                })
        return logs

    # --- Fluentd Log ---
    def load_fluentd(self, path: str) -> list:
        logs = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except:
                    pass
        return logs

    # --- ECS 正規化 ---
    def normalize_to_ecs(self, logs: list) -> list:
        ecs_logs = []

        for l in logs:
            ecs_logs.append({
                "@timestamp": l.get("timestamp"),
                "source.ip": l.get("src_ip"),
                "destination.domain": l.get("dst_domain"),
                "destination.ip": l.get("dst_ip"),
                "http.method": l.get("method"),
                "http.request.body.bytes": l.get("body_size"),
                "process.name": l.get("process"),
            })

        return ecs_logs

    # --- SIEM 用に保存 ---
    def save_siem_json(self, ecs_logs: list, out_path: str):
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(ecs_logs, f, indent=2)
