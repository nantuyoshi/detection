import csv
from pathlib import Path
from datetime import datetime

__all__ = ["LogCollector"]


class LogCollector:
    """
    Proxy / Firewall / Sysmon の CSV ログを読み込み、
    ECS 風フォーマットに正規化する責務を持つクラス
    """

    # =========================
    # ログ読み込み
    # =========================

    def load_proxy(self, path: str) -> list:
        if not Path(path).exists():
            return []
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def load_firewall(self, path: str) -> list:
        if not Path(path).exists():
            return []
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def load_sysmon(self, path: str) -> list:
        """Sysmon CSVを読み込み"""
        if not Path(path).exists():
            return []
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    # =========================
    # ECS 正規化
    # =========================

    def normalize_to_ec(self, logs: list, log_type: str = "proxy") -> list:
        ecs_logs = []

        for log in logs:
            if log_type == "sysmon":
                ecs_log = self._normalize_sysmon(log)
            else:
                ecs_log = self._normalize_proxy_firewall(log)
            
            ecs_logs.append(ecs_log)

        return ecs_logs

    def _normalize_proxy_firewall(self, log: dict) -> dict:
        """Proxy/Firewall用正規化"""
        return {
            # ---- 共通 ----
            "timestamp": self._parse_time(log.get("timestamp")),
            "client_ip": log.get("src_ip"),
            "dst_ip": log.get("dest_ip") or log.get("dst_ip"),
            "type": log.get("type", "unknown"),

            # ---- HTTP系（Proxy想定）----
            "http.request.method": log.get("method"),
            "http.request.body.bytes": self._to_int(log.get("body_bytes")),
            "http.request.body.contents": log.get("body"),
            "destination.domain": log.get("domain"),

            # ---- Network系（Firewall / Proxy 共通）----
            "destination.port": self._to_int(
                log.get("port") or log.get("dest_port")
            ),
            "action": log.get("action"),
        }

    def _normalize_sysmon(self, log: dict) -> dict:
        """Sysmon用正規化（JSON形式から）"""
        import json
        
        # JSONデータを解析
        try:
            data = json.loads(log.get("message", "{}"))
        except json.JSONDecodeError:
            data = {}

        return {
            "timestamp": self._parse_time(log.get("timestamp")),
            "type": "sysmon",
            "event_id": data.get("EventID"),
            "process_id": data.get("ProcessId"),
            "process_name": data.get("Image"),
            "command_line": data.get("CommandLine"),
            "parent_process_id": data.get("ParentProcessId"),
            "parent_process_name": data.get("ParentImage"),
            "user": data.get("User"),
            "src_ip": data.get("SourceIp"),
            "dst_ip": data.get("DestinationIp"),
            "destination.port": self._to_int(data.get("DestinationPort")),
            "protocol": data.get("Protocol"),
            "action": "monitor",  # Sysmonは監視ログ
        }
    
    def to_rule_input(self, ecs_log: dict) -> dict:
        """
        ECSログを RuleEngine が理解できる形式に変換
        """
        return {
            "dst_ip": ecs_log.get("dst_ip"),
            "body_bytes": ecs_log.get("http.request.body.bytes", 0),
            "body": ecs_log.get("http.request.body.contents", ""),
            "process_name": ecs_log.get("process_name"),
            "command_line": ecs_log.get("command_line"),
        }
    
    def to_alert(self, ecs_log: dict, detection: dict) -> dict:
        """
        ECSログ + RuleEngine結果 → ScoringEngine用 alert
        """
        alert = detection.copy()

        alert.update({
            "src_ip": ecs_log.get("client_ip") or ecs_log.get("src_ip"),
            "dest_ip": ecs_log.get("dst_ip"),
            "process_name": ecs_log.get("process_name"),
            "event_id": ecs_log.get("event_id"),
        })

        return alert
    
    # =========================
    # 内部ユーティリティ
    # =========================

    def _to_int(self, value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _parse_time(self, value):
        if not value:
            return datetime.utcnow().isoformat()
        return value