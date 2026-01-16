#log_collector.py
import csv
from pathlib import Path
from datetime import datetime

__all__ = ["LogCollector"]


class LogCollector:
    """
    Proxy / Firewall の CSV ログを読み込み、
    ECS 風フォーマットに正規化する責務を持つクラス
    """

    # =========================
    # ログ読み込み
    # =========================

    def load_proxy(self, path: str) -> list:
        """
        ProxyログCSVを読み込む
        """
        if not Path(path).exists():
            return []

        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def load_firewall(self, path: str) -> list:
        """
        FirewallログCSVを読み込む
        """
        if not Path(path).exists():
            return []

        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    # =========================
    # ECS 正規化
    # =========================

    def normalize_to_ec(self, logs: list) -> list:
        """
        Proxy / Firewall ログを ECS 風構造に正規化
        """
        ecs_logs = []

        for log in logs:
            ecs_logs.append({
                # ---- 共通 ----
                "timestamp": self._parse_time(log.get("timestamp")),
                "client_ip": log.get("src_ip"),
                "dst_ip": log.get("dest_ip") or log.get("dst_ip"),
                "type": log.get("type", "unknown"),

                # ---- HTTP系（Proxy想定）----
                "http.request.method": log.get("method", "POST"),
                "http.request.body.bytes": self._to_int(log.get("body_bytes")),
                "http.request.body.contents": log.get("body", ""),
                "destination.domain": log.get("domain"),

                # ---- Network系（Firewall想定）----
                "destination.port": self._to_int(log.get("port")),
                "action": log.get("action"),
            })

        return ecs_logs

    # =========================
    # 内部ユーティリティ
    # =========================

    def _to_int(self, value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _parse_time(self, value):
        """
        timestamp が無い場合は現在時刻を補完
        """
        if not value:
            return datetime.utcnow().isoformat()

        return value
