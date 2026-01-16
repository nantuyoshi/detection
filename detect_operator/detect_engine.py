# DETECTION/detect_operator/detect_engine.py
import os
import datetime
import re
from .log_collector import LogCollector

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
ALERT_LOG_PATH = os.path.join(BASE_DIR, "alert.log")

collector = LogCollector()

# ホワイトリスト（例）
WHITELIST_DOMAINS = {
    "example.com",
    "localhost"
}

BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{50,}$")


def is_suspicious(event: dict) -> bool:
    """
    event + Proxy/Firewallログを使った検知
    """

    # =========================
    # ① 想定外ドメイン
    # =========================
    domain = event.get("destination.domain")
    if domain and domain not in WHITELIST_DOMAINS:
        return True

    # =========================
    # ② 小サイズ POST
    # =========================
    size = event.get("http.request.body.bytes", 0)
    method = event.get("http.request.method", "")

    if method == "POST" and 0 < size < 1024:
        return True

    # =========================
    # ③ Base64様データ
    # =========================
    body = event.get("http.request.body.contents", "")
    if BASE64_RE.match(body):
        return True

    return False


def detect_from_logs(proxy_log_path: str, fw_log_path: str) -> list:
    """
    log_collector を使ってログから検知
    """
    proxy_logs = collector.load_proxy(proxy_log_path)
    fw_logs = collector.load_firewall(fw_log_path)

    ecs_logs = collector.normalize_to_ec(proxy_logs + fw_logs)

    alerts = []
    for e in ecs_logs:
        if is_suspicious(e):
            alerts.append(e)
            write_alert(e)

    return alerts


def write_alert(event: dict):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"{ts} ALERT {event}\n")
