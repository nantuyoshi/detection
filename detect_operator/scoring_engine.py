from datetime import datetime, timedelta
import json
from collections import defaultdict

class ScoringEngine:

    def __init__(self):
        pass

    # --- ログを IP × IP × 5分ごとにまとめる ---
    def group_by_window(self, logs: list) -> dict:
        grouped = defaultdict(list)

        for log in logs:
            ts = datetime.fromisoformat(log["@timestamp"])
            window = ts - timedelta(minutes=ts.minute % 5, seconds=ts.second)

            key = (
                log.get("source.ip"),
                log.get("destination.ip"),
                window.isoformat()
            )
            grouped[key].append(log)

        return grouped

    # --- スコア算出 ---
    def calc_score(self, grouped: dict) -> list:
        results = []

        for (src, dst, window), logs in grouped.items():

            score = 0

            # 未知の宛先
            if any(l.get("unknown_dst") for l in logs):
                score += 30

            # Base64
            if any(l.get("base64_found") for l in logs):
                score += 25

            # 大容量
            if any(l.get("http.request.body.bytes", 0) > 4096 for l in logs):
                score += 20

            # 短時間大量通信
            if len(logs) >= 10:
                score += 25

            results.append({
                "src_ip": src,
                "dst_ip": dst,
                "window": window,
                "score": score,
                "alert": score >= 70
            })

        return results

    def save_score(self, results: list, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
