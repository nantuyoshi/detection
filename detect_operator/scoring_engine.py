import json
import os
from datetime import datetime, timedelta


class ScoringEngine:
    def __init__(self, out_dir="output"):
        self.out_dir = out_dir
        os.makedirs(self.out_dir, exist_ok=True)

        # ★ 追加：連続検知の状態
        self.history = {}
        self.reset_interval = timedelta(seconds=60)  # 60秒空いたらリセット

    def calc_score(self, alerts):
        """
        alert情報からスコア算出（連続検知で昇格）
        """
        results = []
        now = datetime.now()

        for alert in alerts:
            score = 0
            reasons = []

            src_ip = alert.get("src_ip")

            # ===== 既存ルール =====
            if alert.get("unknown_dst"):
                score += 10
                reasons.append("unknown_dst")

            if alert.get("base64_found"):
                score += 15
                reasons.append("base64_found")

            if alert.get("small_post"):
                score += 10
                reasons.append("small_post")

            # ===== 追加：連続検知 =====
            if src_ip:
                state = self.history.get(src_ip)

                if not state:
                    self.history[src_ip] = {
                        "count": 1,
                        "last_seen": now
                    }
                else:
                    if now - state["last_seen"] > self.reset_interval:
                        state["count"] = 1  # リセット
                    else:
                        state["count"] += 1

                    state["last_seen"] = now

                count = self.history[src_ip]["count"]

                # 連続回数ボーナス
                score += count * 5
                reasons.append(f"repeat_{count}")

            # ===== レベル判定（既存のまま）=====
            if score >= 35:
                level = "HIGH"
            elif score >= 20:
                level = "MEDIUM"
            else:
                level = "LOW"

            results.append({
                "timestamp": now.isoformat(),
                "client_ip": src_ip,
                "dst_ip": alert.get("dest_ip"),
                "score": score,
                "level": level,
                "reason": reasons
            })

        return results

    def save_score(self, scores):
        """
        スコア結果をJSON保存
        """
        if not scores:
            return

        out_path = os.path.join(self.out_dir, "score_result.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(scores, f, indent=2, ensure_ascii=False)

        print(f"[INFO] score saved -> {out_path}")
