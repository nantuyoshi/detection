import json
import os
from datetime import datetime


class ScoringEngine:
    def __init__(self, out_dir="output"):
        self.out_dir = out_dir
        os.makedirs(self.out_dir, exist_ok=True)

    def calc_score(self, alerts):
        """
        alert情報からスコア算出
        """
        results = []

        for alert in alerts:
            score = 0
            reasons = []

            # 宛先IPが未知
            if alert.get("unknown_dst"):
                score += 10
                reasons.append("unknown_dst")

            # Base64らしきデータ
            if alert.get("base64_found"):
                score += 15
                reasons.append("base64_found")

            # POSTサイズが小さい（分割送信疑い）
            if alert.get("small_post"):
                score += 10
                reasons.append("small_post")

            # レベル判定
            if score >= 35:
                level = "HIGH"
            elif score >= 20:
                level = "MEDIUM"
            else:
                level = "LOW"

            results.append({
                "timestamp": datetime.now().isoformat(),
                "client_ip": alert.get("src_ip"),
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
