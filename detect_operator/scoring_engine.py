import json
from datetime import datetime

class ScoringEngine:

    def group_by_window(self, evaluated_logs, window_sec=300):
        grouped = {}

        for item in evaluated_logs:
            log = item["log"]
            rule = item["rule"]

            key = (log["client_ip"], log["dst_ip"])
            grouped.setdefault(key, []).append(rule)

        results = []
        for (client_ip, dst_ip), rules in grouped.items():
            score = self.calc_score(rules)
            level = self.level(score)

            results.append({
                "client_ip": client_ip,
                "dst_ip": dst_ip,
                "score": score,
                "level": level,
                "reason": self.reason(rules),
                "timestamp": datetime.now().isoformat()
            })

        return results

    def calc_score(self, rules):
        score = 0
        for r in rules:
            if r["unknown_dst"]:
                score += 10
            if r["small_post"]:
                score += 5
            if r["base64_found"]:
                score += 20
        return score

    def level(self, score):
        if score >= 40:
            return "HIGH"
        elif score >= 20:
            return "MEDIUM"
        return "LOW"

    def reason(self, rules):
        reasons = set()
        for r in rules:
            for k, v in r.items():
                if v:
                    reasons.add(k)
        return list(reasons)

    def save_score(self, scores, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(scores, f, indent=2, ensure_ascii=False)
