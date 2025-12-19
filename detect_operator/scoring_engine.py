import json
import os
from datetime import datetime

class ScoringEngine:

    def save_score(self, scores, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, "a", encoding="utf-8") as f:
            for s in scores:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")

    def save_alert_log(self, scores, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, "a", encoding="utf-8") as f:
            for s in scores:
                line = (
                    f"[{s['timestamp']}] {s['level']} "
                    f"{s['client_ip']} -> {s['dst_ip']} "
                    f"score={s['score']} reason={','.join(s['reason'])}\n"
                )
                f.write(line)
