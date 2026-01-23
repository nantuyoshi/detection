import time
from datetime import datetime
from log_collector import LogCollector
from rule_engine import RuleEngine
from scoring_engine import ScoringEngine

PROXY_LOG = "logs/proxy.csv"
ALERT_LOG = "alert.log"
INTERVAL = 10

collector = LogCollector()
rule_engine = RuleEngine("rules.yml")
scorer = ScoringEngine(out_dir="output")

last_seen_timestamp = None


def filter_new_logs(logs):
    global last_seen_timestamp
    new_logs = []

    for log in logs:
        ts = log.get("timestamp")
        if not ts:
            continue

        ts_dt = datetime.fromisoformat(ts)

        if last_seen_timestamp is None or ts_dt > last_seen_timestamp:
            new_logs.append(log)

    if new_logs:
        last_seen_timestamp = datetime.fromisoformat(new_logs[-1]["timestamp"])

    return new_logs


def to_rule_input(ecs):
    return {
        "src_ip": ecs.get("client_ip"),
        "dst_ip": ecs.get("dst_ip"),
        "body": ecs.get("http.request.body.contents"),
        "body_bytes": ecs.get("http.request.body.bytes")
    }


def main():
    print("[INFO] 自動ログ収集・検知 開始")

    while True:
        proxy_logs = collector.load_proxy(PROXY_LOG)
        ecs_logs = collector.normalize_to_ec(proxy_logs)

        new_logs = filter_new_logs(ecs_logs)

        if not new_logs:
            print("[INFO] 新規ログなし")
            time.sleep(INTERVAL)
            continue

        alerts = []

        for ecs in new_logs:
            rule_input = to_rule_input(ecs)
            detection = rule_engine.evaluate_rules(rule_input)

            if any(detection.values()):
                alerts.append({
                    **ecs,
                    "reason": [k for k, v in detection.items() if v]
                })

        scores = scorer.calc_score(alerts)
        scorer.save_score(scores)

        for s in scores:
            msg = (
                f"{s['timestamp']} "
                f"LEVEL={s['level']} "
                f"SCORE={s['score']} "
                f"SRC={s['client_ip']} "
                f"DST={s['dst_ip']} "
                f"REASON={','.join(s['reason'])}"
            )
            print(msg)

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
