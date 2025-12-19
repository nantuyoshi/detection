import time
from datetime import datetime

from detect_operator.log_collector import LogCollector
from detect_operator.rule_engine import RuleEngine
from detect_operator.scoring_engine import ScoringEngine

# ===== 設定 =====
INTERVAL = 300  # 5分（秒）
PROXY_LOG = "logs/proxy.csv"
FIREWALL_LOG = "logs/firewall.csv"
RULE_FILE = "detect_operator/rules/rules.yml"
SCORE_OUTPUT = "output/score_result.jsonl"
ALERT_LOG = "output/alert.log"


def main():
    print("[INFO] 自動ログ収集・検知システム起動")

    collector = LogCollector()
    rule_engine = RuleEngine(RULE_FILE)
    scorer = ScoringEngine()

    while True:
        cycle_start = datetime.now()
        print(f"[INFO] cycle start {cycle_start}")

        # =========================
        # 1. ログ収集
        # =========================
        proxy_logs = collector.load_proxy(PROXY_LOG)
        firewall_logs = collector.load_firewall(FIREWALL_LOG)

        if not proxy_logs and not firewall_logs:
            print("[WARN] 収集対象ログなし")

        # =========================
        # 2. 正規化（ECS風）
        # =========================
        ecs_logs = []
        ecs_logs.extend(collector.normalize_to_ecs(proxy_logs))
        ecs_logs.extend(collector.normalize_to_ecs(firewall_logs))

        # =========================
        # 3. ルール適用
        # =========================
        alerts = []
        for log in ecs_logs:
            matched = rule_engine.apply_rules(log)
            if matched:
                alerts.append({
                    "cycle_start": cycle_start.isoformat(),
                    "log": log,
                    "rule": matched
                })

        # =========================
        # 4. スコアリング
        # =========================
        scores = scorer.calc_score(alerts)

        # =========================
        # 5. 結果保存（追記）
        # =========================
        if scores:
            scorer.save_score(scores, SCORE_OUTPUT)
            scorer.save_alert_log(scores, ALERT_LOG)
            print(f"[INFO] {len(scores)} alerts saved")
        else:
            print("[INFO] no alert")

        print("[INFO] cycle end / sleep 5min\n")

        # =========================
        # 6. 次サイクルまで待機
        # =========================
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
