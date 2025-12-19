import time
from datetime import datetime
from detect_operator.log_collector import LogCollector
from detect_operator.rule_engine import RuleEngine
from detect_operator.scoring_engine import ScoringEngine

INTERVAL = 300  # 5分

def main():
    print("[INFO] 自動ログ収集・検知システム起動")

    collector = LogCollector()
    rule_engine = RuleEngine("detect_operator/rules/rules.yml")
    scorer = ScoringEngine()

    while True:
        print(f"[INFO] cycle start {datetime.now()}")

        # ① ログ収集
        proxy_logs = collector.load_proxy("detect_operator/logs/proxy.csv")
        fw_logs = collector.load_firewall("detect_operator/logs/firewall.csv")
        all_logs = proxy_logs + fw_logs

        # ② ルール適用
        evaluated_logs = []
        for log in all_logs:
            rule_result = rule_engine.evaluate_rules(log)
            evaluated_logs.append({
                "log": log,
                "rule": rule_result
            })

        # ③ 5分単位スコアリング
        scores = scorer.group_by_window(evaluated_logs, window_sec=300)

        # ④ JSON出力
        scorer.save_score(scores, "output/score_result.json")

        print("[INFO] cycle end / sleep 5min\n")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
