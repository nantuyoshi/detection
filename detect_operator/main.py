# detect_operator/main.py

import time
from detect_operator.log_collector import LogCollector
from detect_operator.rule_engine import RuleEngine
from detect_operator.scoring_engine import ScoringEngine

def main():
    # --- 初期化 ---
    collector = LogCollector()
    rule_engine = RuleEngine("detect_operator/rules/rules.yml")
    scorer = ScoringEngine()

    # --- 自動収集間隔（秒） ---
    interval = 10

    print("[INFO] 自動ログ収集・検知システム起動")
    try:
        while True:
            # 1. ログ収集
            proxy_logs = collector.load_proxy_logs("logs/proxy.csv")
            firewall_logs = collector.load_firewall_logs("logs/firewall.csv")
            
            all_logs = proxy_logs + firewall_logs

            # 2. ルール適用
            alerts = []
            for log in all_logs:
                result = rule_engine.evaluate_rules(log)
                if any(result.values()):  # いずれかのルールが True の場合アラート
                    alerts.append({"log": log, "alert": result})

            # 3. スコアリング
            scored_alerts = []
            for alert in alerts:
                score = scorer.calc_score(alert)
                scored_alerts.append({"alert": alert, "score": score})

            # 4. アラート出力
            for item in scored_alerts:
                alert = item["alert"]
                score = item["score"]
                print(f"[ALERT] Log: {alert['log']}, Rule Triggered: {alert['alert']}, Score: {score}")

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[INFO] 自動収集停止")

if __name__ == "__main__":
    main()
