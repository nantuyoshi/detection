import time
import os
from detect_operator.log_collector import LogCollector
from detect_operator.rule_engine import RuleEngine
from detect_operator.scoring_engine import ScoringEngine


def main():
    # ★ main.py のあるディレクトリ
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    # ★ logs フォルダの絶対パス
    LOG_DIR = os.path.join(BASE_DIR, "logs")

    collector = LogCollector()
    rule_engine = RuleEngine(os.path.join(BASE_DIR, "rules", "rules.yml"))
    scorer = ScoringEngine()

    interval = 10
    print("[INFO] 自動ログ収集・検知システム起動")

    try:
        while True:
            proxy_logs = collector.load_proxy_logs(
                os.path.join(LOG_DIR, "proxy.csv")
            )
            firewall_logs = collector.load_firewall_logs(
                os.path.join(LOG_DIR, "firewall.csv")
            )

            all_logs = proxy_logs + firewall_logs

            alerts = []
            for log in all_logs:
                result = rule_engine.evaluate_rules(log)
                if any(result.values()):
                    alerts.append({"log": log, "alert": result})

            for alert in alerts:
                score = scorer.calc_score(alert)
                print(
                    f"[ALERT] log={alert['log']} "
                    f"rule={alert['alert']} score={score}"
                )

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[INFO] 自動収集停止")


if __name__ == "__main__":
    main()
