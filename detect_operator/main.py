import time
from datetime import datetime
from pathlib import Path

from detect_operator.log_collector import LogCollector
from detect_operator.rule_engine import RuleEngine
from detect_operator.scoring_engine import ScoringEngine

# ===== 設定 =====
PROXY_LOG = "logs/proxy.csv"
FIREWALL_LOG = "logs/firewall.csv"
RULE_FILE = "detect_operator/rules/rules.yml"
OUTPUT_FILE = "output/score_result.json"

INTERVAL = 300  # 5分（300秒）


def main():
    print("[INFO] 自動ログ収集・検知システム起動")

    collector = LogCollector()
    rule_engine = RuleEngine(RULE_FILE)
    scorer = ScoringEngine()

    # 出力ディレクトリ保証
    Path("output").mkdir(exist_ok=True)

    try:
        while True:
            cycle_start = datetime.now()
            print(f"[INFO] cycle start {cycle_start}")

            # =========================
            # 1. ログ収集
            # =========================
            proxy_logs = collector.load_proxy(PROXY_LOG)
            firewall_logs = collector.load_firewall(FIREWALL_LOG)

            ecs_logs = []
            ecs_logs.extend(collector.normalize_to_ec(proxy_logs))
            ecs_logs.extend(collector.normalize_to_ec(firewall_logs))

            # =========================
            # 2. ガード処理（超重要）
            # =========================
            if not ecs_logs:
                print("[WARN] 収集対象ログなし")
                print("[INFO] cycle end / sleep 5min\n")
                time.sleep(INTERVAL)
                continue   # ← ★ 落ちないための核心
            # =========================

            # =========================
            # 3. 検知ルール適用
            # =========================
            alerts = []
            for log in ecs_logs:
                rule_result = rule_engine.evaluate_rules(log)
                if any(rule_result.values()):
                    alerts.append({
                        "log": log,
                        "rule": rule_result
                    })

            if not alerts:
                print("[INFO] 検知イベントなし")
                print("[INFO] cycle end / sleep 5min\n")
                time.sleep(INTERVAL)
                continue

            # =========================
            # 4. スコアリング
            # =========================
            scores = scorer.calc_score(alerts)

            # =========================
            # 5. 結果保存（追記）
            # =========================
            scorer.save_score(scores)


            print(f"[INFO] alert count = {len(scores)}")
            print("[INFO] cycle end / sleep 5min\n")

            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print("\n[INFO] システムを手動停止しました")


if __name__ == "__main__":
    main()
