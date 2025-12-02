from detect_operator.log_collector import LogCollector
from detect_operator.rule_engine import RuleEngine
from detect_operator.scoring_engine import ScoringEngine


def main():

    collector = LogCollector()
    rule = RuleEngine("detect_operator/rules/rules.yml")
    scorer = ScoringEngine()

    # --- ログ読み込み例 ---
    proxy_logs = collector.load_proxy("sample_proxy.csv")

    # --- ECS 正規化 ---
    ecs_logs = collector.normalize_to_ecs(proxy_logs)

    # --- ルール評価 ---
    evaluated = []
    for log in ecs_logs:
        flags = rule.evaluate_rules(log)
        log.update(flags)
        evaluated.append(log)

    # --- スコアリング ---
    grouped = scorer.group_by_window(evaluated)
    results = scorer.calc_score(grouped)

    # --- 保存 ---
    scorer.save_score(results, "analysis_score.json")

    print("完了：スコアリング結果 → analysis_score.json")

if __name__ == "__main__":
    main()
