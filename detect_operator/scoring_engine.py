class ScoringEngine:

    def calc_score(self, logs):
        """
        logs: list
        ・dict の場合 → ルールベース評価
        ・str の場合 → 仮スコア
        """

        score = 0

        for l in logs:
            # dict を想定した将来用処理
            if isinstance(l, dict):
                if l.get("unknown_dst"):
                    score += 30
                if l.get("large_transfer"):
                    score += 40
                if l.get("rule_hit"):
                    score += 20

            # 現状（文字列ログ）の暫定処理
            elif isinstance(l, str):
                score += 10

        return score
