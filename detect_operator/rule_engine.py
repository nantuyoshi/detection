import yaml
import re

__all__ = ["RuleEngine"]

class RuleEngine:

    def __init__(self, rule_path: str):
        with open(rule_path, "r", encoding="utf-8") as f:
            self.rules = yaml.safe_load(f) or {}

        self.whitelist = self.rules.get("whitelist", [])

    def is_base64(self, text: str) -> bool:
        if not text:
            return False

        pattern = r"^[A-Za-z0-9+/=]{20,}$"
        return bool(re.match(pattern, text))

    def check_destination(self, log: dict) -> bool:
        dst = log.get("destination.domain")
        return dst not in self.whitelist

    def check_body_base64(self, log: dict) -> bool:
        return self.is_base64(log.get("http.request.body.contents", ""))

    def evaluate_rules(self, log: dict) -> dict:
        result = {
            "unknown_dst": False,
            "base64_found": False,
            "small_post": False
        }

        if self.check_destination(log):
            result["unknown_dst"] = True

        if self.check_body_base64(log):
            result["base64_found"] = True

        if log.get("http.request.body.bytes", 0) < 5000:
            result["small_post"] = True

        return result
