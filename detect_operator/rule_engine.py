import yaml
import re
from pathlib import Path

class RuleEngine:

    def __init__(self, rule_path: str):
        base_dir = Path(__file__).resolve().parent
        rule_file = base_dir / "rules" / rule_path

        with open(rule_file, "r", encoding="utf-8") as f:
            self.rules = yaml.safe_load(f)

    def is_base64(self, text: str) -> bool:
        if not text:
            return False
        text = text.strip()  
        return bool(re.match(r"^[A-Za-z0-9+/=]{20,}$", text))


    def evaluate_rules(self, log: dict) -> dict:
        result = {
            "small_post": False,
            "base64_found": False,
            "dns_missing": False
        }

        if log.get("body_bytes", 0) < 5000:
            result["small_post"] = True

        if self.is_base64(log.get("body", "")):
            result["base64_found"] = True

        if not log.get("domain"):
            result["dns_missing"] = True

        return result
