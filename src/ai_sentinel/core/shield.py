"""
Strict phrase-matching SecurityShield engine.
Loads threat signatures directly from config/threat_signatures.yaml, tokenizes on
non-alphanumeric boundaries, enforces a 10-token span constraint, and respects file order.
"""

from pathlib import Path
import re
import yaml


class SecurityShield:

  def __init__(self, config_path: str = "config/threat_signatures.yaml"):
    self.config_path = config_path
    self.rules = self._load_rules()

  def _load_rules(self) -> list[dict]:
    path = Path(self.config_path)
    if not path.is_file():
      raise FileNotFoundError(f"Threat signatures file missing: {self.config_path}")

    try:
      with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    except Exception as e:
      raise ValueError(f"Unreadable or invalid YAML file {self.config_path}: {e}")

    if not data or not isinstance(data, dict) or "rules" not in data:
      raise ValueError(f"Threat signatures file is empty or malformed: {self.config_path}")

    rules = data["rules"]
    if not isinstance(rules, list) or len(rules) == 0:
      raise ValueError(f"Threat signatures rules list is empty in: {self.config_path}")

    return rules

  @staticmethod
  def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())

  def _match_rule(self, text_tokens: list[str], rule_phrase: str) -> bool:
    rule_tokens = self._tokenize(rule_phrase)
    if not rule_tokens:
      return False

    k = len(rule_tokens)
    n = len(text_tokens)
    if k > n:
      return False

    for i in range(n - k + 1):
      first_match_idx = -1
      last_match_idx = -1
      curr = i
      matched = True
      for rt in rule_tokens:
        found = False
        while curr < n:
          if text_tokens[curr] == rt:
            if first_match_idx == -1:
              first_match_idx = curr
            last_match_idx = curr
            curr += 1
            found = True
            break
          curr += 1
        if not found:
          matched = False
          break

      if matched:
        span = last_match_idx - first_match_idx + 1
        if span <= 10:
          return True

    return False

  def evaluate(self, text: str) -> tuple[bool, str, str]:
    """Evaluates input text against loaded threat signature rules.

    Returns: (blocked: bool, rule_id: str, matched_phrase: str)
    """
    text_tokens = self._tokenize(text)

    for rule in self.rules:
      rule_id = rule.get("id", "UNKNOWN")
      phrase = rule.get("phrase", "")
      if self._match_rule(text_tokens, phrase):
        return True, rule_id, phrase

    return False, "", ""