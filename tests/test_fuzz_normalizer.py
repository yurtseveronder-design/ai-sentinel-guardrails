"""
CLI entrypoint for AI Sentinel Guardrails.
"""

import sys
import argparse
from ai_sentinel.core.shield import SecurityShield

def main():
    parser = argparse.ArgumentParser(description="AI Sentinel CLI Guardrail Inspector")
    parser.add_argument("prompt", type=str, help="The prompt text to inspect")
    parser.add_argument("--config", type=str, default="config/threat_signatures.yaml", help="Path to threat signatures config")
    
    args = parser.parse_args()
    
    shield = SecurityShield(config_path=args.config)
    result = shield.evaluate(args.prompt)
    
    # Handle both dict and object returns gracefully
    if isinstance(result, dict):
        action = result.get("action", "ALLOW")
        risk_level = "HIGH" if result.get("flagged", False) else "LOW"
        matched_rules = result.get("matched_rules", [])
    else:
        action = getattr(result, "action", "ALLOW")
        risk_level = "HIGH" if getattr(result, "flagged", False) else "LOW"
        matched_rules = getattr(result, "matched_rules", [])

    print(f"Action: {action}")
    print(f"Risk Level: {risk_level}")
    print(f"Matched Rules: {matched_rules}")

    if action == "BLOCK":
        sys.exit(2)
    else:
      sys.exit(0)

if __name__ == "__main__":
    main()