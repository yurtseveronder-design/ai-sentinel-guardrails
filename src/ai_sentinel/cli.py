"""
CLI entry point for AI-Sentinel Guardrails.
"""

import argparse
import sys

from ai_sentinel.core.shield import SecurityShield


def main():
    parser = argparse.ArgumentParser(description="AI-Sentinel CLI Scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect text input for safety risks")
    inspect_parser.add_argument("text", type=str, help="Text to inspect")

    args = parser.parse_args()

    try:
        shield = SecurityShield()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)

    if args.command == "inspect":
        result = shield.evaluate(args.text)
        action = result.get("action", "ALLOW")
        risk_level = result.get("risk_level", "LOW")
        matched_rules = result.get("matched_rules", [])
        print(f"Action: {action}")
        print(f"Risk Level: {risk_level}")
        print(f"Matched Rules: {matched_rules}")
        if action == "REDACT":
            print(f"Sanitized Text: {result.get('sanitized_text')}")
        sys.exit(1 if action == "BLOCK" else 0)


if __name__ == "__main__":
    main()
