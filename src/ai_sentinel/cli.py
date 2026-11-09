"""
CLI entry point for AI-Sentinel Guardrails.
"""

import sys
import argparse
from ai_sentinel.core.shield import SecurityShield

def main():
    parser = argparse.ArgumentParser(description="AI-Sentinel CLI Scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Inspect text input for safety risks")
    inspect_parser.add_argument("text", type=str, help="Text to inspect")

    args = parser.parse_args()

    try:
        shield = SecurityShield()
        if args.command == "inspect":
            verdict = shield.inspect_input(args.text)
            print(f"Action: {verdict.action}")
            print(f"Risk Score: {verdict.risk_score}")
            print(f"Reasons: {verdict.reasons}")
            
            if verdict.action == "BLOCK":
                sys.exit(1)
            else:
                sys.exit(0)
    except Exception as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()