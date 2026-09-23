from __future__ import annotations

import argparse
import json
from pathlib import Path

from .policy import Policy
from .runner import load_event, run_gateway


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PR Gateway v1")
    parser.add_argument("--event", type=Path, help="GitHub event JSON file")
    parser.add_argument("--policy", type=Path, help="Gateway YAML policy file")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    try:
        result = run_gateway(args.root, load_event(args.event), Policy.load(args.policy))
    except Exception as exc:
        print(json.dumps({"status": "ERROR", "message": f"Gateway internal error: {type(exc).__name__}"}))
        return 2
    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        print("PR GATEWAY")
        for check in result["checks"]:
            print(f"{check['check_id']:<12} {check['status']:<5} {check['name']}")
        print(f"Result: {result['status']}")
        print(f"Failures: {result['failures']}  Warnings: {result['warnings']}")
    if result["status"] == "ERROR":
        return 2
    return 1 if result["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())