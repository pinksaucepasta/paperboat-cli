#!/usr/bin/env python3
"""Write explicit native Windows ARM64 qualification evidence.

Cross-compilation is intentionally never converted into native evidence. A
blocked record is a successful workflow result with a non-passing status so
release automation can distinguish "not tested" from "tested and passed".
"""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--status", choices=("blocked_no_hardware", "native_verified"), required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--runner", default="")
    parser.add_argument("--workflow", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--commit", default="")
    args = parser.parse_args()

    native_tested = args.status == "native_verified"
    if args.status == "blocked_no_hardware" and not args.reason.strip():
        parser.error("--reason is required for blocked_no_hardware evidence")
    if args.status == "native_verified":
        if platform.system().lower() != "windows":
            parser.error("native_verified evidence requires a Windows runner")
        if "arm64" not in platform.machine().lower():
            parser.error("native_verified evidence requires an ARM64 runner")

    evidence = {
        "schema": "paperboat.windows-native-evidence/v1",
        "platform": "windows",
        "architecture": "arm64",
        "stability": "beta",
        "status": args.status,
        "native_tested": native_tested,
        "cross_compile_not_native_evidence": True,
        "reason": args.reason,
        "runner": args.runner,
        "workflow": args.workflow,
        "run_id": args.run_id,
        "commit": args.commit,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
