#!/usr/bin/env python3
"""Convert a native Windows qualification report into TUF publication evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "paperboat.windows-native-qualification-report/v1"
EVIDENCE_SCHEMA = "paperboat.windows-native-qualification/v1"
COMPONENTS = (
    ("cli", "pb.exe"),
    ("runtime", "paperboat-runtime.exe"),
    ("hostd", "paperboat-hostd.exe"),
    ("updater", "paperboat-updater.exe"),
    ("launcher", "pb-launcher.exe"),
)
REQUIRED_EVENTS = frozenset(
    {
        "preflight",
        "native_go_e2e",
        "msiexec_fresh_install",
        "msi_payload_assertions",
        "msiexec_repair",
        "msi_repair_assertions",
        "msiexec_upgrade",
        "msi_upgrade_assertions",
        "msiexec_uninstall",
        "msi_uninstall_assertions",
    }
)
VERSION_PATTERN = re.compile(r"^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$")
BUILD_PATTERN = re.compile(r"^[0-9]{4,10}$")


class EvidenceError(ValueError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--version", required=True)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--output", type=Path)
    output.add_argument("--verify-evidence", type=Path)
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1 << 20:
            raise EvidenceError(f"{path} is not a bounded regular JSON file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain a JSON object")
    return value


def require_string(value: Any, name: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or any(c in value for c in "\x00\r\n"):
        raise EvidenceError(f"report {name} is invalid")
    if pattern is not None and not pattern.fullmatch(value):
        raise EvidenceError(f"report {name} has an invalid format")
    return value


def validate_report(report: dict[str, Any], version: str) -> tuple[str, str]:
    if not VERSION_PATTERN.fullmatch(version):
        raise EvidenceError("release version is invalid")
    required = {
        "schema",
        "platform",
        "architecture",
        "stability",
        "native_tested",
        "version",
        "status",
        "windows_build",
        "runner",
        "upgrade_version",
        "msi_sha256",
        "upgrade_msi_sha256",
        "events",
        "failure",
    }
    if set(report) != required:
        raise EvidenceError("qualification report has an unexpected schema")
    if (
        report["schema"] != REPORT_SCHEMA
        or report["platform"] != "windows"
        or report["architecture"] != "amd64"
        or report["stability"] != "stable"
        or report["native_tested"] is not True
        or report["version"] != version
        or report["status"] != "passed"
        or report["failure"] is not None
    ):
        raise EvidenceError("qualification report is not a passed Windows amd64 stable result")
    windows_build = require_string(report["windows_build"], "windows_build", BUILD_PATTERN)
    runner = require_string(report["runner"], "runner")
    events = report["events"]
    if not isinstance(events, list):
        raise EvidenceError("qualification report events are invalid")
    passed = set()
    for event in events:
        if not isinstance(event, dict) or set(event) != {"name", "status", "detail"}:
            raise EvidenceError("qualification report event is invalid")
        if event["status"] == "failed":
            raise EvidenceError(f"qualification report contains failed event {event['name']!r}")
        if event["status"] == "passed" and isinstance(event["name"], str):
            passed.add(event["name"])
    missing = REQUIRED_EVENTS - passed
    if missing:
        raise EvidenceError(f"qualification report is missing passed events: {', '.join(sorted(missing))}")
    return windows_build, runner


def release_asset_path(artifacts_dir: Path, version: str, filename: str) -> Path:
    path = artifacts_dir / f"paperboat_{version}_windows_amd64_{filename}"
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"final signed release artifact is missing or unsafe: {path}")
    return path


def artifact_record(component: str, path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    length = 0
    try:
        with path.open("rb") as artifact:
            while chunk := artifact.read(1024 * 1024):
                digest.update(chunk)
                length += len(chunk)
    except OSError as exc:
        raise EvidenceError(f"cannot hash {path}: {exc}") from exc
    if length < 1:
        raise EvidenceError(f"final signed release artifact is empty: {path}")
    return {
        "component": component,
        "target_path": f"{component}-windows-amd64",
        "sha256": digest.hexdigest(),
        "length": length,
        "platform": "windows",
        "architecture": "amd64",
        "status": "passed",
    }


def render_evidence(report: dict[str, Any], artifacts_dir: Path, version: str) -> bytes:
    windows_build, runner = validate_report(report, version)
    if artifacts_dir.is_symlink() or not artifacts_dir.is_dir():
        raise EvidenceError("artifacts directory is invalid")
    artifacts = [artifact_record(component, release_asset_path(artifacts_dir, version, filename)) for component, filename in COMPONENTS]
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "release_version": version,
        "platform": "windows",
        "architecture": "amd64",
        "status": "passed",
        "native_tested": True,
        "windows_build": windows_build,
        "runner": runner,
        "artifacts": artifacts,
    }
    return (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")


def atomic_write(path: Path, body: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".paperboat-native-evidence-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main() -> int:
    args = parse_args()
    try:
        body = render_evidence(load_json(args.report), args.artifacts_dir, args.version)
        if args.output is not None:
            atomic_write(args.output, body)
        else:
            if args.verify_evidence.is_symlink() or not args.verify_evidence.is_file():
                raise EvidenceError("native qualification evidence is missing or unsafe")
            if args.verify_evidence.read_bytes() != body:
                raise EvidenceError("native qualification evidence does not exactly match the report and final signed artifacts")
    except (EvidenceError, OSError) as exc:
        print(f"native qualification evidence: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
