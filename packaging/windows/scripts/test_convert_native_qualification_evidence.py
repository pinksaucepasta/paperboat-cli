#!/usr/bin/env python3
"""Deterministic contract tests for native qualification evidence conversion."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("convert-native-qualification-evidence.py")
VERSION = "2026.08.18.9"
COMPONENTS = ("pb.exe", "paperboat-runtime.exe", "paperboat-hostd.exe", "paperboat-updater.exe", "pb-launcher.exe")
EVENTS = (
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
)


class NativeQualificationEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.artifacts = self.root / "dist"
        self.artifacts.mkdir()
        for component in COMPONENTS:
            (self.artifacts / f"paperboat_{VERSION}_windows_amd64_{component}").write_bytes(component.encode("utf-8"))
        self.report = self.root / "report.json"
        self.evidence = self.root / "evidence.json"
        self.write_report()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write_report(self, **overrides: object) -> None:
        report: dict[str, object] = {
            "schema": "paperboat.windows-native-qualification-report/v1",
            "platform": "windows",
            "architecture": "amd64",
            "stability": "stable",
            "native_tested": True,
            "version": VERSION,
            "status": "passed",
            "windows_build": "26100",
            "runner": "windows-11-iot-amd64",
            "upgrade_version": "2026.08.18.10",
            "msi_sha256": "a" * 64,
            "upgrade_msi_sha256": "b" * 64,
            "events": [{"name": event, "status": "passed", "detail": "ok"} for event in EVENTS],
            "failure": None,
        }
        report.update(overrides)
        self.report.write_text(json.dumps(report), encoding="utf-8")

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--report", str(self.report), "--artifacts-dir", str(self.artifacts), "--version", VERSION, *arguments],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_convert_and_verify_binds_final_artifact_hashes(self) -> None:
        converted = self.invoke("--output", str(self.evidence))
        self.assertEqual(converted.returncode, 0, converted.stderr)
        evidence = json.loads(self.evidence.read_text(encoding="utf-8"))
        self.assertEqual(evidence["release_version"], VERSION)
        self.assertEqual([artifact["target_path"] for artifact in evidence["artifacts"]], [
            "cli-windows-amd64",
            "runtime-windows-amd64",
            "hostd-windows-amd64",
            "updater-windows-amd64",
            "launcher-windows-amd64",
        ])
        verified = self.invoke("--verify-evidence", str(self.evidence))
        self.assertEqual(verified.returncode, 0, verified.stderr)
        (self.artifacts / f"paperboat_{VERSION}_windows_amd64_pb.exe").write_bytes(b"changed-after-qualification")
        rejected = self.invoke("--verify-evidence", str(self.evidence))
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("does not exactly match", rejected.stderr)

    def test_rejects_non_passing_native_harness_report(self) -> None:
        self.write_report(status="failed", failure="msi repair failed")
        result = self.invoke("--output", str(self.evidence))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a passed", result.stderr)

    def test_accepts_bom_prefixed_report_from_windows_tooling(self) -> None:
        report = json.loads(self.report.read_text(encoding="utf-8"))
        self.report.write_bytes(("\ufeff" + json.dumps(report)).encode("utf-8"))
        result = self.invoke("--output", str(self.evidence))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.evidence.read_text(encoding="utf-8"))["status"], "passed")

    def test_rejects_report_without_complete_native_lifecycle(self) -> None:
        self.write_report(events=[{"name": "preflight", "status": "passed", "detail": "ok"}])
        result = self.invoke("--output", str(self.evidence))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing passed events", result.stderr)


if __name__ == "__main__":
    unittest.main()
