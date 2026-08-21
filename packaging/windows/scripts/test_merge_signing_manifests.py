import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("merge-signing-manifests.py")


class MergeSigningManifestsTest(unittest.TestCase):
    def test_accepts_utf8_bom_handoffs(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            release = "2026.08.22.4"
            for architecture in ("amd64", "arm64"):
                artifacts = []
                for kind, count in (("pe", 5), ("msi", 1), ("archive", 1)):
                    for index in range(count):
                        name = f"paperboat_{architecture}_{kind}_{index}"
                        (dist / name).write_bytes(f"{architecture}-{kind}-{index}".encode())
                        artifact = {
                            "path": name,
                            "sha256": __import__("hashlib").sha256((dist / name).read_bytes()).hexdigest(),
                            "architecture": architecture,
                            "kind": kind,
                        }
                        if kind in {"pe", "msi"}:
                            artifact["authenticode_status"] = "valid"
                        else:
                            artifact["contents_authenticode_status"] = "valid"
                        artifacts.append(artifact)
                handoff = {
                    "schema": "paperboat.windows-signing/v1",
                    "release": release,
                    "architecture": architecture,
                    "channel": "stable" if architecture == "amd64" else "beta",
                    "artifacts": artifacts,
                }
                (dist / f"windows-signing-manifest-{architecture}.json").write_bytes(
                    ("\ufeff" + json.dumps(handoff)).encode("utf-8")
                )

            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--dist", str(dist), "--release", release],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            merged = json.loads((dist / "windows-signing-manifest.json").read_text())
            self.assertEqual(len(merged["artifacts"]), 14)


if __name__ == "__main__":
    unittest.main()
