#!/usr/bin/env python3
"""Check rendered WinGet manifests against the final signed MSI files."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def require(text: str, needle: str, context: str) -> None:
    if needle not in text:
        raise SystemExit(f"{context} is missing {needle!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", required=True, type=pathlib.Path)
    parser.add_argument("--release", required=True)
    args = parser.parse_args()

    stable_msi = args.dist / f"paperboat_{args.release}_windows_amd64.msi"
    arm64_msi = args.dist / f"paperboat_{args.release}_windows_arm64.msi"
    for path in (stable_msi, arm64_msi):
        if not path.is_file():
            raise SystemExit(f"final MSI is missing from publication directory: {path.name}")

    stable = args.dist / "Pinksaucepasta.Paperboat.installer.yaml"
    beta = args.dist / "Pinksaucepasta.Paperboat.Beta.installer.yaml"
    for path in (stable, beta):
        if not path.is_file():
            raise SystemExit(f"rendered WinGet installer manifest is missing: {path.name}")
        content = path.read_text(encoding="utf-8")
        if "{{" in content or "PLACEHOLDER" in content:
            raise SystemExit(f"rendered WinGet manifest still contains a placeholder: {path.name}")
        require(content, f"PackageVersion: \"{args.release}\"", path.name)

    stable_content = stable.read_text(encoding="utf-8")
    beta_content = beta.read_text(encoding="utf-8")
    stable_hash = digest(stable_msi)
    arm64_hash = digest(arm64_msi)
    require(stable_content, f"Architecture: x64", stable.name)
    require(stable_content, f"InstallerSha256: \"{stable_hash}\"", stable.name)
    require(stable_content, f"paperboat_{args.release}_windows_amd64.msi", stable.name)
    if "Architecture: arm64" in stable_content:
        raise SystemExit("stable WinGet manifest must not expose arm64")
    require(beta_content, f"Architecture: x64", beta.name)
    require(beta_content, f"Architecture: arm64", beta.name)
    require(beta_content, f"InstallerSha256: \"{stable_hash}\"", beta.name)
    require(beta_content, f"InstallerSha256: \"{arm64_hash}\"", beta.name)
    require(beta_content, f"paperboat_{args.release}_windows_amd64.msi", beta.name)
    require(beta_content, f"paperboat_{args.release}_windows_arm64.msi", beta.name)
    print("Rendered WinGet manifests match the final MSI hashes and architecture channels.")


if __name__ == "__main__":
    main()
