#!/usr/bin/env python3
"""Validate and merge signed Windows release handoffs after artifact download."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", required=True, type=pathlib.Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--publisher", default="")
    args = parser.parse_args()

    handoffs = sorted(args.dist.glob("windows-signing-manifest-*.json"))
    if len(handoffs) != 2:
        fail("expected exactly amd64 and arm64 Windows signing handoffs")

    manifests = []
    for path in handoffs:
        try:
            # Windows signing tools commonly write JSON with a UTF-8 BOM.
            # ``utf-8-sig`` accepts both BOM-prefixed and plain UTF-8 files.
            manifest = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"cannot read Windows signing handoff {path.name}: {exc}")
        if manifest.get("schema") != "paperboat.windows-signing/v1":
            fail(f"invalid Windows signing handoff schema: {path.name}")
        if manifest.get("release") != args.release:
            fail(f"Windows signing handoff release mismatch: {path.name}")
        if args.publisher and manifest.get("publisher_subject") not in {args.publisher, ""}:
            fail(f"Windows signing handoff publisher mismatch: {path.name}")
        if manifest.get("architecture") not in {"amd64", "arm64"}:
            fail(f"invalid Windows handoff architecture: {path.name}")
        manifests.append(manifest)

    architectures = {manifest["architecture"] for manifest in manifests}
    if architectures != {"amd64", "arm64"}:
        fail("Windows signing handoffs must cover amd64 and arm64")

    artifacts = []
    seen = set()
    for manifest in manifests:
        for artifact in manifest.get("artifacts", []):
            name = artifact.get("path")
            if not isinstance(name, str) or name in seen:
                fail(f"duplicate or invalid Windows artifact in signing handoffs: {name!r}")
            seen.add(name)
            path = args.dist / name
            if not path.is_file():
                fail(f"signed Windows artifact is missing after download: {name}")
            if artifact.get("sha256") != sha256(path):
                fail(f"signed Windows artifact checksum changed after download: {name}")
            if args.publisher and artifact.get("publisher_subject") not in {args.publisher, ""}:
                fail(f"signed Windows artifact publisher mismatch: {name}")
            if artifact.get("kind") in {"pe", "msi"}:
                if artifact.get("authenticode_status") not in {"valid", "not_present"}:
                    fail(f"Windows artifact has invalid Authenticode evidence: {name}")
            elif artifact.get("kind") == "archive":
                if artifact.get("contents_authenticode_status") not in {"valid", "not_required"}:
                    fail(f"Windows ZIP has invalid Authenticode evidence: {name}")
            else:
                fail(f"unknown Windows artifact kind: {name}")
            artifacts.append(artifact)

    for architecture in ("amd64", "arm64"):
        architecture_artifacts = [item for item in artifacts if item.get("architecture") == architecture]
        if len([item for item in architecture_artifacts if item.get("kind") == "pe"]) != 5:
            fail(f"{architecture} handoff must contain five signed PE artifacts")
        if len([item for item in architecture_artifacts if item.get("kind") == "msi"]) != 1:
            fail(f"{architecture} handoff must contain one signed MSI")
        if len([item for item in architecture_artifacts if item.get("kind") == "archive"]) != 1:
            fail(f"{architecture} handoff must contain one signed-content ZIP")

    merged = {
        "schema": "paperboat.windows-signing/v1",
        "product": "paperboat",
        "release": args.release,
        "platform": "windows",
        "publisher_subject": args.publisher,
        "checksums_refreshed": True,
        "handoffs": [
            {
                "architecture": manifest["architecture"],
                "channel": manifest["channel"],
                "runner": manifest.get("runner"),
                "windows_build": manifest.get("windows_build"),
                "wix_version": manifest.get("wix_version"),
            }
            for manifest in sorted(manifests, key=lambda item: item["architecture"])
        ],
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
    }
    (args.dist / "windows-signing-manifest.json").write_text(
        json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = [f"{item['sha256']} *{item['path']}" for item in merged["artifacts"]]
    (args.dist / "windows-checksums.sha256").write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"Verified and merged {len(merged['artifacts'])} signed Windows artifacts.")


if __name__ == "__main__":
    main()
