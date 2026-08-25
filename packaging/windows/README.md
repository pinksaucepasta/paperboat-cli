# Windows release tooling

Windows releases contain one complete `pb.exe` per architecture:

- `pb-windows-amd64.exe`
- `pb-windows-arm64.exe`

Both files are built from `./cmd/pb`. The same executable handles the CLI,
services, host runtime, updates, and background roles through internal
arguments. Windows services must point at the installed `pb.exe`; no launcher,
runtime, updater, MSI, ZIP, or other split artifact is produced.

The release workflow performs native smoke tests on Blacksmith amd64 and
GitHub `windows-11-arm`, signs the executable when signing credentials are
available, and publishes the exact five release assets. The active contract
check is:

```sh
./packaging/windows/scripts/validate-release-pipeline.sh
```

`sign-and-verify.ps1` accepts only unified PE `.exe` files and verifies their
architecture and Authenticode identity before publication.
