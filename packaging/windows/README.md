# Paperboat Windows packaging

This directory is the first-party packaging contract for native Windows 11
amd64 and arm64. It does not install WSL, use Windows optional capabilities, or
enable a pre-existing system `sshd` service.

The package policy is deliberately separate from the runtime implementation:

- `amd64` is published on the `stable` channel after the native release gates
  pass.
- `arm64` is published on the `stable` channel after its native release gates pass.
- Both architectures use the same files, protocols, service names, local
  state layout, and intended feature set.
- The MSI is machine-wide. The portable ZIP is a client package and does not
  install services or change system configuration.
- `pb.exe`, `pb-launcher.exe`, and the three role-scoped service artifacts
  embed the `longPathAware` application manifest. Regenerate the
  architecture-specific resource objects from
  `resources/paperboat.manifest` with
  `scripts/generate-manifest-resources.sh` when the resource toolchain changes.
- OpenSSH provisioning is an integration hook consumed by Paperboat host setup.
  It identifies the exact WinGet package and approved version. The MSI does not
  silently replace an administrator-owned `sshd` installation.

## Layout contract

The MSI uses these stable paths:

```text
C:\\Program Files\\Paperboat\\
  bin\\
    pb.exe                  # stable public launcher
    pb-launcher.exe          # source copied to pb.exe on Client renewal
  releases\\
    versions\\{{VERSION}}\\
      paperboat-runtime.exe   # runtime commands only
      paperboat-hostd.exe     # host supervisor command only
      paperboat-updater.exe   # updater and activator commands only
    cli-current\\
      pb.exe                  # protected full CLI seeded by the MSI

C:\\ProgramData\\Paperboat\\
  ssh\\
  updates\\current\\
  updates\\rollback\\
  logs\\
```

The MSI registers `PaperboatHostd` and `PaperboatUpdated` with Windows Service
Control Manager. The service executable files are supplied by the release
staging directory; this repository does not fabricate service binaries. The
OpenSSH integration file is installed under the Paperboat-owned SSH state root
and contains no credentials or private material.

The MSI appends `C:\Program Files\Paperboat\bin` to the machine PATH. Its
public `pb.exe` is a stable launcher that resolves the protected current CLI
slot, so Client re-enrollment and ordinary updates never leave PATH pointing at
an older full CLI. Uninstall removes only Paperboat's PATH entry.

## Build inputs

The MSI source expects a real, release-built staging directory containing:

```text
pb.exe
pb-launcher.exe
paperboat-runtime.exe
paperboat-hostd.exe
paperboat-updater.exe
```

All five files are required. The runtime, hostd, and updater files must be
distinct role-stamped builds. The stable launcher is owned exclusively by MSI
so an in-process update never replaces its own process-selection boundary.
Its stable ABI is only: resolve the protected `cli-current` pointer, validate
the selected executable, forward the original arguments/environment, and
return that process's exit status. Release TUF may carry a launcher target for
MSI construction, but the Windows in-process activation transaction explicitly
updates only CLI, runtime, hostd, and updater.

Build an unsigned MSI on a Windows machine with WiX Toolset v4 or newer:

```powershell
./packaging/windows/scripts/build-msi.ps1 `
  -Version 2026.08.18.0 `
  -Architecture amd64 `
  -StagingDirectory C:\\paperboat\\stage\\windows-amd64 `
  -OutputDirectory C:\\paperboat\\out
```

For arm64, use `-Architecture arm64`. The script selects the matching WiX
platform and enforces the stable metadata channel for both architectures. It never downloads
WiX and never invokes a signing tool.

The resulting MSI may be unsigned. Release integrity is provided by TUF target
signatures, SHA-256 checksums, PE architecture validation, SBOM, and
provenance. Authenticode and RFC 3161 timestamping are optional enhancements.

## Portable ZIP

The ZIP contains only the client executable, launcher, and generated package
metadata. It is deterministic: files are sorted, timestamps are supplied by
`SOURCE_DATE_EPOCH` or a fixed epoch, and host filesystem modes and mtimes are
not copied into the archive.

```sh
SOURCE_DATE_EPOCH=0 \
  ./packaging/windows/scripts/package-zip.sh \
  --version 2026.08.18.0 \
  --architecture amd64 \
  --staging ./stage/windows-amd64 \
  --output ./dist/paperboat_2026.08.18.0_windows_amd64.zip
```

The PowerShell wrapper has the same flags. The ZIP tool requires Go, which is
already a release build dependency, and uses only the Go standard library.

## WinGet templates

`winget/stable` is the stable package template with amd64 and arm64 MSI entries. URL, version,
product-code, and SHA-256 values remain placeholders until a release has been
built and the release authority has completed signing and verification.

The templates are not submitted to the WinGet community repository by this
checkout. Rendered manifests must be validated against the current WinGet
schema and the final signed MSI identities during release preparation.

## Validation

Run the deterministic contract validator and package tests from the repository
root:

```sh
./packaging/windows/scripts/validate.sh
go test ./packaging/windows/...
```

On Windows, use `validate.ps1` and `go test ./packaging/windows/...`. The
validator checks architecture/channel metadata, WiX source wiring, service and
OpenSSH hook names, WinGet template placeholders, forbidden capability-based
OpenSSH installation, and secret/signature-claim hygiene. It does not claim
that an MSI is signed and does not replace native MSI, WinGet, or Authenticode
qualification.
