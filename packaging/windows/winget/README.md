# WinGet manifest templates

These files are templates, not submitted manifests. Replace every `{{...}}`
token during release preparation and validate the rendered files with the
current WinGet schema and the final MSI metadata.

The stable package contains separate amd64 and arm64 installers under one package identifier:

```text
Pinksaucepasta.Paperboat
```

The final manifest must use the exact signed MSI URL, SHA-256, product code,
publisher, and version. This repository intentionally contains none of those
release-specific values and contains no certificate or private key material.
