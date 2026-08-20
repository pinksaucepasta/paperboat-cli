# WinGet manifest templates

These files are templates, not submitted manifests. Replace every `{{...}}`
token during release preparation and validate the rendered files with the
current WinGet schema and the final MSI metadata.

The stable package is amd64-only because the arm64 channel is beta. The beta
package has a separate explicit package identifier so a user cannot
accidentally install an arm64 beta through a stable package request:

```text
Pinksaucepasta.Paperboat
Pinksaucepasta.Paperboat.Beta
```

The final manifest must use the exact signed MSI URL, SHA-256, product code,
publisher, and version. This repository intentionally contains none of those
release-specific values and contains no certificate or private key material.
