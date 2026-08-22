// Command validate-winget checks rendered WinGet manifests without requiring
// winget.exe or any Windows package-manager installation.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/pinksaucepasta/paperboat/packaging/windows/winget"
)

func main() {
	directory := flag.String("manifest-directory", "", "directory containing the three rendered WinGet manifests")
	repository := flag.String("repository", os.Getenv("GITHUB_REPOSITORY"), "GitHub repository in owner/name form (defaults to GITHUB_REPOSITORY)")
	version := flag.String("version", os.Getenv("RELEASE_VERSION"), "expected release version (defaults to RELEASE_VERSION)")
	amd64MSI := flag.String("amd64-msi", "", "optional final signed amd64 MSI to hash-check")
	arm64MSI := flag.String("arm64-msi", "", "optional final signed arm64 MSI to hash-check")
	amd64ProductCode := flag.String("amd64-product-code", "", "optional expected amd64 MSI product code")
	arm64ProductCode := flag.String("arm64-product-code", "", "optional expected arm64 MSI product code")
	flag.Parse()

	if *directory == "" {
		fatal("--manifest-directory is required")
	}
	if err := winget.ValidateDirectory(*directory, winget.Options{
		Repository:       *repository,
		Version:          *version,
		AMD64MSI:         *amd64MSI,
		ARM64MSI:         *arm64MSI,
		AMD64ProductCode: *amd64ProductCode,
		ARM64ProductCode: *arm64ProductCode,
	}); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("Rendered WinGet manifests are valid: %s\n", *directory)
}

func fatal(message string) {
	fmt.Fprintf(os.Stderr, "validate-winget: %s\n", message)
	os.Exit(1)
}
