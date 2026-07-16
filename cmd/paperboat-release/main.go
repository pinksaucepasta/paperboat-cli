// Command paperboat-release signs connector release manifests with a local
// Ed25519 PKCS#8 PEM private key. It never emits private key material.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pujan-modha/paperboat-cli/internal/connect"
)

type artifactInput struct {
	Component string `json:"component"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	URL       string `json:"url"`
	Path      string `json:"path"`
	Format    string `json:"format,omitempty"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "sign-manifest" {
		fmt.Fprintln(stderr, "usage: paperboat-release sign-manifest --version VERSION --artifacts FILE --private-key FILE --output FILE")
		return 2
	}
	flags := flag.NewFlagSet("sign-manifest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.String("version", "", "Release version")
	artifactsPath := flags.String("artifacts", "", "JSON artifact input file")
	privateKeyPath := flags.String("private-key", "", "Ed25519 PKCS#8 PEM private key")
	output := flags.String("output", "", "Signed manifest output path")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *version == "" || *artifactsPath == "" || *privateKeyPath == "" || *output == "" {
		return 2
	}
	privateKey, err := loadPrivateKey(*privateKeyPath)
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-release:", err)
		return 1
	}
	contents, err := os.ReadFile(*artifactsPath)
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-release:", err)
		return 1
	}
	var inputs []artifactInput
	if err := json.Unmarshal(contents, &inputs); err != nil {
		fmt.Fprintln(stderr, "paperboat-release: invalid artifacts JSON:", err)
		return 1
	}
	signable := make([]connect.SignableArtifact, len(inputs))
	for i, input := range inputs {
		signable[i] = connect.SignableArtifact(input)
	}
	manifest, err := connect.SignManifest(*version, signable, privateKey)
	if err != nil {
		fmt.Fprintln(stderr, "paperboat-release:", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fmt.Fprintln(stderr, "paperboat-release:", err)
		return 1
	}
	if err := os.WriteFile(*output, append(manifest, '\n'), 0o644); err != nil {
		fmt.Fprintln(stderr, "paperboat-release:", err)
		return 1
	}
	fmt.Fprintln(stdout, *output)
	return 0
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(contents)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("private key must be a PKCS#8 PEM Ed25519 key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return privateKey, nil
}
