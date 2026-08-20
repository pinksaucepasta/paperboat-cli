//go:build !windows

package main

// The fixture is compiled only on Windows. Keeping a tiny non-Windows main
// makes repository-wide package enumeration and cross-platform contract tests
// deterministic instead of reporting an empty package.
func main() {}
