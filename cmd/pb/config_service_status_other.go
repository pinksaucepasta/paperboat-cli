//go:build !windows

package main

func windowsConfigServiceStatus() string { return "not_installed" }
