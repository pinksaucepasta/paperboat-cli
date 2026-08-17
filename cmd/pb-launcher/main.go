package main

import (
	"fmt"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/launcher"
)

func main() {
	target, err := launcher.Resolve(os.Args[1:], os.Environ())
	if err == nil {
		err = launcher.Execute(target)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pb:", err)
		os.Exit(1)
	}
}
