package hostruntimecmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
)

const usage = `pb internal host runtime.

Usage:
  pb __runtime-host

This entry point is managed by Paperboat services and is not a user command.`

func run(args []string, stdout, stderr io.Writer) int {
	return execute(context.Background(), args, os.Stdin, stdout, stderr)
}

func runWithInput(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return execute(context.Background(), args, stdin, stdout, stderr)
}

// Execute runs a validated host-runtime mode from the unified pb command.
func Execute(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if ctx == nil || stdin == nil || stdout == nil || stderr == nil {
		return 2
	}
	return execute(ctx, args, stdin, stdout, stderr)
}

func execute(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, usage)
		return 0
	}

	if args[0] == "version" || args[0] == "--version" || args[0] == "-v" {
		fmt.Fprintf(stdout, "pb %s (%s)\n", buildinfo.Version, buildinfo.Commit)
		return 0
	}
	if args[0] == "bootstrap" {
		if err := runBootstrap(ctx, args[1:], stdin, stdout, stderr); err != nil {
			writeError(stderr, err)
			return 1
		}
		return 0
	}
	if args[0] == "service" {
		if err := runServiceCommand(ctx, args[1:], stdin, stdout, stderr); err != nil {
			writeError(stderr, err)
			return 1
		}
		return 0
	}
	if args[0] == "purge" {
		if err := runPurgeCommand(ctx, args[1:], stdin, stdout, stderr); err != nil {
			writeError(stderr, err)
			return 1
		}
		return 0
	}
	if args[0] == "doctor" {
		if err := runDoctor(ctx, args[1:], stdout, stderr); err != nil {
			writeError(stderr, err)
			return 1
		}
		return 0
	}
	if args[0] == "preview" {
		if err := runPreview(ctx, args[1:], stdout, stderr); err != nil {
			writeError(stderr, err)
			return 1
		}
		return 0
	}
	if args[0] == "run" {
		if len(args) != 1 {
			writeError(stderr, fmt.Errorf("run does not accept arguments"))
			return 2
		}
		if err := runProduction(ctx, stdout); err != nil {
			writeError(stderr, err)
			return 1
		}
		return 0
	}

	err := fmt.Errorf("unknown command %q", args[0])
	writeError(stderr, err)
	return 2
}

func writeError(w io.Writer, err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(w, "pb: %v\n", err)
}
