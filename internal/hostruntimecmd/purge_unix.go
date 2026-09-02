//go:build darwin || linux

package hostruntimecmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

func runPurgeCommand(ctx context.Context, args []string, _ io.Reader, _, _ io.Writer) error {
	if len(args) != 0 {
		return errors.New("purge accepts no arguments")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "--", executable, "__runtime-service", "purge")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return errors.Join(err, errors.New(stderr.String()))
	}
	return nil
}

func purgeSystemInstallation(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("complete uninstall requires administrator approval")
	}
	plan, err := newUnixPurgePlan(runtime.GOOS)
	if err != nil {
		return err
	}
	return applyUnixPurgePlan(ctx, plan,
		func(commandCtx context.Context, executable string, arguments ...string) error {
			return exec.CommandContext(commandCtx, executable, arguments...).Run()
		}, os.RemoveAll)
}

// unixPurgePlan is the complete set of Paperboat-owned native declarations and
// payload roots removed by an explicit privileged purge. Keeping the plan
// separate from command execution makes both supported service managers
// auditable without requiring a live systemd or launchd host in unit tests.
type unixPurgePlan struct {
	platform           string
	systemdUnits       []string
	systemdDefinitions []string
	launchdLabels      []string
	launchdDefinitions []string
	payloadPaths       []string
}

func newUnixPurgePlan(platform string) (unixPurgePlan, error) {
	switch platform {
	case "linux":
		units := []string{
			"paperboat-runtime-host.service",
			"paperboat-runtime-privileged.service",
			"paperboat-hostd.service",
			"paperboat-updated.service",
			"paperboat-helper.service",
			"paperboat-host-service.service",
			"paperboat-console.service",
		}
		return unixPurgePlan{
			platform:           platform,
			systemdUnits:       units,
			systemdDefinitions: appendSystemdDefinitions(units),
			payloadPaths: []string{
				"/usr/local/libexec/paperboat",
				"/var/lib/paperboat-installer",
				"/var/lib/paperboat",
				"/var/lib/paperboat-updated",
				"/var/run/paperboat",
				"/var/run/paperboat-hostd",
				"/var/run/paperboat-updated",
				"/usr/local/bin/pb",
			},
		}, nil
	case "darwin":
		labels := []string{service.Label, service.HostLabel, service.HostdLabel, service.UpdaterLabel}
		definitions := make([]string, 0, len(labels))
		for _, label := range labels {
			definitions = append(definitions, filepath.Join("/Library", "LaunchDaemons", label+".plist"))
		}
		return unixPurgePlan{
			platform:           platform,
			launchdLabels:      labels,
			launchdDefinitions: definitions,
			payloadPaths: []string{
				"/Library/PrivilegedHelperTools/Paperboat",
				"/Library/Application Support/Paperboat",
				"/var/run/paperboat",
				"/var/run/paperboat-hostd",
				"/var/run/paperboat-updated",
				"/usr/local/bin/pb",
			},
		}, nil
	default:
		return unixPurgePlan{}, errors.New("unsupported purge platform")
	}
}

func appendSystemdDefinitions(units []string) []string {
	definitions := make([]string, 0, len(units)+1)
	for _, unit := range units {
		definitions = append(definitions, filepath.Join("/etc", "systemd", "system", unit))
	}
	definitions = append(definitions, "/etc/systemd/system/paperboat-helper.service.d")
	return definitions
}

func applyUnixPurgePlan(ctx context.Context, plan unixPurgePlan, run func(context.Context, string, ...string) error, remove func(string) error) error {
	if ctx == nil || run == nil || remove == nil {
		return errors.New("invalid purge operation")
	}
	if plan.platform == "linux" {
		for _, action := range []string{"stop", "disable"} {
			arguments := append([]string{action}, plan.systemdUnits...)
			_ = run(ctx, "/usr/bin/systemctl", arguments...)
		}
	} else if plan.platform == "darwin" {
		for _, label := range plan.launchdLabels {
			_ = run(ctx, "/bin/launchctl", "bootout", "system/"+label)
		}
	}

	var result error
	definitions := plan.systemdDefinitions
	if plan.platform == "darwin" {
		definitions = plan.launchdDefinitions
	}
	for _, path := range append(definitions, plan.payloadPaths...) {
		result = errors.Join(result, remove(path))
	}
	if plan.platform == "linux" {
		_ = run(ctx, "/usr/bin/systemctl", "daemon-reload")
		arguments := append([]string{"reset-failed"}, plan.systemdUnits...)
		_ = run(ctx, "/usr/bin/systemctl", arguments...)
	}
	return result
}
