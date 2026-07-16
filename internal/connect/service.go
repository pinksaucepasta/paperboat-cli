package connect

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrServiceUnsupported = errors.New("connector service installation is unsupported on this platform")

type ServiceSpec struct {
	Label, Executable, WorkingDirectory, LogDirectory string
	Arguments                                         []string
}

func (s ServiceSpec) Validate() error {
	if strings.TrimSpace(s.Label) == "" || !filepath.IsAbs(s.Executable) || !filepath.IsAbs(s.WorkingDirectory) || !filepath.IsAbs(s.LogDirectory) || len(s.Arguments) == 0 {
		return errors.New("connector service specification is incomplete")
	}
	for _, value := range append([]string{s.Executable}, s.Arguments...) {
		if strings.ContainsRune(value, '\x00') {
			return errors.New("connector service specification contains a NUL byte")
		}
	}
	return nil
}

func RenderUserService(spec ServiceSpec, platform string) ([]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	switch platform {
	case "darwin":
		return renderLaunchAgent(spec)
	case "linux":
		return renderSystemdUserUnit(spec), nil
	default:
		return nil, ErrServiceUnsupported
	}
}

func InstallUserService(spec ServiceSpec, home, platform string) (string, error) {
	if !filepath.IsAbs(home) {
		return "", errors.New("home directory must be absolute")
	}
	contents, err := RenderUserService(spec, platform)
	if err != nil {
		return "", err
	}
	var path string
	switch platform {
	case "darwin":
		path = filepath.Join(home, "Library", "LaunchAgents", spec.Label+".plist")
	case "linux":
		path = filepath.Join(home, ".config", "systemd", "user", spec.Label+".service")
	default:
		return "", ErrServiceUnsupported
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := atomicWrite(path, contents, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

type CommandRunner interface {
	Run(name string, arguments ...string) error
}
type execCommandRunner struct{}

func (execCommandRunner) Run(name string, arguments ...string) error {
	return exec.Command(name, arguments...).Run()
}

// ActivateUserService loads the rendered unit into the user's native service
// manager. It deliberately does not require root access or write outside HOME.
func ActivateUserService(path, platform string, runner CommandRunner) error {
	if runner == nil {
		runner = execCommandRunner{}
	}
	if !filepath.IsAbs(path) {
		return errors.New("service path must be absolute")
	}
	switch platform {
	case "darwin":
		return runner.Run("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), path)
	case "linux":
		if err := runner.Run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		return runner.Run("systemctl", "--user", "enable", "--now", filepath.Base(path))
	default:
		return ErrServiceUnsupported
	}
}

func renderLaunchAgent(spec ServiceSpec) ([]byte, error) {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n")
	launchdKeyString(&b, "Label", spec.Label)
	b.WriteString("<key>ProgramArguments</key><array>")
	for _, arg := range append([]string{spec.Executable}, spec.Arguments...) {
		b.WriteString("<string>")
		b.WriteString(xmlEscape(arg))
		b.WriteString("</string>")
	}
	b.WriteString("</array>\n")
	launchdKeyString(&b, "WorkingDirectory", spec.WorkingDirectory)
	b.WriteString("<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n")
	launchdKeyString(&b, "StandardOutPath", filepath.Join(spec.LogDirectory, "connector.log"))
	launchdKeyString(&b, "StandardErrorPath", filepath.Join(spec.LogDirectory, "connector.err.log"))
	b.WriteString("</dict></plist>\n")
	return []byte(b.String()), nil
}

func launchdKeyString(b *strings.Builder, key, value string) {
	b.WriteString("<key>")
	b.WriteString(xmlEscape(key))
	b.WriteString("</key><string>")
	b.WriteString(xmlEscape(value))
	b.WriteString("</string>\n")
}
func xmlEscape(value string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

func renderSystemdUserUnit(spec ServiceSpec) []byte {
	args := make([]string, 0, len(spec.Arguments)+1)
	for _, arg := range append([]string{spec.Executable}, spec.Arguments...) {
		args = append(args, systemdEscape(arg))
	}
	return []byte(fmt.Sprintf("[Unit]\nDescription=Paperboat connected-machine supervisor\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nWorkingDirectory=%s\nExecStart=%s\nRestart=always\nRestartSec=5\nStandardOutput=append:%s\nStandardError=append:%s\n\n[Install]\nWantedBy=default.target\n", systemdEscape(spec.WorkingDirectory), strings.Join(args, " "), systemdEscape(filepath.Join(spec.LogDirectory, "connector.log")), systemdEscape(filepath.Join(spec.LogDirectory, "connector.err.log"))))
}

func systemdEscape(value string) string {
	return "\"" + strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "\"", "\\\"") + "\""
}
