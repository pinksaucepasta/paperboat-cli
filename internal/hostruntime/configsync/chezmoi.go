package configsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

var ErrConfigRepositoryInvalid = errors.New("invalid config repository")

type ChezmoiSourceConfig struct {
	Binary      string
	RuntimeRoot string
	SourceRoot  string
	HomeRoot    string
	Runner      ChezmoiRunner
}

type ChezmoiRunner func(context.Context, string, ...string) error

type ChezmoiSource struct {
	binary     string
	configPath string
	sourceRoot string
	homeRoot   string
	runner     ChezmoiRunner
}

func NewChezmoiSource(config ChezmoiSourceConfig) (*ChezmoiSource, error) {
	if strings.TrimSpace(config.Binary) == "" ||
		!canonicalAbsolutePath(config.RuntimeRoot) || !canonicalAbsolutePath(config.SourceRoot) ||
		!canonicalAbsolutePath(config.HomeRoot) {
		return nil, ErrConfigRepositoryInvalid
	}
	if config.Runner == nil {
		config.Runner = runChezmoi
	}
	return &ChezmoiSource{
		binary: config.Binary, configPath: filepath.Join(config.RuntimeRoot, "chezmoi.toml"),
		sourceRoot: config.SourceRoot, homeRoot: config.HomeRoot, runner: config.Runner,
	}, nil
}

func (s *ChezmoiSource) Apply(ctx context.Context) error {
	return s.ApplyPaths(ctx, nil)
}

func (s *ChezmoiSource) ApplyPaths(ctx context.Context, paths []string) error {
	if err := ValidateConfigRepository(s.sourceRoot); err != nil {
		return err
	}
	if err := s.writeConfig(); err != nil {
		return err
	}
	arguments := []string{"--config", s.configPath, "apply", "--force", "--no-tty"}
	if len(paths) > 0 {
		arguments = append(arguments, "--")
		for _, path := range paths {
			if !safeRelativeStatusPath(path) {
				return ErrConfigRepositoryInvalid
			}
			arguments = append(arguments, filepath.Join(s.homeRoot, filepath.FromSlash(path)))
		}
	}
	return s.runner(ctx, s.binary, arguments...)
}

func (s *ChezmoiSource) Add(ctx context.Context, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	if err := s.writeConfig(); err != nil {
		return err
	}
	arguments := []string{"--config", s.configPath, "add", "--"}
	for _, path := range paths {
		if !safeRelativeStatusPath(path) {
			return ErrConfigRepositoryInvalid
		}
		arguments = append(arguments, filepath.Join(s.homeRoot, filepath.FromSlash(path)))
	}
	return s.runner(ctx, s.binary, arguments...)
}

func (s *ChezmoiSource) Forget(ctx context.Context, path string) error {
	if !safeRelativeStatusPath(path) {
		return ErrConfigRepositoryInvalid
	}
	if err := s.writeConfig(); err != nil {
		return err
	}
	return s.runner(ctx, s.binary, "--config", s.configPath, "forget", "--", filepath.Join(s.homeRoot, filepath.FromSlash(path)))
}

func (s *ChezmoiSource) writeConfig() error {
	if err := os.MkdirAll(filepath.Dir(s.configPath), 0o700); err != nil {
		return err
	}
	var body bytes.Buffer
	_, _ = fmt.Fprintf(&body, "sourceDir = %q\ndestDir = %q\n", s.sourceRoot, s.homeRoot)
	return writePrivateAtomic(s.configPath, body.Bytes())
}

func ValidateConfigRepository(root string) error {
	if !canonicalAbsolutePath(root) {
		return ErrConfigRepositoryInvalid
	}
	return filepath.WalkDir(root, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, full)
		if err != nil || relative == "." {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == ".git" || strings.HasPrefix(relative, ".git/") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: repository symlink at %q", ErrConfigRepositoryInvalid, relative)
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".tmpl") {
			return fmt.Errorf("%w: template at %q", ErrConfigRepositoryInvalid, relative)
		}
		if unsafeChezmoiSourceName(name) {
			return fmt.Errorf("%w: unsafe chezmoi attribute at %q", ErrConfigRepositoryInvalid, relative)
		}
		if !entry.IsDir() {
			info, infoErr := entry.Info()
			if infoErr != nil || !info.Mode().IsRegular() {
				return errors.Join(ErrConfigRepositoryInvalid, infoErr)
			}
		}
		return nil
	})
}

func unsafeChezmoiSourceName(name string) bool {
	// chezmoi's literal attribute stops subsequent filename attributes from
	// taking effect. Preserve ordinary target files whose names happen to use a
	// reserved word while still rejecting attributes that occur before literal.
	if strings.HasSuffix(name, ".literal") {
		return false
	}
	if index := strings.Index(name, "literal_"); index >= 0 {
		name = name[:index]
	}
	for _, unsafe := range []string{
		"run_", "run_once_", "run_onchange_", "modify_", "external_", "remove_",
		"create_", "exact_", "encrypted_",
	} {
		if strings.HasPrefix(name, unsafe) || strings.Contains(name, "_"+unsafe) {
			return true
		}
	}
	return false
}

func writePrivateAtomic(path string, data []byte) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrConfigRepositoryInvalid, err)
	}
	return atomicfile.Write(path, data, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func canonicalAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func runChezmoi(ctx context.Context, binary string, arguments ...string) error {
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = append(os.Environ(), "CHEZMOI_NO_PAGER=1")
	if _, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: chezmoi operation failed", ErrConfigRepositoryInvalid)
	}
	return nil
}
