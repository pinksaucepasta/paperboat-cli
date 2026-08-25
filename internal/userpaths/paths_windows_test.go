package userpaths

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestWindowsPathsUseProfileEnvironmentWithoutShellAPIs(t *testing.T) {
	t.Setenv("USERPROFILE", `C:\Users\owner`)
	t.Setenv("APPDATA", `C:\Users\owner\AppData\Roaming`)
	t.Setenv("LOCALAPPDATA", `C:\Users\owner\AppData\Local`)
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "XDG_DOWNLOAD_DIR"} {
		t.Setenv(name, "")
	}
	checks := map[string]struct {
		call func() (string, error)
		want string
	}{
		"config":    {func() (string, error) { return Config("paperboat/config.json") }, `C:\Users\owner\AppData\Local\paperboat\config.json`},
		"cache":     {func() (string, error) { return Cache("paperboat/cache.json") }, `C:\Users\owner\AppData\Local\cache\paperboat\cache.json`},
		"data":      {func() (string, error) { return Data("paperboat/data.json") }, `C:\Users\owner\AppData\Local\paperboat\data.json`},
		"state":     {func() (string, error) { return State("paperboat/state.json") }, `C:\Users\owner\AppData\Local\paperboat\state.json`},
		"runtime":   {func() (string, error) { return Runtime("paperboat/runtime.json") }, `C:\Users\owner\AppData\Local\paperboat\runtime.json`},
		"downloads": {Downloads, `C:\Users\owner\Downloads`},
		"home":      {Home, `C:\Users\owner`},
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			got, err := check.call()
			if err != nil || got != filepath.Clean(check.want) {
				t.Fatalf("path = %q, want %q: %v", got, filepath.Clean(check.want), err)
			}
		})
	}
}

func TestWindowsPathsHonorAbsoluteXDGOverrides(t *testing.T) {
	t.Setenv("USERPROFILE", `C:\Users\owner`)
	t.Setenv("LOCALAPPDATA", `C:\Users\owner\AppData\Local`)
	t.Setenv("XDG_CONFIG_HOME", `D:\redirected\config`)
	t.Setenv("XDG_DOWNLOAD_DIR", `D:\redirected\downloads`)
	configPath, configErr := Config("paperboat/config.json")
	downloadsPath, downloadsErr := Downloads()
	if configErr != nil || configPath != `D:\redirected\config\paperboat\config.json` {
		t.Fatalf("config path = %q: %v", configPath, configErr)
	}
	if downloadsErr != nil || downloadsPath != `D:\redirected\downloads` {
		t.Fatalf("downloads path = %q: %v", downloadsPath, downloadsErr)
	}
}

func TestWindowsPathsRejectMissingOrInvalidEnvironment(t *testing.T) {
	t.Setenv("USERPROFILE", "")
	t.Setenv("LOCALAPPDATA", "")
	t.Setenv("XDG_CONFIG_HOME", "relative")
	t.Setenv("XDG_DOWNLOAD_DIR", "relative")
	for name, call := range map[string]func() (string, error){
		"config":    func() (string, error) { return Config("paperboat/config.json") },
		"home":      Home,
		"downloads": Downloads,
	} {
		t.Run(name, func(t *testing.T) {
			if path, err := call(); path != "" || !errors.Is(err, ErrInvalid) {
				t.Fatalf("path = %q, error = %v, want ErrInvalid", path, err)
			}
		})
	}
}
