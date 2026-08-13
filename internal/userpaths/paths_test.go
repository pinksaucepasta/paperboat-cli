package userpaths

import "testing"

func TestCanonicalXDGPathsAreAbsolute(t *testing.T) {
	checks := []func() (string, error){
		func() (string, error) { return Config("paperboat/config.json") },
		func() (string, error) { return Cache("paperboat/file-index.json") },
		func() (string, error) { return Data("paperboat") },
		func() (string, error) { return State("paperboat") },
		Downloads,
		Home,
	}
	for _, check := range checks {
		if path, err := check(); err != nil || path == "" {
			t.Fatalf("path=%q error=%v", path, err)
		}
	}
	if _, err := Config("../escape"); err == nil {
		t.Fatal("escaping path accepted")
	}
}
