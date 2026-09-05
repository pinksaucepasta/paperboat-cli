package api

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Keep local test servers independent of the developer's system proxy settings.
	if err := os.Setenv("NO_PROXY", "127.0.0.1,localhost,::1"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
