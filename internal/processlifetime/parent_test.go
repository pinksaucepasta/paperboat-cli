//go:build linux || darwin

package processlifetime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	parentDeathRoleEnv = "PAPERBOAT_TEST_PARENT_DEATH_ROLE"
	parentDeathPIDEnv  = "PAPERBOAT_TEST_PARENT_DEATH_PID_FILE"
)

func TestArmParentDeathTerminatesChild(t *testing.T) {
	pidFile := os.Getenv(parentDeathPIDEnv)
	switch os.Getenv(parentDeathRoleEnv) {
	case "child":
		if err := ArmParentDeath(); err != nil {
			panic(err)
		}
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			panic(err)
		}
		select {}
	case "parent":
		command := exec.Command(os.Args[0], "-test.run=^TestArmParentDeathTerminatesChild$")
		command.Env = append(os.Environ(), parentDeathRoleEnv+"=child")
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Start(); err != nil {
			panic(err)
		}
		waitForPIDFile(pidFile)
		return
	}

	pidFile = t.TempDir() + "/child.pid"
	command := exec.Command(os.Args[0], "-test.run=^TestArmParentDeathTerminatesChild$")
	command.Env = append(os.Environ(), parentDeathRoleEnv+"=parent", parentDeathPIDEnv+"="+pidFile)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("parent helper: %v\n%s", err, output)
	}
	value, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(value)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })

	deadline := time.Now().Add(5 * time.Second)
	for {
		err = unix.Kill(pid, 0)
		if errors.Is(err, unix.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("child %d survived parent exit: %v", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForPIDFile(path string) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			panic(fmt.Sprintf("child did not arm parent death for %s", path))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
