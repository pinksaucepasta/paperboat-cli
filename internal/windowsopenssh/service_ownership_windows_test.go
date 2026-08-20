//go:build windows

package windowsopenssh

import "testing"

func TestOwnedServiceCommandRequiresExactPaperboatExecutable(t *testing.T) {
	config := DefaultConfig(nil)
	expected := `C:\Program Files\Paperboat\bin\pb.exe`
	command := `"` + expected + `" __windows-sshd-service --sshd "C:\Program Files\OpenSSH\sshd.exe" --config C:\ProgramData\Paperboat\ssh\sshd_config`
	if !sameOwnedServiceCommand(command, expected, config) {
		t.Fatal("exact Paperboat service command was rejected")
	}
	foreign := `"C:\Program Files\Foreign\service.exe" __windows-sshd-service --sshd "C:\Program Files\OpenSSH\sshd.exe" --config C:\ProgramData\Paperboat\ssh\sshd_config`
	if sameOwnedServiceCommand(foreign, expected, config) {
		t.Fatal("foreign service executable was accepted as Paperboat-owned")
	}
}
