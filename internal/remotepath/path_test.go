package remotepath

import "testing"

func TestAbsoluteRecognizesRemotePathsIndependentOfLocalPlatform(t *testing.T) {
	for _, value := range []string{"/srv/workspace", `C:\Users\paperboat\workspace`, "D:/workspace", `\\server\share\workspace`} {
		if !Absolute(value) {
			t.Errorf("Absolute(%q) = false", value)
		}
	}
	for _, value := range []string{"", "relative/path", `C:relative`, `\rooted`, `\\server`, " bad", "bad\npath", "bad\x00path"} {
		if Absolute(value) {
			t.Errorf("Absolute(%q) = true", value)
		}
	}
}

func TestAbsoluteForTargetUsesRemotePlatform(t *testing.T) {
	tests := []struct {
		name      string
		platform  string
		reference string
		value     string
		want      bool
	}{
		{name: "Windows client to Linux target", platform: "linux", reference: "/root", value: "/root", want: true},
		{name: "Windows client to macOS target", platform: "darwin", reference: "/Users/paperboat", value: "/tmp", want: true},
		{name: "Unix client to Windows target", platform: "windows", reference: `C:\workspace`, value: `C:\workspace\project`, want: true},
		{name: "Windows target rejects Unix", platform: "windows", reference: `C:\workspace`, value: "/root"},
		{name: "Linux target rejects Windows", platform: "linux", reference: "/root", value: `C:\workspace`},
		{name: "missing platform infers Unix", reference: "/root", value: "/root/project", want: true},
		{name: "missing platform infers Windows", reference: `C:\workspace`, value: `D:\project`, want: true},
		{name: "missing platform keeps inferred convention", reference: "/root", value: `C:\workspace`},
		{name: "missing metadata accepts a valid remote path", value: "/workspace", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := AbsoluteForTarget(test.platform, test.reference, test.value); got != test.want {
				t.Fatalf("AbsoluteForTarget(%q, %q, %q) = %v, want %v", test.platform, test.reference, test.value, got, test.want)
			}
		})
	}
}
