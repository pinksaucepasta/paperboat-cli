package codexsession

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testCodecNonce = "0123456789abcdef0123456789abcdef"

func TestCodexPathCodecConfigIsWindowsOnlyAndVersionPinned(t *testing.T) {
	config, err := newCodexPathCodecConfig("linux", "0.149.1", "0.149.1", "/root", testCodecNonce)
	if err != nil || config != nil {
		t.Fatalf("non-Windows config = %#v, %v", config, err)
	}
	for _, versions := range [][2]string{{"0.149.0", "0.149.1"}, {"0.149.1", "0.149.0"}, {"0.150.0", "0.150.0"}} {
		if _, err := newCodexPathCodecConfig("windows", versions[0], versions[1], "/root", testCodecNonce); err == nil {
			t.Fatalf("versions %v unexpectedly accepted", versions)
		}
	}
	if _, err := newCodexPathCodecConfig("windows", "0.149.1", "0.149.1", "root", testCodecNonce); err == nil {
		t.Fatal("relative remote root unexpectedly accepted")
	}
	if _, err := newCodexPathCodecConfig("windows", "0.149.1", "0.149.1", "/root", "short"); err == nil {
		t.Fatal("unsafe namespace unexpectedly accepted")
	}
}

func TestCodexPathCodecRoundTripsCollisionFreeWindowsSurrogates(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	segments := []string{"A", "a", "CON", "nul.txt", "trail.", "trail ", "%", `back\slash`, "é"}
	seen := make(map[string]string)
	for _, segment := range segments {
		remote := "/" + segment
		local := config.remoteToLocal(remote)
		collisionKey := strings.ToLower(local)
		if previous, exists := seen[collisionKey]; exists {
			t.Fatalf("%q and %q collide as %q", previous, remote, local)
		}
		seen[collisionKey] = remote
		if strings.HasSuffix(local, ".") || strings.HasSuffix(local, " ") || strings.Contains(local, `\CON`) || strings.Contains(local, `\nul.txt`) {
			t.Fatalf("unsafe Windows surrogate %q", local)
		}
		decoded, ok, err := config.localToRemote(local)
		if err != nil || !ok || decoded != remote {
			t.Fatalf("round trip %q => %q => %q, %v, %v", remote, local, decoded, ok, err)
		}
	}
	for _, remote := range []string{"/", "/root/a b/%/back\\slash/é", "/tmp/.hidden"} {
		local := config.remoteToLocal(remote)
		decoded, ok, err := config.localToRemote(local)
		if err != nil || !ok || decoded != remote {
			t.Fatalf("round trip %q => %q => %q, %v, %v", remote, local, decoded, ok, err)
		}
	}
	for _, invalid := range []string{"raw", "%4", "%GG", "%2F", "%00", "%FF"} {
		if _, err := decodeRemoteSegment(invalid); err == nil {
			t.Fatalf("invalid segment %q accepted", invalid)
		}
	}
	if _, ok, err := config.localToRemote(config.localPrefix + `\raw`); err == nil || !ok {
		t.Fatalf("unencoded namespace child returned ok=%v err=%v", ok, err)
	}
	if _, ok, err := config.localToRemote(`C:\elsewhere`); err != nil || ok {
		t.Fatalf("foreign local path returned ok=%v err=%v", ok, err)
	}
}

func TestCodexPathCodecTransformsLifecycleAndTypedItems(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	codec := config.newCodec()
	wantRoot := config.remoteToLocal("/root")

	start := transformClientJSON(t, codec, `{
		"jsonrpc":"2.0","id":1,"method":"thread/start","params":{
			"cwd":"`+jsonEscape(wantRoot)+`","runtimeWorkspaceRoots":["`+jsonEscape(config.remoteToLocal("/root"))+`","`+jsonEscape(config.remoteToLocal("/work"))+`"],
			"config":{"freeText":"/root/must-stay-raw"}
		}}`)
	assertJSONPointerString(t, start, []string{"params", "cwd"}, "/root")
	assertJSONPointerString(t, start, []string{"params", "runtimeWorkspaceRoots", "0"}, "/root")
	assertJSONPointerString(t, start, []string{"params", "runtimeWorkspaceRoots", "1"}, "/work")
	assertJSONPointerString(t, start, []string{"params", "config", "freeText"}, "/root/must-stay-raw")

	response := transformServerJSON(t, codec, `{
		"jsonrpc":"2.0","id":1,"result":{
			"cwd":"/root","runtimeWorkspaceRoots":["/root"],
			"sandbox":{"type":"workspaceWrite","writableRoots":["/root"]},
			"thread":{"cwd":"/root","path":"/root/.codex/session.jsonl","preview":"text /root raw","turns":[{"items":[
				{"type":"subAgentActivity","agentPath":"/root","id":"a"},
				{"type":"userMessage","content":[
					{"type":"mention","name":"logical","path":"/root"},
					{"type":"localImage","path":"/root/image.png"}
				]},
				{"type":"fileChange","changes":[{"path":"/root/a.txt","kind":{"type":"update","move_path":"/root/b.txt"}}]},
				{"type":"commandExecution","cwd":"/root","commandActions":[{"type":"read","path":"/root/raw.txt"}]}
			]}]
		}}
	}`)
	assertJSONPointerString(t, response, []string{"result", "cwd"}, wantRoot)
	assertJSONPointerString(t, response, []string{"result", "thread", "cwd"}, wantRoot)
	assertJSONPointerString(t, response, []string{"result", "thread", "path"}, config.remoteToLocal("/root/.codex/session.jsonl"))
	assertJSONPointerString(t, response, []string{"result", "thread", "preview"}, "text /root raw")
	assertJSONPointerString(t, response, []string{"result", "thread", "turns", "0", "items", "0", "agentPath"}, "/root")
	assertJSONPointerString(t, response, []string{"result", "thread", "turns", "0", "items", "1", "content", "0", "path"}, "/root")
	assertJSONPointerString(t, response, []string{"result", "thread", "turns", "0", "items", "1", "content", "1", "path"}, config.remoteToLocal("/root/image.png"))
	assertJSONPointerString(t, response, []string{"result", "thread", "turns", "0", "items", "2", "changes", "0", "path"}, config.remoteToLocal("/root/a.txt"))
	assertJSONPointerString(t, response, []string{"result", "thread", "turns", "0", "items", "2", "changes", "0", "kind", "move_path"}, config.remoteToLocal("/root/b.txt"))
	assertJSONPointerString(t, response, []string{"result", "thread", "turns", "0", "items", "3", "cwd"}, "/root")
	assertJSONPointerString(t, response, []string{"result", "thread", "turns", "0", "items", "3", "commandActions", "0", "path"}, "/root/raw.txt")

	turn := transformClientJSON(t, codec, `{
		"jsonrpc":"2.0","id":2,"method":"turn/start","params":{
			"threadId":"t","cwd":"`+jsonEscape(wantRoot)+`","runtimeWorkspaceRoots":["`+jsonEscape(config.remoteToLocal("/work"))+`"],
			"sandboxPolicy":{"type":"workspaceWrite","writableRoots":["`+jsonEscape(config.remoteToLocal("/root/narrow"))+`","`+jsonEscape(config.remoteToLocal("/tmp/extra"))+`"]},
			"input":[{"type":"mention","name":"logical","path":"/root"},{"type":"localImage","path":"`+jsonEscape(config.remoteToLocal("/root/image.png"))+`"}]
		}}`)
	assertJSONPointerString(t, turn, []string{"params", "cwd"}, "/root")
	assertJSONPointerString(t, turn, []string{"params", "runtimeWorkspaceRoots", "0"}, "/work")
	assertJSONPointerString(t, turn, []string{"params", "sandboxPolicy", "writableRoots", "0"}, "/root/narrow")
	assertJSONPointerString(t, turn, []string{"params", "sandboxPolicy", "writableRoots", "1"}, "/tmp/extra")
	assertJSONPointerString(t, turn, []string{"params", "input", "0", "path"}, "/root")
	assertJSONPointerString(t, turn, []string{"params", "input", "1", "path"}, "/root/image.png")
}

func TestCodexPathCodecKeepsRemoteProjectTrustPathsConsistent(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	codec := config.newCodec()
	request := transformClientJSON(t, codec, `{"id":20,"method":"config/read","params":{"includeLayers":true,"cwd":"`+jsonEscape(config.remoteToLocal("/root"))+`"}}`)
	assertJSONPointerString(t, request, []string{"params", "cwd"}, "/root")

	response := transformServerJSON(t, codec, `{
		"id":20,"result":{
			"config":{"projects":{"/root":{"trust_level":"untrusted"},"/work":{"trust_level":"trusted"}}},
			"layers":[{"name":{"type":"project","dotCodexFolder":"/root/.codex"},"version":"1","config":{},"disabledReason":"/root is marked as untrusted in the effective configuration."}],
			"origins":{}
		}}`)
	localRoot := config.remoteToLocal("/root")
	localWork := config.remoteToLocal("/work")
	projects := jsonAt(t, response, []string{"result", "config", "projects"}).(map[string]any)
	if _, ok := projects[localRoot]; !ok {
		t.Fatalf("translated projects has no %q: %#v", localRoot, projects)
	}
	if _, ok := projects[localWork]; !ok {
		t.Fatalf("translated projects has no %q: %#v", localWork, projects)
	}
	assertJSONPointerString(t, response, []string{"result", "layers", "0", "name", "dotCodexFolder"}, config.remoteToLocal("/root/.codex"))
	assertJSONPointerString(t, response, []string{"result", "layers", "0", "disabledReason"}, localRoot+" is marked as untrusted in the effective configuration.")

	localKeyPathBody, _ := json.Marshal(localRoot)
	localKeyPath := "projects." + string(localKeyPathBody) + ".trust_level"
	write := transformClientJSON(t, codec, `{"id":21,"method":"config/batchWrite","params":{"edits":[
		{"keyPath":"model","value":"gpt-5.6-terra","mergeStrategy":"replace"},
		{"keyPath":"`+jsonEscape(localKeyPath)+`","value":"trusted","mergeStrategy":"replace"}
	]}}`)
	assertJSONPointerString(t, write, []string{"params", "edits", "0", "keyPath"}, "model")
	assertJSONPointerString(t, write, []string{"params", "edits", "1", "keyPath"}, `projects."/root".trust_level`)

	for _, keyPath := range []string{"projects", `projects.root.trust_level`, `projects."C:\\outside".trust_level`} {
		fresh := config.newCodec()
		if _, err := fresh.clientToServer([]byte(`{"id":1,"method":"config/value/write","params":{"keyPath":"` + jsonEscape(keyPath) + `","value":"trusted","mergeStrategy":"replace"}}`)); err == nil {
			t.Fatalf("unsafe project key path %q accepted", keyPath)
		}
	}
}

func TestCodexProjectDisabledReasonHandlesDelimiterBearingPaths(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	tests := []struct {
		name        string
		projectPath string
		reason      func(string) string
	}{
		{
			name:        "untrusted delimiter in project path",
			projectPath: "/tmp/project is marked as untrusted sibling",
			reason: func(projectPath string) string {
				return projectPath + " is marked as untrusted in the effective configuration."
			},
		},
		{
			name:        "undecided delimiter in project path",
			projectPath: "/tmp/project as a trusted project in sibling",
			reason: func(projectPath string) string {
				return "To load project-local config, hooks, and exec policies, add " + projectPath + " as a trusted project in /root/.codex/config.toml."
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := test.reason(test.projectPath)
			want := test.reason(config.remoteToLocal(test.projectPath))
			got, err := transformCodexProjectDisabledReason(raw, func(path string) (string, error) {
				return config.remoteToLocal(path), nil
			})
			if err != nil || got != want {
				t.Fatalf("transform = %q, %v; want %q", got, err, want)
			}
		})
	}

	const unrelated = "To load text is marked as untrusted, without a project path"
	got, err := transformCodexProjectDisabledReason(unrelated, func(string) (string, error) {
		return "", errors.New("unexpected path transform")
	})
	if err != nil || got != unrelated {
		t.Fatalf("unrelated reason = %q, %v", got, err)
	}
}

func TestCodexLaunchArgsNeverContainBridgeBearer(t *testing.T) {
	const bridgeToken = "secret-bridge-bearer-that-must-stay-out-of-argv"
	config, err := newCodexPathCodecConfig("windows", "0.149.1", "0.149.1", "/root", testCodecNonce)
	if err != nil {
		t.Fatal(err)
	}
	args := codexLaunchArgs("127.0.0.1:1234", config.remoteToLocal("/root"), []string{"--version"})
	if joined := strings.Join(args, "\x00"); strings.Contains(joined, bridgeToken) {
		t.Fatalf("bridge bearer leaked into launch argv: %q", args)
	}
	if joined := strings.Join(args, "\x00"); strings.Contains(joined, "PAPERBOAT_CODEX_BRIDGE_TOKEN="+bridgeToken) {
		t.Fatalf("bridge bearer environment assignment leaked into launch argv: %q", args)
	}
	if !strings.Contains(config.localPrefix, testCodecNonce) {
		t.Fatalf("launch path does not contain the independent namespace: %q", config.localPrefix)
	}
}

func TestCodexPathCodecSupportsExperimentalPaginationAndUnionShapes(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	codec := config.newCodec()
	transformClientJSON(t, codec, `{"jsonrpc":"2.0","id":10,"method":"thread/items/list","params":{"threadId":"t"}}`)
	items := transformServerJSON(t, codec, `{"jsonrpc":"2.0","id":10,"result":{"data":[{"item":{"type":"fileChange","changes":[{"path":"/root/a","kind":{"type":"add"}}]}}]}}`)
	assertJSONPointerString(t, items, []string{"result", "data", "0", "item", "changes", "0", "path"}, config.remoteToLocal("/root/a"))

	for index, cwd := range []string{`"` + jsonEscape(config.remoteToLocal("/root")) + `"`,
		`["` + jsonEscape(config.remoteToLocal("/root")) + `","` + jsonEscape(config.remoteToLocal("/work")) + `"]`} {
		fresh := config.newCodec()
		frame := transformClientJSON(t, fresh, `{"jsonrpc":"2.0","id":`+string(rune('1'+index))+`,"method":"thread/list","params":{"cwd":`+cwd+`}}`)
		value := jsonAt(t, frame, []string{"params", "cwd"})
		switch got := value.(type) {
		case string:
			if got != "/root" {
				t.Fatalf("scalar cwd = %q", got)
			}
		case []any:
			if len(got) != 2 || got[0] != "/root" || got[1] != "/work" {
				t.Fatalf("array cwd = %#v", got)
			}
		default:
			t.Fatalf("cwd has type %T", value)
		}
	}
}

func TestCodexPathCodecTransformsServerRequestsAndCorrelatesResponses(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	codec := config.newCodec()
	request := transformServerJSON(t, codec, `{
		"jsonrpc":"2.0","id":"approval-1","method":"item/permissions/requestApproval","params":{
			"cwd":"/root","permissions":{"fileSystem":{"entries":[
				{"path":{"type":"special","value":{"kind":"unknown","path":"/root/a"}}},
				{"path":{"type":"path","path":"/root/foreign-aware"}}
			]}}
		}}`)
	assertJSONPointerString(t, request, []string{"params", "cwd"}, config.remoteToLocal("/root"))
	assertJSONPointerString(t, request, []string{"params", "permissions", "fileSystem", "entries", "0", "path", "value", "path"}, config.remoteToLocal("/root/a"))
	assertJSONPointerString(t, request, []string{"params", "permissions", "fileSystem", "entries", "1", "path", "path"}, "/root/foreign-aware")
	transformClientJSON(t, codec, `{"jsonrpc":"2.0","id":"approval-1","result":{"permissions":{},"scope":"turn"}}`)
	if _, err := codec.clientToServer([]byte(`{"jsonrpc":"2.0","id":"approval-1","result":{}}`)); err == nil {
		t.Fatal("duplicate/unmatched server response unexpectedly accepted")
	}
}

func TestCodexPathCodecHonorsAbsolutePathVariantScopes(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	initializeCodec := config.newCodec()
	transformClientJSON(t, initializeCodec, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	initialize := transformServerJSON(t, initializeCodec, `{"jsonrpc":"2.0","id":1,"result":{"codexHome":"/root/.codex"}}`)
	assertJSONPointerString(t, initialize, []string{"result", "codexHome"}, "/root/.codex")

	codec := config.newCodec()
	transformClientJSON(t, codec, `{"jsonrpc":"2.0","id":1,"method":"plugin/list","params":{"cwds":["`+jsonEscape(config.remoteToLocal("/root"))+`"]}}`)
	response := transformServerJSON(t, codec, `{"jsonrpc":"2.0","id":1,"result":{"marketplaces":[{"plugins":[
		{"source":{"type":"local","path":"/root/local-plugin"}},
		{"source":{"type":"git","path":"relative/subdir"}}
	]}]}}`)
	assertJSONPointerString(t, response, []string{"result", "marketplaces", "0", "plugins", "0", "source", "path"}, config.remoteToLocal("/root/local-plugin"))
	assertJSONPointerString(t, response, []string{"result", "marketplaces", "0", "plugins", "1", "source", "path"}, "relative/subdir")

	for _, actionType := range []string{"command", "execve", "applyPatch"} {
		notification := transformServerJSON(t, codec, `{"jsonrpc":"2.0","method":"item/autoApprovalReview/started","params":{"action":{"type":"`+actionType+`","cwd":"/root"}}}`)
		assertJSONPointerString(t, notification, []string{"params", "action", "cwd"}, config.remoteToLocal("/root"))
	}
}

func TestCodexPathCodecValidatesEnvelopeBeforePendingState(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	invalid := []string{
		`{"id":1,"method":"initialize","params":{},"result":{}}`,
		`{"method":"initialized","error":{"code":1}}`,
		`{"id":1}`,
		`{"id":1,"result":{},"error":{"code":1}}`,
		`{"id":1,"result":{},"params":{}}`,
		`{"id":1,"method":7,"params":{}}`,
	}
	for _, frame := range invalid {
		if _, err := config.newCodec().clientToServer([]byte(frame)); err == nil {
			t.Fatalf("invalid envelope accepted: %s", frame)
		}
	}

	codec := config.newCodec()
	if _, err := codec.clientToServer([]byte(`{"id":1,"method":"turn/start","params":{"input":[{"type":"localImage","path":"C:\\outside.png"}]}}`)); err == nil {
		t.Fatal("out-of-namespace path unexpectedly accepted")
	}
	if _, err := codec.clientToServer([]byte(`{"id":1,"method":"initialize","params":{}}`)); err != nil {
		t.Fatalf("failed path transform poisoned pending id: %v", err)
	}

	responseCodec := config.newCodec()
	if _, err := responseCodec.clientToServer([]byte(`{"id":2,"method":"thread/start","params":{}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := responseCodec.serverToClient([]byte(`{"id":2,"result":{"cwd":"C:\\foreign"}}`)); err == nil {
		t.Fatal("foreign strict response path unexpectedly accepted")
	}
	if _, err := responseCodec.serverToClient([]byte(`{"id":2,"result":{"cwd":"/root"}}`)); err != nil {
		t.Fatalf("failed response transform deleted pending id: %v", err)
	}
}

func TestCodexPathCodecFailsClosed(t *testing.T) {
	config := mustTestCodexPathCodecConfig(t)
	tests := []struct {
		name  string
		apply func(*codexPathCodec) error
	}{
		{"unknown client method", func(codec *codexPathCodec) error {
			_, err := codec.clientToServer([]byte(`{"id":1,"method":"future/method","params":{}}`))
			return err
		}},
		{"unknown server notification", func(codec *codexPathCodec) error {
			_, err := codec.serverToClient([]byte(`{"method":"future/event","params":{}}`))
			return err
		}},
		{"unmatched response", func(codec *codexPathCodec) error {
			_, err := codec.serverToClient([]byte(`{"id":1,"result":{}}`))
			return err
		}},
		{"malformed json", func(codec *codexPathCodec) error { _, err := codec.clientToServer([]byte(`{"id":`)); return err }},
		{"multiple json values", func(codec *codexPathCodec) error { _, err := codec.clientToServer([]byte(`{} {}`)); return err }},
		{"union wrong shape", func(codec *codexPathCodec) error {
			_, err := codec.clientToServer([]byte(`{"id":1,"method":"thread/list","params":{"cwd":{"bad":true}}}`))
			return err
		}},
		{"unexpected path variant", func(codec *codexPathCodec) error {
			_, err := codec.clientToServer([]byte(`{"id":1,"method":"turn/start","params":{"input":[{"type":"future","path":"C:\\x"}]}}`))
			return err
		}},
		{"foreign writable root", func(codec *codexPathCodec) error {
			_, err := codec.clientToServer([]byte(`{"id":1,"method":"turn/start","params":{"sandboxPolicy":{"type":"workspaceWrite","writableRoots":["D:\\outside"]}}}`))
			return err
		}},
		{"foreign strict response path", func(codec *codexPathCodec) error {
			if _, err := codec.clientToServer([]byte(`{"id":1,"method":"thread/start","params":{}}`)); err != nil {
				return err
			}
			_, err := codec.serverToClient([]byte(`{"id":1,"result":{"cwd":"C:\\remote"}}`))
			return err
		}},
		{"duplicate pending id", func(codec *codexPathCodec) error {
			if _, err := codec.clientToServer([]byte(`{"id":1,"method":"initialize","params":{}}`)); err != nil {
				return err
			}
			_, err := codec.clientToServer([]byte(`{"id":1,"method":"initialize","params":{}}`))
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.apply(config.newCodec()); err == nil {
				t.Fatal("frame unexpectedly accepted")
			}
		})
	}
}

func TestCodexPathManifestHasPinnedCompleteCoverage(t *testing.T) {
	manifest, err := loadCodexPathManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.ClientRequests) != 153 || len(manifest.ClientResponses) != 153 || len(manifest.ServerNotifications) != 77 {
		t.Fatalf("method counts client=%d responses=%d notifications=%d", len(manifest.ClientRequests), len(manifest.ClientResponses), len(manifest.ServerNotifications))
	}
	for _, method := range []string{"thread/start", "thread/resume", "thread/fork", "turn/start", "thread/turns/list", "thread/items/list", "process/spawn", "plugin/search", "getConversationSummary"} {
		if _, exists := manifest.ClientRequests[method]; !exists {
			t.Fatalf("missing client method %s", method)
		}
		if _, exists := manifest.ClientResponses[method]; !exists {
			t.Fatalf("missing client response %s", method)
		}
	}
	for _, method := range []string{"rawResponseItem/completed", "rawResponse/completed", "thread/started", "thread/settings/updated", "item/started", "item/completed"} {
		if _, exists := manifest.ServerNotifications[method]; !exists {
			t.Fatalf("missing server notification %s", method)
		}
	}
	assertManifestPattern(t, manifest.ClientRequests["thread/list"], "/params/cwd", "path-or-array", nil, nil)
	assertManifestPattern(t, manifest.ClientRequests["config/batchWrite"], "/params/edits/*/keyPath", "project-key-path", nil, nil)
	assertManifestPattern(t, manifest.ClientRequests["config/value/write"], "/params/keyPath", "project-key-path", nil, nil)
	assertManifestPattern(t, manifest.ClientResponses["config/read"], "/result/config/projects", "path-map-keys", nil, nil)
	assertManifestPattern(t, manifest.ClientResponses["config/read"], "/result/layers/*/disabledReason", "project-disabled-reason", nil, nil)
	assertManifestPattern(t, manifest.ClientResponses["thread/start"], "/result/thread/cwd", "absolute", nil, nil)
	assertManifestPattern(t, manifest.ClientResponses["thread/start"], "/result/sandbox/writableRoots/*", "absolute", []string{"workspaceWrite"}, nil)
	assertManifestPattern(t, manifest.ClientResponses["thread/items/list"], "/result/data/*/item/changes/*/kind/move_path", "path", []string{"update"}, nil)
	assertManifestPattern(t, manifest.ClientRequests["turn/start"], "/params/input/*/path", "path", []string{"localAudio", "localImage", "skill"}, []string{"mention"})
	assertManifestPattern(t, manifest.ClientResponses["plugin/list"], "/result/marketplaces/*/plugins/*/source/path", "absolute", []string{"local"}, []string{"git"})
	assertManifestPattern(t, manifest.ServerNotifications["item/autoApprovalReview/started"], "/params/action/cwd", "absolute", []string{"applyPatch", "command", "execve"}, nil)
	if !slicesEqual(manifest.PreservedClientResponsePaths["initialize"], []string{"/result/codexHome"}) {
		t.Fatalf("preserved initialize paths = %v", manifest.PreservedClientResponsePaths["initialize"])
	}
	for _, methods := range []map[string][]codexPathPattern{manifest.ClientRequests, manifest.ClientResponses, manifest.ServerRequests, manifest.ServerNotifications} {
		for method, patterns := range methods {
			for _, pattern := range patterns {
				if strings.Contains(pattern.Pointer, "agentPath") || strings.Contains(pattern.Pointer, "commandActions") ||
					(strings.Contains(pattern.Pointer, "keyPath") && pattern.Kind != "project-key-path") {
					t.Fatalf("logical/foreign field mapped for %s: %s", method, pattern.Pointer)
				}
			}
		}
	}
}

func mustTestCodexPathCodecConfig(t *testing.T) *codexPathCodecConfig {
	t.Helper()
	config, err := newCodexPathCodecConfig("windows", "0.149.1", "0.149.1", "/root", testCodecNonce)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func transformClientJSON(t *testing.T, codec *codexPathCodec, input string) map[string]any {
	t.Helper()
	body, err := codec.clientToServer([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return decodeTestJSON(t, body)
}

func transformServerJSON(t *testing.T, codec *codexPathCodec, input string) map[string]any {
	t.Helper()
	body, err := codec.serverToClient([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return decodeTestJSON(t, body)
}

func decodeTestJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertJSONPointerString(t *testing.T, value any, path []string, want string) {
	t.Helper()
	got := jsonAt(t, value, path)
	if got != want {
		t.Fatalf("%s = %#v, want %q", strings.Join(path, "/"), got, want)
	}
}

func jsonAt(t *testing.T, value any, path []string) any {
	t.Helper()
	current := value
	for _, part := range path {
		switch node := current.(type) {
		case map[string]any:
			current = node[part]
		case []any:
			var index int
			if _, err := fmtSscanfIndex(part, &index); err != nil || index < 0 || index >= len(node) {
				t.Fatalf("invalid array path %q", part)
			}
			current = node[index]
		default:
			t.Fatalf("path %q reached %T", part, current)
		}
	}
	return current
}

func fmtSscanfIndex(value string, target *int) (int, error) {
	decoder := json.NewDecoder(strings.NewReader(value))
	return 1, decoder.Decode(target)
}

func jsonEscape(value string) string {
	body, _ := json.Marshal(value)
	return string(body[1 : len(body)-1])
}

func assertManifestPattern(t *testing.T, patterns []codexPathPattern, pointer, kind string, variants, ignored []string) {
	t.Helper()
	for _, pattern := range patterns {
		if pattern.Pointer == pointer && pattern.Kind == kind && slicesEqual(pattern.Variants, variants) && slicesEqual(pattern.IgnoredVariants, ignored) {
			return
		}
	}
	t.Fatalf("missing manifest pattern %s %s variants=%v ignored=%v in %#v", pointer, kind, variants, ignored, patterns)
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
