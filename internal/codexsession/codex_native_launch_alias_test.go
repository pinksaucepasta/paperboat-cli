package codexsession

import (
	"encoding/json"
	"strconv"
	"testing"
)

const (
	pluginListGoldenRequestID  = "plugin-list-00000000-0000-0000-0000-000000000000"
	commandExecGoldenRequestID = "workspace-command-00000000-0000-0000-0000-000000000000"
)

func TestCodexPathCodecNativeLaunchCWDGoldenRequestsAndGenericResponses(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	codec := config.newCodec()

	pluginInput := `{"id":"` + pluginListGoldenRequestID + `","method":"plugin/list","params":{"cwds":["C:\\Users\\Pujan"],"marketplaceKinds":null}}`
	pluginWant := `{"id":"` + pluginListGoldenRequestID + `","method":"plugin/list","params":{"cwds":["/root"],"marketplaceKinds":null}}`
	assertCodexRequestBytes(t, codec, pluginInput, pluginWant)
	pluginResponse := transformServerJSON(t, codec, `{"id":"`+pluginListGoldenRequestID+`","result":{"marketplaces":[{"name":"repo","path":"/root/.codex/plugins","plugins":[]}],"marketplaceLoadErrors":[],"featuredPluginIds":[],"opaque":{"path":"/root/free-form"}}}`)
	assertJSONPointerString(t, pluginResponse, []string{"result", "marketplaces", "0", "path"}, config.remoteToLocal("/root/.codex/plugins"))
	assertJSONPointerString(t, pluginResponse, []string{"result", "opaque", "path"}, "/root/free-form")

	resumeInput := `{"id":31,"method":"thread/resume","params":{"threadId":"thread-1","cwd":null,"runtimeWorkspaceRoots":["C:\\Users\\Pujan"]}}`
	resumeWant := `{"id":31,"method":"thread/resume","params":{"cwd":null,"runtimeWorkspaceRoots":["/root"],"threadId":"thread-1"}}`
	assertCodexRequestBytes(t, codec, resumeInput, resumeWant)
	resumeResponse := transformServerJSON(t, codec, `{"id":31,"result":{"cwd":"/root","runtimeWorkspaceRoots":["/root"],"thread":{"cwd":"/root","path":null}}}`)
	assertGenericThreadResponseRoots(t, config, resumeResponse)

	forkInput := `{"id":32,"method":"thread/fork","params":{"threadId":"thread-1","cwd":null,"runtimeWorkspaceRoots":["c:/users/PUJAN/."]}}`
	forkWant := `{"id":32,"method":"thread/fork","params":{"cwd":null,"runtimeWorkspaceRoots":["/root"],"threadId":"thread-1"}}`
	assertCodexRequestBytes(t, codec, forkInput, forkWant)
	forkResponse := transformServerJSON(t, codec, `{"id":32,"result":{"cwd":"/root","runtimeWorkspaceRoots":["/root"],"thread":{"cwd":"/root","path":null}}}`)
	assertGenericThreadResponseRoots(t, config, forkResponse)

	commandInput := `{"id":"` + commandExecGoldenRequestID + `","method":"command/exec","params":{"command":["git","status","--short"],"processId":null,"outputBytesCap":1048576,"timeoutMs":2000,"cwd":"C:\\Users\\Pujan","env":{"GIT_OPTIONAL_LOCKS":"0"},"size":null,"sandboxPolicy":null,"permissionProfile":null}}`
	commandWant := `{"id":"` + commandExecGoldenRequestID + `","method":"command/exec","params":{"command":["git","status","--short"],"cwd":"/root","env":{"GIT_OPTIONAL_LOCKS":"0"},"outputBytesCap":1048576,"permissionProfile":null,"processId":null,"sandboxPolicy":null,"size":null,"timeoutMs":2000}}`
	assertCodexRequestBytes(t, codec, commandInput, commandWant)
	commandResponse := transformServerJSON(t, codec, `{"id":"`+commandExecGoldenRequestID+`","result":{"exitCode":0,"stdout":"","stderr":"","opaque":{"cwd":"/root","path":"C:\\Users\\Pujan"}}}`)
	assertJSONPointerString(t, commandResponse, []string{"result", "opaque", "cwd"}, "/root")
	assertJSONPointerString(t, commandResponse, []string{"result", "opaque", "path"}, `C:\Users\Pujan`)

	if len(codec.clientPending) != 0 {
		t.Fatalf("golden request responses leaked pending state: %v", codec.clientPending)
	}
}

func TestCodexPathCodecNativeLaunchCWDAliasIsExactAndFailClosed(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	for _, method := range []string{"plugin/list", "thread/resume", "thread/fork", "command/exec"} {
		t.Run(method+" normalized drive alias", func(t *testing.T) {
			codec := config.newCodec()
			request := transformClientJSON(t, codec, nativeLaunchAliasFrame(method, "normalized", []string{`c:/users/PUJAN/.`}, nil))
			assertJSONPointerString(t, request, nativeLaunchAliasPointer(method, 0), "/root")
			transformServerJSON(t, codec, nativeLaunchAliasResponse(method, "normalized"))
			if len(codec.clientPending) != 0 {
				t.Fatalf("%s response leaked pending state: %v", method, codec.clientPending)
			}
		})

		for _, test := range []struct {
			name string
			path string
		}{
			{name: "sibling", path: `C:\Users\Pujan2`},
			{name: "ancestor", path: `C:\Users`},
			{name: "other_drive", path: `D:\Users\Pujan`},
			{name: "UNC", path: `\\server\share\project`},
			{name: "device", path: `\\.\C:\Users\Pujan`},
			{name: "extended", path: `\\?\C:\Users\Pujan`},
			{name: "relative", path: `relative`},
		} {
			t.Run(method+" "+test.name, func(t *testing.T) {
				codec := config.newCodec()
				frame := nativeLaunchAliasFrame(method, "reject", []string{test.path}, nil)
				assertCodexPathFieldRejected(t, codec, frame)
			})
		}
	}
}

func TestCodexPathCodecNativeLaunchCWDListsRejectExtraAndOversizedRoots(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	for _, method := range []string{"plugin/list", "thread/resume", "thread/fork"} {
		t.Run(method+" foreign extra", func(t *testing.T) {
			codec := config.newCodec()
			frame := nativeLaunchAliasFrame(method, "mixed", []string{`C:\Users\Pujan`, `D:\cache`}, nil)
			assertCodexPathFieldRejected(t, codec, frame)
		})
		t.Run(method+" oversized", func(t *testing.T) {
			codec := config.newCodec()
			field := "runtimeWorkspaceRoots"
			if method == "plugin/list" {
				field = "cwds"
			}
			values := make([]any, maxNativeLaunchCWDEntries+1)
			if _, err := codec.transformNativeLaunchCWDList(map[string]any{"params": map[string]any{field: values}}, method, field); err == nil {
				t.Fatalf("oversized %s request unexpectedly accepted", method)
			}
		})
	}

	for _, root := range []string{`C:\Users\Pujan`, `D:\cache`} {
		codec := config.newCodec()
		frame := nativeLaunchAliasFrame("command/exec", "sandbox", []string{`C:\Users\Pujan`}, map[string]any{
			"sandboxPolicy": map[string]any{"type": "workspaceWrite", "writableRoots": []any{root}},
		})
		assertCodexPathFieldRejected(t, codec, frame)
	}
}

func TestCodexPathCodecNativeLaunchCWDAliasRejectsNonDriveLaunchNamespaces(t *testing.T) {
	for _, launchCWD := range []string{
		`\\server\share\project`,
		`\\.\C:\Users\Pujan`,
		`\\?\C:\Users\Pujan`,
		`\\?\UNC\server\share\project`,
	} {
		config := mustTestCodexPathCodecConfigWithLaunchCWD(t, launchCWD)
		for _, method := range []string{"plugin/list", "thread/resume", "thread/fork", "command/exec"} {
			codec := config.newCodec()
			frame := nativeLaunchAliasFrame(method, "non-drive", []string{launchCWD}, nil)
			assertCodexPathFieldRejected(t, codec, frame)
		}
	}
}

func TestCodexPathCodecNativeLaunchCWDAliasMalformedRetryAndErrorCleanup(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	for _, method := range []string{"plugin/list", "thread/resume", "thread/fork", "command/exec"} {
		t.Run(method, func(t *testing.T) {
			codec := config.newCodec()
			malformed := nativeLaunchAliasMalformedFrame(method, "retry")
			assertCodexPathFieldRejected(t, codec, malformed)

			valid := nativeLaunchAliasFrame(method, "retry", []string{`C:\Users\Pujan`}, map[string]any{"opaque": map[string]any{"path": `C:\Users\Pujan`}})
			request := transformClientJSON(t, codec, valid)
			assertJSONPointerString(t, request, nativeLaunchAliasPointer(method, 0), "/root")
			assertJSONPointerString(t, request, []string{"params", "opaque", "path"}, `C:\Users\Pujan`)
			if _, err := codec.serverToClient([]byte(`{"id":"retry","error":{"code":-32603,"message":"opaque"}}`)); err != nil {
				t.Fatal(err)
			}
			if len(codec.clientPending) != 0 {
				t.Fatalf("%s error response leaked pending state: %v", method, codec.clientPending)
			}

			transformClientJSON(t, codec, valid)
			transformServerJSON(t, codec, nativeLaunchAliasResponse(method, "retry"))
			if len(codec.clientPending) != 0 {
				t.Fatalf("%s retry response leaked pending state: %v", method, codec.clientPending)
			}
		})
	}
}

func TestCodexPathCodecNativeLaunchCWDAliasConcurrentResponsesRemainGeneric(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	codec := config.newCodec()
	methods := []string{"plugin/list", "thread/resume", "thread/fork", "command/exec"}
	for _, method := range methods {
		request := transformClientJSON(t, codec, nativeLaunchAliasFrame(method, method, []string{`C:\Users\Pujan`}, nil))
		assertJSONPointerString(t, request, nativeLaunchAliasPointer(method, 0), "/root")
	}
	if len(codec.clientPending) != len(methods) {
		t.Fatalf("concurrent pending count = %d, want %d", len(codec.clientPending), len(methods))
	}
	for index := len(methods) - 1; index >= 0; index-- {
		method := methods[index]
		response := transformServerJSON(t, codec, nativeLaunchAliasResponse(method, method))
		switch method {
		case "thread/resume", "thread/fork":
			assertGenericThreadResponseRoots(t, config, response)
		case "plugin/list":
			assertJSONPointerString(t, response, []string{"result", "marketplaces", "0", "path"}, config.remoteToLocal("/root/plugins"))
		case "command/exec":
			assertJSONPointerString(t, response, []string{"result", "opaque", "cwd"}, "/root")
		}
	}
	if len(codec.clientPending) != 0 {
		t.Fatalf("concurrent responses leaked pending state: %v", codec.clientPending)
	}
}

func TestCodexPathCodecNativeLaunchCWDAliasManifestScopeIsRequestOnly(t *testing.T) {
	manifest, err := loadCodexPathManifest()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"plugin/list":   "/params/cwds/*",
		"thread/resume": "/params/runtimeWorkspaceRoots/*",
		"thread/fork":   "/params/runtimeWorkspaceRoots/*",
		"command/exec":  "/params/cwd",
	}
	seen := make(map[string]bool, len(want))
	for method, patterns := range manifest.ClientRequests {
		for _, pattern := range patterns {
			if pattern.Kind != "native-launch-cwd-alias" {
				continue
			}
			if want[method] != pattern.Pointer || seen[method] {
				t.Fatalf("native launch cwd alias escaped pinned scope: %s %#v", method, pattern)
			}
			seen[method] = true
		}
	}
	for method, pointer := range want {
		if !seen[method] {
			t.Fatalf("missing native launch cwd alias for %s %s", method, pointer)
		}
	}
	for method, patterns := range manifest.ClientResponses {
		for _, pattern := range patterns {
			if pattern.Kind == "native-launch-cwd-alias" {
				t.Fatalf("native launch cwd alias escaped into client response %s: %#v", method, pattern)
			}
		}
	}
	assertManifestPattern(t, manifest.ClientResponses["thread/resume"], "/result/runtimeWorkspaceRoots/*", "absolute", nil, nil)
	assertManifestPattern(t, manifest.ClientResponses["thread/fork"], "/result/runtimeWorkspaceRoots/*", "absolute", nil, nil)
}

func assertCodexRequestBytes(t *testing.T, codec *codexPathCodec, input, want string) {
	t.Helper()
	output, err := codec.clientToServer([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != want {
		t.Fatalf("request = %s, want %s", output, want)
	}
}

func assertCodexPathFieldRejected(t *testing.T, codec *codexPathCodec, frame string) {
	t.Helper()
	if _, err := codec.clientToServer([]byte(frame)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
		t.Fatalf("path field error = %v", err)
	}
	if len(codec.clientPending) != 0 {
		t.Fatalf("rejected request changed pending state: %v", codec.clientPending)
	}
}

func assertGenericThreadResponseRoots(t *testing.T, config *codexPathCodecConfig, response map[string]any) {
	t.Helper()
	clientRoot := config.remoteToLocal("/root")
	assertJSONPointerString(t, response, []string{"result", "cwd"}, clientRoot)
	assertJSONPointerString(t, response, []string{"result", "runtimeWorkspaceRoots", "0"}, clientRoot)
	assertJSONPointerString(t, response, []string{"result", "thread", "cwd"}, clientRoot)
	if got := jsonAt(t, response, []string{"result", "runtimeWorkspaceRoots", "0"}); got == `C:\Users\Pujan` {
		t.Fatal("authoritative response root was incorrectly restored to the native launch cwd")
	}
}

func nativeLaunchAliasFrame(method, id string, paths []string, extra map[string]any) string {
	params := map[string]any{}
	switch method {
	case "plugin/list":
		params["cwds"] = paths
		params["marketplaceKinds"] = nil
	case "thread/resume", "thread/fork":
		params["threadId"] = "thread-1"
		params["runtimeWorkspaceRoots"] = paths
	case "command/exec":
		params["command"] = []string{"git", "status", "--short"}
		params["cwd"] = paths[0]
	default:
		panic("unsupported test method " + method)
	}
	for key, value := range extra {
		params[key] = value
	}
	frame, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		panic(err)
	}
	return string(frame)
}

func nativeLaunchAliasMalformedFrame(method, id string) string {
	field := "runtimeWorkspaceRoots"
	if method == "plugin/list" {
		field = "cwds"
	}
	params := map[string]any{field: `C:\Users\Pujan`}
	if method == "command/exec" {
		params = map[string]any{"command": []string{"git", "status"}, "cwd": []string{`C:\Users\Pujan`}}
	}
	frame, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		panic(err)
	}
	return string(frame)
}

func nativeLaunchAliasPointer(method string, index int) []string {
	if method == "plugin/list" {
		return []string{"params", "cwds", jsonIndex(index)}
	}
	if method == "command/exec" {
		return []string{"params", "cwd"}
	}
	return []string{"params", "runtimeWorkspaceRoots", jsonIndex(index)}
}

func nativeLaunchAliasResponse(method, id string) string {
	var result map[string]any
	switch method {
	case "plugin/list":
		result = map[string]any{
			"marketplaces":          []any{map[string]any{"name": "repo", "path": "/root/plugins", "plugins": []any{}}},
			"marketplaceLoadErrors": []any{},
			"featuredPluginIds":     []any{},
		}
	case "thread/resume", "thread/fork":
		result = map[string]any{
			"cwd":                   "/root",
			"runtimeWorkspaceRoots": []any{"/root"},
			"thread":                map[string]any{"cwd": "/root", "path": nil},
		}
	case "command/exec":
		result = map[string]any{"exitCode": 0, "stdout": "", "stderr": "", "opaque": map[string]any{"cwd": "/root"}}
	default:
		panic("unsupported test method " + method)
	}
	frame, err := json.Marshal(map[string]any{"id": id, "result": result})
	if err != nil {
		panic(err)
	}
	return string(frame)
}

func jsonIndex(index int) string {
	return strconv.Itoa(index)
}
