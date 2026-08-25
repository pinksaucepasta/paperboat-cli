package codexsession

import "testing"

const hooksListLiveRequestID = "hooks-list-00000000-0000-0000-0000-000000000000"

func TestCodexPathCodecHooksListLiveFrameRoundTrip(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	codec := config.newCodec()
	liveFrame := []byte(`{"id":"` + hooksListLiveRequestID + `","method":"hooks/list","params":{"cwds":["C:\\Users\\Pujan"]}}`)
	if got := len(liveFrame); got != 117 {
		t.Fatalf("live hooks/list frame length = %d, want 117", got)
	}
	request, err := codec.clientToServer(liveFrame)
	if err != nil {
		t.Fatal(err)
	}
	wantRequest := `{"id":"` + hooksListLiveRequestID + `","method":"hooks/list","params":{"cwds":["/root"]}}`
	if string(request) != wantRequest {
		t.Fatalf("request = %s, want %s", request, wantRequest)
	}

	response := transformServerJSON(t, codec, `{"id":"`+hooksListLiveRequestID+`","result":{"data":[{"cwd":"/root","hooks":[],"warnings":[],"errors":[],"opaque":{"path":"/root/free-form"}}],"opaque":"C:\\Users\\Pujan"}}`)
	assertJSONPointerString(t, response, []string{"result", "data", "0", "cwd"}, `C:\Users\Pujan`)
	assertJSONPointerString(t, response, []string{"result", "data", "0", "opaque", "path"}, "/root/free-form")
	assertJSONPointerString(t, response, []string{"result", "opaque"}, `C:\Users\Pujan`)
	if len(codec.clientPending) != 0 || len(codec.clientHooksListAliases) != 0 {
		t.Fatalf("pending request state leaked: methods=%v aliases=%v", codec.clientPending, codec.clientHooksListAliases)
	}
}

func TestCodexPathCodecHooksListAliasesArePositionalAndConcurrent(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	codec := config.newCodec()
	requestA := transformClientJSON(t, codec, `{"id":"hooks-a","method":"hooks/list","params":{"cwds":["c:/users/PUJAN","`+jsonEscape(config.remoteToLocal("/root"))+`","`+jsonEscape(config.remoteToLocal("/work"))+`","relative"],"opaque":{"path":"C:\\Users\\Pujan"}}}`)
	assertJSONPointerString(t, requestA, []string{"params", "cwds", "0"}, "/root")
	assertJSONPointerString(t, requestA, []string{"params", "cwds", "1"}, "/root")
	assertJSONPointerString(t, requestA, []string{"params", "cwds", "2"}, "/work")
	assertJSONPointerString(t, requestA, []string{"params", "cwds", "3"}, "relative")
	assertJSONPointerString(t, requestA, []string{"params", "opaque", "path"}, `C:\Users\Pujan`)
	transformClientJSON(t, codec, `{"id":"hooks-b","method":"hooks/list","params":{"cwds":["C:\\Users\\Pujan\\."]}}`)

	responseB := transformServerJSON(t, codec, `{"id":"hooks-b","result":{"data":[{"cwd":"/root","hooks":[],"warnings":[],"errors":[]}]}}`)
	assertJSONPointerString(t, responseB, []string{"result", "data", "0", "cwd"}, `C:\Users\Pujan\.`)
	responseA := transformServerJSON(t, codec, `{"id":"hooks-a","result":{"data":[{"cwd":"/root"},{"cwd":"/root"},{"cwd":"/work"},{"cwd":"relative"}]}}`)
	assertJSONPointerString(t, responseA, []string{"result", "data", "0", "cwd"}, "c:/users/PUJAN")
	assertJSONPointerString(t, responseA, []string{"result", "data", "1", "cwd"}, config.remoteToLocal("/root"))
	assertJSONPointerString(t, responseA, []string{"result", "data", "2", "cwd"}, config.remoteToLocal("/work"))
	assertJSONPointerString(t, responseA, []string{"result", "data", "3", "cwd"}, "relative")
	if len(codec.clientPending) != 0 || len(codec.clientHooksListAliases) != 0 {
		t.Fatalf("concurrent request state leaked: methods=%v aliases=%v", codec.clientPending, codec.clientHooksListAliases)
	}
}

func TestCodexPathCodecHooksListAliasFailsClosedAndRetainsCorrelation(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	overLimit := make([]any, maxHooksListCWDEntries+1)
	if _, _, err := config.newCodec().transformHooksListRequest(map[string]any{"params": map[string]any{"cwds": overLimit}}); err == nil {
		t.Fatal("oversized hooks/list cwd alias context unexpectedly accepted")
	}
	for _, frame := range []string{
		`{"id":"sibling","method":"hooks/list","params":{"cwds":["C:\\Users\\Pujan2"]}}`,
		`{"id":"ancestor","method":"hooks/list","params":{"cwds":["C:\\Users"]}}`,
		`{"id":"other-method","method":"externalAgentConfig/detect","params":{"cwds":["C:\\Users\\Pujan"]}}`,
	} {
		codec := config.newCodec()
		if _, err := codec.clientToServer([]byte(frame)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
			t.Fatalf("foreign native path error = %v", err)
		}
		if len(codec.clientPending) != 0 || len(codec.clientHooksListAliases) != 0 {
			t.Fatalf("rejected request changed pending state: methods=%v aliases=%v", codec.clientPending, codec.clientHooksListAliases)
		}
	}

	codec := config.newCodec()
	transformClientJSON(t, codec, `{"id":"retry","method":"hooks/list","params":{"cwds":["C:\\Users\\Pujan"]}}`)
	if _, err := codec.serverToClient([]byte(`{"id":"retry","result":{"data":"malformed"}}`)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
		t.Fatalf("malformed response error = %v", err)
	}
	if codec.clientPending["s:retry"] != "hooks/list" || len(codec.clientHooksListAliases["s:retry"]) != 1 {
		t.Fatalf("malformed response lost correlation: methods=%v aliases=%v", codec.clientPending, codec.clientHooksListAliases)
	}
	if _, err := codec.serverToClient([]byte(`{"id":"retry","result":{"data":[{"cwd":"/elsewhere"}]}}`)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
		t.Fatalf("mismatched response error = %v", err)
	}
	if codec.clientPending["s:retry"] != "hooks/list" || len(codec.clientHooksListAliases["s:retry"]) != 1 {
		t.Fatalf("failed response lost correlation: methods=%v aliases=%v", codec.clientPending, codec.clientHooksListAliases)
	}
	response := transformServerJSON(t, codec, `{"id":"retry","result":{"data":[{"cwd":"/root"}]}}`)
	assertJSONPointerString(t, response, []string{"result", "data", "0", "cwd"}, `C:\Users\Pujan`)

	transformClientJSON(t, codec, `{"id":"error-cleanup","method":"hooks/list","params":{"cwds":["C:\\Users\\Pujan"]}}`)
	if _, err := codec.serverToClient([]byte(`{"id":"error-cleanup","error":{"code":-32603,"message":"opaque"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := codec.clientToServer([]byte(`{"id":"error-cleanup","method":"hooks/list","params":{"cwds":["C:\\Users\\Pujan"]}}`)); err != nil {
		t.Fatalf("error response did not clean alias state: %v", err)
	}
	transformServerJSON(t, codec, `{"id":"error-cleanup","result":{"data":[{"cwd":"/root"}]}}`)
	if len(codec.clientPending) != 0 || len(codec.clientHooksListAliases) != 0 {
		t.Fatalf("retry state leaked: methods=%v aliases=%v", codec.clientPending, codec.clientHooksListAliases)
	}
}

func TestCodexPathCodecHooksListAliasRejectsNonDriveLaunchPaths(t *testing.T) {
	tests := []struct {
		name       string
		launchCWD  string
		requestCWD string
	}{
		{
			name:       "UNC same share",
			launchCWD:  `\\server\share\project`,
			requestCWD: `\\server\share\folder\..\project`,
		},
		{
			name:       "UNC cross share",
			launchCWD:  `\\server\share2\project`,
			requestCWD: `\\server\share\..\share2\project`,
		},
		{
			name:       "device path",
			launchCWD:  `\\.\C:\Users\Pujan`,
			requestCWD: `\\.\C:\Users\Pujan`,
		},
		{
			name:       "extended drive path",
			launchCWD:  `\\?\C:\Users\Pujan`,
			requestCWD: `\\?\C:\Users\Pujan`,
		},
		{
			name:       "extended UNC path",
			launchCWD:  `\\?\UNC\server\share\project`,
			requestCWD: `\\?\UNC\server\share\project`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if sameNormalizedWindowsPath(test.launchCWD, test.requestCWD) {
				t.Fatal("non-drive launch cwd unexpectedly matched")
			}
			config := mustTestCodexPathCodecConfigWithLaunchCWD(t, test.launchCWD)
			codec := config.newCodec()
			frame := `{"id":"reject","method":"hooks/list","params":{"cwds":["` + jsonEscape(test.requestCWD) + `"]}}`
			if _, err := codec.clientToServer([]byte(frame)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
				t.Fatalf("non-drive native path error = %v", err)
			}
			if len(codec.clientPending) != 0 || len(codec.clientHooksListAliases) != 0 {
				t.Fatalf("rejected request changed pending state: methods=%v aliases=%v", codec.clientPending, codec.clientHooksListAliases)
			}
		})
	}
}

func TestCodexPathCodecHooksListManifestIsExplicitlyScoped(t *testing.T) {
	manifest, err := loadCodexPathManifest()
	if err != nil {
		t.Fatal(err)
	}
	assertManifestPattern(t, manifest.ClientRequests["hooks/list"], "/params/cwds/*", "hooks-list-cwd-alias", nil, nil)
	assertManifestPattern(t, manifest.ClientResponses["hooks/list"], "/result/data/*/cwd", "hooks-list-cwd-alias", nil, nil)
	for method, patterns := range manifest.ClientRequests {
		for _, pattern := range patterns {
			if pattern.Kind == "hooks-list-cwd-alias" && (method != "hooks/list" || pattern.Pointer != "/params/cwds/*") {
				t.Fatalf("request alias escaped hooks/list scope: %s %#v", method, pattern)
			}
		}
	}
	for method, patterns := range manifest.ClientResponses {
		for _, pattern := range patterns {
			if pattern.Kind == "hooks-list-cwd-alias" && (method != "hooks/list" || pattern.Pointer != "/result/data/*/cwd") {
				t.Fatalf("response alias escaped hooks/list scope: %s %#v", method, pattern)
			}
		}
	}
}

func mustTestCodexPathCodecConfigWithLaunchCWD(t *testing.T, launchCWD string) *codexPathCodecConfig {
	t.Helper()
	config, err := newCodexPathCodecConfigWithLaunchCWD("windows", "0.149.1", "0.149.1", "/root", testCodecNonce, launchCWD)
	if err != nil {
		t.Fatal(err)
	}
	return config
}
