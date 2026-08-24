package codexsession

import "testing"

const skillsListLiveRequestID = "startup-skills-list-00000000-0000-0000-0000-000000000000"

func TestCodexPathCodecSkillsListLiveFrameRequestAliasAndAuthoritativeResponse(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	codec := config.newCodec()
	liveFrame := []byte(`{"id":"` + skillsListLiveRequestID + `","method":"skills/list","params":{"cwds":["C:\\Users\\Pujan"],"forceReload":true}}`)
	if got := len(liveFrame); got != 146 {
		t.Fatalf("live skills/list frame length = %d, want 146", got)
	}
	request, err := codec.clientToServer(liveFrame)
	if err != nil {
		t.Fatal(err)
	}
	wantRequest := `{"id":"` + skillsListLiveRequestID + `","method":"skills/list","params":{"cwds":["/root"],"forceReload":true}}`
	if string(request) != wantRequest {
		t.Fatalf("request = %s, want %s", request, wantRequest)
	}

	response := transformServerJSON(t, codec, `{"id":"`+skillsListLiveRequestID+`","result":{"data":[{"cwd":"/root","skills":[],"errors":[{"path":"/root/.codex/skills/bad/SKILL.md","message":"opaque"}],"opaque":{"path":"/root/free-form"}}]}}`)
	clientRoot := config.remoteToLocal("/root")
	assertJSONPointerString(t, response, []string{"result", "data", "0", "cwd"}, clientRoot)
	assertJSONPointerString(t, response, []string{"result", "data", "0", "errors", "0", "path"}, config.remoteToLocal("/root/.codex/skills/bad/SKILL.md"))
	assertJSONPointerString(t, response, []string{"result", "data", "0", "opaque", "path"}, "/root/free-form")
	if got := jsonAt(t, response, []string{"result", "data", "0", "cwd"}); got == `C:\Users\Pujan` {
		t.Fatal("authoritative skills/list response cwd was incorrectly restored to the native launch cwd")
	}
	if len(codec.clientPending) != 0 {
		t.Fatalf("skills/list response leaked pending request state: %v", codec.clientPending)
	}
}

func TestCodexPathCodecSkillsListRequestAliasIsNarrowAndConcurrent(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	codec := config.newCodec()
	requestA := transformClientJSON(t, codec, `{"id":"skills-a","method":"skills/list","params":{"cwds":["c:/users/PUJAN/.","`+jsonEscape(config.remoteToLocal("/work"))+`","/tmp","relative"],"forceReload":true,"opaque":{"path":"C:\\Users\\Pujan"}}}`)
	assertJSONPointerString(t, requestA, []string{"params", "cwds", "0"}, "/root")
	assertJSONPointerString(t, requestA, []string{"params", "cwds", "1"}, "/work")
	assertJSONPointerString(t, requestA, []string{"params", "cwds", "2"}, "/tmp")
	assertJSONPointerString(t, requestA, []string{"params", "cwds", "3"}, "relative")
	assertJSONPointerString(t, requestA, []string{"params", "opaque", "path"}, `C:\Users\Pujan`)
	requestB := transformClientJSON(t, codec, `{"id":"skills-b","method":"skills/list","params":{"cwds":["C:\\Users\\Pujan\\."]}}`)
	assertJSONPointerString(t, requestB, []string{"params", "cwds", "0"}, "/root")
	if len(codec.clientPending) != 2 {
		t.Fatalf("concurrent skills/list pending count = %d, want 2", len(codec.clientPending))
	}

	responseB := transformServerJSON(t, codec, `{"id":"skills-b","result":{"data":[{"cwd":"/root","skills":[],"errors":[]}]}}`)
	assertJSONPointerString(t, responseB, []string{"result", "data", "0", "cwd"}, config.remoteToLocal("/root"))
	responseA := transformServerJSON(t, codec, `{"id":"skills-a","result":{"data":[{"cwd":"/root"},{"cwd":"/work"},{"cwd":"/tmp"},{"cwd":"relative"}]}}`)
	assertJSONPointerString(t, responseA, []string{"result", "data", "0", "cwd"}, config.remoteToLocal("/root"))
	assertJSONPointerString(t, responseA, []string{"result", "data", "1", "cwd"}, config.remoteToLocal("/work"))
	assertJSONPointerString(t, responseA, []string{"result", "data", "2", "cwd"}, config.remoteToLocal("/tmp"))
	assertJSONPointerString(t, responseA, []string{"result", "data", "3", "cwd"}, "relative")
	if len(codec.clientPending) != 0 {
		t.Fatalf("concurrent skills/list state leaked: %v", codec.clientPending)
	}

	for _, test := range []struct {
		name string
		cwd  string
	}{
		{name: "sibling", cwd: `C:\Users\Pujan2`},
		{name: "ancestor", cwd: `C:\Users`},
		{name: "other drive", cwd: `D:\Users\Pujan`},
		{name: "UNC", cwd: `\\server\share\project`},
		{name: "device", cwd: `\\.\C:\Users\Pujan`},
		{name: "extended", cwd: `\\?\C:\Users\Pujan`},
	} {
		t.Run(test.name, func(t *testing.T) {
			codec := config.newCodec()
			frame := `{"id":"reject","method":"skills/list","params":{"cwds":["` + jsonEscape(test.cwd) + `"]}}`
			if _, err := codec.clientToServer([]byte(frame)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
				t.Fatalf("foreign native cwd error = %v", err)
			}
			if len(codec.clientPending) != 0 {
				t.Fatalf("rejected skills/list request changed pending state: %v", codec.clientPending)
			}
		})
	}
}

func TestCodexPathCodecSkillsListRejectsNonDriveLaunchAliases(t *testing.T) {
	for _, path := range []string{
		`\\server\share\project`,
		`\\.\C:\Users\Pujan`,
		`\\?\C:\Users\Pujan`,
		`\\?\UNC\server\share\project`,
	} {
		config := mustTestCodexPathCodecConfigWithLaunchCWD(t, path)
		codec := config.newCodec()
		frame := `{"id":"reject","method":"skills/list","params":{"cwds":["` + jsonEscape(path) + `"]}}`
		if _, err := codec.clientToServer([]byte(frame)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
			t.Fatalf("non-drive launch cwd %q error = %v", path, err)
		}
		if len(codec.clientPending) != 0 {
			t.Fatalf("rejected non-drive launch request changed pending state: %v", codec.clientPending)
		}
	}
}

func TestCodexPathCodecSkillsListMalformedFramesAreTransactional(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	codec := config.newCodec()
	for _, frame := range []string{
		`{"id":"retry","method":"skills/list","params":{"cwds":"C:\\Users\\Pujan"}}`,
		`{"id":"retry","method":"skills/list","params":{"cwds":null}}`,
		`{"id":"retry","method":"skills/list","params":{"cwds":[1]}}`,
	} {
		if _, err := codec.clientToServer([]byte(frame)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
			t.Fatalf("malformed skills/list request error = %v", err)
		}
		if len(codec.clientPending) != 0 {
			t.Fatalf("malformed skills/list request changed pending state: %v", codec.clientPending)
		}
	}
	request := transformClientJSON(t, codec, `{"id":"retry","method":"skills/list","params":{"cwds":["C:\\Users\\Pujan"]}}`)
	assertJSONPointerString(t, request, []string{"params", "cwds", "0"}, "/root")
	if _, err := codec.serverToClient([]byte(`{"id":"retry","result":{"data":"malformed"}}`)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
		t.Fatalf("malformed skills/list response error = %v", err)
	}
	if codec.clientPending["s:retry"] != "skills/list" {
		t.Fatalf("malformed skills/list response lost correlation: %v", codec.clientPending)
	}
	transformServerJSON(t, codec, `{"id":"retry","result":{"data":[{"cwd":"/root","skills":[],"errors":[]}]}}`)

	transformClientJSON(t, codec, `{"id":"error-cleanup","method":"skills/list","params":{"cwds":["C:\\Users\\Pujan"]}}`)
	if _, err := codec.serverToClient([]byte(`{"id":"error-cleanup","error":{"code":-32603,"message":"opaque"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := codec.clientToServer([]byte(`{"id":"error-cleanup","method":"skills/list","params":{"cwds":["C:\\Users\\Pujan"]}}`)); err != nil {
		t.Fatalf("skills/list error response did not clean pending state: %v", err)
	}
	transformServerJSON(t, codec, `{"id":"error-cleanup","result":{"data":[{"cwd":"/root","skills":[],"errors":[]}]}}`)
	if len(codec.clientPending) != 0 {
		t.Fatalf("skills/list retry state leaked: %v", codec.clientPending)
	}

	overLimit := make([]any, maxSkillsListCWDEntries+1)
	if _, err := codec.transformSkillsListRequest(map[string]any{"params": map[string]any{"cwds": overLimit}}); err == nil {
		t.Fatal("oversized skills/list cwd array unexpectedly accepted")
	}
}

func TestCodexPathCodecSkillsListManifestAliasIsRequestOnly(t *testing.T) {
	manifest, err := loadCodexPathManifest()
	if err != nil {
		t.Fatal(err)
	}
	assertManifestPattern(t, manifest.ClientRequests["skills/list"], "/params/cwds/*", "skills-list-cwd-alias", nil, nil)
	assertManifestPattern(t, manifest.ClientResponses["skills/list"], "/result/data/*/cwd", "path", nil, nil)
	for method, patterns := range manifest.ClientRequests {
		for _, pattern := range patterns {
			if pattern.Kind == "skills-list-cwd-alias" && (method != "skills/list" || pattern.Pointer != "/params/cwds/*") {
				t.Fatalf("skills/list cwd alias escaped request scope: %s %#v", method, pattern)
			}
		}
	}
	for method, patterns := range manifest.ClientResponses {
		for _, pattern := range patterns {
			if pattern.Kind == "skills-list-cwd-alias" {
				t.Fatalf("skills/list cwd alias escaped into client response %s: %#v", method, pattern)
			}
		}
	}
}
