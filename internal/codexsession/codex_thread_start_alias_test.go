package codexsession

import (
	"strings"
	"testing"
)

const threadStartLiveRequestID = "startup-thread-start-00000000-0000-0000-0000-000000000000"

func TestCodexPathCodecThreadStartLiveSizeWorkspaceRootAlias(t *testing.T) {
	const liveNonce = "ABCDEFGHIJKLMNOPQRSTUVWX"
	config, err := newCodexPathCodecConfigWithLaunchCWD("windows", "0.149.1", "0.149.1", "/root", liveNonce, `C:\Users\Pujan`)
	if err != nil {
		t.Fatal(err)
	}
	codec := config.newCodec()
	// The bridge deliberately does not retain payloads. This reconstructs the
	// pinned 0.149.1 path-bearing shape at the observed 778-byte wire size;
	// opaqueSettings stands in only for unlogged, non-path config overrides.
	opaqueSettings := strings.Repeat("x", 59)
	liveFrame := []byte(`{"id":"` + threadStartLiveRequestID + `","method":"thread/start","params":{"model":null,"modelProvider":null,"cwd":"` + jsonEscape(config.remoteToLocal("/root")) + `","runtimeWorkspaceRoots":["C:\\Users\\Pujan"],"approvalPolicy":"on-request","approvalsReviewer":null,"sandbox":"read-only","permissions":null,"config":{"web_search":"live","opaque":"` + opaqueSettings + `"},"serviceName":null,"baseInstructions":null,"developerInstructions":null,"personality":null,"multiAgentMode":null,"ephemeral":false,"historyMode":"paginated","sessionStartSource":null,"threadSource":"user","projectId":null,"environments":null,"dynamicTools":null,"selectedCapabilityRoots":null,"mockExperimentalField":null}}`)
	if got := len(liveFrame); got != 778 {
		t.Fatalf("reconstructed live thread/start frame length = %d, want 778", got)
	}
	request := transformClientJSON(t, codec, string(liveFrame))
	assertJSONPointerString(t, request, []string{"params", "cwd"}, "/root")
	assertJSONPointerString(t, request, []string{"params", "runtimeWorkspaceRoots", "0"}, "/root")
	assertJSONPointerString(t, request, []string{"params", "config", "opaque"}, opaqueSettings)

	response := transformServerJSON(t, codec, `{"id":"`+threadStartLiveRequestID+`","result":{"cwd":"/root","runtimeWorkspaceRoots":["/root"],"thread":{"cwd":"/root","path":null}}}`)
	clientRoot := config.remoteToLocal("/root")
	assertJSONPointerString(t, response, []string{"result", "cwd"}, clientRoot)
	assertJSONPointerString(t, response, []string{"result", "runtimeWorkspaceRoots", "0"}, clientRoot)
	assertJSONPointerString(t, response, []string{"result", "thread", "cwd"}, clientRoot)
	if got := jsonAt(t, response, []string{"result", "runtimeWorkspaceRoots", "0"}); got == `C:\Users\Pujan` {
		t.Fatal("authoritative remote workspace root was incorrectly restored to the native launch cwd")
	}
	if len(codec.clientPending) != 0 {
		t.Fatalf("thread/start response leaked correlation state: %v", codec.clientPending)
	}
}

func TestCodexPathCodecThreadStartWorkspaceRootAliasIsNarrow(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	codec := config.newCodec()
	request := transformClientJSON(t, codec, `{"id":"roots","method":"thread/start","params":{"cwd":"`+jsonEscape(config.remoteToLocal("/root"))+`","runtimeWorkspaceRoots":["c:/users/PUJAN/.","`+jsonEscape(config.remoteToLocal("/work"))+`","/tmp"]}}`)
	assertJSONPointerString(t, request, []string{"params", "runtimeWorkspaceRoots", "0"}, "/root")
	assertJSONPointerString(t, request, []string{"params", "runtimeWorkspaceRoots", "1"}, "/work")
	assertJSONPointerString(t, request, []string{"params", "runtimeWorkspaceRoots", "2"}, "/tmp")
	transformServerJSON(t, codec, `{"id":"roots","result":{"cwd":"/root","runtimeWorkspaceRoots":["/root","/work","/tmp"],"thread":{"cwd":"/root"}}}`)

	for _, test := range []struct {
		name  string
		frame string
	}{
		{name: "sibling", frame: `{"id":"reject","method":"thread/start","params":{"runtimeWorkspaceRoots":["C:\\Users\\Pujan2"]}}`},
		{name: "ancestor", frame: `{"id":"reject","method":"thread/start","params":{"runtimeWorkspaceRoots":["C:\\Users"]}}`},
		{name: "UNC", frame: `{"id":"reject","method":"thread/start","params":{"runtimeWorkspaceRoots":["\\\\server\\share\\project"]}}`},
		{name: "device", frame: `{"id":"reject","method":"thread/start","params":{"runtimeWorkspaceRoots":["\\\\.\\C:\\Users\\Pujan"]}}`},
		{name: "extended", frame: `{"id":"reject","method":"thread/start","params":{"runtimeWorkspaceRoots":["\\\\?\\C:\\Users\\Pujan"]}}`},
		{name: "relative", frame: `{"id":"reject","method":"thread/start","params":{"runtimeWorkspaceRoots":["relative"]}}`},
		{name: "unscoped turn method", frame: `{"id":"reject","method":"turn/start","params":{"runtimeWorkspaceRoots":["C:\\Users\\Pujan"]}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			codec := config.newCodec()
			if _, err := codec.clientToServer([]byte(test.frame)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
				t.Fatalf("foreign workspace root error = %v", err)
			}
			if len(codec.clientPending) != 0 {
				t.Fatalf("rejected request changed pending state: %v", codec.clientPending)
			}
		})
	}
}

func TestCodexPathCodecThreadStartWorkspaceRootAliasMalformedRequestCanRetry(t *testing.T) {
	config := mustTestCodexPathCodecConfigWithLaunchCWD(t, `C:\Users\Pujan`)
	codec := config.newCodec()
	if _, err := codec.clientToServer([]byte(`{"id":"retry","method":"thread/start","params":{"runtimeWorkspaceRoots":"C:\\Users\\Pujan"}}`)); err == nil || codexCodecFailureClassOf(err) != string(codexCodecFailurePathField) {
		t.Fatalf("malformed roots error = %v", err)
	}
	if len(codec.clientPending) != 0 {
		t.Fatalf("malformed request changed pending state: %v", codec.clientPending)
	}
	request := transformClientJSON(t, codec, `{"id":"retry","method":"thread/start","params":{"runtimeWorkspaceRoots":["C:\\Users\\Pujan"]}}`)
	assertJSONPointerString(t, request, []string{"params", "runtimeWorkspaceRoots", "0"}, "/root")
	transformServerJSON(t, codec, `{"id":"retry","result":{"cwd":"/root","runtimeWorkspaceRoots":["/root"],"thread":{"cwd":"/root"}}}`)

	overLimit := make([]any, maxThreadStartWorkspaceRoots+1)
	if _, err := codec.transformThreadStartRuntimeWorkspaceRoots(map[string]any{"params": map[string]any{"runtimeWorkspaceRoots": overLimit}}); err == nil {
		t.Fatal("oversized thread/start runtime workspace roots unexpectedly accepted")
	}
}

func TestCodexPathCodecThreadStartWorkspaceRootAliasManifestScope(t *testing.T) {
	manifest, err := loadCodexPathManifest()
	if err != nil {
		t.Fatal(err)
	}
	assertManifestPattern(t, manifest.ClientRequests["thread/start"], "/params/runtimeWorkspaceRoots/*", "thread-start-runtime-root-alias", nil, nil)
	for method, patterns := range manifest.ClientRequests {
		for _, pattern := range patterns {
			if pattern.Kind == "thread-start-runtime-root-alias" && (method != "thread/start" || pattern.Pointer != "/params/runtimeWorkspaceRoots/*") {
				t.Fatalf("thread/start workspace-root alias escaped scope: %s %#v", method, pattern)
			}
		}
	}
	assertManifestPattern(t, manifest.ClientResponses["thread/start"], "/result/runtimeWorkspaceRoots/*", "absolute", nil, nil)
}
