package codexsession

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	codexPathManifestSchema      = "paperboat.codex-path-manifest/v1"
	codexPathShimVersion         = "0.149.1"
	codexPathSourceCommit        = "ff29a44391deccde0aba0f8390337d7f3c319ea4"
	codexPathInputsSHA256        = "53badd0b6c55734f1e7ae3f6820125e37401a790457cc594eedde05e77ae23c9"
	codexPathManifestSHA256      = "3f44cefa007a8d199073b20d40dfa649096280089edce204cd10110d96726f88"
	maxPendingCodexRequests      = 4096
	maxHooksListCWDEntries       = 1024
	maxSkillsListCWDEntries      = 1024
	maxThreadStartWorkspaceRoots = 1024
	maxNativeLaunchCWDEntries    = 1024
)

// Regenerate only from the pinned official openai/codex checkout documented in
// the manifest. The generator refuses any checkout whose rust-v0.149.1 tag does
// not resolve to codexPathSourceCommit.
//
//go:embed codex_path_manifest_0_149_1.json
var codexPathManifestBytes []byte

type codexPathPattern struct {
	Pointer         string   `json:"pointer"`
	Kind            string   `json:"kind"`
	VariantPointer  string   `json:"variant_pointer,omitempty"`
	Variants        []string `json:"variants,omitempty"`
	IgnoredVariants []string `json:"ignored_variants,omitempty"`
}

type codexPathManifest struct {
	Schema                       string                        `json:"schema"`
	CodexVersion                 string                        `json:"codex_version"`
	SourceTag                    string                        `json:"source_tag"`
	SourceCommit                 string                        `json:"source_commit"`
	InputsSHA256                 string                        `json:"inputs_sha256"`
	ClientRequests               map[string][]codexPathPattern `json:"client_requests"`
	ClientNotifications          map[string][]codexPathPattern `json:"client_notifications"`
	ClientResponses              map[string][]codexPathPattern `json:"client_responses"`
	ServerRequests               map[string][]codexPathPattern `json:"server_requests"`
	ServerNotifications          map[string][]codexPathPattern `json:"server_notifications"`
	ServerResponses              map[string][]codexPathPattern `json:"server_responses"`
	PreservedClientResponsePaths map[string][]string           `json:"preserved_client_response_paths"`
}

var (
	embeddedCodexPathManifest     *codexPathManifest
	embeddedCodexPathManifestErr  error
	embeddedCodexPathManifestOnce sync.Once
)

type codexPathCodecConfig struct {
	manifest        *codexPathManifest
	remoteRoot      string
	localPrefix     string
	nativeLaunchCWD string
}

type codexPathCodec struct {
	config                 *codexPathCodecConfig
	mu                     sync.Mutex
	clientPending          map[string]string
	serverPending          map[string]string
	clientHooksListAliases map[string][]codexHooksListCWDAlias
}

type codexHooksListCWDAlias struct {
	clientPath string
	serverPath string
	aliased    bool
}

type codexPathDirection uint8

const (
	codexPathsToServer codexPathDirection = iota + 1
	codexPathsToClient
)

type codexCodecFailureClass string

const (
	codexCodecFailureEnvelope      codexCodecFailureClass = "envelope"
	codexCodecFailureUnknownMethod codexCodecFailureClass = "unknown_method"
	codexCodecFailureCorrelation   codexCodecFailureClass = "correlation"
	codexCodecFailurePathField     codexCodecFailureClass = "path_field"
	codexCodecFailureEncode        codexCodecFailureClass = "encode"
)

type codexCodecFailure struct {
	class codexCodecFailureClass
	err   error
}

func (e *codexCodecFailure) Error() string { return e.err.Error() }
func (e *codexCodecFailure) Unwrap() error { return e.err }

func newCodexCodecFailure(class codexCodecFailureClass, err error) error {
	if err == nil {
		return nil
	}
	return &codexCodecFailure{class: class, err: err}
}

func codexCodecFailureClassOf(err error) string {
	var failure *codexCodecFailure
	if errors.As(err, &failure) {
		switch failure.class {
		case codexCodecFailureEnvelope, codexCodecFailureUnknownMethod, codexCodecFailureCorrelation, codexCodecFailurePathField, codexCodecFailureEncode:
			return string(failure.class)
		}
	}
	return string(codexCodecFailureEnvelope)
}

func newCodexPathCodecConfig(goos, localVersion, remoteVersion, remoteRoot, nonce string) (*codexPathCodecConfig, error) {
	if goos != "windows" {
		return nil, nil
	}
	nativeLaunchCWD, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve native Codex launch directory: %w", err)
	}
	return newCodexPathCodecConfigWithLaunchCWD(goos, localVersion, remoteVersion, remoteRoot, nonce, nativeLaunchCWD)
}

func newCodexPathCodecConfigWithLaunchCWD(goos, localVersion, remoteVersion, remoteRoot, nonce, nativeLaunchCWD string) (*codexPathCodecConfig, error) {
	if goos != "windows" {
		return nil, nil
	}
	manifest, err := loadCodexPathManifest()
	if err != nil {
		return nil, err
	}
	if localVersion != manifest.CodexVersion || remoteVersion != manifest.CodexVersion {
		return nil, fmt.Errorf("native Windows remote Codex requires local and remote Codex %s for path-safe app-server compatibility; local=%s remote=%s", manifest.CodexVersion, localVersion, remoteVersion)
	}
	if !canonicalRemotePath(remoteRoot) {
		return nil, fmt.Errorf("remote Codex path %q is not a normalized absolute POSIX path", remoteRoot)
	}
	if !safeCodecNonce(nonce) {
		return nil, errors.New("invalid Codex path codec namespace")
	}
	drive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if len(drive) != 2 || !asciiLetter(drive[0]) || drive[1] != ':' {
		drive = "C:"
	}
	return &codexPathCodecConfig{
		manifest:        manifest,
		remoteRoot:      remoteRoot,
		localPrefix:     drive + `\.paperboat-remote\` + nonce + `\rootfs`,
		nativeLaunchCWD: nativeLaunchCWD,
	}, nil
}

func (c *codexPathCodecConfig) newCodec() *codexPathCodec {
	if c == nil {
		return nil
	}
	return &codexPathCodec{
		config:                 c,
		clientPending:          make(map[string]string),
		serverPending:          make(map[string]string),
		clientHooksListAliases: make(map[string][]codexHooksListCWDAlias),
	}
}

func loadCodexPathManifest() (*codexPathManifest, error) {
	embeddedCodexPathManifestOnce.Do(func() {
		digest := sha256.Sum256(codexPathManifestBytes)
		if hex.EncodeToString(digest[:]) != codexPathManifestSHA256 {
			embeddedCodexPathManifestErr = errors.New("embedded Codex path manifest content hash is invalid")
			return
		}
		var manifest codexPathManifest
		if err := json.Unmarshal(codexPathManifestBytes, &manifest); err != nil {
			embeddedCodexPathManifestErr = fmt.Errorf("decode embedded Codex path manifest: %w", err)
			return
		}
		if manifest.Schema != codexPathManifestSchema || manifest.CodexVersion != codexPathShimVersion ||
			manifest.SourceCommit != codexPathSourceCommit || manifest.InputsSHA256 != codexPathInputsSHA256 ||
			len(manifest.ClientRequests) != 153 || len(manifest.ClientResponses) != 153 ||
			len(manifest.ServerRequests) != 11 || len(manifest.ServerResponses) != 11 ||
			len(manifest.ServerNotifications) != 77 ||
			!hasCodexPathPattern(manifest.ClientRequests["hooks/list"], "/params/cwds/*", "hooks-list-cwd-alias") ||
			!hasCodexPathPattern(manifest.ClientResponses["hooks/list"], "/result/data/*/cwd", "hooks-list-cwd-alias") ||
			!hasCodexPathPattern(manifest.ClientRequests["skills/list"], "/params/cwds/*", "skills-list-cwd-alias") ||
			!hasCodexPathPattern(manifest.ClientResponses["skills/list"], "/result/data/*/cwd", "path") ||
			!hasCodexPathPattern(manifest.ClientRequests["thread/start"], "/params/runtimeWorkspaceRoots/*", "thread-start-runtime-root-alias") ||
			!hasCodexPathPattern(manifest.ClientRequests["plugin/list"], "/params/cwds/*", "native-launch-cwd-alias") ||
			!hasCodexPathPattern(manifest.ClientRequests["thread/resume"], "/params/runtimeWorkspaceRoots/*", "native-launch-cwd-alias") ||
			!hasCodexPathPattern(manifest.ClientRequests["thread/fork"], "/params/runtimeWorkspaceRoots/*", "native-launch-cwd-alias") ||
			!hasCodexPathPattern(manifest.ClientRequests["command/exec"], "/params/cwd", "native-launch-cwd-alias") ||
			!stringSlicesExactly(manifest.PreservedClientResponsePaths["initialize"], []string{"/result/codexHome"}) {
			embeddedCodexPathManifestErr = errors.New("embedded Codex path manifest provenance is invalid")
			return
		}
		for label, methods := range map[string]map[string][]codexPathPattern{
			"client requests": manifest.ClientRequests, "client notifications": manifest.ClientNotifications,
			"client responses": manifest.ClientResponses, "server requests": manifest.ServerRequests,
			"server notifications": manifest.ServerNotifications, "server responses": manifest.ServerResponses,
		} {
			if len(methods) == 0 {
				embeddedCodexPathManifestErr = fmt.Errorf("embedded Codex path manifest has no %s", label)
				return
			}
			for method, patterns := range methods {
				if method == "" {
					embeddedCodexPathManifestErr = fmt.Errorf("embedded Codex path manifest has an empty %s method", label)
					return
				}
				for _, pattern := range patterns {
					_, pointerErr := parseCodexPointer(pattern.Pointer)
					_, variantPointerErr := parseOptionalCodexPointer(pattern.VariantPointer)
					variantScoped := len(pattern.Variants) != 0 || len(pattern.IgnoredVariants) != 0
					if pointerErr != nil || variantPointerErr != nil || variantScoped != (pattern.VariantPointer != "") ||
						(pattern.Kind != "absolute" && pattern.Kind != "path" && pattern.Kind != "path-or-array" &&
							pattern.Kind != "path-map-keys" && pattern.Kind != "project-key-path" &&
							pattern.Kind != "project-disabled-reason" && pattern.Kind != "hooks-list-cwd-alias" &&
							pattern.Kind != "skills-list-cwd-alias" &&
							pattern.Kind != "thread-start-runtime-root-alias" &&
							pattern.Kind != "native-launch-cwd-alias") {
						embeddedCodexPathManifestErr = fmt.Errorf("embedded Codex path manifest has invalid %s pattern for %s", label, method)
						return
					}
				}
			}
		}
		embeddedCodexPathManifest = &manifest
	})
	return embeddedCodexPathManifest, embeddedCodexPathManifestErr
}

func (c *codexPathCodec) clientToServer(data []byte) ([]byte, error) {
	output, _, err := c.transformDiagnosticFrame(data, codexPathsToServer)
	return output, err
}

func (c *codexPathCodec) serverToClient(data []byte) ([]byte, error) {
	output, _, err := c.transformDiagnosticFrame(data, codexPathsToClient)
	return output, err
}

func (c *codexPathCodec) transformDiagnosticFrame(data []byte, direction codexPathDirection) ([]byte, string, error) {
	if c == nil {
		return data, codexDiagnosticMethodUnavailable, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	method := c.diagnosticMethodLocked(data, direction)
	output, err := c.transform(data, direction)
	return output, method, err
}

func (c *codexPathCodec) diagnosticMethodLocked(data []byte, direction codexPathDirection) string {
	value, err := decodeCodexFrame(data)
	if err != nil {
		return codexDiagnosticMethodUnavailable
	}
	if rawMethod, hasMethod := value["method"]; hasMethod {
		method, ok := rawMethod.(string)
		if !ok || method == "" {
			return codexDiagnosticMethodUnavailable
		}
		_, hasID := value["id"]
		var methods map[string][]codexPathPattern
		switch {
		case direction == codexPathsToServer && hasID:
			methods = c.config.manifest.ClientRequests
		case direction == codexPathsToServer:
			methods = c.config.manifest.ClientNotifications
		case hasID:
			methods = c.config.manifest.ServerRequests
		default:
			methods = c.config.manifest.ServerNotifications
		}
		if _, exists := methods[method]; exists {
			return method
		}
		return codexDiagnosticMethodUnavailable
	}
	id, hasID := value["id"]
	if !hasID {
		return codexDiagnosticMethodUnavailable
	}
	key, err := codexRequestID(id)
	if err != nil {
		return codexDiagnosticMethodUnavailable
	}
	pending := c.clientPending
	if direction == codexPathsToServer {
		pending = c.serverPending
	}
	if method, exists := pending[key]; exists {
		return method
	}
	return codexDiagnosticMethodUnavailable
}

func (c *codexPathCodec) pendingDiagnosticMethod(direction codexPathDirection) string {
	if c == nil {
		return codexDiagnosticMethodUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pending := c.clientPending
	if direction == codexPathsToServer {
		pending = c.serverPending
	}
	unique := make(map[string]struct{}, len(pending))
	for _, method := range pending {
		unique[method] = struct{}{}
	}
	if len(unique) == 0 {
		return codexDiagnosticMethodUnavailable
	}
	if len(unique) > 4 {
		return "multiple_pending"
	}
	methods := make([]string, 0, len(unique))
	for method := range unique {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	return strings.Join(methods, ",")
}

func (c *codexPathCodec) transform(data []byte, direction codexPathDirection) ([]byte, error) {
	value, err := decodeCodexFrame(data)
	if err != nil {
		return nil, newCodexCodecFailure(codexCodecFailureEnvelope, err)
	}
	rawMethod, hasMethod := value["method"]
	method := ""
	if hasMethod {
		var ok bool
		method, ok = rawMethod.(string)
		if !ok || method == "" {
			return nil, newCodexCodecFailure(codexCodecFailureEnvelope, errors.New("Codex app-server frame method must be a non-empty string"))
		}
	}
	id, hasID := value["id"]
	_, hasResult := value["result"]
	_, hasError := value["error"]
	_, hasParams := value["params"]
	if hasMethod && (hasResult || hasError) {
		return nil, newCodexCodecFailure(codexCodecFailureEnvelope, errors.New("Codex request or notification cannot contain result or error"))
	}
	if !hasMethod {
		if !hasID || hasResult == hasError || hasParams {
			return nil, newCodexCodecFailure(codexCodecFailureEnvelope, errors.New("Codex response must contain id and exactly one of result or error, without method or params"))
		}
	}
	var patterns []codexPathPattern
	var pendingAdd map[string]string
	var pendingDelete map[string]string
	var pendingKey string
	var hooksListAliases []codexHooksListCWDAlias
	var responseHooksListAliases []codexHooksListCWDAlias
	addHooksListAliases := false
	deleteHooksListAliases := false
	changed := false
	if hasMethod {
		if hasID {
			key, keyErr := codexRequestID(id)
			if keyErr != nil {
				return nil, newCodexCodecFailure(codexCodecFailureCorrelation, keyErr)
			}
			if direction == codexPathsToServer {
				patterns, hasMethod = c.config.manifest.ClientRequests[method]
				if !hasMethod {
					return nil, newCodexCodecFailure(codexCodecFailureUnknownMethod, fmt.Errorf("Codex %s client request method %q is not in the pinned path manifest", codexPathShimVersion, method))
				}
				if err := validateCodexRequest(c.clientPending, key); err != nil {
					return nil, newCodexCodecFailure(codexCodecFailureCorrelation, err)
				}
				pendingAdd = c.clientPending
				addHooksListAliases = method == "hooks/list"
			} else {
				patterns, hasMethod = c.config.manifest.ServerRequests[method]
				if !hasMethod {
					return nil, newCodexCodecFailure(codexCodecFailureUnknownMethod, fmt.Errorf("Codex %s server request method %q is not in the pinned path manifest", codexPathShimVersion, method))
				}
				if err := validateCodexRequest(c.serverPending, key); err != nil {
					return nil, newCodexCodecFailure(codexCodecFailureCorrelation, err)
				}
				pendingAdd = c.serverPending
			}
			pendingKey = key
		} else if direction == codexPathsToServer {
			patterns, hasMethod = c.config.manifest.ClientNotifications[method]
			if !hasMethod {
				return nil, newCodexCodecFailure(codexCodecFailureUnknownMethod, fmt.Errorf("Codex %s client notification method %q is not in the pinned path manifest", codexPathShimVersion, method))
			}
		} else {
			patterns, hasMethod = c.config.manifest.ServerNotifications[method]
			if !hasMethod {
				return nil, newCodexCodecFailure(codexCodecFailureUnknownMethod, fmt.Errorf("Codex %s server notification method %q is not in the pinned path manifest", codexPathShimVersion, method))
			}
		}
	} else if hasID {
		key, keyErr := codexRequestID(id)
		if keyErr != nil {
			return nil, newCodexCodecFailure(codexCodecFailureCorrelation, keyErr)
		}
		if direction == codexPathsToServer {
			method, hasMethod = c.serverPending[key]
			if !hasMethod {
				return nil, newCodexCodecFailure(codexCodecFailureCorrelation, fmt.Errorf("Codex response id %s has no pending server request", key))
			}
			pendingDelete = c.serverPending
			patterns = c.config.manifest.ServerResponses[method]
		} else {
			method, hasMethod = c.clientPending[key]
			if !hasMethod {
				return nil, newCodexCodecFailure(codexCodecFailureCorrelation, fmt.Errorf("Codex response id %s has no pending client request", key))
			}
			pendingDelete = c.clientPending
			patterns = c.config.manifest.ClientResponses[method]
			if method == "hooks/list" {
				var aliasesExist bool
				responseHooksListAliases, aliasesExist = c.clientHooksListAliases[key]
				if !aliasesExist {
					return nil, newCodexCodecFailure(codexCodecFailureCorrelation, errors.New("Codex hooks/list response has no pending cwd alias context"))
				}
				deleteHooksListAliases = true
			}
		}
		pendingKey = key
		if hasError {
			patterns = nil
		}
	}
	for _, pattern := range patterns {
		var patternChanged bool
		var patternErr error
		if pattern.Kind == "thread-start-runtime-root-alias" {
			switch {
			case method != "thread/start" || pattern.Pointer != "/params/runtimeWorkspaceRoots/*":
				patternErr = errors.New("thread/start workspace-root alias pattern is attached outside its pinned field")
			case direction != codexPathsToServer || !hasID:
				patternErr = errors.New("thread/start workspace-root alias pattern is attached to an unsupported frame")
			default:
				patternChanged, patternErr = c.transformThreadStartRuntimeWorkspaceRoots(value)
			}
		} else if pattern.Kind == "hooks-list-cwd-alias" {
			switch {
			case method != "hooks/list":
				patternErr = errors.New("hooks/list cwd alias pattern is attached to another method")
			case direction == codexPathsToServer && hasID:
				hooksListAliases, patternChanged, patternErr = c.transformHooksListRequest(value)
			case direction == codexPathsToClient && hasID:
				patternChanged, patternErr = c.transformHooksListResponse(value, responseHooksListAliases)
			default:
				patternErr = errors.New("hooks/list cwd alias pattern is attached to an unsupported frame")
			}
		} else if pattern.Kind == "skills-list-cwd-alias" {
			switch {
			case method != "skills/list" || pattern.Pointer != "/params/cwds/*":
				patternErr = errors.New("skills/list cwd alias pattern is attached outside its pinned field")
			case direction != codexPathsToServer || !hasID:
				patternErr = errors.New("skills/list cwd alias pattern is attached to an unsupported frame")
			default:
				patternChanged, patternErr = c.transformSkillsListRequest(value)
			}
		} else if pattern.Kind == "native-launch-cwd-alias" {
			switch {
			case direction != codexPathsToServer || !hasID:
				patternErr = errors.New("native launch cwd alias pattern is attached to an unsupported frame")
			case method == "plugin/list" && pattern.Pointer == "/params/cwds/*":
				patternChanged, patternErr = c.transformNativeLaunchCWDList(value, method, "cwds")
			case method == "thread/resume" && pattern.Pointer == "/params/runtimeWorkspaceRoots/*":
				patternChanged, patternErr = c.transformNativeLaunchCWDList(value, method, "runtimeWorkspaceRoots")
			case method == "thread/fork" && pattern.Pointer == "/params/runtimeWorkspaceRoots/*":
				patternChanged, patternErr = c.transformNativeLaunchCWDList(value, method, "runtimeWorkspaceRoots")
			case method == "command/exec" && pattern.Pointer == "/params/cwd":
				patternChanged, patternErr = c.transformNativeLaunchCWDScalar(value, method, "cwd")
			default:
				patternErr = errors.New("native launch cwd alias pattern is attached outside its pinned fields")
			}
		} else {
			parts, _ := parseCodexPointer(pattern.Pointer)
			pathKind := pattern.Kind
			switch pathKind {
			case "path-or-array":
				pathKind = "path"
			case "path-map-keys", "project-key-path", "project-disabled-reason":
				pathKind = "absolute"
			}
			patternChanged, patternErr = applyCodexPathPattern(value, value, parts, pattern, nil, func(raw string) (string, error) {
				return c.transformPath(raw, pathKind, direction)
			})
		}
		if patternErr != nil {
			return nil, newCodexCodecFailure(codexCodecFailurePathField, fmt.Errorf("Codex %s path field %s: %w", method, pattern.Pointer, patternErr))
		}
		changed = changed || patternChanged
	}
	output := data
	if changed {
		output, err = encodeCodexFrame(value)
		if err != nil {
			return nil, newCodexCodecFailure(codexCodecFailureEncode, err)
		}
	}
	if pendingAdd != nil {
		pendingAdd[pendingKey] = method
	}
	if addHooksListAliases {
		c.clientHooksListAliases[pendingKey] = hooksListAliases
	}
	if pendingDelete != nil {
		delete(pendingDelete, pendingKey)
	}
	if deleteHooksListAliases {
		delete(c.clientHooksListAliases, pendingKey)
	}
	return output, nil
}

func (c *codexPathCodec) transformThreadStartRuntimeWorkspaceRoots(value map[string]any) (bool, error) {
	paramsRaw, exists := value["params"]
	if !exists {
		return false, nil
	}
	params, ok := paramsRaw.(map[string]any)
	if !ok {
		return false, fmt.Errorf("expected thread/start params object, got %T", paramsRaw)
	}
	rootsRaw, exists := params["runtimeWorkspaceRoots"]
	if !exists || rootsRaw == nil {
		return false, nil
	}
	roots, ok := rootsRaw.([]any)
	if !ok {
		return false, fmt.Errorf("expected thread/start runtimeWorkspaceRoots array, got %T", rootsRaw)
	}
	if len(roots) > maxThreadStartWorkspaceRoots {
		return false, fmt.Errorf("thread/start runtime workspace root count %d exceeds limit %d", len(roots), maxThreadStartWorkspaceRoots)
	}
	changed := false
	for index, item := range roots {
		raw, ok := item.(string)
		if !ok {
			return false, fmt.Errorf("expected thread/start runtime workspace root string at index %d, got %T", index, item)
		}
		updated := ""
		var err error
		if sameNormalizedWindowsPath(raw, c.config.nativeLaunchCWD) {
			updated = c.config.remoteRoot
		} else {
			updated, err = c.transformPath(raw, "absolute", codexPathsToServer)
			if err != nil {
				return false, err
			}
		}
		if updated != raw {
			roots[index] = updated
			changed = true
		}
	}
	return changed, nil
}

func (c *codexPathCodec) transformHooksListRequest(value map[string]any) ([]codexHooksListCWDAlias, bool, error) {
	paramsRaw, exists := value["params"]
	if !exists {
		return nil, false, nil
	}
	params, ok := paramsRaw.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("expected hooks/list params object, got %T", paramsRaw)
	}
	cwdsRaw, exists := params["cwds"]
	if !exists {
		return nil, false, nil
	}
	cwds, ok := cwdsRaw.([]any)
	if !ok {
		return nil, false, fmt.Errorf("expected hooks/list cwds array, got %T", cwdsRaw)
	}
	if len(cwds) > maxHooksListCWDEntries {
		return nil, false, fmt.Errorf("hooks/list cwd count %d exceeds limit %d", len(cwds), maxHooksListCWDEntries)
	}
	aliases := make([]codexHooksListCWDAlias, len(cwds))
	changed := false
	for index, item := range cwds {
		raw, ok := item.(string)
		if !ok {
			return nil, false, fmt.Errorf("expected hooks/list cwd string at index %d, got %T", index, item)
		}
		updated := ""
		aliased := sameNormalizedWindowsPath(raw, c.config.nativeLaunchCWD)
		var err error
		if aliased {
			updated = c.config.remoteRoot
		} else {
			updated, err = c.transformPath(raw, "path", codexPathsToServer)
			if err != nil {
				return nil, false, err
			}
		}
		aliases[index] = codexHooksListCWDAlias{clientPath: raw, serverPath: updated, aliased: aliased}
		if updated != raw {
			cwds[index] = updated
			changed = true
		}
	}
	return aliases, changed, nil
}

func (c *codexPathCodec) transformHooksListResponse(value map[string]any, aliases []codexHooksListCWDAlias) (bool, error) {
	resultRaw, exists := value["result"]
	if !exists {
		return false, errors.New("hooks/list response has no result")
	}
	result, ok := resultRaw.(map[string]any)
	if !ok {
		return false, fmt.Errorf("expected hooks/list result object, got %T", resultRaw)
	}
	dataRaw, exists := result["data"]
	if !exists {
		return false, errors.New("hooks/list response has no data")
	}
	data, ok := dataRaw.([]any)
	if !ok {
		return false, fmt.Errorf("expected hooks/list data array, got %T", dataRaw)
	}
	if len(aliases) != 0 && len(data) != len(aliases) {
		return false, fmt.Errorf("hooks/list response cwd count %d does not match request count %d", len(data), len(aliases))
	}
	changed := false
	for index, item := range data {
		entry, ok := item.(map[string]any)
		if !ok {
			return false, fmt.Errorf("expected hooks/list data object at index %d, got %T", index, item)
		}
		cwdRaw, exists := entry["cwd"]
		if !exists {
			return false, fmt.Errorf("hooks/list data object at index %d has no cwd", index)
		}
		cwd, ok := cwdRaw.(string)
		if !ok {
			return false, fmt.Errorf("expected hooks/list response cwd string at index %d, got %T", index, cwdRaw)
		}
		updated := ""
		var err error
		if index < len(aliases) && aliases[index].aliased {
			if cwd != aliases[index].serverPath {
				return false, fmt.Errorf("hooks/list response cwd at index %d does not match its aliased request", index)
			}
			updated = aliases[index].clientPath
		} else {
			updated, err = c.transformPath(cwd, "path", codexPathsToClient)
			if err != nil {
				return false, err
			}
		}
		if updated != cwd {
			entry["cwd"] = updated
			changed = true
		}
	}
	return changed, nil
}

func (c *codexPathCodec) transformSkillsListRequest(value map[string]any) (bool, error) {
	paramsRaw, exists := value["params"]
	if !exists {
		return false, nil
	}
	params, ok := paramsRaw.(map[string]any)
	if !ok {
		return false, fmt.Errorf("expected skills/list params object, got %T", paramsRaw)
	}
	cwdsRaw, exists := params["cwds"]
	if !exists {
		return false, nil
	}
	cwds, ok := cwdsRaw.([]any)
	if !ok {
		return false, fmt.Errorf("expected skills/list cwds array, got %T", cwdsRaw)
	}
	if len(cwds) > maxSkillsListCWDEntries {
		return false, fmt.Errorf("skills/list cwd count %d exceeds limit %d", len(cwds), maxSkillsListCWDEntries)
	}
	changed := false
	for index, item := range cwds {
		raw, ok := item.(string)
		if !ok {
			return false, fmt.Errorf("expected skills/list cwd string at index %d, got %T", index, item)
		}
		updated := ""
		var err error
		if sameNormalizedWindowsPath(raw, c.config.nativeLaunchCWD) {
			updated = c.config.remoteRoot
		} else {
			updated, err = c.transformPath(raw, "path", codexPathsToServer)
			if err != nil {
				return false, err
			}
		}
		if updated != raw {
			cwds[index] = updated
			changed = true
		}
	}
	return changed, nil
}

func (c *codexPathCodec) transformNativeLaunchCWDList(value map[string]any, method, field string) (bool, error) {
	paramsRaw, exists := value["params"]
	if !exists {
		return false, nil
	}
	params, ok := paramsRaw.(map[string]any)
	if !ok {
		return false, fmt.Errorf("expected %s params object, got %T", method, paramsRaw)
	}
	valuesRaw, exists := params[field]
	if !exists || valuesRaw == nil {
		return false, nil
	}
	values, ok := valuesRaw.([]any)
	if !ok {
		return false, fmt.Errorf("expected %s %s array, got %T", method, field, valuesRaw)
	}
	if len(values) > maxNativeLaunchCWDEntries {
		return false, fmt.Errorf("%s %s count %d exceeds limit %d", method, field, len(values), maxNativeLaunchCWDEntries)
	}
	changed := false
	for index, item := range values {
		raw, ok := item.(string)
		if !ok {
			return false, fmt.Errorf("expected %s %s string at index %d, got %T", method, field, index, item)
		}
		updated, err := c.transformNativeLaunchCWD(raw)
		if err != nil {
			return false, err
		}
		if updated != raw {
			values[index] = updated
			changed = true
		}
	}
	return changed, nil
}

func (c *codexPathCodec) transformNativeLaunchCWDScalar(value map[string]any, method, field string) (bool, error) {
	paramsRaw, exists := value["params"]
	if !exists {
		return false, nil
	}
	params, ok := paramsRaw.(map[string]any)
	if !ok {
		return false, fmt.Errorf("expected %s params object, got %T", method, paramsRaw)
	}
	rawValue, exists := params[field]
	if !exists || rawValue == nil {
		return false, nil
	}
	raw, ok := rawValue.(string)
	if !ok {
		return false, fmt.Errorf("expected %s %s string, got %T", method, field, rawValue)
	}
	updated, err := c.transformNativeLaunchCWD(raw)
	if err != nil {
		return false, err
	}
	if updated == raw {
		return false, nil
	}
	params[field] = updated
	return true, nil
}

func (c *codexPathCodec) transformNativeLaunchCWD(raw string) (string, error) {
	if sameNormalizedWindowsPath(raw, c.config.nativeLaunchCWD) {
		return c.config.remoteRoot, nil
	}
	return c.transformPath(raw, "absolute", codexPathsToServer)
}

func (c *codexPathCodec) transformPath(raw, kind string, direction codexPathDirection) (string, error) {
	if raw == "" && kind == "path" {
		return raw, nil
	}
	if direction == codexPathsToClient {
		if canonicalRemotePath(raw) {
			return c.config.remoteToLocal(raw), nil
		}
		if kind == "path" && !looksAbsolutePath(raw) {
			return raw, nil
		}
		return "", fmt.Errorf("remote value %q is not a normalized absolute POSIX path", raw)
	}
	if decoded, ok, err := c.config.localToRemote(raw); err != nil {
		return "", err
	} else if ok {
		return decoded, nil
	}
	if canonicalRemotePath(raw) {
		return raw, nil
	}
	if kind == "path" && !looksAbsolutePath(raw) {
		return raw, nil
	}
	return "", fmt.Errorf("client value %q is outside the Paperboat remote path namespace", raw)
}

func (c *codexPathCodecConfig) remoteToLocal(remote string) string {
	if remote == "/" {
		return c.localPrefix
	}
	parts := strings.Split(strings.TrimPrefix(remote, "/"), "/")
	for index := range parts {
		parts[index] = encodeRemoteSegment(parts[index])
	}
	return c.localPrefix + `\` + strings.Join(parts, `\`)
}

func (c *codexPathCodecConfig) localToRemote(local string) (string, bool, error) {
	normalized := strings.ReplaceAll(local, "/", `\`)
	prefix := c.localPrefix
	if len(normalized) < len(prefix) || !strings.EqualFold(normalized[:len(prefix)], prefix) {
		return "", false, nil
	}
	if len(normalized) == len(prefix) {
		return "/", true, nil
	}
	if normalized[len(prefix)] != '\\' {
		return "", false, nil
	}
	encoded := strings.Split(normalized[len(prefix)+1:], `\`)
	parts := make([]string, len(encoded))
	for index, segment := range encoded {
		decoded, err := decodeRemoteSegment(segment)
		if err != nil {
			return "", true, err
		}
		parts[index] = decoded
	}
	remote := "/" + strings.Join(parts, "/")
	if !canonicalRemotePath(remote) {
		return "", true, fmt.Errorf("decoded remote path %q is not normalized", remote)
	}
	return remote, true, nil
}

func decodeCodexFrame(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode Codex app-server frame: %w", err)
	}
	if value == nil {
		return nil, errors.New("Codex app-server frame is not an object")
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, errors.New("Codex app-server frame contains multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode Codex app-server frame trailer: %w", err)
	}
	if version, exists := value["jsonrpc"]; exists && version != "2.0" {
		return nil, errors.New("Codex app-server frame has an invalid jsonrpc version")
	}
	return value, nil
}

func encodeCodexFrame(value map[string]any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("encode Codex app-server frame: %w", err)
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func codexRequestID(value any) (string, error) {
	switch id := value.(type) {
	case string:
		return "s:" + id, nil
	case json.Number:
		if id == "" {
			return "", errors.New("Codex request has an empty numeric id")
		}
		return "n:" + id.String(), nil
	default:
		return "", errors.New("Codex request id must be a string or number")
	}
}

func validateCodexRequest(pending map[string]string, key string) error {
	if _, exists := pending[key]; exists {
		return fmt.Errorf("duplicate pending Codex request id %s", key)
	}
	if len(pending) >= maxPendingCodexRequests {
		return errors.New("too many pending Codex app-server requests")
	}
	return nil
}

func parseCodexPointer(pointer string) ([]string, error) {
	if pointer == "" || pointer[0] != '/' {
		return nil, errors.New("JSON pointer must start with /")
	}
	raw := strings.Split(pointer[1:], "/")
	parts := make([]string, len(raw))
	for index, part := range raw {
		part = strings.ReplaceAll(part, "~1", "/")
		part = strings.ReplaceAll(part, "~0", "~")
		if part == "" {
			return nil, errors.New("JSON pointer contains an empty part")
		}
		parts[index] = part
	}
	return parts, nil
}

func parseOptionalCodexPointer(pointer string) ([]string, error) {
	if pointer == "" {
		return nil, nil
	}
	return parseCodexPointer(pointer)
}

func applyCodexPathPattern(root, node any, parts []string, pattern codexPathPattern, wildcardValues []string, transform func(string) (string, error)) (bool, error) {
	if node == nil {
		return false, nil
	}
	if len(parts) == 0 {
		return false, errors.New("path pattern cannot replace a detached scalar")
	}
	part := parts[0]
	switch current := node.(type) {
	case map[string]any:
		if part == "*" {
			keys := make([]string, 0, len(current))
			for key := range current {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			changed := false
			for _, key := range keys {
				itemChanged, err := applyCodexPathValue(root, current, key, parts[1:], pattern, appendWildcardValue(wildcardValues, key), transform)
				if err != nil {
					return false, err
				}
				changed = changed || itemChanged
			}
			return changed, nil
		}
		if _, exists := current[part]; !exists {
			return false, nil
		}
		return applyCodexPathValue(root, current, part, parts[1:], pattern, wildcardValues, transform)
	case []any:
		if part != "*" {
			return false, fmt.Errorf("expected array wildcard, got %q", part)
		}
		changed := false
		for index := range current {
			itemChanged, err := applyCodexArrayValue(root, current, index, parts[1:], pattern, appendWildcardValue(wildcardValues, strconv.Itoa(index)), transform)
			if err != nil {
				return false, err
			}
			changed = changed || itemChanged
		}
		return changed, nil
	default:
		return false, fmt.Errorf("encountered %T before path pattern ended", node)
	}
}

func applyCodexPathValue(root any, parent map[string]any, key string, rest []string, pattern codexPathPattern, wildcardValues []string, transform func(string) (string, error)) (bool, error) {
	if len(rest) != 0 {
		return applyCodexPathPattern(root, parent[key], rest, pattern, wildcardValues, transform)
	}
	if parent[key] == nil {
		return false, nil
	}
	transformVariant, err := codexPathVariantDisposition(root, pattern, wildcardValues)
	if err != nil {
		return false, err
	}
	if !transformVariant {
		return false, nil
	}
	if pattern.Kind == "path-or-array" {
		return applyCodexPathOrArray(parent, key, transform)
	}
	if pattern.Kind == "path-map-keys" {
		return applyCodexPathMapKeys(parent, key, transform)
	}
	raw, ok := parent[key].(string)
	if !ok {
		return false, fmt.Errorf("expected string at %q, got %T", key, parent[key])
	}
	var updated string
	if pattern.Kind == "project-key-path" {
		updated, err = transformCodexProjectKeyPath(raw, transform)
	} else if pattern.Kind == "project-disabled-reason" {
		updated, err = transformCodexProjectDisabledReason(raw, transform)
	} else {
		updated, err = transform(raw)
	}
	if err != nil {
		return false, err
	}
	if updated == raw {
		return false, nil
	}
	parent[key] = updated
	return true, nil
}

func applyCodexArrayValue(root any, parent []any, index int, rest []string, pattern codexPathPattern, wildcardValues []string, transform func(string) (string, error)) (bool, error) {
	if len(rest) != 0 {
		return applyCodexPathPattern(root, parent[index], rest, pattern, wildcardValues, transform)
	}
	if parent[index] == nil {
		return false, nil
	}
	transformVariant, err := codexPathVariantDisposition(root, pattern, wildcardValues)
	if err != nil {
		return false, err
	}
	if !transformVariant {
		return false, nil
	}
	raw, ok := parent[index].(string)
	if !ok {
		return false, fmt.Errorf("expected string at array index %d, got %T", index, parent[index])
	}
	updated, err := transform(raw)
	if err != nil {
		return false, err
	}
	if updated == raw {
		return false, nil
	}
	parent[index] = updated
	return true, nil
}

func codexPathVariantDisposition(root any, pattern codexPathPattern, wildcardValues []string) (bool, error) {
	if len(pattern.Variants) == 0 && len(pattern.IgnoredVariants) == 0 {
		return true, nil
	}
	parts, _ := parseCodexPointer(pattern.VariantPointer)
	value, exists, err := codexValueAtPointer(root, parts, wildcardValues)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, errors.New("variant-scoped path has no type discriminator")
	}
	variant, ok := value.(string)
	if !ok || variant == "" {
		return false, errors.New("variant-scoped path has no string type discriminator")
	}
	if stringInSlice(pattern.Variants, variant) {
		return true, nil
	}
	if stringInSlice(pattern.IgnoredVariants, variant) {
		return false, nil
	}
	return false, fmt.Errorf("variant-scoped path has unexpected type %q", variant)
}

func appendWildcardValue(values []string, value string) []string {
	out := make([]string, len(values)+1)
	copy(out, values)
	out[len(values)] = value
	return out
}

func codexValueAtPointer(root any, parts, wildcardValues []string) (any, bool, error) {
	current := root
	wildcardIndex := 0
	for _, part := range parts {
		if part == "*" {
			if wildcardIndex >= len(wildcardValues) {
				return nil, false, errors.New("variant pointer has more wildcards than its path field")
			}
			part = wildcardValues[wildcardIndex]
			wildcardIndex++
		}
		switch node := current.(type) {
		case map[string]any:
			value, exists := node[part]
			if !exists {
				return nil, false, nil
			}
			current = value
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				return nil, false, fmt.Errorf("variant pointer has invalid array index %q", part)
			}
			current = node[index]
		default:
			return nil, false, fmt.Errorf("variant pointer encountered %T before it ended", current)
		}
	}
	return current, true, nil
}

func applyCodexPathOrArray(parent map[string]any, key string, transform func(string) (string, error)) (bool, error) {
	switch value := parent[key].(type) {
	case string:
		updated, err := transform(value)
		if err != nil {
			return false, err
		}
		if updated == value {
			return false, nil
		}
		parent[key] = updated
		return true, nil
	case []any:
		changed := false
		for index, item := range value {
			raw, ok := item.(string)
			if !ok {
				return false, fmt.Errorf("expected string at array index %d, got %T", index, item)
			}
			updated, err := transform(raw)
			if err != nil {
				return false, err
			}
			if updated != raw {
				value[index] = updated
				changed = true
			}
		}
		return changed, nil
	default:
		return false, fmt.Errorf("expected string or string array at %q, got %T", key, parent[key])
	}
}

func applyCodexPathMapKeys(parent map[string]any, key string, transform func(string) (string, error)) (bool, error) {
	values, ok := parent[key].(map[string]any)
	if !ok {
		return false, fmt.Errorf("expected object at %q, got %T", key, parent[key])
	}
	keys := make([]string, 0, len(values))
	for valueKey := range values {
		keys = append(keys, valueKey)
	}
	sort.Strings(keys)
	updatedValues := make(map[string]any, len(values))
	changed := false
	for _, valueKey := range keys {
		updatedKey, err := transform(valueKey)
		if err != nil {
			return false, err
		}
		if _, exists := updatedValues[updatedKey]; exists {
			return false, fmt.Errorf("path-map keys %q and another key collide after translation", valueKey)
		}
		updatedValues[updatedKey] = values[valueKey]
		changed = changed || updatedKey != valueKey
	}
	if changed {
		parent[key] = updatedValues
	}
	return changed, nil
}

func transformCodexProjectKeyPath(raw string, transform func(string) (string, error)) (string, error) {
	const prefix = `projects.`
	if raw != "projects" && !strings.HasPrefix(raw, prefix) {
		return raw, nil
	}
	if !strings.HasPrefix(raw, prefix+`"`) {
		return "", fmt.Errorf("unsupported project config key path %q", raw)
	}
	quotedStart := len(prefix)
	quotedEnd := -1
	escaped := false
	for index := quotedStart + 1; index < len(raw); index++ {
		switch {
		case escaped:
			escaped = false
		case raw[index] == '\\':
			escaped = true
		case raw[index] == '"':
			quotedEnd = index
			index = len(raw)
		}
	}
	if quotedEnd < 0 || raw[quotedEnd+1:] != ".trust_level" {
		return "", fmt.Errorf("unsupported project config key path %q", raw)
	}
	var projectPath string
	if err := json.Unmarshal([]byte(raw[quotedStart:quotedEnd+1]), &projectPath); err != nil {
		return "", fmt.Errorf("decode project config path: %w", err)
	}
	updated, err := transform(projectPath)
	if err != nil {
		return "", err
	}
	quoted, err := json.Marshal(updated)
	if err != nil {
		return "", fmt.Errorf("encode project config path: %w", err)
	}
	return prefix + string(quoted) + ".trust_level", nil
}

func transformCodexProjectDisabledReason(raw string, transform func(string) (string, error)) (string, error) {
	const untrusted = " is marked as untrusted"
	if end := strings.LastIndex(raw, untrusted); end > 0 {
		projectPath := raw[:end]
		if canonicalRemotePath(projectPath) {
			updated, err := transform(projectPath)
			if err != nil {
				return "", err
			}
			return updated + raw[end:], nil
		}
	}
	const add = ", add "
	const trusted = " as a trusted project in "
	start := strings.Index(raw, add)
	end := strings.LastIndex(raw, trusted)
	if start < 0 || end <= start+len(add) {
		return raw, nil
	}
	start += len(add)
	updated, err := transform(raw[start:end])
	if err != nil {
		return "", err
	}
	return raw[:start] + updated + raw[end:], nil
}

func stringInSlice(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func hasCodexPathPattern(patterns []codexPathPattern, pointer, kind string) bool {
	found := false
	for _, pattern := range patterns {
		if pattern.Pointer != pointer {
			continue
		}
		if found || pattern.Kind != kind || pattern.VariantPointer != "" || len(pattern.Variants) != 0 || len(pattern.IgnoredVariants) != 0 {
			return false
		}
		found = true
	}
	return found
}

func sameNormalizedWindowsPath(left, right string) bool {
	left, leftOK := normalizeWindowsDriveAbsolutePath(left)
	right, rightOK := normalizeWindowsDriveAbsolutePath(right)
	return leftOK && rightOK && strings.EqualFold(left, right)
}

func normalizeWindowsDriveAbsolutePath(value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, 0) {
		return "", false
	}
	normalized := strings.ReplaceAll(value, `\`, "/")
	if len(normalized) < 3 || !asciiLetter(normalized[0]) || normalized[1] != ':' || normalized[2] != '/' {
		return "", false
	}
	if strings.Contains(normalized[2:], ":") {
		return "", false
	}
	cleaned := pathpkg.Clean(normalized)
	if len(cleaned) < 3 || cleaned[1] != ':' || cleaned[2] != '/' {
		return "", false
	}
	return cleaned, true
}

func stringSlicesExactly(left, right []string) bool {
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

func canonicalRemotePath(value string) bool {
	return value != "" && strings.HasPrefix(value, "/") && !strings.ContainsRune(value, 0) && pathpkg.Clean(value) == value
}

func looksAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") || looksWindowsAbsolute(value)
}

func looksWindowsAbsolute(value string) bool {
	if len(value) >= 3 && asciiLetter(value[0]) && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
		return true
	}
	return strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, "//")
}

func safeCodecNonce(value string) bool {
	if len(value) < 16 || len(value) > 64 {
		return false
	}
	for index := range value {
		if !(asciiLetter(value[index]) || value[index] >= '0' && value[index] <= '9' || value[index] == '-' || value[index] == '_') {
			return false
		}
	}
	return true
}

func asciiLetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func encodeRemoteSegment(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var output strings.Builder
	output.Grow(len(value) * 3)
	for index := 0; index < len(value); index++ {
		b := value[index]
		output.WriteByte('%')
		output.WriteByte(hexDigits[b>>4])
		output.WriteByte(hexDigits[b&15])
	}
	return output.String()
}

func decodeRemoteSegment(value string) (string, error) {
	if value == "" || len(value)%3 != 0 {
		return "", errors.New("invalid encoded remote path segment")
	}
	decoded := make([]byte, 0, len(value)/3)
	for index := 0; index < len(value); index += 3 {
		if value[index] != '%' {
			return "", errors.New("remote path segment contains an unescaped byte")
		}
		high, okHigh := hexNibble(value[index+1])
		low, okLow := hexNibble(value[index+2])
		if !okHigh || !okLow {
			return "", errors.New("remote path segment has an invalid escape")
		}
		decoded = append(decoded, high<<4|low)
	}
	if !utf8.Valid(decoded) || bytes.IndexByte(decoded, 0) >= 0 || bytes.IndexByte(decoded, '/') >= 0 {
		return "", errors.New("remote path segment does not decode to a valid JSON path component")
	}
	return string(decoded), nil
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}
