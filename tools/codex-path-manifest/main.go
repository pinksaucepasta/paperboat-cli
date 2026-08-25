// Command codex-path-manifest generates the version-pinned app-server path
// manifest used by Paperboat's native-Windows remote Codex bridge.
//
// Source of truth: the generated JSON schemas and request/response declarations
// from an official openai/codex checkout at rust-v0.149.1. The command refuses
// any other commit so a later protocol cannot silently inherit this manifest.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	manifestSchema = "paperboat.codex-path-manifest/v1"
	codexVersion   = "0.149.1"
	sourceTag      = "rust-v0.149.1"
	sourceCommit   = "ff29a44391deccde0aba0f8390337d7f3c319ea4"
)

type pathPattern struct {
	Pointer         string   `json:"pointer"`
	Kind            string   `json:"kind"`
	VariantPointer  string   `json:"variant_pointer,omitempty"`
	Variants        []string `json:"variants,omitempty"`
	IgnoredVariants []string `json:"ignored_variants,omitempty"`
}

type manifest struct {
	Schema                       string                   `json:"schema"`
	CodexVersion                 string                   `json:"codex_version"`
	SourceTag                    string                   `json:"source_tag"`
	SourceCommit                 string                   `json:"source_commit"`
	InputsSHA256                 string                   `json:"inputs_sha256"`
	ClientRequests               map[string][]pathPattern `json:"client_requests"`
	ClientNotifications          map[string][]pathPattern `json:"client_notifications"`
	ClientResponses              map[string][]pathPattern `json:"client_responses"`
	ServerRequests               map[string][]pathPattern `json:"server_requests"`
	ServerNotifications          map[string][]pathPattern `json:"server_notifications"`
	ServerResponses              map[string][]pathPattern `json:"server_responses"`
	PreservedClientResponsePaths map[string][]string      `json:"preserved_client_response_paths"`
}

type schemaDoc struct {
	Root        map[string]any
	Definitions map[string]any
}

type recorder struct {
	root  string
	files map[string][]byte
}

type schemaStore map[string][]byte

func main() {
	var source, output string
	flag.StringVar(&source, "source", "", "official openai/codex checkout at rust-v0.149.1")
	flag.StringVar(&output, "output", "", "manifest output path")
	flag.Parse()
	if source == "" || output == "" {
		fatal(errors.New("-source and -output are required"))
	}
	absSource, err := filepath.Abs(source)
	if err != nil {
		fatal(err)
	}
	if err := verifyCommit(absSource); err != nil {
		fatal(err)
	}
	r := &recorder{root: absSource, files: make(map[string][]byte)}
	protocolPath := filepath.Join(absSource, "codex-rs", "app-server-protocol", "src", "protocol", "common.rs")
	schemas, err := loadExperimentalSchemas(r, absSource)
	if err != nil {
		fatal(err)
	}

	clientRequests, err := envelopeManifest(schemas, "ClientRequest.json")
	if err != nil {
		fatal(err)
	}
	clientNotifications, err := envelopeManifest(schemas, "ClientNotification.json")
	if err != nil {
		fatal(err)
	}
	serverRequests, err := envelopeManifest(schemas, "ServerRequest.json")
	if err != nil {
		fatal(err)
	}
	serverNotifications, err := envelopeManifest(schemas, "ServerNotification.json")
	if err != nil {
		fatal(err)
	}
	protocol, err := r.read(protocolPath)
	if err != nil {
		fatal(err)
	}
	allClientResponseTypes, err := requestResponseTypes(protocol, "client_request_definitions!", "server_request_definitions!")
	if err != nil {
		fatal(err)
	}
	clientResponseTypes := filterResponseTypes(allClientResponseTypes, clientRequests)
	serverResponseTypes, err := requestResponseTypes(protocol, "server_request_definitions!", "}")
	if err != nil {
		fatal(err)
	}
	serverResponseTypes = filterResponseTypes(serverResponseTypes, serverRequests)
	clientResponses, err := responseManifest(schemas, clientResponseTypes)
	if err != nil {
		fatal(err)
	}
	serverResponses, err := responseManifest(schemas, serverResponseTypes)
	if err != nil {
		fatal(err)
	}
	if err := augmentDeprecatedClientMethods(r, absSource, clientRequests, clientResponses); err != nil {
		fatal(err)
	}
	if err := augmentRemoteProjectTrustPaths(r, absSource, clientRequests, clientResponses); err != nil {
		fatal(err)
	}
	preservedClientResponsePaths, err := preserveForeignAwareClientPaths(r, absSource, clientResponses)
	if err != nil {
		fatal(err)
	}
	serverNotificationMethods, err := notificationMethods(protocol, "server_notification_definitions!")
	if err != nil {
		fatal(err)
	}
	for _, method := range []string{"rawResponseItem/completed", "rawResponse/completed"} {
		if _, declared := serverNotificationMethods[method]; !declared {
			fatal(fmt.Errorf("pinned protocol no longer declares %s", method))
		}
		if _, exists := serverNotifications[method]; !exists {
			serverNotifications[method] = []pathPattern{}
		}
	}
	if err := requireExactMethods("client requests", clientRequests, allClientResponseTypes); err != nil {
		fatal(err)
	}
	if err := requireExactMethods("client responses", clientResponses, allClientResponseTypes); err != nil {
		fatal(err)
	}
	if err := requireExactMethods("server requests", serverRequests, serverResponseTypes); err != nil {
		fatal(err)
	}
	if err := requireExactMethods("server responses", serverResponses, serverResponseTypes); err != nil {
		fatal(err)
	}
	if err := requireExactMethods("server notifications", serverNotifications, serverNotificationMethods); err != nil {
		fatal(err)
	}
	m := manifest{
		Schema: manifestSchema, CodexVersion: codexVersion, SourceTag: sourceTag,
		SourceCommit: sourceCommit, InputsSHA256: r.digest(),
		ClientRequests: clientRequests, ClientNotifications: clientNotifications,
		ClientResponses: clientResponses, ServerRequests: serverRequests,
		ServerNotifications: serverNotifications, ServerResponses: serverResponses,
		PreservedClientResponsePaths: preservedClientResponsePaths,
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fatal(err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(output, body, 0o644); err != nil {
		fatal(err)
	}
}

func augmentRemoteProjectTrustPaths(r *recorder, source string, requests, responses map[string][]pathPattern) error {
	checks := map[string][]string{
		filepath.Join(source, "codex-rs", "tui", "src", "config_update.rs"): {
			`response["config"]["projects"].as_object()`,
			`layer["name"]["dotCodexFolder"].as_str()`,
			`format!("projects.\"{project_key}\".trust_level")`,
		},
		filepath.Join(source, "codex-rs", "app-server-protocol", "src", "protocol", "v2", "config.rs"): {
			`pub additional: HashMap<String, JsonValue>`,
			`pub config: JsonValue`,
			`pub key_path: String`,
		},
		filepath.Join(source, "codex-rs", "config", "src", "loader", "mod.rs"): {
			`{trust_key} is marked as untrusted in the effective configuration.`,
			`add {trust_key} as a trusted project in {user_config_file}.`,
		},
	}
	for file, markers := range checks {
		body, err := r.read(file)
		if err != nil {
			return err
		}
		for _, marker := range markers {
			if !bytes.Contains(body, []byte(marker)) {
				return fmt.Errorf("pinned remote project-trust consumer %s no longer contains %q", file, marker)
			}
		}
	}
	for _, method := range []string{"config/batchWrite", "config/value/write", "config/read"} {
		if _, ok := requests[method]; !ok {
			return fmt.Errorf("pinned protocol no longer declares %s", method)
		}
	}
	if _, ok := responses["config/read"]; !ok {
		return errors.New("pinned protocol has no config/read response")
	}
	requests["config/batchWrite"] = append(requests["config/batchWrite"], pathPattern{
		Pointer: "/params/edits/*/keyPath", Kind: "project-key-path",
	})
	requests["config/value/write"] = append(requests["config/value/write"], pathPattern{
		Pointer: "/params/keyPath", Kind: "project-key-path",
	})
	responses["config/read"] = append(responses["config/read"], pathPattern{
		Pointer: "/result/config/projects", Kind: "path-map-keys",
	})
	responses["config/read"] = append(responses["config/read"], pathPattern{
		Pointer: "/result/layers/*/disabledReason", Kind: "project-disabled-reason",
	})
	sortPathPatterns(requests["config/batchWrite"])
	sortPathPatterns(requests["config/value/write"])
	sortPathPatterns(responses["config/read"])
	return nil
}

func preserveForeignAwareClientPaths(r *recorder, source string, responses map[string][]pathPattern) (map[string][]string, error) {
	checks := map[string][]string{
		filepath.Join(source, "codex-rs", "app-server-client", "src", "remote.rs"): {
			`.get("codexHome")`,
			`.map(str::to_string)`,
		},
		filepath.Join(source, "codex-rs", "app-server-client", "src", "path.rs"): {
			`pub struct AppServerPath(String);`,
			`pub fn from_app_server(path: impl Into<String>)`,
		},
		filepath.Join(source, "codex-rs", "tui", "src", "goal_files.rs"): {
			`write_goal_file(app_server, path.clone()`,
			`format!("pasted text file: {path}. Read this file before continuing.")`,
		},
	}
	for file, markers := range checks {
		body, err := r.read(file)
		if err != nil {
			return nil, err
		}
		for _, marker := range markers {
			if !bytes.Contains(body, []byte(marker)) {
				return nil, fmt.Errorf("pinned foreign-path consumer %s no longer contains %q", file, marker)
			}
		}
	}
	const pointer = "/result/codexHome"
	patterns := responses["initialize"]
	filtered := make([]pathPattern, 0, len(patterns))
	found := false
	for _, pattern := range patterns {
		if pattern.Pointer == pointer && pattern.Kind == "absolute" {
			found = true
			continue
		}
		filtered = append(filtered, pattern)
	}
	if !found {
		return nil, errors.New("experimental schema no longer exposes initialize.result.codexHome as AbsolutePathBuf")
	}
	responses["initialize"] = filtered
	return map[string][]string{"initialize": {pointer}}, nil
}

func augmentDeprecatedClientMethods(r *recorder, source string, requests, responses map[string][]pathPattern) error {
	protocolPath := filepath.Join(source, "codex-rs", "app-server-protocol", "src", "protocol", "v1.rs")
	body, err := r.read(protocolPath)
	if err != nil {
		return err
	}
	required := []string{
		"pub enum GetConversationSummaryParams",
		"rollout_path: PathBuf",
		"pub cwd: PathBuf",
		"pub struct GitDiffToRemoteParams",
		"pub struct GetAuthStatusParams",
	}
	for _, marker := range required {
		if !bytes.Contains(body, []byte(marker)) {
			return fmt.Errorf("pinned v1 protocol no longer contains %q", marker)
		}
	}
	requests["getConversationSummary"] = []pathPattern{{Pointer: "/params/rolloutPath", Kind: "path"}}
	responses["getConversationSummary"] = []pathPattern{
		{Pointer: "/result/summary/cwd", Kind: "path"},
		{Pointer: "/result/summary/path", Kind: "path"},
	}
	requests["gitDiffToRemote"] = []pathPattern{{Pointer: "/params/cwd", Kind: "path"}}
	responses["gitDiffToRemote"] = []pathPattern{}
	requests["getAuthStatus"] = []pathPattern{}
	responses["getAuthStatus"] = []pathPattern{}
	return nil
}

func notificationMethods(protocol []byte, marker string) (map[string]responseType, error) {
	start := bytes.Index(protocol, []byte(marker+" {"))
	if start < 0 {
		return nil, fmt.Errorf("missing %s invocation", marker)
	}
	body := protocol[start+len(marker)+2:]
	end := bytes.Index(body, []byte("\n}"))
	if end < 0 {
		return nil, fmt.Errorf("unterminated %s invocation", marker)
	}
	body = body[:end]
	entry := regexp.MustCompile(`(?m)^\s*([A-Z][A-Za-z0-9_]*)\s*(?:=>\s*"([^"]+)")?\s*\(`)
	out := make(map[string]responseType)
	for _, match := range entry.FindAllSubmatch(body, -1) {
		method := string(match[2])
		if method == "" {
			method = lowerCamel(string(match[1]))
		}
		out[method] = responseType{}
	}
	if _, legacyShape := out["accountLoginCompleted"]; legacyShape && bytes.Contains(body, []byte(`#[serde(rename = "account/login/completed")]`)) {
		delete(out, "accountLoginCompleted")
		out["account/login/completed"] = responseType{}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no methods parsed from %s", marker)
	}
	return out, nil
}

func requireExactMethods(label string, actual map[string][]pathPattern, expected map[string]responseType) error {
	missing := make([]string, 0)
	extra := make([]string, 0)
	for method := range expected {
		if _, exists := actual[method]; !exists {
			missing = append(missing, method)
		}
	}
	for method := range actual {
		if _, exists := expected[method]; !exists {
			extra = append(extra, method)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return fmt.Errorf("%s do not match pinned protocol: missing=%v extra=%v", label, missing, extra)
}

func loadExperimentalSchemas(r *recorder, source string) (schemaStore, error) {
	archivePath := filepath.Join(source, "codex-rs", "app-server-protocol", "schema", "precomputed", "app-server-exports-experimental.json.zst")
	compressed, err := r.read(archivePath)
	if err != nil {
		return nil, err
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("create zstd decoder: %w", err)
	}
	decompressed, err := decoder.DecodeAll(compressed, nil)
	decoder.Close()
	if err != nil {
		return nil, fmt.Errorf("decompress experimental Codex schema: %w", err)
	}
	var exports struct {
		JSONSchema map[string]string `json:"json_schema"`
	}
	if err := json.Unmarshal(decompressed, &exports); err != nil {
		return nil, fmt.Errorf("decode experimental Codex schema archive: %w", err)
	}
	if len(exports.JSONSchema) == 0 {
		return nil, errors.New("experimental Codex schema archive is empty")
	}
	store := make(schemaStore, len(exports.JSONSchema))
	for name, body := range exports.JSONSchema {
		clean := filepath.ToSlash(filepath.Clean(name))
		if clean != name || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return nil, fmt.Errorf("experimental Codex schema has unsafe path %q", name)
		}
		store[name] = []byte(body)
	}
	return store, nil
}

func filterResponseTypes(types map[string]responseType, methods map[string][]pathPattern) map[string]responseType {
	out := make(map[string]responseType, len(methods))
	for method := range methods {
		if typ, ok := types[method]; ok {
			out[method] = typ
		}
	}
	return out
}

func verifyCommit(source string) error {
	command := exec.Command("git", "-C", source, "rev-parse", sourceTag+"^{}")
	body, err := command.Output()
	if err != nil {
		return fmt.Errorf("resolve %s: %w", sourceTag, err)
	}
	if got := strings.TrimSpace(string(body)); got != sourceCommit {
		return fmt.Errorf("%s resolves to %s, want %s", sourceTag, got, sourceCommit)
	}
	return nil
}

func (r *recorder) read(path string) ([]byte, error) {
	rel, err := filepath.Rel(r.root, path)
	if err != nil {
		return nil, err
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, fmt.Errorf("source input %s is outside the pinned checkout", path)
	}
	command := exec.Command("git", "-C", r.root, "show", sourceCommit+":"+rel)
	body, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("read pinned source blob %s: %w", rel, err)
	}
	r.files[rel] = append([]byte(nil), body...)
	return body, nil
}

func (s schemaStore) loadSchema(path string) (schemaDoc, error) {
	path = filepath.ToSlash(path)
	body, ok := s[path]
	if !ok {
		return schemaDoc{}, fmt.Errorf("experimental Codex schema has no %s", path)
	}
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return schemaDoc{}, fmt.Errorf("decode %s: %w", path, err)
	}
	definitions, _ := root["definitions"].(map[string]any)
	return schemaDoc{Root: root, Definitions: definitions}, nil
}

func (r *recorder) digest() string {
	names := make([]string, 0, len(r.files))
	for name := range r.files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(r.files[name])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func envelopeManifest(schemas schemaStore, path string) (map[string][]pathPattern, error) {
	doc, err := schemas.loadSchema(path)
	if err != nil {
		return nil, err
	}
	branches, ok := doc.Root["oneOf"].([]any)
	if !ok {
		return nil, fmt.Errorf("%s has no oneOf envelope", path)
	}
	out := make(map[string][]pathPattern, len(branches))
	for _, rawBranch := range branches {
		branch, ok := rawBranch.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s contains a non-object envelope branch", path)
		}
		properties, _ := branch["properties"].(map[string]any)
		method, err := enumString(properties["method"])
		if err != nil {
			return nil, fmt.Errorf("%s method: %w", path, err)
		}
		collector := newCollector(doc)
		if params, exists := properties["params"]; exists {
			collector.walk(params, []string{"params"}, nil, "", "")
		}
		patterns, err := collector.patterns()
		if err != nil {
			return nil, fmt.Errorf("%s %s path schema: %w", path, method, err)
		}
		out[method] = patterns
	}
	return out, nil
}

type responseType struct {
	Namespace string
	Name      string
}

func requestResponseTypes(protocol []byte, startMarker, endMarker string) (map[string]responseType, error) {
	start := bytes.Index(protocol, []byte(startMarker))
	if start < 0 {
		return nil, fmt.Errorf("missing %s", startMarker)
	}
	body := protocol[start+len(startMarker):]
	if endMarker != "}" {
		end := bytes.Index(body, []byte(endMarker))
		if end < 0 {
			return nil, fmt.Errorf("missing %s after %s", endMarker, startMarker)
		}
		body = body[:end]
	}
	entry := regexp.MustCompile(`(?ms)^\s*([A-Z][A-Za-z0-9_]*)\s*(?:=>\s*"([^"]+)")?\s*\{(.*?)^\s*\},?`)
	response := regexp.MustCompile(`response:\s*(?:([A-Za-z0-9_]+)::)?([A-Za-z0-9_]+)\s*,`)
	out := make(map[string]responseType)
	for _, match := range entry.FindAllSubmatch(body, -1) {
		method := string(match[2])
		if method == "" {
			method = lowerCamel(string(match[1]))
		}
		responseMatch := response.FindSubmatch(match[3])
		if responseMatch == nil {
			continue
		}
		out[method] = responseType{Namespace: string(responseMatch[1]), Name: string(responseMatch[2])}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no request definitions parsed after %s", startMarker)
	}
	return out, nil
}

func responseManifest(schemas schemaStore, types map[string]responseType) (map[string][]pathPattern, error) {
	methods := make([]string, 0, len(types))
	for method := range types {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	out := make(map[string][]pathPattern, len(methods))
	for _, method := range methods {
		typ := types[method]
		candidates := []string{}
		if typ.Namespace != "" {
			candidates = append(candidates, filepath.ToSlash(filepath.Join(typ.Namespace, typ.Name+".json")))
		}
		candidates = append(candidates, typ.Name+".json")
		var schemaPath string
		for _, candidate := range candidates {
			if _, exists := schemas[candidate]; exists {
				schemaPath = candidate
				break
			}
		}
		if schemaPath == "" {
			return nil, fmt.Errorf("missing response schema for %s (%s::%s)", method, typ.Namespace, typ.Name)
		}
		doc, err := schemas.loadSchema(schemaPath)
		if err != nil {
			return nil, err
		}
		collector := newCollector(doc)
		collector.walk(doc.Root, []string{"result"}, nil, "", "")
		patterns, err := collector.patterns()
		if err != nil {
			return nil, fmt.Errorf("%s response path schema: %w", method, err)
		}
		out[method] = patterns
	}
	return out, nil
}

type collector struct {
	doc     schemaDoc
	found   map[string]*collectedPath
	blocked map[string]struct{}
	err     error
}

type collectedPath struct {
	kind            string
	unconditional   bool
	variantPointer  string
	variants        map[string]struct{}
	ignoredVariants map[string]struct{}
}

func newCollector(doc schemaDoc) *collector {
	return &collector{
		doc:     doc,
		found:   make(map[string]*collectedPath),
		blocked: make(map[string]struct{}),
	}
}

func (c *collector) add(path []string, kind, variant, variantPointer string) {
	if c.err != nil {
		return
	}
	if variant != "" && variantPointer == "" {
		c.err = fmt.Errorf("variant %q for %s has no discriminator pointer", variant, codexPointer(path))
		return
	}
	pointer := codexPointer(path)
	if _, blocked := c.blocked[pointer]; blocked && kind == "path" {
		return
	}
	entry := c.found[pointer]
	if entry != nil && !entry.unconditional && variant != "" && entry.variantPointer != "" && entry.variantPointer != variantPointer {
		c.err = fmt.Errorf("path %s has incompatible variant pointers %s and %s", pointer, entry.variantPointer, variantPointer)
		return
	}
	if entry != nil && entry.kind == "absolute" {
		if kind == "absolute" {
			if variant == "" {
				entry.unconditional = true
				entry.variantPointer = ""
				clear(entry.variants)
				clear(entry.ignoredVariants)
			} else if !entry.unconditional {
				if entry.variantPointer == "" {
					entry.variantPointer = variantPointer
				}
				entry.variants[variant] = struct{}{}
			}
		} else if variant != "" && !entry.unconditional {
			if entry.variantPointer == "" {
				entry.variantPointer = variantPointer
			}
			entry.ignoredVariants[variant] = struct{}{}
		}
		return
	}
	if entry != nil && kind == "absolute" {
		replacement := &collectedPath{kind: kind, variants: make(map[string]struct{}), ignoredVariants: make(map[string]struct{})}
		if !entry.unconditional {
			for existing := range entry.variants {
				replacement.ignoredVariants[existing] = struct{}{}
			}
			for existing := range entry.ignoredVariants {
				replacement.ignoredVariants[existing] = struct{}{}
			}
		}
		entry = replacement
		c.found[pointer] = entry
	} else if entry == nil {
		entry = &collectedPath{kind: kind, variants: make(map[string]struct{}), ignoredVariants: make(map[string]struct{})}
		c.found[pointer] = entry
	}
	if variant == "" {
		entry.unconditional = true
		entry.variantPointer = ""
		clear(entry.variants)
		clear(entry.ignoredVariants)
	} else if !entry.unconditional {
		if entry.variantPointer == "" {
			entry.variantPointer = variantPointer
		}
		entry.variants[variant] = struct{}{}
	}
}

func (c *collector) ignoreSemanticVariant(path []string, variant, variantPointer string) {
	if c.err != nil || variant == "" {
		return
	}
	if variantPointer == "" {
		c.err = fmt.Errorf("ignored variant %q for %s has no discriminator pointer", variant, codexPointer(path))
		return
	}
	pointer := codexPointer(path)
	if _, blocked := c.blocked[pointer]; blocked {
		return
	}
	entry := c.found[pointer]
	if entry == nil {
		entry = &collectedPath{kind: "path", variants: make(map[string]struct{}), ignoredVariants: make(map[string]struct{})}
		c.found[pointer] = entry
	}
	if !entry.unconditional && entry.variantPointer != "" && entry.variantPointer != variantPointer {
		c.err = fmt.Errorf("path %s has incompatible variant pointers %s and %s", pointer, entry.variantPointer, variantPointer)
		return
	}
	if !entry.unconditional {
		if entry.variantPointer == "" {
			entry.variantPointer = variantPointer
		}
		entry.ignoredVariants[variant] = struct{}{}
	}
}

func (c *collector) blockSemanticPath(path []string) {
	pointer := codexPointer(path)
	c.blocked[pointer] = struct{}{}
	if entry := c.found[pointer]; entry != nil && entry.kind == "path" {
		delete(c.found, pointer)
	}
}

func (c *collector) patterns() ([]pathPattern, error) {
	if c.err != nil {
		return nil, c.err
	}
	out := make([]pathPattern, 0, len(c.found))
	for pointer, entry := range c.found {
		if !entry.unconditional && len(entry.variants) == 0 {
			continue
		}
		out = append(out, pathPattern{
			Pointer: pointer, Kind: entry.kind,
			VariantPointer: entry.variantPointer,
			Variants:       sortedSet(entry.variants), IgnoredVariants: sortedSet(entry.ignoredVariants),
		})
	}
	out = mergeScalarArrayPatterns(out)
	sortPathPatterns(out)
	return out, nil
}

func sortPathPatterns(patterns []pathPattern) {
	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].Pointer == patterns[j].Pointer {
			return patterns[i].Kind < patterns[j].Kind
		}
		return patterns[i].Pointer < patterns[j].Pointer
	})
}

func codexPointer(path []string) string {
	pointer := ""
	for _, part := range path {
		pointer += "/" + strings.ReplaceAll(strings.ReplaceAll(part, "~", "~0"), "/", "~1")
	}
	return pointer
}

func sortedSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func mergeScalarArrayPatterns(patterns []pathPattern) []pathPattern {
	byPointer := make(map[string]int, len(patterns))
	for index, pattern := range patterns {
		byPointer[pattern.Pointer] = index
	}
	removed := make(map[int]struct{})
	for index, pattern := range patterns {
		arrayIndex, exists := byPointer[pattern.Pointer+"/*"]
		if !exists || pattern.Kind != "path" || patterns[arrayIndex].Kind != "path" ||
			pattern.VariantPointer != patterns[arrayIndex].VariantPointer ||
			!stringSlicesEqual(pattern.Variants, patterns[arrayIndex].Variants) ||
			!stringSlicesEqual(pattern.IgnoredVariants, patterns[arrayIndex].IgnoredVariants) {
			continue
		}
		patterns[index].Kind = "path-or-array"
		removed[arrayIndex] = struct{}{}
	}
	out := make([]pathPattern, 0, len(patterns)-len(removed))
	for index, pattern := range patterns {
		if _, skip := removed[index]; !skip {
			out = append(out, pattern)
		}
	}
	return out
}

func stringSlicesEqual(left, right []string) bool {
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

func (c *collector) walk(raw any, path, refStack []string, directVariant, directVariantPointer string) {
	node, ok := raw.(map[string]any)
	if !ok {
		return
	}
	if ref, _ := node["$ref"].(string); ref != "" {
		name := strings.TrimPrefix(ref, "#/definitions/")
		if name == "AbsolutePathBuf" || strings.HasSuffix(name, "/AbsolutePathBuf") {
			c.add(path, "absolute", directVariant, directVariantPointer)
			return
		}
		if contains(refStack, name) {
			return
		}
		target := c.doc.Definitions[name]
		if target == nil {
			return
		}
		c.walk(target, path, append(refStack, name), directVariant, directVariantPointer)
		return
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if branches, ok := node[keyword].([]any); ok {
			for _, branch := range branches {
				c.walk(branch, path, refStack, directVariant, directVariantPointer)
			}
		}
	}
	if properties, ok := node["properties"].(map[string]any); ok {
		variant := directVariant
		variantPointer := directVariantPointer
		if discriminator, localVariant := schemaDiscriminator(properties); localVariant != "" {
			variant = localVariant
			variantPointer = codexPointer(appendPath(path, discriminator))
		}
		names := make([]string, 0, len(properties))
		for name := range properties {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			childPath := appendPath(path, name)
			child := properties[name]
			if semanticPathName(name) {
				if logicalSemanticPath(name, variant) {
					c.ignoreSemanticVariant(childPath, variant, variantPointer)
					c.walk(child, childPath, refStack, variant, variantPointer)
					continue
				}
				if foreignPathSchema(child) {
					c.blockSemanticPath(childPath)
				} else {
					c.walkSemantic(child, childPath, nil, variant, variantPointer)
				}
			}
			c.walk(child, childPath, refStack, variant, variantPointer)
		}
	}
	if items, exists := node["items"]; exists {
		switch value := items.(type) {
		case []any:
			for index, item := range value {
				c.walk(item, appendPath(path, fmt.Sprintf("%d", index)), refStack, directVariant, directVariantPointer)
			}
		default:
			c.walk(value, appendPath(path, "*"), refStack, directVariant, directVariantPointer)
		}
	}
	if additional, ok := node["additionalProperties"].(map[string]any); ok {
		c.walk(additional, appendPath(path, "*"), refStack, directVariant, directVariantPointer)
	}
}

func (c *collector) walkSemantic(raw any, path, refStack []string, variant, variantPointer string) {
	node, ok := raw.(map[string]any)
	if !ok {
		return
	}
	if ref, _ := node["$ref"].(string); ref != "" {
		name := strings.TrimPrefix(ref, "#/definitions/")
		if name == "AbsolutePathBuf" || strings.HasSuffix(name, "/AbsolutePathBuf") {
			return
		}
		if foreignPathType(name) {
			// A JSON pointer can be shared by variants of an enum. If any
			// variant deliberately uses a cross-platform path wrapper, leave
			// that pointer raw for every variant rather than applying a
			// discriminator-blind rewrite to it.
			c.blockSemanticPath(path)
			return
		}
		if contains(refStack, name) {
			return
		}
		c.walkSemantic(c.doc.Definitions[name], path, append(refStack, name), variant, variantPointer)
		return
	}
	if schemaHasType(node, "string") {
		c.add(path, "path", variant, variantPointer)
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if branches, ok := node[keyword].([]any); ok {
			for _, branch := range branches {
				c.walkSemantic(branch, path, refStack, variant, variantPointer)
			}
		}
	}
	if items, exists := node["items"]; exists {
		c.walkSemantic(items, appendPath(path, "*"), refStack, variant, variantPointer)
	}
}

func schemaHasType(node map[string]any, wanted string) bool {
	switch value := node["type"].(type) {
	case string:
		return value == wanted
	case []any:
		for _, candidate := range value {
			if candidate == wanted {
				return true
			}
		}
	}
	return false
}

func enumString(raw any) (string, error) {
	node, ok := raw.(map[string]any)
	if !ok {
		return "", errors.New("method schema is not an object")
	}
	values, ok := node["enum"].([]any)
	if !ok || len(values) != 1 {
		return "", errors.New("method schema does not have one enum value")
	}
	value, ok := values[0].(string)
	if !ok || value == "" {
		return "", errors.New("method enum is not a string")
	}
	return value, nil
}

func semanticPathName(name string) bool {
	switch name {
	case "agentPath", "agent_path", "keyPath", "key_path", "scriptPath", "script_path":
		return false
	}
	switch name {
	case "cwd", "cwds", "path", "paths", "root", "roots":
		return true
	case "extraLogFiles", "extra_log_files", "managedDir", "managed_dir", "windowsManagedDir", "windows_managed_dir":
		return true
	}
	return strings.HasSuffix(name, "Path") || strings.HasSuffix(name, "Paths") ||
		strings.HasSuffix(name, "Root") || strings.HasSuffix(name, "Roots") ||
		strings.HasSuffix(name, "_path") || strings.HasSuffix(name, "_paths") ||
		strings.HasSuffix(name, "_root") || strings.HasSuffix(name, "_roots")
}

func schemaDiscriminator(properties map[string]any) (string, string) {
	for _, name := range []string{"type", "kind"} {
		node, _ := properties[name].(map[string]any)
		values, _ := node["enum"].([]any)
		if len(values) != 1 {
			continue
		}
		if value, ok := values[0].(string); ok && value != "" {
			return name, value
		}
	}
	return "", ""
}

func logicalSemanticPath(name, variant string) bool {
	// UserInput::Mention.path is a logical reference, unlike the PathBuf
	// fields used by the localImage, localAudio, and skill variants at the
	// same JSON pointer.
	return name == "path" && variant == "mention"
}

func foreignPathSchema(raw any) bool {
	node, _ := raw.(map[string]any)
	ref, _ := node["$ref"].(string)
	return foreignPathType(strings.TrimPrefix(ref, "#/definitions/"))
}

func foreignPathType(name string) bool {
	return name == "LegacyAppPathString" || name == "PathUri" || name == "AgentPath" ||
		strings.HasSuffix(name, "/LegacyAppPathString") || strings.HasSuffix(name, "/PathUri")
}

func lowerCamel(value string) string {
	if value == "" {
		return value
	}
	return strings.ToLower(value[:1]) + value[1:]
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func appendPath(path []string, part string) []string {
	out := make([]string, len(path)+1)
	copy(out, path)
	out[len(path)] = part
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
