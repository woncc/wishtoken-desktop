package basispoints

import (
	"container/list"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type toolInfo struct {
	Name       string
	Namespace  string
	Kind       string
	Definition string
	Parameters object
}

// ---------------------------------------------------------------------------
// Replay cache: native run_officejs identities per scope
// ---------------------------------------------------------------------------

type replayEntry struct {
	key             string
	raw             []byte
	callFingerprint string
}

// ReplayCache retains native tool identities so multi-turn tool loops can be
// replayed to the gateway. Entries are scoped so two conversations (or two
// accounts) never observe each other's call ids. Size is bounded by entry
// count and bytes because tool arguments can be large.
type ReplayCache struct {
	mu         sync.Mutex
	entries    map[string]*list.Element
	order      list.List
	bytes      int
	MaxEntries int
	MaxBytes   int
}

// NewReplayCache returns a cache with default bounds.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{MaxEntries: 4096, MaxBytes: 64 << 20}
}

func (c *ReplayCache) put(scope, id string, item object, clientCall ...object) {
	if c == nil || id == "" {
		return
	}
	raw, err := json.Marshal(item)
	if err != nil || len(raw) > 1<<20 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
	}
	maxEntries, maxBytes := c.MaxEntries, c.MaxBytes
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	key := scope + "\x00" + id
	if old := c.entries[key]; old != nil {
		entry, _ := old.Value.(replayEntry)
		c.bytes -= len(entry.raw)
		c.order.Remove(old)
	}
	var signature string
	if len(clientCall) == 1 {
		signature = historyCallFingerprint(clientCall[0])
	}
	c.entries[key] = c.order.PushBack(replayEntry{key: key, raw: raw, callFingerprint: signature})
	c.bytes += len(raw)
	for len(c.entries) > maxEntries || c.bytes > maxBytes {
		old := c.order.Front()
		if old == nil {
			break
		}
		entry, _ := old.Value.(replayEntry)
		delete(c.entries, entry.key)
		c.bytes -= len(entry.raw)
		c.order.Remove(old)
	}
}

func (c *ReplayCache) get(scope, id string) object {
	return c.getMatching(scope, id, "", false)
}

func (c *ReplayCache) getForCall(scope, id string, clientCall object) object {
	signature := historyCallFingerprint(clientCall)
	if signature == "" {
		return nil
	}
	return c.getMatching(scope, id, signature, true)
}

func (c *ReplayCache) getMatching(scope, id, signature string, requireSignature bool) object {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[scope+"\x00"+id]
	if entry == nil {
		return nil
	}
	cached, ok := entry.Value.(replayEntry)
	if !ok || (requireSignature && cached.callFingerprint != signature) {
		return nil
	}
	c.order.MoveToBack(entry)
	var item object
	if decode(cached.raw, &item) != nil {
		return nil
	}
	return item
}

// Len returns the number of cached identities.
func (c *ReplayCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// historyCallFingerprint identifies a complete client call by kind, id, name,
// namespace and arguments, ignoring wire-only item ids and status.
func historyCallFingerprint(item object) string {
	kind, id, name := text(item["type"]), text(item["call_id"]), text(item["name"])
	if id == "" || name == "" || strings.TrimSpace(id) != id || strings.TrimSpace(name) != name {
		return ""
	}
	namespace := ""
	if raw, exists := item["namespace"]; exists {
		var ok bool
		namespace, ok = raw.(string)
		if !ok {
			return ""
		}
	}
	canonical := object{"type": kind, "call_id": id, "name": name, "namespace": namespace}
	switch kind {
	case "function_call":
		arguments := item["arguments"]
		if raw, ok := arguments.(string); ok {
			if decode([]byte(raw), &arguments) != nil {
				return ""
			}
		}
		if args, ok := arguments.(object); !ok || args == nil {
			return ""
		}
		canonical["arguments"] = arguments
	case "custom_tool_call":
		input, ok := item["input"].(string)
		if !ok {
			return ""
		}
		canonical["input"] = input
	default:
		return ""
	}
	return fingerprint(canonical)
}

// ---------------------------------------------------------------------------
// Catalog collection and description
// ---------------------------------------------------------------------------

func (b *Bridge) collectTools(value any, namespace string) ([]any, error) {
	var catalog []any
	items, _ := value.([]any)
	for _, raw := range items {
		item, ok := raw.(object)
		if !ok {
			return nil, prepareErr(CategoryToolCatalog, "invalid client tool declaration")
		}
		kind, name := text(item["type"]), text(item["name"])
		if kind == "namespace" {
			if name == "" {
				return nil, prepareErr(CategoryToolCatalog, "client namespaces require a name")
			}
			nested := name
			if namespace != "" {
				nested = namespace + "." + name
			}
			entries, err := b.collectTools(item["tools"], nested)
			if err != nil {
				return nil, err
			}
			catalog = append(catalog, entries...)
			continue
		}
		if isHostedTool(kind) {
			b.unsupportedTools[strings.ToLower(kind)] = true
			continue
		}
		switch kind {
		case "function", "custom":
		case "local_shell":
			// Codex's built-in shell tool declared natively; relay it as a function.
			kind = "function"
			if name == "" {
				name = "local_shell"
			}
			if item["parameters"] == nil {
				item = object{"type": "function", "name": name, "description": "Run a shell command on the client machine.",
					"parameters": object{"type": "object", "properties": object{"command": object{"type": "array", "items": object{"type": "string"}}}, "required": []any{"command"}}}
			}
		default:
			return nil, prepareErr(CategoryToolCatalog, "Basispoints does not support hosted tool %q; use client function or custom tools", kind)
		}
		if name == "" {
			return nil, prepareErr(CategoryToolCatalog, "client tools require a name")
		}
		key := name
		if namespace != "" {
			key = namespace + "." + name
		}
		entry := object{"type": kind, "name": key}
		for _, field := range []string{"description", "format", "parameters"} {
			if v, exists := item[field]; exists && v != nil {
				entry[field] = v
			}
		}
		if kind == "function" && entry["parameters"] == nil {
			if v := item["inputSchema"]; v != nil {
				entry["parameters"] = v
			} else if v := item["input_schema"]; v != nil {
				entry["parameters"] = v
			}
		}
		definition := fingerprint(item)
		if previous, exists := b.tools[key]; exists {
			if previous.Definition != definition || previous.Namespace != namespace || previous.Name != name {
				return nil, prepareErr(CategoryToolCatalog, "conflicting duplicate client tool %q", key)
			}
			continue
		}
		parameters, _ := entry["parameters"].(object)
		b.tools[key] = toolInfo{Name: name, Namespace: namespace, Kind: kind, Definition: definition, Parameters: parameters}
		catalog = append(catalog, entry)
	}
	return catalog, nil
}

// describeCatalog renders tool contracts as documentation lines.
func describeCatalog(catalog []any) string {
	lines := make([]string, 0, len(catalog))
	for _, raw := range catalog {
		entry, _ := raw.(object)
		line := "Client tool " + quoted(entry["name"]) + " (" + text(entry["type"]) + ")."
		if description := text(entry["description"]); description != "" {
			line += " " + description
		}
		if text(entry["type"]) == "custom" {
			line += " Set " + TransportTool + " summary to " + quoted(CustomMarker+text(entry["name"])) + " and pass its exact raw text directly in code."
			if format := entry["format"]; format != nil {
				line += " Input format: " + quoted(format) + "."
			}
		} else {
			line += " Pass a JSON object in the envelope's arguments field. Argument contract: " + describeSchema(entry["parameters"], 0)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n\n")
}

func quoted(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func describeSchema(value any, depth int) string {
	schema, ok := value.(object)
	if !ok || depth >= 8 {
		if value == nil {
			return "Use the arguments described by the tool."
		}
		return quoted(value)
	}
	var parts []string
	if kind := schema["type"]; kind != nil {
		parts = append(parts, "Value type: "+quoted(kind)+".")
	}
	if description := text(schema["description"]); description != "" {
		parts = append(parts, description)
	}
	required := make(map[string]bool)
	if names, ok := schema["required"].([]any); ok {
		for _, name := range names {
			required[text(name)] = true
		}
	}
	if properties, ok := schema["properties"].(object); ok {
		names := make([]string, 0, len(properties))
		for name := range properties {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			presence := "optional"
			if required[name] {
				presence = "required"
			}
			parts = append(parts, fmt.Sprintf("Field %s (%s): %s", quoted(name), presence, describeSchema(properties[name], depth+1)))
		}
	}
	if items := schema["items"]; items != nil {
		parts = append(parts, "Each array item: "+describeSchema(items, depth+1))
	}
	constraints := make(object)
	for key, v := range schema {
		switch key {
		case "type", "description", "properties", "items", "title", "$schema", "additionalProperties":
		default:
			constraints[key] = v
		}
	}
	if len(constraints) > 0 {
		parts = append(parts, "Additional constraints: "+quoted(constraints)+".")
	}
	if len(parts) == 0 {
		return "Any JSON value."
	}
	return strings.Join(parts, " ")
}

// catalogTool resolves a model-supplied name, accepting the "functions."
// display prefix some hosts add.
func (b *Bridge) catalogTool(name string) (string, toolInfo, bool) {
	if info, ok := b.tools[name]; ok {
		return name, info, true
	}
	if trimmed := strings.TrimPrefix(name, "functions."); trimmed != name {
		if info, ok := b.tools[trimmed]; ok {
			return trimmed, info, true
		}
	}
	return "", toolInfo{}, false
}

// ---------------------------------------------------------------------------
// History translation (client -> gateway)
// ---------------------------------------------------------------------------

// rebuildNativeHistoryCall re-expresses a complete client tool call as the
// run_officejs transport item the gateway expects in history.
func rebuildNativeHistoryCall(item object) (object, error) {
	id, name := text(item["call_id"]), text(item["name"])
	if id == "" || name == "" {
		return nil, prepareErr(CategoryToolHistory, "history recovery requires a complete tool call with call_id and name")
	}
	if value, exists := item["namespace"]; exists {
		namespace, ok := value.(string)
		if !ok {
			return nil, prepareErr(CategoryToolHistory, "history tool namespace must be a string")
		}
		if namespace != "" {
			name = namespace + "." + name
		}
	}
	envelope := object{"name": name}
	switch text(item["type"]) {
	case "function_call":
		arguments := item["arguments"]
		if encoded, ok := arguments.(string); ok {
			if strings.TrimSpace(encoded) == "" {
				encoded = "{}"
			}
			if decode([]byte(encoded), &arguments) != nil {
				return nil, prepareErr(CategoryToolHistory, "history function arguments must be one valid JSON object")
			}
		}
		if args, ok := arguments.(object); !ok || args == nil {
			return nil, prepareErr(CategoryToolHistory, "history function arguments must be a JSON object")
		}
		envelope["arguments"] = arguments
	case "custom_tool_call":
		input, ok := item["input"].(string)
		if !ok {
			return nil, prepareErr(CategoryToolHistory, "history custom tool input must be a string")
		}
		envelope["input"] = input
	default:
		return nil, prepareErr(CategoryToolHistory, "history recovery requires a function or custom tool call")
	}
	code, err := json.Marshal(envelope)
	if err != nil {
		return nil, prepareErr(CategoryToolHistory, "history tool arguments cannot be serialized")
	}
	arguments, err := json.Marshal(object{
		"code":             string(code),
		"summary":          "Replay a previously requested client tool",
		"extended_summary": "The supplied client history contains this tool call; consume its recorded result without repeating it.",
		"destructive":      false,
		"references":       []any{},
	})
	if err != nil {
		return nil, prepareErr(CategoryToolHistory, "history transport cannot be serialized")
	}
	itemID := text(item["id"])
	if !strings.HasPrefix(itemID, "fc_") || len(itemID) > 64 {
		itemID = "fc_" + fingerprint(id)
	}
	return object{
		"type": "function_call", "id": itemID, "call_id": id, "name": TransportTool,
		"arguments": string(arguments), "status": "completed",
	}, nil
}

func (b *Bridge) translateHistory(input []any) ([]any, error) {
	result := make([]any, 0, len(input))
	seenCalls := make(map[string]bool)
	var trigger any
	for index, raw := range input {
		item, ok := raw.(object)
		if !ok {
			return nil, prepareErr(CategoryRequestJSON, "invalid input item at index %d", index)
		}
		item = cloneObject(item)
		delete(item, "internal_chat_message_metadata_passthrough")
		switch text(item["type"]) {
		case "additional_tools":
			continue
		case "item_reference":
			return nil, prepareErr(CategoryHistoryRef, "Basispoints requires full history; item_reference is unsupported")
		case "compaction_trigger":
			trigger = item
			continue
		case "reasoning":
			if encrypted := text(item["encrypted_content"]); encrypted != "" {
				result = append(result, object{"type": "reasoning", "summary": []any{}, "encrypted_content": encrypted})
			}
			continue
		case "function_call", "custom_tool_call":
			id := text(item["call_id"])
			if native := b.replay.getForCall(b.scope, id, item); native != nil {
				item = native
			} else {
				native, err := rebuildNativeHistoryCall(item)
				if err != nil {
					return nil, err
				}
				b.replay.put(b.scope, id, native, item)
				item = native
			}
			seenCalls[id] = true
		case "function_call_output", "custom_tool_call_output":
			id := text(item["call_id"])
			if !seenCalls[id] {
				native := b.replay.get(b.scope, id)
				if native == nil {
					return nil, prepareErr(CategoryToolHistory, "original tool item is unavailable for this tool result; start a new conversation")
				}
				result = append(result, native)
				seenCalls[id] = true
			}
			item["type"] = "function_call_output"
			if err := b.validateHistoryContent(item["output"], true); err != nil {
				return nil, err
			}
			// Custom results carry ctco_ ids; the gateway wants fc_ ids here.
			itemID := text(item["id"])
			if itemID == "" {
				itemID = "fc_" + id
			}
			if !strings.HasPrefix(itemID, "fc_") || len(itemID) > 64 {
				itemID = "fc_" + fingerprint(itemID)
			}
			item["id"] = itemID
		case "configuration_update":
			return nil, prepareErr(CategoryReasoning, "Basispoints does not support configuration_update; start a new request with the desired effort")
		case "message", "":
			if role := text(item["role"]); role == "system" {
				item["role"] = "developer"
			}
			if s, ok := item["content"].(string); ok {
				role := text(item["role"])
				partType := "input_text"
				if role == "assistant" {
					partType = "output_text"
				}
				item["content"] = []any{object{"type": partType, "text": s}}
			}
		}
		if err := b.validateHistoryContent(item["content"], false); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if trigger != nil {
		result = append(result, trigger)
	}
	return result, nil
}

func (b *Bridge) validateHistoryContent(value any, toolOutput bool) error {
	content, _ := value.([]any)
	for _, rawPart := range content {
		part, _ := rawPart.(object)
		switch text(part["type"]) {
		case "input_text", "output_text", "text", "refusal":
		case "input_image":
			if err := validateImage(part, toolOutput, b.toolImages); err != nil {
				return err
			}
		default:
			return prepareErr(CategoryRequestShape, "Basispoints supports text and image content only (got %q)", safeType(part["type"]))
		}
	}
	return nil
}

func safeType(v any) string {
	s, ok := v.(string)
	if !ok {
		return "non_string"
	}
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

func cloneObject(src object) object {
	dst := make(object, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func isTool(item object) bool {
	return text(item["type"]) == "function_call" || text(item["type"]) == "custom_tool_call"
}

// ---------------------------------------------------------------------------
// Call translation (gateway -> client)
// ---------------------------------------------------------------------------

// translateCall converts a native gateway tool call into the client's tool
// call. It only recognises declared catalog tools and never executes code.
func (b *Bridge) translateCall(native object) (object, error) {
	name := text(native["name"])
	if text(native["type"]) == "function_call" && (name == "update_plan" || name == "functions.update_plan") {
		if translated, err := b.translateNativePlan(native); err == nil {
			return translated, nil
		}
	}
	if name != TransportTool && name != "functions."+TransportTool {
		return b.translateDirectCatalogCall(native)
	}
	var arguments object
	if value, ok := native["arguments"].(object); ok {
		arguments = value
	} else if err := decode([]byte(text(native["arguments"])), &arguments); err != nil {
		return nil, fmt.Errorf("Basispoints returned invalid tool transport arguments")
	}
	if arguments == nil {
		return nil, fmt.Errorf("Basispoints returned empty tool transport arguments")
	}
	envelope, marked, err := customTransportEnvelope(arguments)
	if !marked && err == nil {
		envelope, err = decodeTransportEnvelope(arguments["code"])
		if err != nil {
			if recovered, ok := b.recoverTransportEnvelope(arguments); ok {
				envelope, err = recovered, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	toolName, err := envelopeName(envelope)
	if err != nil {
		return nil, err
	}
	_, info, allowed := b.catalogTool(toolName)
	if !allowed {
		return nil, fmt.Errorf("Basispoints returned a tool outside the client's catalog")
	}
	result, err := b.finishClientToolCall(native, info, envelope, marked)
	if err != nil {
		return nil, err
	}
	// run_officejs is a real gateway tool; replay its item verbatim next turn.
	b.replay.put(b.scope, text(native["call_id"]), native, result)
	return result, nil
}

// translateDirectCatalogCall accepts a call the model addressed by the
// catalog name directly instead of through the transport.
func (b *Bridge) translateDirectCatalogCall(native object) (object, error) {
	_, info, ok := b.catalogTool(text(native["name"]))
	if !ok {
		return nil, fmt.Errorf("Basispoints returned an unsupported native tool; no tool was executed")
	}
	kind := text(native["type"])
	var envelope object
	switch info.Kind {
	case "function":
		args := native["arguments"]
		if kind == "custom_tool_call" {
			args = native["input"]
		}
		envelope = object{"name": info.Name, "arguments": args}
	case "custom":
		var input string
		switch kind {
		case "custom_tool_call":
			s, ok := native["input"].(string)
			if !ok {
				return nil, fmt.Errorf("Basispoints direct custom tool input must be a string")
			}
			input = s
		default:
			s, ok := native["arguments"].(string)
			if !ok {
				return nil, fmt.Errorf("Basispoints direct custom tool input must be a string")
			}
			// A function-shaped call to a custom tool usually wraps the raw
			// input in {"input": "..."}; unwrap it when unambiguous.
			var parsed object
			if decode([]byte(s), &parsed) == nil {
				if inner, ok := parsed["input"].(string); ok && len(parsed) == 1 {
					s = inner
				}
			}
			input = s
		}
		envelope = object{"name": info.Name, "input": input}
	default:
		return nil, fmt.Errorf("Basispoints returned an unsupported native tool; no tool was executed")
	}
	result, err := b.finishClientToolCall(native, info, envelope, false)
	if err != nil {
		return nil, err
	}
	wrapped, err := rebuildNativeHistoryCall(result)
	if err != nil {
		return nil, err
	}
	b.replay.put(b.scope, text(native["call_id"]), wrapped, result)
	return result, nil
}

// finishClientToolCall builds the client-facing item for a resolved tool.
func (b *Bridge) finishClientToolCall(native object, info toolInfo, envelope object, marked bool) (object, error) {
	if marked && info.Kind != "custom" {
		return nil, fmt.Errorf("Basispoints raw transport requires a declared custom tool")
	}
	id := text(native["call_id"])
	if id == "" {
		return nil, fmt.Errorf("Basispoints tool call is missing call_id")
	}
	itemID := text(native["id"])
	if itemID == "" {
		itemID = "fc_" + fingerprint(id)
	}
	result := object{"type": info.Kind + "_call", "id": itemID, "call_id": id, "name": info.Name, "status": "completed"}
	if info.Namespace != "" {
		result["namespace"] = info.Namespace
	}
	if info.Kind == "custom" {
		value, hasInput := envelope["input"]
		if alias, hasAlias := envelope["args"]; hasAlias {
			if hasInput {
				return nil, fmt.Errorf("Basispoints custom tool envelope contains conflicting input fields")
			}
			value = alias
		}
		if arguments, exists := envelope["arguments"]; exists && !hasInput {
			// Tolerate {"arguments":{"input":"..."}} or {"arguments":"raw"}.
			switch a := arguments.(type) {
			case string:
				value = a
			case object:
				if inner, ok := a["input"].(string); ok && len(a) == 1 {
					value = inner
				} else {
					return nil, fmt.Errorf("Basispoints custom tools require input text, not arguments")
				}
			}
		}
		input, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("Basispoints custom tool input must be a string")
		}
		result["type"] = "custom_tool_call"
		result["id"] = "ctc_" + fingerprint(id)
		result["input"] = input
		return result, nil
	}
	args, err := envelopeArguments(envelope)
	if err != nil {
		return nil, err
	}
	if raw, ok := args.(string); ok {
		if strings.TrimSpace(raw) == "" {
			raw = "{}"
		}
		if decode([]byte(raw), &args) != nil {
			return nil, fmt.Errorf("Basispoints function arguments are invalid JSON")
		}
	}
	if args == nil {
		args = object{}
	}
	if _, ok := args.(object); !ok {
		return nil, fmt.Errorf("Basispoints function arguments must be an object")
	}
	encoded, _ := json.Marshal(args)
	result["arguments"] = string(encoded)
	return result, nil
}

// translateResponse rewrites the terminal response in place.
func (b *Bridge) translateResponse(response object) error {
	if response == nil {
		return nil
	}
	output, _ := response["output"].([]any)
	for i, raw := range output {
		item, _ := raw.(object)
		if isTool(item) {
			translated, err := b.translateCall(item)
			if err != nil {
				return err
			}
			output[i] = translated
		}
	}
	response["reasoning"] = object{"effort": b.Effort}
	response["parallel_tool_calls"] = false
	return nil
}

func isToolEvent(kind string) bool {
	return strings.HasPrefix(kind, "response.function_call_arguments.") || strings.HasPrefix(kind, "response.custom_tool_call_input.")
}
