package basispoints

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type object = map[string]any

// Options tune request preparation.
type Options struct {
	// Scope isolates replayed tool identities (account + conversation).
	Scope string
	// DefaultEffort applies when the request carries no reasoning effort.
	DefaultEffort string
	// CompactThreshold overrides the gateway compaction threshold.
	CompactThreshold int
	// Replay is the shared tool identity cache. nil disables replay.
	Replay *ReplayCache
	// ToolImages lists inline tool-output images validated by the caller.
	ToolImages map[string]bool
	// ParallelToolCalls advertises that several independent calls may be
	// emitted in one response. Codex handles them; other clients may not.
	ParallelToolCalls bool
}

// Prepared is a request ready for the gateway.
type Prepared struct {
	Body     []byte
	Bridge   *Bridge
	Model    string
	Effort   string
	Warnings []string
}

// Bridge carries per-request translation state between Prepare and Stream.
type Bridge struct {
	RequestedEffort string
	Effort          string
	Warnings        []string

	tools            map[string]toolInfo
	unsupportedTools map[string]bool
	structured       *structuredOutput
	replay           *ReplayCache
	scope            string
	toolImages       map[string]bool
}

func decode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected one JSON value")
	}
	return nil
}

func text(value any) string {
	s, _ := value.(string)
	return s
}

func fingerprint(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func message(role, content string) object {
	return object{"type": "message", "role": role, "content": []any{object{"type": "input_text", "text": content}}}
}

// Prepare translates a Responses request body into the gateway wire shape.
func Prepare(raw []byte, opts Options) (*Prepared, error) {
	var source object
	if err := decode(raw, &source); err != nil || source == nil {
		return nil, prepareErr(CategoryRequestJSON, "invalid request JSON")
	}
	model := strings.TrimSpace(text(source["model"]))
	if model == "" {
		return nil, prepareErr(CategoryModel, "request has no model")
	}
	if text(source["previous_response_id"]) != "" {
		return nil, prepareErr(CategoryHistoryRef, "Basispoints requires expanded history instead of previous_response_id")
	}
	requested := text(source["reasoning_effort"])
	if reasoning, ok := source["reasoning"].(object); ok {
		if e := text(reasoning["effort"]); e != "" {
			requested = e
		}
		if mode := text(reasoning["mode"]); mode != "" && mode != "standard" {
			return nil, prepareErr(CategoryReasoning, "Basispoints does not support reasoning mode %q", mode)
		}
	}
	if requested == "" {
		requested = opts.DefaultEffort
	}
	effort, known := NormalizeEffort(requested)
	if !known || (requested != "" && effort != strings.ToLower(strings.TrimSpace(requested))) {
		return nil, prepareErr(CategoryReasoning, "requested reasoning effort %q cannot be preserved; BPS supports low, medium, high or xhigh (max returns upstream HTTP 422)", requested)
	}
	b := &Bridge{
		RequestedEffort:  requested,
		Effort:           effort,
		tools:            make(map[string]toolInfo),
		unsupportedTools: make(map[string]bool),
		replay:           opts.Replay,
		scope:            opts.Scope,
		toolImages:       opts.ToolImages,
	}
	if !known && requested != "" {
		b.Warnings = append(b.Warnings, fmt.Sprintf("reasoning effort %q is unknown; using medium", requested))
	}
	structured, err := prepareStructuredOutput(source["text"], source["response_format"])
	if err != nil {
		return nil, err
	}
	b.structured = structured

	choice := source["tool_choice"]
	switch v := choice.(type) {
	case nil:
	case string:
		if v != "auto" && v != "none" && v != "" {
			return nil, prepareErr(CategoryToolChoice, "Basispoints supports tool_choice auto or none only")
		}
	default:
		return nil, prepareErr(CategoryToolChoice, "Basispoints supports tool_choice auto or none only")
	}

	var catalog []any
	if text(choice) != "none" {
		catalog, err = b.collectTools(source["tools"], "")
		if err != nil {
			return nil, err
		}
		if input, ok := source["input"].([]any); ok {
			for _, raw := range input {
				item, _ := raw.(object)
				if text(item["type"]) == "additional_tools" {
					additional, err := b.collectTools(item["tools"], "")
					if err != nil {
						return nil, err
					}
					catalog = append(catalog, additional...)
				}
			}
		}
	}

	var input []any
	switch v := source["input"].(type) {
	case string:
		input = []any{message("user", v)}
	case []any:
		input = v
	case nil:
		return nil, prepareErr(CategoryRequestJSON, "request has no input")
	default:
		return nil, prepareErr(CategoryRequestJSON, "input must be text or a Responses item array")
	}
	translated, err := b.translateHistory(input)
	if err != nil {
		return nil, err
	}

	prologue := make([]any, 0, 3)
	if instructions := text(source["instructions"]); strings.TrimSpace(instructions) != "" {
		prologue = append(prologue, message("developer", instructions))
	}
	prologue = append(prologue, message("developer", b.protocolPrompt(catalog, opts.ParallelToolCalls)))

	cacheKey := text(source["prompt_cache_key"])
	conversation := cacheKey
	if conversation == "" && len(input) > 0 {
		conversation = fingerprint(input[0])
	}
	turnEnd := 0
	if len(input) > 0 {
		turnEnd = 1
	}
	iteration := 1
	for i := len(input) - 1; i >= 0; i-- {
		item, _ := input[i].(object)
		if text(item["role"]) == "user" {
			turnEnd = i + 1
			break
		}
		if strings.HasSuffix(text(item["type"]), "_call_output") {
			iteration++
		}
	}
	threshold := opts.CompactThreshold
	if threshold <= 0 {
		threshold = DefaultCompactThreshold
	}
	output := object{
		"model":            model,
		"model_selection":  "explicit",
		"stream":           true,
		"store":            false,
		"input":            append(prologue, translated...),
		"reasoning_effort": effort,
		"context_management": []any{
			object{"type": "compaction", "compact_threshold": threshold},
		},
		"metadata": object{
			"task_id":         fingerprint([]any{opts.Scope, conversation}),
			"turn_id":         fingerprint([]any{opts.Scope, input[:turnEnd]}),
			"agent_iteration": fmt.Sprint(iteration),
		},
	}
	if cacheKey != "" {
		output["prompt_cache_key"] = "bps-" + fingerprint([]any{opts.Scope, cacheKey})
	}
	if management, ok := source["context_management"].([]any); ok && len(management) > 0 {
		output["context_management"] = management
	}
	body, err := json.Marshal(output)
	if err != nil {
		return nil, prepareErr(CategoryRequestJSON, "encode gateway request: %v", err)
	}
	return &Prepared{Body: body, Bridge: b, Model: model, Effort: effort, Warnings: b.Warnings}, nil
}

// protocolPrompt explains the transport contract to the model. The catalog is
// part of the stable prefix so the upstream prompt cache keeps working.
func (b *Bridge) protocolPrompt(catalog []any, parallel bool) string {
	var sb strings.Builder
	sb.WriteString("This request comes from an external Responses API client relayed through a local bridge, not from a live Excel workbook. ")
	if len(catalog) == 0 {
		sb.WriteString("Return assistant text. Do not call Excel, Office, workbook or connector tools such as read_ranges, search_workbook or write_ranges; they do not exist for this request and fail if called.")
	} else {
		sb.WriteString("Use only the client tools in the catalog below. Host workbook tools such as read_ranges, search_workbook, write_ranges or get_selection do not exist here; the catalog tools are the only way to read files, search code or run commands. ")
		sb.WriteString("The bridge intercepts the native " + TransportTool + " function as a transport and never executes Office code. To call one client tool, call native " + TransportTool + " using the transport matching its catalog type. ")
		sb.WriteString("FUNCTION: code must contain one serialized JSON object {\"name\":\"CATALOG_NAME\",\"arguments\":{...}}. Arguments is a JSON object, not a JSON string. ")
		sb.WriteString("CUSTOM: set summary to exactly " + CustomMarker + "CATALOG_NAME and put the exact raw tool input directly in code without wrapping it in JSON or Markdown fences. ")
		sb.WriteString("For example, custom tool apply_patch uses summary=" + CustomMarker + "apply_patch and code containing the raw patch text. The marker is mandatory for raw input. ")
		sb.WriteString("CATALOG_NAME includes its exact namespace. Outer " + TransportTool + " arguments also include extended_summary, destructive=false and references=[]. For FUNCTION transport use an ordinary descriptive summary. ")
		sb.WriteString("Never nest " + TransportTool + " inside code. Serialize the outer native arguments with proper JSON escaping; inside FUNCTION envelopes escape quotes, backslashes, newlines, carriage returns and tabs within JSON string values. ")
		if parallel {
			sb.WriteString("Independent tool calls may be emitted as separate " + TransportTool + " calls in the same response; wait for a result only when the next call depends on it. ")
		} else {
			sb.WriteString("Call one client tool at a time. ")
		}
		sb.WriteString("After receiving a tool result continue the task; do not repeat completed calls. Tool results replayed under " + TransportTool + " are the named client tool's results. ")
		sb.WriteString("When a tool is needed, emit its call in this response instead of only announcing it. Do not call other native tools and do not claim that shell, filesystem or workspace access is unavailable when a suitable catalog tool exists. ")
		sb.WriteString("If no tool is needed, answer as assistant text. Client tool catalog:\n")
		sb.WriteString(describeCatalog(catalog))
		sb.WriteString("\nEnd of catalog. Invoke native " + TransportTool + " for client tools. FUNCTION uses a JSON envelope in code. CUSTOM uses the exact " + CustomMarker + "CATALOG_NAME summary marker and raw input in code. No Office code is executed by the bridge.")
	}
	if len(b.unsupportedTools) > 0 {
		kinds := make([]string, 0, len(b.unsupportedTools))
		for kind := range b.unsupportedTools {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		warning := "Hosted tools unavailable through Basispoints: " + strings.Join(kinds, ", ")
		b.Warnings = append(b.Warnings, warning)
		sb.WriteString("\n" + warning + ". These declarations were omitted. Do not claim to have used them. If the task requires one, explain the limitation or use a suitable declared client tool.")
		if b.omitsWebSearch() {
			sb.WriteString(" If the user needs current web information, say that web search is off on this channel and that enabling live web search in the client (for example Codex --search) turns it on.")
		}
	}
	if b.structured != nil {
		sb.WriteString("\n" + b.structured.instructions())
	}
	return sb.String()
}

func (b *Bridge) omitsWebSearch() bool {
	for kind := range b.unsupportedTools {
		if strings.HasPrefix(kind, "web_search") {
			return true
		}
	}
	return false
}
