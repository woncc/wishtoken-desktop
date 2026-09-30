package basispoints

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/xxx-holic/wishtoken-desktop/internal/testutil"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func weatherTool() object {
	return object{"type": "function", "name": "get_weather", "description": "Get weather", "parameters": object{"type": "object", "properties": object{"city": object{"type": "string"}}, "required": []any{"city"}}}
}

func transportArgs(t *testing.T, envelope any, summary string) string {
	t.Helper()
	code := ""
	switch e := envelope.(type) {
	case string:
		code = e
	default:
		code = string(mustJSON(t, e))
	}
	return string(mustJSON(t, object{"code": code, "summary": summary, "extended_summary": "", "destructive": false, "references": []any{}}))
}

func TestPrepareBuildsGatewayBody(t *testing.T) {
	req := object{
		"model":            "gpt-6-astra",
		"instructions":     "Be terse.",
		"input":            []any{object{"type": "message", "role": "user", "content": []any{object{"type": "input_text", "text": "weather in Tokyo?"}}}},
		"tools":            []any{weatherTool(), object{"type": "web_search", "external_web_access": false}},
		"reasoning":        object{"effort": "xhigh"},
		"tool_choice":      "auto",
		"prompt_cache_key": "conv-1",
		"temperature":      0.2,
	}
	prepared, err := Prepare(mustJSON(t, req), Options{Scope: "acct|conv-1", Replay: NewReplayCache()})
	if err != nil {
		t.Fatal(err)
	}
	var body object
	if err := json.Unmarshal(prepared.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body["model"] != "gpt-6-astra" || body["model_selection"] != "explicit" || body["stream"] != true || body["store"] != false {
		t.Fatalf("base fields: %v", body)
	}
	if body["reasoning_effort"] != "xhigh" {
		t.Fatalf("effort: %v", body["reasoning_effort"])
	}
	if _, has := body["tools"]; has {
		t.Fatal("tools must not be sent natively")
	}
	if _, has := body["temperature"]; has {
		t.Fatal("unknown fields must be dropped")
	}
	input := body["input"].([]any)
	if len(input) != 3 {
		t.Fatalf("expected instructions + protocol + user, got %d", len(input))
	}
	dev := input[1].(object)
	protocol := dev["content"].([]any)[0].(object)["text"].(string)
	if !strings.Contains(protocol, "Client tool \"get_weather\" (function)") || !strings.Contains(protocol, TransportTool) {
		t.Fatalf("protocol prompt missing catalog: %s", protocol)
	}
	if !strings.Contains(protocol, "Hosted tools unavailable through Basispoints: web_search") {
		t.Fatalf("web_search omission not announced: %s", protocol)
	}
	meta := body["metadata"].(object)
	if meta["task_id"] == "" || meta["turn_id"] == "" || meta["agent_iteration"] != "1" {
		t.Fatalf("metadata: %v", meta)
	}
	if !strings.HasPrefix(body["prompt_cache_key"].(string), "bps-") {
		t.Fatalf("prompt cache key: %v", body["prompt_cache_key"])
	}
	cm := body["context_management"].([]any)[0].(object)
	if cm["compact_threshold"].(float64) != DefaultCompactThreshold {
		t.Fatalf("compact threshold: %v", cm)
	}
}

func TestPrepareRejectsUnsupportedShapes(t *testing.T) {
	cases := []struct {
		name string
		req  object
		cat  string
	}{
		{"previous_response_id", object{"model": "gpt-6-astra", "input": "hi", "previous_response_id": "resp_1"}, CategoryHistoryRef},
		{"forced tool choice", object{"model": "gpt-6-astra", "input": "hi", "tool_choice": object{"type": "function", "name": "x"}}, CategoryToolChoice},
		{"no model", object{"input": "hi"}, CategoryModel},
		{"item_reference", object{"model": "gpt-6-astra", "input": []any{object{"type": "item_reference", "id": "x"}}}, CategoryHistoryRef},
	}
	for _, tc := range cases {
		_, err := Prepare(mustJSON(t, tc.req), Options{})
		if err == nil || Category(err) != tc.cat {
			t.Fatalf("%s: expected category %s, got %v (%s)", tc.name, tc.cat, err, Category(err))
		}
	}
}

func TestStreamTranslatesTransportToolCall(t *testing.T) {
	req := object{"model": "gpt-6-astra", "input": "weather?", "tools": []any{weatherTool()}}
	replay := NewReplayCache()
	prepared, err := Prepare(mustJSON(t, req), Options{Scope: "s1", Replay: replay})
	if err != nil {
		t.Fatal(err)
	}
	args := transportArgs(t, object{"name": "get_weather", "arguments": object{"city": "Tokyo"}}, "Look up weather")
	native := object{"type": "function_call", "id": "fc_native1", "call_id": "call_1", "name": TransportTool, "arguments": args, "status": "completed"}
	upstream := testutil.SSE(
		object{"type": "response.created", "response": object{"id": "resp_1", "status": "in_progress", "output": []any{}}},
		object{"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "delta": "Checking"},
		object{"type": "response.output_item.added", "output_index": 1, "item": object{"type": "function_call", "id": "fc_native1", "call_id": "call_1", "name": TransportTool, "arguments": "", "status": "in_progress"}},
		object{"type": "response.function_call_arguments.delta", "item_id": "fc_native1", "output_index": 1, "delta": args},
		object{"type": "response.output_item.done", "output_index": 1, "item": native},
		object{"type": "response.completed", "response": object{"id": "resp_1", "status": "completed", "output": []any{
			object{"type": "message", "id": "msg_1", "role": "assistant", "content": []any{object{"type": "output_text", "text": "Checking"}}}, native,
		}, "usage": object{"input_tokens": 10, "output_tokens": 5}}},
	)
	out, err := io.ReadAll(prepared.Bridge.Stream(io.NopCloser(strings.NewReader(upstream))))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, `"delta":"Checking"`) {
		t.Fatalf("text delta not streamed: %s", text)
	}
	if strings.Contains(text, TransportTool) {
		t.Fatalf("native transport leaked to client: %s", text)
	}
	if !strings.Contains(text, `"name":"get_weather"`) || !strings.Contains(text, `{\"city\":\"Tokyo\"}`) {
		t.Fatalf("translated tool call missing: %s", text)
	}
	if !strings.Contains(text, "event: response.function_call_arguments.done") || !strings.Contains(text, "event: response.completed") {
		t.Fatalf("expected synthesized tool events and completion: %s", text)
	}
	// The next turn replays the call and its output through the cache.
	next := object{"model": "gpt-6-astra", "tools": []any{weatherTool()}, "input": []any{
		object{"type": "message", "role": "user", "content": []any{object{"type": "input_text", "text": "weather?"}}},
		object{"type": "function_call", "id": "fc_client", "call_id": "call_1", "name": "get_weather", "arguments": `{"city":"Tokyo"}`},
		object{"type": "function_call_output", "call_id": "call_1", "output": "sunny"},
	}}
	prepared2, err := Prepare(mustJSON(t, next), Options{Scope: "s1", Replay: replay})
	if err != nil {
		t.Fatal(err)
	}
	var body object
	_ = json.Unmarshal(prepared2.Body, &body)
	input := body["input"].([]any)
	var sawTransport, sawOutput bool
	for _, raw := range input {
		item := raw.(object)
		if item["type"] == "function_call" && item["name"] == TransportTool && item["call_id"] == "call_1" {
			sawTransport = true
		}
		if item["type"] == "function_call_output" && strings.HasPrefix(item["id"].(string), "fc_") {
			sawOutput = true
		}
	}
	if !sawTransport || !sawOutput {
		t.Fatalf("history not replayed as transport: %s", prepared2.Body)
	}
	if body["metadata"].(object)["agent_iteration"] != "2" {
		t.Fatalf("agent_iteration should advance: %v", body["metadata"])
	}
}

func TestStreamRejectsUnknownNativeTool(t *testing.T) {
	prepared, err := Prepare(mustJSON(t, object{"model": "gpt-6-astra", "input": "hi", "tools": []any{weatherTool()}}), Options{Scope: "s2", Replay: NewReplayCache()})
	if err != nil {
		t.Fatal(err)
	}
	native := object{"type": "function_call", "id": "fc_x", "call_id": "call_x", "name": "read_ranges", "arguments": "{}", "status": "completed"}
	upstream := testutil.SSE(
		object{"type": "response.output_item.done", "output_index": 0, "item": native},
		object{"type": "response.completed", "response": object{"id": "r", "status": "completed", "output": []any{native}}},
	)
	out, _ := io.ReadAll(prepared.Bridge.Stream(io.NopCloser(strings.NewReader(upstream))))
	if !strings.Contains(string(out), "response.failed") || !strings.Contains(string(out), "basispoints_protocol_error") {
		t.Fatalf("expected protocol failure, got: %s", out)
	}
}

func TestEnvelopeDecoding(t *testing.T) {
	b := &Bridge{tools: map[string]toolInfo{"exec_command": {Name: "exec_command", Kind: "function"}, "apply_patch": {Name: "apply_patch", Kind: "custom"}}}
	cases := []any{
		object{"name": "exec_command", "arguments": object{"cmd": "pwd"}},
		`{"name":"exec_command","arguments":{"cmd":"pwd"}}`,
		"```json\n{\"name\":\"exec_command\",\"arguments\":{\"cmd\":\"pwd\"}}\n```",
		"Here is the call: {\"name\":\"exec_command\",\"arguments\":{\"cmd\":\"pwd\"}}",
		`{"name":"run_officejs","arguments":{"code":"{\"name\":\"exec_command\",\"arguments\":{\"cmd\":\"pwd\"}}"}}`,
	}
	for i, c := range cases {
		env, err := decodeTransportEnvelope(c)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if name, _ := envelopeName(env); name != "exec_command" {
			t.Fatalf("case %d: name %q", i, name)
		}
	}
	env, ok := b.recoverTransportEnvelope(object{"code": `functions.exec_command({"cmd":"pwd"})`})
	if !ok || env["name"] != "exec_command" {
		t.Fatalf("call-shaped recovery failed: %v %v", ok, env)
	}
	custom, marked, err := customTransportEnvelope(object{"summary": CustomMarker + "apply_patch", "code": "*** Begin Patch\n*** End Patch"})
	if err != nil || !marked || custom["name"] != "apply_patch" || custom["input"] != "*** Begin Patch\n*** End Patch" {
		t.Fatalf("custom transport: %v %v %v", custom, marked, err)
	}
	if _, err := decodeTransportEnvelope("just some prose without json"); err == nil {
		t.Fatal("expected failure for prose")
	}
	fixed := repairTransportJSONStrings("{\"a\":\"line1\nline2\\q\"}")
	if !json.Valid([]byte(fixed)) {
		t.Fatalf("repair failed: %s", fixed)
	}
}

func TestRouteDecisions(t *testing.T) {
	cases := []struct {
		body   object
		reason string
	}{
		{object{"input": "x", "tools": []any{object{"type": "web_search", "external_web_access": false}}}, ""},
		{object{"input": "x", "tools": []any{object{"type": "web_search", "external_web_access": true}}}, RouteWebSearch},
		{object{"input": "x", "tools": []any{object{"type": "image_generation"}}}, RouteImageGeneration},
		{object{"input": "x", "tool_choice": "required"}, RouteToolChoice},
		{object{"input": "x", "previous_response_id": "r"}, RouteHistory},
		{object{"input": []any{object{"type": "message", "role": "user", "content": []any{object{"type": "input_file", "file_id": "f"}}}}}, RouteInputContent},
		{object{"input": []any{object{"type": "message", "role": "user", "content": []any{object{"type": "input_image", "image_url": "data:image/png;base64,AAAA"}}}}}, ""},
		{object{"input": []any{object{"type": "message", "role": "user", "content": []any{object{"type": "input_image", "image_url": "http://insecure/x.png"}}}}}, RouteImageInput},
	}
	for i, tc := range cases {
		if got := NativeReason(tc.body); got != tc.reason {
			t.Fatalf("case %d: expected %q got %q", i, tc.reason, got)
		}
	}
	body := object{"tools": []any{weatherTool(), object{"type": "web_search"}, object{"type": "mcp", "server_label": "x"}}, "tool_choice": object{"type": "web_search"}}
	removed := StripHostedTools(body)
	if len(removed) != 2 || len(body["tools"].([]any)) != 1 || body["tool_choice"] != "auto" {
		t.Fatalf("strip: removed=%v body=%v", removed, body)
	}
}

func TestResolveModel(t *testing.T) {
	cases := map[string]Resolved{
		"gpt-6-astra":          {Upstream: "gpt-6-astra"},
		"GPT-6-Astra:bps":      {Upstream: "gpt-6-astra", ForceRoute: "bps"},
		"gpt-5.6-sol-codex":    {Upstream: "gpt-5.6-sol", ForceRoute: "codex"},
		"gpt-6-astra-1m-excel": {Upstream: "gpt-6-astra", LongContext: true},
		"gpt-6-astra-xhigh":    {Upstream: "gpt-6-astra", Effort: "xhigh"},
		"gpt-5.6-sol(high)":    {Upstream: "gpt-5.6-sol", Effort: "high"},
		"gpt-6-astra-1m:bps":   {Upstream: "gpt-6-astra", ForceRoute: "bps", LongContext: true},
		"gpt-5.5":              {Upstream: "gpt-5.5"},
		"gpt-5.5-high":         {Upstream: "gpt-5.5-high"},
	}
	for in, want := range cases {
		got := ResolveModel(in)
		if got.Upstream != want.Upstream || got.ForceRoute != want.ForceRoute || got.LongContext != want.LongContext || got.Effort != want.Effort {
			t.Fatalf("%s: got %+v want %+v", in, got, want)
		}
	}
}

func TestImagePlanUploads(t *testing.T) {
	png := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nfakepngdata"))
	req := object{"model": "gpt-6-astra", "input": []any{
		object{"type": "message", "role": "user", "content": []any{object{"type": "input_image", "image_url": "data:image/png;base64," + png}, object{"type": "input_text", "text": "what is this"}}},
		object{"type": "function_call", "call_id": "c1", "name": "screenshot", "arguments": "{}"},
		object{"type": "function_call_output", "call_id": "c1", "output": []any{object{"type": "input_image", "image_url": "data:image/png;base64," + png}}},
	}}
	plan, err := PlanImages(mustJSON(t, req))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasUploads() || len(plan.ToolImages()) != 1 {
		t.Fatalf("plan: uploads=%v toolImages=%d", plan.HasUploads(), len(plan.ToolImages()))
	}
	uploads := 0
	cache := &AttachmentCache{}
	body, err := plan.Apply(context.Background(), cache, "scope", func(ctx context.Context, att Attachment) (string, error) {
		uploads++
		if att.MIME != "image/png" || len(att.Data) == 0 {
			t.Fatalf("attachment: %+v", att)
		}
		return "file-abc123", nil
	})
	if err != nil || uploads != 1 {
		t.Fatalf("apply: %v uploads=%d", err, uploads)
	}
	if !strings.Contains(string(body), `"file_id":"file-abc123"`) || strings.Count(string(body), "data:image/png") != 1 {
		t.Fatalf("rewritten body: %s", body)
	}
	// Second apply hits the cache.
	plan2, _ := PlanImages(mustJSON(t, req))
	_, _ = plan2.Apply(context.Background(), cache, "scope", func(ctx context.Context, att Attachment) (string, error) {
		uploads++
		return "file-abc123", nil
	})
	if uploads != 1 {
		t.Fatalf("expected cached upload, uploads=%d", uploads)
	}
	// The rewritten body must now pass Prepare (file ids accepted).
	if _, err := Prepare(body, Options{Scope: "s", Replay: NewReplayCache(), ToolImages: plan.ToolImages()}); err != nil {
		t.Fatalf("prepare after upload: %v", err)
	}
}

func TestStructuredOutputEmulation(t *testing.T) {
	req := object{"model": "gpt-6-astra", "input": "give json", "text": object{"format": object{"type": "json_schema", "name": "answer", "schema": object{"type": "object", "properties": object{"ok": object{"type": "boolean"}}, "required": []any{"ok"}}}}}
	prepared, err := Prepare(mustJSON(t, req), Options{Scope: "s3", Replay: NewReplayCache()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prepared.Body), "structured final answer") {
		t.Fatalf("structured instructions missing")
	}
	msg := object{"type": "message", "id": "m", "role": "assistant", "content": []any{object{"type": "output_text", "text": "```json\n{\"ok\": true}\n```"}}}
	upstream := testutil.SSE(
		object{"type": "response.output_text.delta", "item_id": "m", "output_index": 0, "delta": "```json"},
		object{"type": "response.completed", "response": object{"id": "r", "status": "completed", "output": []any{msg}}},
	)
	out, _ := io.ReadAll(prepared.Bridge.Stream(io.NopCloser(strings.NewReader(upstream))))
	text := string(out)
	if strings.Contains(text, "```") {
		t.Fatalf("fences must be stripped: %s", text)
	}
	if !strings.Contains(text, `{\"ok\": true}`) || !strings.Contains(text, "response.completed") {
		t.Fatalf("structured answer not emitted: %s", text)
	}
	bad := object{"type": "message", "id": "m", "role": "assistant", "content": []any{object{"type": "output_text", "text": "not json"}}}
	prepared2, _ := Prepare(mustJSON(t, req), Options{Scope: "s3", Replay: NewReplayCache()})
	out, _ = io.ReadAll(prepared2.Bridge.Stream(io.NopCloser(strings.NewReader(testutil.SSE(object{"type": "response.completed", "response": object{"id": "r", "status": "completed", "output": []any{bad}}})))))
	if !strings.Contains(string(out), "response.failed") {
		t.Fatalf("invalid JSON must fail: %s", out)
	}
}
