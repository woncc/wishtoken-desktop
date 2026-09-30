package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xxx-holic/wishtoken-desktop/internal/testutil"
)

func TestChatToResponses(t *testing.T) {
	body := object{
		"model": "gpt-6-astra",
		"messages": []any{
			object{"role": "system", "content": "You are helpful."},
			object{"role": "user", "content": []any{object{"type": "text", "text": "hi"}, object{"type": "image_url", "image_url": object{"url": "https://x/y.png"}}}},
			object{"role": "assistant", "content": nil, "tool_calls": []any{object{"id": "call_1", "type": "function", "function": object{"name": "f", "arguments": `{"a":1}`}}}},
			object{"role": "tool", "tool_call_id": "call_1", "content": "result"},
		},
		"tools":            []any{object{"type": "function", "function": object{"name": "f", "description": "d", "parameters": object{"type": "object"}}}},
		"tool_choice":      object{"type": "function", "function": object{"name": "f"}},
		"reasoning_effort": "high",
		"response_format":  object{"type": "json_object"},
		"max_tokens":       100,
	}
	out, err := ChatToResponses(body, Defaults{Model: "gpt-5.6-sol", Effort: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	if out["instructions"] != "You are helpful." || out["model"] != "gpt-6-astra" {
		t.Fatalf("instructions/model: %v", out)
	}
	input := out["input"].([]any)
	if len(input) != 3 {
		t.Fatalf("expected 3 input items, got %d: %v", len(input), input)
	}
	if input[1].(object)["type"] != "function_call" || input[2].(object)["type"] != "function_call_output" {
		t.Fatalf("tool history: %v", input)
	}
	tools := out["tools"].([]any)
	if tools[0].(object)["name"] != "f" || out["tool_choice"].(object)["name"] != "f" {
		t.Fatalf("tools: %v %v", tools, out["tool_choice"])
	}
	if out["reasoning"].(object)["effort"] != "high" || out["text"].(object)["format"].(object)["type"] != "json_object" {
		t.Fatalf("reasoning/format: %v %v", out["reasoning"], out["text"])
	}
}

func TestCompactTerminalRetainsStreamedItems(t *testing.T) {
	stream := testutil.SSE(
		object{"type": "response.output_text.delta", "item_id": "msg", "output_index": 0, "delta": "OK"},
		object{"type": "response.output_item.done", "output_index": 1, "item": object{"type": "function_call", "name": "example", "arguments": "{}"}},
		object{"type": "response.completed", "response": object{"status": "completed", "output": []any{}}},
	)
	collected, err := Collect(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if OutputText(collected.Response) != "OK" || len(collected.Response["output"].([]any)) != 2 {
		t.Fatal("lost streamed output")
	}
	if _, err := Collect(strings.NewReader(testutil.SSE(object{"type": "response.output_text.delta", "delta": "partial"}))); err == nil {
		t.Fatal("accepted missing terminal event")
	}
}

func toolCallStream() string {
	return testutil.SSE(
		object{"type": "response.created", "response": object{"id": "r1"}},
		object{"type": "response.reasoning_summary_text.delta", "item_id": "rs", "delta": "thinking..."},
		object{"type": "response.output_text.delta", "item_id": "m1", "output_index": 0, "delta": "Hello "},
		object{"type": "response.output_text.delta", "item_id": "m1", "output_index": 0, "delta": "world"},
		object{"type": "response.output_item.added", "output_index": 1, "item": object{"type": "function_call", "id": "fc1", "call_id": "call_9", "name": "get_weather", "arguments": "", "status": "in_progress"}},
		object{"type": "response.function_call_arguments.delta", "item_id": "fc1", "delta": `{"city":`},
		object{"type": "response.function_call_arguments.delta", "item_id": "fc1", "delta": `"Tokyo"}`},
		object{"type": "response.output_item.done", "output_index": 1, "item": object{"type": "function_call", "id": "fc1", "call_id": "call_9", "name": "get_weather", "arguments": `{"city":"Tokyo"}`, "status": "completed"}},
		object{"type": "response.completed", "response": object{"id": "r1", "status": "completed", "output": []any{
			object{"type": "message", "id": "m1", "role": "assistant", "content": []any{object{"type": "output_text", "text": "Hello world"}}},
			object{"type": "function_call", "id": "fc1", "call_id": "call_9", "name": "get_weather", "arguments": `{"city":"Tokyo"}`},
		}, "usage": object{"input_tokens": 12, "output_tokens": 7, "output_tokens_details": object{"reasoning_tokens": 3}}}},
	)
}

func TestChatStreamAndCompletion(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := ChatStream(rec, strings.NewReader(toolCallStream()), "gpt-6-astra"); err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"content":"Hello "`) || !strings.Contains(body, `"reasoning_content":"thinking..."`) {
		t.Fatalf("missing deltas: %s", body)
	}
	if !strings.Contains(body, `"name":"get_weather"`) || !strings.Contains(body, `"arguments":"{\"city\":"`) || !strings.Contains(body, `"finish_reason":"tool_calls"`) {
		t.Fatalf("missing tool call chunks: %s", body)
	}
	if !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Fatalf("missing DONE: %s", body)
	}
	completion, serr := ChatCompletion(strings.NewReader(toolCallStream()), "gpt-6-astra")
	if serr != nil {
		t.Fatal(serr)
	}
	raw, _ := json.Marshal(completion)
	if !strings.Contains(string(raw), `"content":"Hello world"`) || !strings.Contains(string(raw), `"tool_calls"`) || !strings.Contains(string(raw), `"prompt_tokens":12`) {
		t.Fatalf("completion: %s", raw)
	}
}

func TestMessagesToResponsesAndStream(t *testing.T) {
	body := object{
		"model":  "claude-sonnet-4-5",
		"system": []any{object{"type": "text", "text": "sys"}},
		"messages": []any{
			object{"role": "user", "content": "hi"},
			object{"role": "assistant", "content": []any{object{"type": "text", "text": "calling"}, object{"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": object{"city": "Tokyo"}}}},
			object{"role": "user", "content": []any{object{"type": "tool_result", "tool_use_id": "toolu_1", "content": "sunny"}}},
		},
		"tools":       []any{object{"name": "get_weather", "description": "d", "input_schema": object{"type": "object"}}},
		"tool_choice": object{"type": "any"},
		"thinking":    object{"type": "enabled", "budget_tokens": 20000},
		"max_tokens":  500,
	}
	out, err := MessagesToResponses(body, AnthropicOptions{ModelMap: map[string]string{"claude-sonnet": "gpt-5.6-sol"}, DefaultModel: "gpt-6-astra", DefaultEffort: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	if out["model"] != "gpt-5.6-sol" || out["instructions"] != "sys" || out["tool_choice"] != "required" {
		t.Fatalf("mapping: %v", out)
	}
	input := out["input"].([]any)
	if len(input) != 4 || input[2].(object)["type"] != "function_call" || input[3].(object)["type"] != "function_call_output" {
		t.Fatalf("input: %v", input)
	}
	if out["reasoning"].(object)["effort"] != "high" {
		t.Fatalf("thinking budget mapping: %v", out["reasoning"])
	}
	rec := httptest.NewRecorder()
	if err := AnthropicStream(rec, strings.NewReader(toolCallStream()), "claude-sonnet-4-5"); err != nil {
		t.Fatal(err)
	}
	stream := rec.Body.String()
	for _, needle := range []string{"event: message_start", `"type":"thinking_delta"`, `"text":"Hello ","type":"text_delta"`, `"id":"call_9","input":{},"name":"get_weather","type":"tool_use"`, `"partial_json":"{\"city\":"`, `"stop_reason":"tool_use"`, "event: message_stop"} {
		if !strings.Contains(stream, needle) {
			t.Fatalf("missing %s in %s", needle, stream)
		}
	}
	msg, serr := AnthropicMessage(strings.NewReader(toolCallStream()), "claude-sonnet-4-5")
	if serr != nil {
		t.Fatal(serr)
	}
	raw, _ := json.Marshal(msg)
	if !strings.Contains(string(raw), `"type":"tool_use"`) || !strings.Contains(string(raw), `"input":{"city":"Tokyo"}`) || !strings.Contains(string(raw), `"stop_reason":"tool_use"`) {
		t.Fatalf("message: %s", raw)
	}
}

func TestCollectHandlesFailure(t *testing.T) {
	stream := testutil.SSE(object{"type": "response.failed", "response": object{"status": "failed", "error": object{"code": "x", "message": "boom"}}})
	collected, err := Collect(strings.NewReader(stream))
	if err != nil || collected.Failed == nil || collected.Failed["message"] != "boom" {
		t.Fatalf("collect failure: %v %v", err, collected)
	}
}
