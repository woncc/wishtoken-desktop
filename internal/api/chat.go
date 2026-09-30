package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Defaults fill fields a client omitted.
type Defaults struct {
	Model  string
	Effort string
}

// ChatToResponses converts a Chat Completions request into a Responses
// request. Only the fields the ChatGPT backends accept are produced.
func ChatToResponses(body object, defaults Defaults) (object, error) {
	out := object{"stream": true, "store": false}
	model := strings.TrimSpace(str(body["model"]))
	if model == "" {
		model = defaults.Model
	}
	out["model"] = model

	messages, _ := body["messages"].([]any)
	if len(messages) == 0 {
		return nil, fmt.Errorf("messages must be a non-empty array")
	}
	var instructions []string
	input := make([]any, 0, len(messages))
	for i, raw := range messages {
		msg, ok := raw.(object)
		if !ok {
			return nil, fmt.Errorf("messages[%d] must be an object", i)
		}
		role := str(msg["role"])
		switch role {
		case "system", "developer":
			if text := contentText(msg["content"]); text != "" {
				instructions = append(instructions, text)
			}
		case "user":
			parts, err := userContentParts(msg["content"])
			if err != nil {
				return nil, fmt.Errorf("messages[%d]: %w", i, err)
			}
			input = append(input, object{"type": "message", "role": "user", "content": parts})
		case "assistant":
			if text := contentText(msg["content"]); text != "" {
				input = append(input, object{"type": "message", "role": "assistant", "content": []any{object{"type": "output_text", "text": text}}})
			}
			calls, _ := msg["tool_calls"].([]any)
			for _, rawCall := range calls {
				call, _ := rawCall.(object)
				fn, _ := call["function"].(object)
				args := strings.TrimSpace(str(fn["arguments"]))
				if args == "" {
					args = "{}"
				}
				if !json.Valid([]byte(args)) {
					continue
				}
				id := str(call["id"])
				if id == "" {
					id = fmt.Sprintf("call_%d_%d", i, len(input))
				}
				input = append(input, object{"type": "function_call", "call_id": id, "name": str(fn["name"]), "arguments": args})
			}
		case "tool", "function":
			id := str(msg["tool_call_id"])
			if id == "" {
				id = str(msg["name"])
			}
			input = append(input, object{"type": "function_call_output", "call_id": id, "output": toolOutput(msg["content"])})
		default:
			return nil, fmt.Errorf("messages[%d]: unsupported role %q", i, role)
		}
	}
	if len(instructions) > 0 {
		out["instructions"] = strings.Join(instructions, "\n\n")
	}
	out["input"] = input

	if tools, ok := body["tools"].([]any); ok && len(tools) > 0 {
		converted := make([]any, 0, len(tools))
		for _, raw := range tools {
			tool, _ := raw.(object)
			if tool == nil {
				continue
			}
			if fn, ok := tool["function"].(object); ok {
				entry := object{"type": "function", "name": str(fn["name"])}
				if d := str(fn["description"]); d != "" {
					entry["description"] = d
				}
				if p, ok := fn["parameters"]; ok && p != nil {
					entry["parameters"] = p
				} else {
					entry["parameters"] = object{"type": "object", "properties": object{}}
				}
				if s, ok := fn["strict"].(bool); ok {
					entry["strict"] = s
				}
				converted = append(converted, entry)
				continue
			}
			if str(tool["type"]) == "function" && str(tool["name"]) != "" {
				converted = append(converted, tool)
			}
		}
		if len(converted) > 0 {
			out["tools"] = converted
		}
	}
	switch choice := body["tool_choice"].(type) {
	case string:
		if choice != "" {
			out["tool_choice"] = choice
		}
	case object:
		if fn, ok := choice["function"].(object); ok {
			out["tool_choice"] = object{"type": "function", "name": str(fn["name"])}
		} else if str(choice["type"]) != "" {
			out["tool_choice"] = choice
		}
	}
	if v, ok := body["parallel_tool_calls"].(bool); ok {
		out["parallel_tool_calls"] = v
	}
	effort := strings.TrimSpace(str(body["reasoning_effort"]))
	if reasoning, ok := body["reasoning"].(object); ok && effort == "" {
		effort = str(reasoning["effort"])
	}
	if effort == "" {
		effort = defaults.Effort
	}
	reasoning := object{"summary": "auto"}
	if effort != "" {
		reasoning["effort"] = effort
	}
	out["reasoning"] = reasoning
	if format, ok := body["response_format"].(object); ok {
		switch str(format["type"]) {
		case "json_object":
			out["text"] = object{"format": object{"type": "json_object"}}
		case "json_schema":
			schema, _ := format["json_schema"].(object)
			f := object{"type": "json_schema"}
			for k, v := range schema {
				f[k] = v
			}
			out["text"] = object{"format": f}
		}
	}
	if v := body["max_completion_tokens"]; v != nil {
		out["max_output_tokens"] = v
	} else if v := body["max_tokens"]; v != nil {
		out["max_output_tokens"] = v
	}
	if key := str(body["prompt_cache_key"]); key != "" {
		out["prompt_cache_key"] = key
	} else if user := str(body["user"]); user != "" {
		out["prompt_cache_key"] = user
	}
	return out, nil
}

func contentText(content any) string {
	switch v := content.(type) {
	case string:
		return v
	case []any:
		var sb strings.Builder
		for _, raw := range v {
			part, _ := raw.(object)
			if t := str(part["text"]); t != "" {
				if sb.Len() > 0 {
					sb.WriteString("\n")
				}
				sb.WriteString(t)
			}
		}
		return sb.String()
	}
	return ""
}

func userContentParts(content any) ([]any, error) {
	switch v := content.(type) {
	case string:
		return []any{object{"type": "input_text", "text": v}}, nil
	case []any:
		parts := make([]any, 0, len(v))
		for _, raw := range v {
			part, _ := raw.(object)
			switch str(part["type"]) {
			case "text", "input_text":
				parts = append(parts, object{"type": "input_text", "text": str(part["text"])})
			case "image_url", "input_image":
				var url, detail string
				switch img := part["image_url"].(type) {
				case string:
					url = img
				case object:
					url, detail = str(img["url"]), str(img["detail"])
				}
				if url == "" {
					continue
				}
				image := object{"type": "input_image", "image_url": url}
				if detail != "" {
					image["detail"] = detail
				} else if d := str(part["detail"]); d != "" {
					image["detail"] = d
				}
				parts = append(parts, image)
			case "input_audio", "audio", "file", "input_file":
				return nil, fmt.Errorf("content type %q is not supported", str(part["type"]))
			default:
				if t := str(part["text"]); t != "" {
					parts = append(parts, object{"type": "input_text", "text": t})
				}
			}
		}
		if len(parts) == 0 {
			parts = append(parts, object{"type": "input_text", "text": ""})
		}
		return parts, nil
	case nil:
		return []any{object{"type": "input_text", "text": ""}}, nil
	}
	return nil, fmt.Errorf("content must be a string or an array of parts")
}

func toolOutput(content any) any {
	switch v := content.(type) {
	case string:
		return v
	case []any:
		hasImage := false
		for _, raw := range v {
			part, _ := raw.(object)
			if str(part["type"]) == "image_url" || str(part["type"]) == "input_image" {
				hasImage = true
			}
		}
		if !hasImage {
			return contentText(v)
		}
		parts, err := userContentParts(v)
		if err != nil {
			return contentText(v)
		}
		return parts
	case nil:
		return ""
	}
	raw, _ := json.Marshal(content)
	return string(raw)
}

// ---------------------------------------------------------------------------
// Responses stream -> Chat Completions
// ---------------------------------------------------------------------------

type chatToolState struct {
	index     int
	sentArgs  bool
	callID    string
	name      string
	arguments strings.Builder
	custom    bool
}

// ChatStream converts a Responses SSE stream to Chat Completions chunks.
func ChatStream(w http.ResponseWriter, r io.Reader, model string) error {
	sse := NewSSEWriter(w)
	id := "chatcmpl-" + fmt.Sprint(time.Now().UnixNano())
	created := time.Now().Unix()
	tools := map[string]*chatToolState{}
	toolCount := 0
	sentRole := false
	var reasoning strings.Builder
	chunk := func(delta object, finish any, usage object) error {
		payload := object{"id": id, "object": "chat.completion.chunk", "created": created, "model": model,
			"choices": []any{object{"index": 0, "delta": delta, "finish_reason": finish}}}
		if usage != nil {
			payload["usage"] = usage
		}
		return sse.Event("", payload)
	}
	ensureRole := func() error {
		if sentRole {
			return nil
		}
		sentRole = true
		return chunk(object{"role": "assistant", "content": ""}, nil, nil)
	}
	toolDelta := func(state *chatToolState, name, args string, first bool) error {
		call := object{"index": state.index, "function": object{"arguments": args}}
		if first {
			call["id"] = state.callID
			call["type"] = "function"
			call["function"] = object{"name": name, "arguments": args}
		}
		return chunk(object{"tool_calls": []any{call}}, nil, nil)
	}
	err := ReadEvents(r, func(ev Event) error {
		switch ev.Type {
		case "response.created", "response.in_progress":
			return ensureRole()
		case "response.output_text.delta":
			if err := ensureRole(); err != nil {
				return err
			}
			return chunk(object{"content": str(ev.Data["delta"])}, nil, nil)
		case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
			if err := ensureRole(); err != nil {
				return err
			}
			delta := str(ev.Data["delta"])
			reasoning.WriteString(delta)
			return chunk(object{"reasoning_content": delta, "reasoning": delta}, nil, nil)
		case "response.reasoning_summary_part.done":
			if reasoning.Len() > 0 {
				reasoning.WriteString("\n\n")
				return chunk(object{"reasoning_content": "\n\n", "reasoning": "\n\n"}, nil, nil)
			}
		case "response.output_item.added":
			item, _ := ev.Data["item"].(object)
			kind := str(item["type"])
			if kind != "function_call" && kind != "custom_tool_call" {
				return nil
			}
			if err := ensureRole(); err != nil {
				return err
			}
			state := &chatToolState{index: toolCount, callID: str(item["call_id"]), name: str(item["name"]), custom: kind == "custom_tool_call"}
			toolCount++
			tools[str(item["id"])] = state
			return toolDelta(state, state.name, "", true)
		case "response.function_call_arguments.delta", "response.custom_tool_call_input.delta":
			state := tools[str(ev.Data["item_id"])]
			if state == nil {
				return nil
			}
			delta := str(ev.Data["delta"])
			state.arguments.WriteString(delta)
			state.sentArgs = true
			if state.custom {
				return nil // custom input is emitted whole on done
			}
			return toolDelta(state, state.name, delta, false)
		case "response.output_item.done":
			item, _ := ev.Data["item"].(object)
			kind := str(item["type"])
			if kind != "function_call" && kind != "custom_tool_call" {
				return nil
			}
			state := tools[str(item["id"])]
			if state == nil {
				if err := ensureRole(); err != nil {
					return err
				}
				state = &chatToolState{index: toolCount, callID: str(item["call_id"]), name: str(item["name"]), custom: kind == "custom_tool_call"}
				toolCount++
				tools[str(item["id"])] = state
				if err := toolDelta(state, state.name, "", true); err != nil {
					return err
				}
			}
			if state.custom {
				raw, _ := json.Marshal(object{"input": str(item["input"])})
				return toolDelta(state, state.name, string(raw), false)
			}
			if !state.sentArgs {
				args := str(item["arguments"])
				if args == "" {
					args = "{}"
				}
				return toolDelta(state, state.name, args, false)
			}
			return nil
		case "response.completed", "response.incomplete":
			resp, _ := ev.Data["response"].(object)
			finish := "stop"
			if toolCount > 0 {
				finish = "tool_calls"
			}
			if details, ok := resp["incomplete_details"].(object); ok && str(details["reason"]) == "max_output_tokens" {
				finish = "length"
			}
			if err := ensureRole(); err != nil {
				return err
			}
			if err := chunk(object{}, finish, chatUsage(resp)); err != nil {
				return err
			}
			sse.Done()
			return io.EOF
		case "response.failed", "error":
			message, code := failureMessage(ev)
			if !sse.Started() {
				return &StreamError{Status: http.StatusBadGateway, Code: code, Message: message}
			}
			_ = sse.Event("", object{"error": object{"message": message, "code": code, "type": "server_error"}})
			sse.Done()
			return io.EOF
		}
		return nil
	})
	if err != nil && err != io.EOF {
		var se *StreamError
		if !sse.Started() {
			if asStreamError(err, &se) {
				return se
			}
			return &StreamError{Status: http.StatusBadGateway, Code: "upstream_stream_error", Message: err.Error()}
		}
		_ = sse.Event("", object{"error": object{"message": err.Error(), "type": "server_error"}})
		sse.Done()
	}
	return nil
}

func failureMessage(ev Event) (string, string) {
	if resp, ok := ev.Data["response"].(object); ok {
		if e, ok := resp["error"].(object); ok {
			return str(e["message"]), str(e["code"])
		}
	}
	if e, ok := ev.Data["error"].(object); ok {
		return str(e["message"]), str(e["code"])
	}
	if m := str(ev.Data["message"]); m != "" {
		return m, str(ev.Data["code"])
	}
	return "upstream response failed", "upstream_failed"
}

// StreamError is a failure that happened before any bytes were sent.
type StreamError struct {
	Status  int
	Code    string
	Message string
}

func (e *StreamError) Error() string { return e.Message }

func asStreamError(err error, target **StreamError) bool {
	se, ok := err.(*StreamError)
	if ok {
		*target = se
	}
	return ok
}

func chatUsage(resp object) object {
	in, out, reasoning, cached := Usage(resp)
	return object{
		"prompt_tokens": in, "completion_tokens": out, "total_tokens": in + out,
		"completion_tokens_details": object{"reasoning_tokens": reasoning},
		"prompt_tokens_details":     object{"cached_tokens": cached},
	}
}

// ChatCompletion converts an aggregated Responses stream into a
// chat.completion object.
func ChatCompletion(r io.Reader, model string) (object, *StreamError) {
	collected, err := Collect(r)
	if err != nil {
		return nil, &StreamError{Status: http.StatusBadGateway, Code: "upstream_stream_error", Message: err.Error()}
	}
	if collected.Failed != nil {
		return nil, &StreamError{Status: http.StatusBadGateway, Code: str(collected.Failed["code"]), Message: str(collected.Failed["message"])}
	}
	resp := collected.Response
	message := object{"role": "assistant", "content": nil}
	var text, reasoning strings.Builder
	var toolCalls []any
	output, _ := resp["output"].([]any)
	for _, raw := range output {
		item, _ := raw.(object)
		switch str(item["type"]) {
		case "message":
			content, _ := item["content"].([]any)
			for _, rawPart := range content {
				part, _ := rawPart.(object)
				if str(part["type"]) == "output_text" {
					text.WriteString(str(part["text"]))
				}
			}
		case "reasoning":
			summary, _ := item["summary"].([]any)
			for _, rawPart := range summary {
				part, _ := rawPart.(object)
				if t := str(part["text"]); t != "" {
					if reasoning.Len() > 0 {
						reasoning.WriteString("\n\n")
					}
					reasoning.WriteString(t)
				}
			}
		case "function_call":
			args := str(item["arguments"])
			if args == "" {
				args = "{}"
			}
			toolCalls = append(toolCalls, object{"id": str(item["call_id"]), "type": "function", "function": object{"name": str(item["name"]), "arguments": args}})
		case "custom_tool_call":
			rawInput, _ := json.Marshal(object{"input": str(item["input"])})
			toolCalls = append(toolCalls, object{"id": str(item["call_id"]), "type": "function", "function": object{"name": str(item["name"]), "arguments": string(rawInput)}})
		}
	}
	if text.Len() > 0 || len(toolCalls) == 0 {
		message["content"] = text.String()
	}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	finish := "stop"
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
		finish = "tool_calls"
	}
	if details, ok := resp["incomplete_details"].(object); ok && str(details["reason"]) == "max_output_tokens" {
		finish = "length"
	}
	return object{
		"id": "chatcmpl-" + str(resp["id"]), "object": "chat.completion", "created": time.Now().Unix(), "model": model,
		"choices": []any{object{"index": 0, "message": message, "finish_reason": finish}},
		"usage":   chatUsage(resp),
	}, nil
}
