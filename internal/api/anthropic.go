package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AnthropicOptions configure the Messages conversion.
type AnthropicOptions struct {
	// ModelMap maps lower-case Claude model prefixes to GPT models.
	ModelMap map[string]string
	// DefaultModel is used when no mapping matches a claude-* name.
	DefaultModel string
	// DefaultEffort applies when the request has no thinking configuration.
	DefaultEffort string
}

// MapAnthropicModel resolves a Claude model name to a GPT model.
func MapAnthropicModel(model string, opts AnthropicOptions) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return opts.DefaultModel
	}
	if !strings.HasPrefix(m, "claude") {
		return model
	}
	best, bestLen := "", -1
	for prefix, target := range opts.ModelMap {
		p := strings.ToLower(strings.TrimSpace(prefix))
		if strings.HasPrefix(m, p) && len(p) > bestLen {
			best, bestLen = target, len(p)
		}
	}
	if best != "" {
		return best
	}
	switch {
	case strings.Contains(m, "haiku"):
		return "gpt-5.6-luna"
	case strings.Contains(m, "opus"):
		return "gpt-6-astra"
	}
	if opts.DefaultModel != "" {
		return opts.DefaultModel
	}
	return "gpt-5.6-sol"
}

// MessagesToResponses converts an Anthropic Messages request.
func MessagesToResponses(body object, opts AnthropicOptions) (object, error) {
	out := object{"stream": true, "store": false}
	out["model"] = MapAnthropicModel(str(body["model"]), opts)

	if system := anthropicText(body["system"]); system != "" {
		out["instructions"] = system
	}
	messages, _ := body["messages"].([]any)
	if len(messages) == 0 {
		return nil, fmt.Errorf("messages must be a non-empty array")
	}
	input := make([]any, 0, len(messages))
	for i, raw := range messages {
		msg, ok := raw.(object)
		if !ok {
			return nil, fmt.Errorf("messages[%d] must be an object", i)
		}
		role := str(msg["role"])
		switch content := msg["content"].(type) {
		case string:
			input = append(input, textMessage(role, content))
		case []any:
			var parts []any
			flush := func() {
				if len(parts) > 0 {
					input = append(input, object{"type": "message", "role": role, "content": parts})
					parts = nil
				}
			}
			for _, rawBlock := range content {
				block, _ := rawBlock.(object)
				switch str(block["type"]) {
				case "text":
					if role == "assistant" {
						parts = append(parts, object{"type": "output_text", "text": str(block["text"])})
					} else {
						parts = append(parts, object{"type": "input_text", "text": str(block["text"])})
					}
				case "image":
					if url := anthropicImageURL(block["source"]); url != "" {
						parts = append(parts, object{"type": "input_image", "image_url": url, "detail": "auto"})
					}
				case "tool_use":
					flush()
					args, _ := json.Marshal(block["input"])
					if block["input"] == nil {
						args = []byte("{}")
					}
					input = append(input, object{"type": "function_call", "call_id": str(block["id"]), "name": str(block["name"]), "arguments": string(args)})
				case "tool_result":
					flush()
					input = append(input, object{"type": "function_call_output", "call_id": str(block["tool_use_id"]), "output": anthropicToolResult(block["content"], block["is_error"])})
				case "thinking", "redacted_thinking":
					// Not replayable across providers; dropped.
				case "document":
					parts = append(parts, object{"type": "input_text", "text": "[document omitted: unsupported content type]"})
				}
			}
			flush()
		case nil:
			input = append(input, textMessage(role, ""))
		default:
			return nil, fmt.Errorf("messages[%d]: unsupported content", i)
		}
	}
	out["input"] = input

	if tools, ok := body["tools"].([]any); ok && len(tools) > 0 {
		converted := make([]any, 0, len(tools))
		for _, raw := range tools {
			tool, _ := raw.(object)
			if tool == nil || str(tool["name"]) == "" {
				continue
			}
			kind := str(tool["type"])
			if kind != "" && kind != "custom" && tool["input_schema"] == nil {
				continue // Anthropic server tools (web search, computer) cannot be relayed
			}
			entry := object{"type": "function", "name": str(tool["name"])}
			if d := str(tool["description"]); d != "" {
				entry["description"] = d
			}
			if schema, ok := tool["input_schema"]; ok && schema != nil {
				entry["parameters"] = schema
			} else {
				entry["parameters"] = object{"type": "object", "properties": object{}}
			}
			converted = append(converted, entry)
		}
		if len(converted) > 0 {
			out["tools"] = converted
		}
	}
	if choice, ok := body["tool_choice"].(object); ok {
		switch str(choice["type"]) {
		case "auto":
			out["tool_choice"] = "auto"
		case "any":
			out["tool_choice"] = "required"
		case "none":
			out["tool_choice"] = "none"
		case "tool":
			out["tool_choice"] = object{"type": "function", "name": str(choice["name"])}
		}
		if disable, ok := choice["disable_parallel_tool_use"].(bool); ok && disable {
			out["parallel_tool_calls"] = false
		}
	}
	effort := ""
	if thinking, ok := body["thinking"].(object); ok {
		if str(thinking["type"]) == "enabled" {
			budget := num(thinking["budget_tokens"])
			switch {
			case budget > 0 && budget < 4096:
				effort = "low"
			case budget < 16000:
				effort = "medium"
			case budget < 40000:
				effort = "high"
			default:
				effort = "xhigh"
			}
		} else if str(thinking["type"]) == "disabled" {
			effort = "low"
		}
	}
	if e := str(body["effort"]); e != "" {
		effort = e
	}
	if outputCfg, ok := body["output_config"].(object); ok {
		if e := str(outputCfg["effort"]); e != "" {
			effort = e
		}
	}
	if effort == "" {
		effort = opts.DefaultEffort
	}
	reasoning := object{"summary": "auto"}
	if effort != "" {
		reasoning["effort"] = effort
	}
	out["reasoning"] = reasoning
	if v := body["max_tokens"]; v != nil {
		out["max_output_tokens"] = v
	}
	if metadata, ok := body["metadata"].(object); ok {
		if user := str(metadata["user_id"]); user != "" {
			sum := sha256.Sum256([]byte(user))
			out["prompt_cache_key"] = "anthropic-" + hex.EncodeToString(sum[:8])
		}
	}
	return out, nil
}

func textMessage(role, text string) object {
	partType := "input_text"
	if role == "assistant" {
		partType = "output_text"
	}
	return object{"type": "message", "role": role, "content": []any{object{"type": partType, "text": text}}}
}

func anthropicText(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []any:
		var sb strings.Builder
		for _, raw := range s {
			block, _ := raw.(object)
			if str(block["type"]) == "text" {
				if sb.Len() > 0 {
					sb.WriteString("\n\n")
				}
				sb.WriteString(str(block["text"]))
			}
		}
		return sb.String()
	}
	return ""
}

func anthropicImageURL(source any) string {
	src, _ := source.(object)
	switch str(src["type"]) {
	case "base64":
		return "data:" + str(src["media_type"]) + ";base64," + str(src["data"])
	case "url":
		return str(src["url"])
	}
	return ""
}

func anthropicToolResult(content any, isError any) any {
	prefix := ""
	if b, ok := isError.(bool); ok && b {
		prefix = "[error] "
	}
	switch c := content.(type) {
	case string:
		return prefix + c
	case []any:
		var texts []string
		var parts []any
		hasImage := false
		for _, raw := range c {
			block, _ := raw.(object)
			switch str(block["type"]) {
			case "text":
				texts = append(texts, str(block["text"]))
				parts = append(parts, object{"type": "input_text", "text": str(block["text"])})
			case "image":
				if url := anthropicImageURL(block["source"]); url != "" {
					hasImage = true
					parts = append(parts, object{"type": "input_image", "image_url": url, "detail": "auto"})
				}
			}
		}
		if hasImage {
			if prefix != "" {
				parts = append([]any{object{"type": "input_text", "text": prefix}}, parts...)
			}
			return parts
		}
		return prefix + strings.Join(texts, "\n")
	case nil:
		return prefix
	}
	raw, _ := json.Marshal(content)
	return prefix + string(raw)
}

// ---------------------------------------------------------------------------
// Responses stream -> Anthropic Messages stream
// ---------------------------------------------------------------------------

type anthropicBlock struct {
	index int
	kind  string // text | thinking | tool_use
	open  bool
}

// AnthropicStream converts a Responses SSE stream to Anthropic events.
func AnthropicStream(w http.ResponseWriter, r io.Reader, model string) error {
	sse := NewSSEWriter(w)
	msgID := "msg_" + fmt.Sprint(time.Now().UnixNano())
	started := false
	nextIndex := 0
	var current *anthropicBlock // open text/thinking block
	toolBlocks := map[string]*anthropicBlock{}
	toolArgsSeen := map[string]bool{}
	hasTool := false

	start := func() error {
		if started {
			return nil
		}
		started = true
		if err := sse.Event("message_start", object{"type": "message_start", "message": object{
			"id": msgID, "type": "message", "role": "assistant", "model": model, "content": []any{},
			"stop_reason": nil, "stop_sequence": nil, "usage": object{"input_tokens": 0, "output_tokens": 0},
		}}); err != nil {
			return err
		}
		return sse.Event("ping", object{"type": "ping"})
	}
	closeCurrent := func() error {
		if current == nil || !current.open {
			current = nil
			return nil
		}
		current.open = false
		err := sse.Event("content_block_stop", object{"type": "content_block_stop", "index": current.index})
		current = nil
		return err
	}
	openBlock := func(kind string) error {
		if current != nil && current.kind == kind && current.open {
			return nil
		}
		if err := closeCurrent(); err != nil {
			return err
		}
		block := &anthropicBlock{index: nextIndex, kind: kind, open: true}
		nextIndex++
		current = block
		var content object
		if kind == "thinking" {
			content = object{"type": "thinking", "thinking": ""}
		} else {
			content = object{"type": "text", "text": ""}
		}
		return sse.Event("content_block_start", object{"type": "content_block_start", "index": block.index, "content_block": content})
	}
	openTool := func(itemID, callID, name string) (*anthropicBlock, error) {
		if err := closeCurrent(); err != nil {
			return nil, err
		}
		hasTool = true
		block := &anthropicBlock{index: nextIndex, kind: "tool_use", open: true}
		nextIndex++
		toolBlocks[itemID] = block
		if err := sse.Event("content_block_start", object{"type": "content_block_start", "index": block.index,
			"content_block": object{"type": "tool_use", "id": callID, "name": name, "input": object{}}}); err != nil {
			return nil, err
		}
		return block, nil
	}
	closeTool := func(block *anthropicBlock) error {
		if block == nil || !block.open {
			return nil
		}
		block.open = false
		return sse.Event("content_block_stop", object{"type": "content_block_stop", "index": block.index})
	}

	err := ReadEvents(r, func(ev Event) error {
		switch ev.Type {
		case "response.created":
			return start()
		case "response.output_text.delta":
			if err := start(); err != nil {
				return err
			}
			if err := openBlock("text"); err != nil {
				return err
			}
			return sse.Event("content_block_delta", object{"type": "content_block_delta", "index": current.index, "delta": object{"type": "text_delta", "text": str(ev.Data["delta"])}})
		case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
			if err := start(); err != nil {
				return err
			}
			if err := openBlock("thinking"); err != nil {
				return err
			}
			return sse.Event("content_block_delta", object{"type": "content_block_delta", "index": current.index, "delta": object{"type": "thinking_delta", "thinking": str(ev.Data["delta"])}})
		case "response.output_item.added":
			item, _ := ev.Data["item"].(object)
			kind := str(item["type"])
			if kind != "function_call" && kind != "custom_tool_call" {
				return nil
			}
			if err := start(); err != nil {
				return err
			}
			_, err := openTool(str(item["id"]), str(item["call_id"]), str(item["name"]))
			return err
		case "response.function_call_arguments.delta":
			block := toolBlocks[str(ev.Data["item_id"])]
			if block == nil {
				return nil
			}
			toolArgsSeen[str(ev.Data["item_id"])] = true
			return sse.Event("content_block_delta", object{"type": "content_block_delta", "index": block.index, "delta": object{"type": "input_json_delta", "partial_json": str(ev.Data["delta"])}})
		case "response.output_item.done":
			item, _ := ev.Data["item"].(object)
			kind := str(item["type"])
			if kind != "function_call" && kind != "custom_tool_call" {
				return nil
			}
			if err := start(); err != nil {
				return err
			}
			id := str(item["id"])
			block := toolBlocks[id]
			if block == nil {
				var err error
				block, err = openTool(id, str(item["call_id"]), str(item["name"]))
				if err != nil {
					return err
				}
			}
			if kind == "custom_tool_call" {
				raw, _ := json.Marshal(object{"input": str(item["input"])})
				if err := sse.Event("content_block_delta", object{"type": "content_block_delta", "index": block.index, "delta": object{"type": "input_json_delta", "partial_json": string(raw)}}); err != nil {
					return err
				}
			} else if !toolArgsSeen[id] {
				args := str(item["arguments"])
				if strings.TrimSpace(args) == "" {
					args = "{}"
				}
				if err := sse.Event("content_block_delta", object{"type": "content_block_delta", "index": block.index, "delta": object{"type": "input_json_delta", "partial_json": args}}); err != nil {
					return err
				}
			}
			return closeTool(block)
		case "response.completed", "response.incomplete":
			if err := start(); err != nil {
				return err
			}
			if err := closeCurrent(); err != nil {
				return err
			}
			for _, block := range toolBlocks {
				if err := closeTool(block); err != nil {
					return err
				}
			}
			resp, _ := ev.Data["response"].(object)
			stop := "end_turn"
			if hasTool {
				stop = "tool_use"
			}
			if details, ok := resp["incomplete_details"].(object); ok && str(details["reason"]) == "max_output_tokens" {
				stop = "max_tokens"
			}
			in, out, _, cached := Usage(resp)
			if err := sse.Event("message_delta", object{"type": "message_delta", "delta": object{"stop_reason": stop, "stop_sequence": nil},
				"usage": object{"input_tokens": in, "output_tokens": out, "cache_read_input_tokens": cached, "cache_creation_input_tokens": 0}}); err != nil {
				return err
			}
			if err := sse.Event("message_stop", object{"type": "message_stop"}); err != nil {
				return err
			}
			return io.EOF
		case "response.failed", "error":
			message, code := failureMessage(ev)
			if !sse.Started() {
				return &StreamError{Status: http.StatusBadGateway, Code: code, Message: message}
			}
			_ = sse.Event("error", object{"type": "error", "error": object{"type": "api_error", "message": message}})
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
		_ = sse.Event("error", object{"type": "error", "error": object{"type": "api_error", "message": err.Error()}})
	}
	return nil
}

// AnthropicMessage converts an aggregated Responses stream into a Messages
// response object.
func AnthropicMessage(r io.Reader, model string) (object, *StreamError) {
	collected, err := Collect(r)
	if err != nil {
		return nil, &StreamError{Status: http.StatusBadGateway, Code: "upstream_stream_error", Message: err.Error()}
	}
	if collected.Failed != nil {
		return nil, &StreamError{Status: http.StatusBadGateway, Code: str(collected.Failed["code"]), Message: str(collected.Failed["message"])}
	}
	resp := collected.Response
	content := []any{}
	hasTool := false
	output, _ := resp["output"].([]any)
	for _, raw := range output {
		item, _ := raw.(object)
		switch str(item["type"]) {
		case "reasoning":
			summary, _ := item["summary"].([]any)
			var sb strings.Builder
			for _, rawPart := range summary {
				part, _ := rawPart.(object)
				if t := str(part["text"]); t != "" {
					if sb.Len() > 0 {
						sb.WriteString("\n\n")
					}
					sb.WriteString(t)
				}
			}
			if sb.Len() > 0 {
				content = append(content, object{"type": "thinking", "thinking": sb.String(), "signature": ""})
			}
		case "message":
			parts, _ := item["content"].([]any)
			var sb strings.Builder
			for _, rawPart := range parts {
				part, _ := rawPart.(object)
				if str(part["type"]) == "output_text" {
					sb.WriteString(str(part["text"]))
				}
			}
			if sb.Len() > 0 {
				content = append(content, object{"type": "text", "text": sb.String()})
			}
		case "function_call":
			hasTool = true
			var input any = object{}
			if args := str(item["arguments"]); strings.TrimSpace(args) != "" {
				var parsed any
				if json.Unmarshal([]byte(args), &parsed) == nil {
					input = parsed
				}
			}
			content = append(content, object{"type": "tool_use", "id": str(item["call_id"]), "name": str(item["name"]), "input": input})
		case "custom_tool_call":
			hasTool = true
			content = append(content, object{"type": "tool_use", "id": str(item["call_id"]), "name": str(item["name"]), "input": object{"input": str(item["input"])}})
		}
	}
	stop := "end_turn"
	if hasTool {
		stop = "tool_use"
	}
	if details, ok := resp["incomplete_details"].(object); ok && str(details["reason"]) == "max_output_tokens" {
		stop = "max_tokens"
	}
	in, out, _, cached := Usage(resp)
	return object{
		"id": "msg_" + str(resp["id"]), "type": "message", "role": "assistant", "model": model, "content": content,
		"stop_reason": stop, "stop_sequence": nil,
		"usage": object{"input_tokens": in, "output_tokens": out, "cache_read_input_tokens": cached, "cache_creation_input_tokens": 0},
	}, nil
}

// EstimateTokens returns a rough token count for count_tokens requests.
func EstimateTokens(body object) int64 {
	raw, _ := json.Marshal(body)
	return int64(len(raw)/4) + 1
}
