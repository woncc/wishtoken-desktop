package basispoints

import (
	"strings"
)

// Route reasons explain why a request cannot use the gateway. They are fixed
// labels safe for logs and headers.
const (
	RouteWebSearch       = "web_search"
	RouteImageGeneration = "image_generation"
	RouteHostedTool      = "hosted_tool"
	RouteToolChoice      = "tool_choice"
	RouteImageInput      = "image_input"
	RouteInputContent    = "input_content"
	RouteHistory         = "history_reference"
	RouteOutputFormat    = "output_format"
)

// hostedToolKinds are executed on OpenAI servers and cannot be relayed.
var hostedToolKinds = map[string]bool{
	"web_search": true, "web_search_preview": true, "web_search_preview_2025_03_11": true,
	"web_search_2025_08_26": true, "web_search_2025_08_26_preview": true,
	"image_generation": true, "code_interpreter": true, "file_search": true,
	"computer": true, "computer_use_preview": true, "mcp": true, "tool_search": true,
	"local_shell": false, // client executed; handled as a function-like tool by Codex
}

func isHostedTool(kind string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if hostedToolKinds[kind] {
		return true
	}
	return strings.HasPrefix(kind, "web_search")
}

// StripHostedTools removes hosted tools from body["tools"] and reports the
// removed kinds. An emptied tools array is deleted because the gateway
// rejects an empty array. tool_choice naming a removed tool becomes "auto".
func StripHostedTools(body object) []string {
	tools, ok := body["tools"].([]any)
	if !ok {
		return nil
	}
	var removed []string
	kept := make([]any, 0, len(tools))
	for _, raw := range tools {
		tool, _ := raw.(object)
		kind := text(tool["type"])
		if isHostedTool(kind) {
			removed = append(removed, strings.ToLower(kind))
			continue
		}
		kept = append(kept, raw)
	}
	if len(removed) == 0 {
		return nil
	}
	if len(kept) == 0 {
		delete(body, "tools")
	} else {
		body["tools"] = kept
	}
	if choice, ok := body["tool_choice"].(object); ok {
		name := strings.ToLower(text(choice["name"]) + " " + text(choice["type"]))
		for _, kind := range removed {
			if strings.Contains(name, kind) {
				body["tool_choice"] = "auto"
				break
			}
		}
	}
	return removed
}

// NativeReason reports why body needs the native Codex channel, or "" when
// Basispoints can serve it. Codex CLI declares web_search on every request
// in cached mode (external_web_access=false); that carries no search intent
// and stays on Basispoints. Inline data-URL images are acceptable because the
// bridge uploads them as attachments before the request leaves.
func NativeReason(body object) string {
	if text(body["previous_response_id"]) != "" {
		return RouteHistory
	}
	if reason := toolChoiceReason(body["tool_choice"]); reason != "" {
		return reason
	}
	if reason := declaredToolsReason(body["tools"]); reason != "" {
		return reason
	}
	if input, ok := body["input"].([]any); ok {
		for _, raw := range input {
			item, _ := raw.(object)
			switch text(item["type"]) {
			case "additional_tools":
				if reason := declaredToolsReason(item["tools"]); reason != "" {
					return reason
				}
			case "item_reference":
				return RouteHistory
			}
			if reason := contentReason(item["content"], false); reason != "" {
				return reason
			}
			if text(item["type"]) == "function_call_output" || text(item["type"]) == "custom_tool_call_output" {
				if reason := contentReason(item["output"], true); reason != "" {
					return reason
				}
			}
		}
	}
	return ""
}

func toolChoiceReason(choice any) string {
	switch v := choice.(type) {
	case nil:
		return ""
	case string:
		switch strings.TrimSpace(v) {
		case "", "auto", "none":
			return ""
		}
		return RouteToolChoice
	case object:
		kind := strings.ToLower(text(v["type"]))
		switch {
		case strings.HasPrefix(kind, "web_search"):
			return RouteWebSearch
		case kind == "image_generation":
			return RouteImageGeneration
		}
		return RouteToolChoice
	}
	return RouteToolChoice
}

func declaredToolsReason(value any) string {
	tools, _ := value.([]any)
	for _, raw := range tools {
		tool, _ := raw.(object)
		kind := strings.ToLower(text(tool["type"]))
		switch {
		case kind == "namespace":
			if reason := declaredToolsReason(tool["tools"]); reason != "" {
				return reason
			}
		case strings.HasPrefix(kind, "web_search"):
			if external, ok := tool["external_web_access"].(bool); ok && external {
				return RouteWebSearch
			}
			if text(tool["search_context_size"]) == "high" {
				return RouteWebSearch
			}
		case kind == "image_generation":
			return RouteImageGeneration
		case kind == "code_interpreter", kind == "file_search", kind == "computer_use_preview", kind == "computer", kind == "mcp":
			return RouteHostedTool
		}
	}
	return ""
}

func contentReason(value any, toolOutput bool) string {
	parts, ok := value.([]any)
	if !ok {
		return ""
	}
	for _, raw := range parts {
		part, _ := raw.(object)
		switch text(part["type"]) {
		case "input_text", "output_text", "text", "refusal":
		case "input_image":
			url := text(part["image_url"])
			fileID := text(part["file_id"])
			switch {
			case IsDataURL(url):
				// Uploaded as an attachment before sending.
			case strings.HasPrefix(strings.ToLower(url), "https://"):
			case fileID != "" && strings.HasPrefix(fileID, "file-") && url == "":
				// Attachment ids minted by this bridge replay fine.
			default:
				return RouteImageInput
			}
		default:
			return RouteInputContent
		}
	}
	return ""
}

// IsDataURL reports whether s embeds its bytes inline.
func IsDataURL(s string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "data:")
}
