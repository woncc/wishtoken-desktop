// Package basispoints translates OpenAI Responses API traffic to and from
// the ChatGPT Excel add-in gateway ("Basispoints", bps.openai.com).
//
// The gateway speaks a dialect of the Responses API: client tools must be
// described as prose, tool calls travel inside the native run_officejs
// function, several request fields are rejected and every request needs a
// task/turn identity. This package owns that translation and nothing else:
// it never executes tools, never stores credentials and never contacts the
// network directly (uploads are delegated to a caller supplied function).
//
// Protocol knowledge was derived from public implementations credited in
// NOTICE.md (hloolx/codex2api, MIKUbiu/bps-local, lingxi-lx/excel-codex-bridge,
// Nonary/ghcp_proxy); the code here is an independent implementation.
package basispoints

import (
	"strings"
)

const (
	// ResponsesURL is the streaming Responses endpoint of the gateway.
	ResponsesURL = "https://bps.openai.com/basispoints/api/responses"
	// AttachmentsURL accepts multipart image uploads and returns a file id.
	AttachmentsURL = "https://bps.openai.com/basispoints/api/attachments"
	// ImageGenerationsURL and ImageEditsURL back the image endpoints.
	ImageGenerationsURL = "https://bps.openai.com/basispoints/api/images/generations"
	ImageEditsURL       = "https://bps.openai.com/basispoints/api/images/edits"

	// TransportTool is the native gateway function reused as a tool-call carrier.
	TransportTool = "run_officejs"
	// CustomMarker prefixes the summary of raw custom-tool transports.
	CustomMarker = "gptbridge.custom/"
	// legacyCustomMarker is accepted for compatibility with other bridges.
	legacyCustomMarker = "codex2api.custom/"

	// DefaultCompactThreshold is the gateway-side compaction threshold for
	// the standard 272k context window.
	DefaultCompactThreshold = 200000
	// LongCompactThreshold applies to the "-1m" long context aliases.
	LongCompactThreshold = 870000
	// DefaultContextWindow is the standard context size of Basispoints models.
	DefaultContextWindow = 272000
	// LongContextWindow is the measured usable long context (~918k tokens).
	LongContextWindow = 918000
)

// ModelInfo describes a model the gateway is known to serve.
type ModelInfo struct {
	ID            string `json:"id"`
	DisplayName   string `json:"display_name"`
	ContextWindow int    `json:"context_window"`
	Note          string `json:"note,omitempty"`
}

// Catalog lists the model families observed on the gateway. Availability is
// decided upstream per account; the router keeps its own allowlist.
var Catalog = []ModelInfo{
	{ID: "gpt-6-astra", DisplayName: "GPT-6 Astra", ContextWindow: DefaultContextWindow},
	{ID: "gpt-6-sol", DisplayName: "GPT-6 Sol", ContextWindow: DefaultContextWindow},
	{ID: "gpt-6-luna", DisplayName: "GPT-6 Luna", ContextWindow: DefaultContextWindow},
	{ID: "gpt-5.6-sol", DisplayName: "GPT-5.6 Sol", ContextWindow: DefaultContextWindow},
	{ID: "gpt-5.6-terra", DisplayName: "GPT-5.6 Terra", ContextWindow: DefaultContextWindow},
	{ID: "gpt-5.6-luna", DisplayName: "GPT-5.6 Luna", ContextWindow: DefaultContextWindow},
}

// Efforts were verified against BPS. max is rejected upstream with HTTP 422.
var Efforts = []string{"low", "medium", "high", "xhigh"}

// Known returns catalog information for id.
func Known(id string) (ModelInfo, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, m := range Catalog {
		if m.ID == id {
			return m, true
		}
	}
	return ModelInfo{}, false
}

// Resolved is the outcome of parsing a requested model name.
type Resolved struct {
	// Requested is the original name.
	Requested string
	// Upstream is the model name sent to the gateway.
	Upstream string
	// ForceRoute is "bps", "codex" or "" when the name carried a routing suffix.
	ForceRoute string
	// LongContext is set for "-1m" aliases.
	LongContext bool
	// Effort is set when the name carried a reasoning effort suffix.
	Effort string
}

// ResolveModel strips routing, effort and context suffixes from a model name:
//
//	gpt-6-astra:bps / gpt-6-astra-bps        force the Basispoints channel
//	gpt-6-astra:codex / gpt-6-astra-native   force the native Codex channel
//	gpt-6-astra-xhigh / gpt-6-astra(high)     reasoning effort alias
//	gpt-6-astra-1m / gpt-6-astra-1m-excel     long context alias
//	gpt-6-astra-excel                          Excel-bridge style alias
func ResolveModel(requested string) Resolved {
	r := Resolved{Requested: requested}
	name := strings.ToLower(strings.TrimSpace(requested))
	if open := strings.Index(name, "("); open > 0 && strings.HasSuffix(name, ")") {
		r.Effort = name[open+1 : len(name)-1]
		name = strings.TrimSpace(name[:open])
	}
	for _, suffix := range []string{":bps", "@bps", "-bps", ":basispoints", "-basispoints"} {
		if strings.HasSuffix(name, suffix) {
			name = strings.TrimSuffix(name, suffix)
			r.ForceRoute = "bps"
			break
		}
	}
	if r.ForceRoute == "" {
		for _, suffix := range []string{":codex", "@codex", "-codex", ":native", "-native"} {
			if strings.HasSuffix(name, suffix) {
				name = strings.TrimSuffix(name, suffix)
				r.ForceRoute = "codex"
				break
			}
		}
	}
	name = strings.TrimSuffix(name, "-excel")
	if strings.HasSuffix(name, "-1m") {
		name = strings.TrimSuffix(name, "-1m")
		r.LongContext = true
	}
	if r.Effort == "" {
		for _, effort := range []string{"xhigh", "high", "medium", "low", "minimal", "max", "ultra"} {
			for _, sep := range []string{"-", ":", "@"} {
				if strings.HasSuffix(name, sep+effort) {
					base := strings.TrimSuffix(name, sep+effort)
					if _, known := Known(base); known || sep != "-" {
						r.Effort = effort
						name = base
					}
					break
				}
			}
			if r.Effort != "" {
				break
			}
		}
	}
	r.Upstream = name
	return r
}

// CompactThreshold returns the compaction threshold for the resolved model.
func (r Resolved) CompactThreshold() int {
	if r.LongContext {
		return LongCompactThreshold
	}
	return DefaultCompactThreshold
}

// ContextWindow returns the context window for the resolved model.
func (r Resolved) ContextWindow() int {
	if r.LongContext {
		return LongContextWindow
	}
	return DefaultContextWindow
}

// NormalizeEffort maps client effort names to the gateway tiers. The second
// result is false when the value was unknown and medium was substituted.
func NormalizeEffort(effort string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "", "medium", "default":
		return "medium", true
	case "low", "high":
		return strings.ToLower(strings.TrimSpace(effort)), true
	case "xhigh", "x-high", "extra-high", "extra_high", "max", "ultra", "very_high", "very-high":
		return "xhigh", true
	case "none", "minimal", "min":
		return "low", true
	default:
		return "medium", false
	}
}
