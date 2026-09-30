// Package api converts between the OpenAI Responses stream produced by the
// router and the Chat Completions / Anthropic Messages formats.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/xxx-holic/wishtoken-desktop/internal/basispoints"
)

type object = map[string]any

// Event is one decoded Responses SSE event.
type Event struct {
	Type string
	Data object
	Raw  []byte
}

func decode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(target)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) int64 {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

// ReadEvents decodes a Responses SSE stream. Returning io.EOF from fn stops
// reading early without error.
func ReadEvents(r io.Reader, fn func(Event) error) error {
	return basispoints.ReadEvents(r, func(event string, data []byte) error {
		if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
			return nil
		}
		var payload object
		if err := decode(data, &payload); err != nil || payload == nil {
			return fmt.Errorf("invalid SSE event")
		}
		kind := str(payload["type"])
		if kind == "" {
			kind = event
		}
		return fn(Event{Type: kind, Data: payload, Raw: data})
	})
}

// Collected is the aggregation of a Responses stream.
type Collected struct {
	Response object
	Failed   object // error payload from response.failed / error events
}

// Collect aggregates a Responses SSE stream into the terminal response.
func Collect(r io.Reader) (*Collected, error) {
	out := &Collected{}
	var textByItem = map[string]*strings.Builder{}
	items := map[int64]object{}
	textIndex := map[string]int64{}
	err := ReadEvents(r, func(ev Event) error {
		switch ev.Type {
		case "response.output_item.done":
			if item, ok := ev.Data["item"].(object); ok {
				items[num(ev.Data["output_index"])] = item
			}
		case "response.completed", "response.incomplete":
			if resp, ok := ev.Data["response"].(object); ok {
				out.Response = resp
			}
			return io.EOF
		case "response.failed":
			if resp, ok := ev.Data["response"].(object); ok {
				out.Response = resp
				if e, ok := resp["error"].(object); ok {
					out.Failed = e
				}
			}
			if out.Failed == nil {
				out.Failed = object{"message": "response failed"}
			}
			return io.EOF
		case "error":
			if e, ok := ev.Data["error"].(object); ok {
				out.Failed = e
			} else {
				out.Failed = object{"message": str(ev.Data["message"]), "code": str(ev.Data["code"])}
			}
			return io.EOF
		case "response.output_text.delta":
			id := str(ev.Data["item_id"])
			textIndex[id] = num(ev.Data["output_index"])
			if textByItem[id] == nil {
				textByItem[id] = &strings.Builder{}
			}
			textByItem[id].WriteString(str(ev.Data["delta"]))
		}
		return nil
	})
	if err != nil && err != io.EOF {
		return nil, err
	}
	if out.Response == nil && out.Failed == nil {
		return nil, io.ErrUnexpectedEOF
	}
	// Some native streams send full items before a compact terminal event
	// whose output is empty. Preserve their actual streamed content.
	if out.Response != nil {
		output, _ := out.Response["output"].([]any)
		if len(output) == 0 {
			for id, text := range textByItem {
				idx := textIndex[id]
				if _, exists := items[idx]; !exists {
					items[idx] = object{"id": id, "type": "message", "role": "assistant", "content": []any{object{"type": "output_text", "text": text.String()}}}
				}
			}
			indices := make([]int64, 0, len(items))
			for idx := range items {
				indices = append(indices, idx)
			}
			sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
			for _, idx := range indices {
				output = append(output, items[idx])
			}
			out.Response["output"] = output
		}
	}
	return out, nil
}

// ErrorPayload renders an OpenAI style error body.
func ErrorPayload(status int, code, kind, message string) []byte {
	if kind == "" {
		kind = "invalid_request_error"
		if status >= 500 {
			kind = "server_error"
		}
	}
	raw, _ := json.Marshal(object{"error": object{"message": message, "type": kind, "code": code, "status": status}})
	return raw
}

// WriteJSON writes v as JSON with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// SSEWriter writes server-sent events with flushing.
type SSEWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	started bool
}

// NewSSEWriter prepares w for SSE output (headers are written lazily).
func NewSSEWriter(w http.ResponseWriter) *SSEWriter {
	f, _ := w.(http.Flusher)
	return &SSEWriter{w: w, flusher: f}
}

func (s *SSEWriter) start() {
	if s.started {
		return
	}
	s.started = true
	h := s.w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	s.w.WriteHeader(http.StatusOK)
}

// Started reports whether headers were sent.
func (s *SSEWriter) Started() bool { return s.started }

// Event writes one event with a JSON payload.
func (s *SSEWriter) Event(kind string, payload any) error {
	s.start()
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if kind != "" {
		if _, err := fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", kind, raw); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(s.w, "data: %s\n\n", raw); err != nil {
		return err
	}
	if s.flusher != nil {
		s.flusher.Flush()
	}
	return nil
}

// Raw writes a raw line block (already formatted).
func (s *SSEWriter) Raw(block []byte) error {
	s.start()
	if _, err := s.w.Write(block); err != nil {
		return err
	}
	if s.flusher != nil {
		s.flusher.Flush()
	}
	return nil
}

// Done writes the OpenAI [DONE] sentinel.
func (s *SSEWriter) Done() {
	s.start()
	_, _ = io.WriteString(s.w, "data: [DONE]\n\n")
	if s.flusher != nil {
		s.flusher.Flush()
	}
}

// Comment writes an SSE comment (keepalive).
func (s *SSEWriter) Comment(text string) {
	s.start()
	_, _ = fmt.Fprintf(s.w, ": %s\n\n", text)
	if s.flusher != nil {
		s.flusher.Flush()
	}
}

// Pipe copies a Responses SSE stream to w, flushing as data arrives.
func Pipe(w http.ResponseWriter, r io.Reader) error {
	s := NewSSEWriter(w)
	s.start()
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := s.w.Write(buf[:n]); werr != nil {
				return werr
			}
			if s.flusher != nil {
				s.flusher.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// OutputText concatenates the assistant text of a terminal response.
func OutputText(response object) string {
	var sb strings.Builder
	output, _ := response["output"].([]any)
	for _, raw := range output {
		item, _ := raw.(object)
		if str(item["type"]) != "message" {
			continue
		}
		content, _ := item["content"].([]any)
		for _, rawPart := range content {
			part, _ := rawPart.(object)
			if str(part["type"]) == "output_text" {
				sb.WriteString(str(part["text"]))
			}
		}
	}
	return sb.String()
}

// Usage extracts token counts from a terminal response.
func Usage(response object) (input, output, reasoning, cached int64) {
	usage, _ := response["usage"].(object)
	if usage == nil {
		return 0, 0, 0, 0
	}
	input = num(usage["input_tokens"])
	output = num(usage["output_tokens"])
	if details, ok := usage["output_tokens_details"].(object); ok {
		reasoning = num(details["reasoning_tokens"])
	}
	if details, ok := usage["input_tokens_details"].(object); ok {
		cached = num(details["cached_tokens"])
	}
	return
}
