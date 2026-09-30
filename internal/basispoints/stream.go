package basispoints

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// KeepaliveInterval is how often an SSE comment is written while the
// upstream is silent (long reasoning), so client idle timeouts do not fire.
var KeepaliveInterval = 15 * time.Second

type protocolError struct{ error }

type streamBody struct {
	*io.PipeReader
	upstream io.ReadCloser
	once     sync.Once
	err      error
}

func (b *streamBody) closeUpstream() error {
	b.once.Do(func() { b.err = b.upstream.Close() })
	return b.err
}

func (b *streamBody) Close() error {
	readerErr := b.PipeReader.Close()
	return errors.Join(readerErr, b.closeUpstream())
}

// Stream translates the gateway SSE stream into a client-facing Responses
// SSE stream. Text streams incrementally; native tool events are withheld
// until the terminal response validates so a malformed envelope never
// reaches the client as a partial tool call.
func (b *Bridge) Stream(upstream io.ReadCloser) io.ReadCloser {
	reader, writer := io.Pipe()
	body := &streamBody{PipeReader: reader, upstream: upstream}
	go func() {
		err := b.transform(upstream, writer)
		_ = body.closeUpstream()
		_ = writer.CloseWithError(err)
	}()
	return body
}

type pendingTool struct {
	item  object
	order int
}

type lockedWriter struct {
	mu        sync.Mutex
	w         io.Writer
	lastWrite time.Time
}

func (l *lockedWriter) write(p []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.w.Write(p)
	l.lastWrite = time.Now()
	return err
}

func (l *lockedWriter) idle(d time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Since(l.lastWrite) >= d
}

func (b *Bridge) transform(reader io.Reader, writer io.Writer) error {
	out := &lockedWriter{w: writer, lastWrite: time.Now()}
	stopKeepalive := make(chan struct{})
	defer close(stopKeepalive)
	if KeepaliveInterval > 0 {
		go func() {
			ticker := time.NewTicker(KeepaliveInterval / 3)
			defer ticker.Stop()
			for {
				select {
				case <-stopKeepalive:
					return
				case <-ticker.C:
					if out.idle(KeepaliveInterval) {
						if err := out.write([]byte(": keepalive\n\n")); err != nil {
							return
						}
					}
				}
			}
		}()
	}

	sequence := 0
	terminal := false
	emitted := make(map[string]bool)
	pendingTools := make(map[string]pendingTool)
	doneCount := 0
	toolKey := func(item object) string { return text(item["call_id"]) + "\x00" + text(item["id"]) }

	emit := func(kind string, payload object) error {
		payload["type"] = kind
		payload["sequence_number"] = sequence
		sequence++
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		return out.write([]byte(fmt.Sprintf("event: %s\ndata: %s\n\n", kind, raw)))
	}
	emitTool := func(item object, index any) error {
		id := text(item["id"])
		if emitted[id] {
			return nil
		}
		emitted[id] = true
		field, prefix := "arguments", "response.function_call_arguments"
		if text(item["type"]) == "custom_tool_call" {
			field, prefix = "input", "response.custom_tool_call_input"
		}
		added := cloneObject(item)
		added[field], added["status"] = "", "in_progress"
		if err := emit("response.output_item.added", object{"output_index": index, "item": added}); err != nil {
			return err
		}
		if err := emit(prefix+".delta", object{"output_index": index, "item_id": id, "delta": item[field]}); err != nil {
			return err
		}
		if err := emit(prefix+".done", object{"output_index": index, "item_id": id, field: item[field]}); err != nil {
			return err
		}
		return emit("response.output_item.done", object{"output_index": index, "item": item})
	}

	process := func(event string, data []byte) error {
		if string(data) == "[DONE]" {
			return nil
		}
		var payload object
		if decode(data, &payload) != nil || payload == nil {
			return fmt.Errorf("invalid Basispoints SSE event")
		}
		kind := text(payload["type"])
		if kind == "" {
			kind = event
		}
		if isToolEvent(kind) {
			return nil
		}
		item, _ := payload["item"].(object)
		if b.structured != nil && isStructuredMessageEvent(kind, item) {
			return nil
		}
		if kind == "response.output_item.added" && isTool(item) {
			return nil
		}
		if kind == "response.output_item.done" && isTool(item) {
			if len(pendingTools) >= 1024 {
				return fmt.Errorf("Basispoints response contains too many tool items")
			}
			pendingTools[toolKey(item)] = pendingTool{item: item, order: doneCount}
			doneCount++
			return nil
		}
		if response, ok := payload["response"].(object); ok {
			if kind == "response.completed" {
				output, _ := response["output"].([]any)
				completedCalls := make(map[string]bool)
				for _, raw := range output {
					item, _ := raw.(object)
					if isTool(item) {
						delete(pendingTools, toolKey(item))
						completedCalls[text(item["call_id"])] = true
					}
				}
				if len(pendingTools) != 0 {
					// The completed payload sometimes omits items that already
					// arrived complete in output_item.done; restore them in order.
					output = completeOutputFromDoneItems(output, pendingTools, completedCalls)
					response["output"] = output
					pendingTools = make(map[string]pendingTool)
				}
				if b.structured != nil {
					if err := b.structured.validate(response); err != nil {
						return err
					}
				}
				if err := b.translateResponse(response); err != nil {
					return err
				}
				output, _ = response["output"].([]any)
				for i, raw := range output {
					item, _ := raw.(object)
					if isTool(item) {
						if err := emitTool(item, i); err != nil {
							return err
						}
					} else if b.structured != nil && text(item["type"]) == "message" {
						if err := emitStructuredMessage(item, i, emit); err != nil {
							return err
						}
					}
				}
			} else {
				// Never expose native or incomplete tool arguments to the client.
				output, _ := response["output"].([]any)
				filtered := make([]any, 0, len(output))
				for _, raw := range output {
					item, _ := raw.(object)
					if !isTool(item) && (b.structured == nil || text(item["type"]) != "message") {
						filtered = append(filtered, raw)
					}
				}
				response["output"] = filtered
				response["reasoning"] = object{"effort": b.Effort}
			}
		}
		terminal = kind == "response.completed" || kind == "response.incomplete" || kind == "response.failed" || kind == "error"
		return emit(kind, payload)
	}

	err := ReadEvents(reader, func(event string, data []byte) error {
		if terminal {
			return io.EOF
		}
		if err := process(event, data); err != nil {
			return protocolError{err}
		}
		if terminal {
			return io.EOF
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		var invalid protocolError
		if errors.Is(err, io.ErrClosedPipe) || !errors.As(err, &invalid) {
			return err
		}
		return emit("response.failed", object{"response": object{
			"status": "failed", "output": []any{},
			"error": object{"code": "basispoints_protocol_error", "message": ProtocolFailureMessage(err)},
		}})
	}
	if !terminal {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func completeOutputFromDoneItems(output []any, pending map[string]pendingTool, completedCalls map[string]bool) []any {
	missing := make([]pendingTool, 0, len(pending))
	for _, entry := range pending {
		if !completedCalls[text(entry.item["call_id"])] {
			missing = append(missing, entry)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].order < missing[j].order })
	for _, entry := range missing {
		output = append(output, entry.item)
	}
	return output
}

// ReadEvents parses an SSE stream and calls consume for every event.
// Returning io.EOF from consume stops reading without error.
func ReadEvents(reader io.Reader, consume func(event string, data []byte) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 16<<20)
	var data strings.Builder
	event := ""
	flush := func() error {
		if data.Len() == 0 {
			event = ""
			return nil
		}
		err := consume(event, []byte(strings.TrimSuffix(data.String(), "\n")))
		data.Reset()
		event = ""
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if err := flush(); err != nil {
				return err
			}
		case strings.HasPrefix(line, ":"):
			// comment / keepalive
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			data.WriteByte('\n')
			if data.Len() > 16<<20 {
				return protocolError{fmt.Errorf("Basispoints SSE event exceeds 16 MiB")}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return protocolError{fmt.Errorf("Basispoints SSE line exceeds 16 MiB")}
		}
		return err
	}
	return flush()
}
