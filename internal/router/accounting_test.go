package router

import (
	"io"
	"strings"
	"testing"
)

func TestAccountingTracksCompletionAfterLargeOutput(t *testing.T) {
	prefix := strings.Repeat("data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\r\n\r\n", 80000)
	terminal := "data: { \"type\": \"response.completed\", \"response\": {\"model\":\"reported-model\",\"service_tier\":\"default\",\"usage\":{\"output_tokens\":42}}}\r\n\r\n"
	calls := 0
	stream := &accounting{ReadCloser: io.NopCloser(strings.NewReader(prefix + terminal)), done: func(response object, err error) {
		calls++
		if err != nil || response["model"] != "reported-model" || response["service_tier"] != "default" {
			t.Fatalf("unexpected completion: %v %v", response, err)
		}
	}}
	_, _ = io.Copy(io.Discard, stream)
	_ = stream.Close()
	if calls != 1 {
		t.Fatalf("expected one completion callback, got %d", calls)
	}
}

func TestAccountingDoesNotTreatTruncatedStreamAsSuccess(t *testing.T) {
	called := false
	stream := &accounting{ReadCloser: io.NopCloser(strings.NewReader("data: {\"type\":\"response.created\"}\n\n")), done: func(response object, err error) {
		called = true
		if response != nil || err == nil {
			t.Fatal("truncated stream was marked successful")
		}
	}}
	_, _ = io.Copy(io.Discard, stream)
	_ = stream.Close()
	if !called {
		t.Fatal("completion callback not called")
	}
}
