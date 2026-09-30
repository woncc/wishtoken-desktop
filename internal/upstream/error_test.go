package upstream

import (
	"strings"
	"testing"
)

func TestUpstreamFailureKeepsOperatorText(t *testing.T) {
	body := `{"error":{"code":"server_error","message":"403: This request was blocked by our usage policy."}}`
	err := NewHTTPError(403, "basispoints", body)
	if err.ErrorCode() != "server_error" || err.Message() != "403: This request was blocked by our usage policy." {
		t.Fatalf("policy text changed: code=%q message=%q", err.ErrorCode(), err.Message())
	}
	denied := NewHTTPError(403, "basispoints", `{"error":{"code":"basispoints_model_access_changed","message":"model access changed"}}`)
	if denied.ErrorCode() != "basispoints_model_access_changed" || denied.Message() != "model access changed" {
		t.Fatalf("model denial changed: %+v", denied)
	}
}

func TestUpstreamFailureStripsCredentials(t *testing.T) {
	token := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	refresh := "rt_upstream_123456789"
	body := `{"error":{"code":"invalid_request","message":"rejected ` + token + ` ` + refresh + `"}}`
	err := NewHTTPError(401, "codex", body)
	if err.ErrorCode() != "invalid_request" {
		t.Fatalf("code: %q", err.ErrorCode())
	}
	for _, leaked := range []string{token, "eyJ", refresh} {
		if strings.Contains(err.Message(), leaked) || strings.Contains(err.Error(), leaked) {
			t.Fatalf("leaked %q in message=%q error=%q", leaked, err.Message(), err.Error())
		}
	}
	if !strings.Contains(err.Message(), "rejected") {
		t.Fatalf("lost context: %q", err.Message())
	}
	html := NewHTTPError(502, "basispoints", "<html><body>"+token+"</body></html>")
	if html.ErrorCode() != "" || strings.Contains(html.Message(), token) || !strings.Contains(html.Message(), "gateway error") {
		t.Fatalf("html error: code=%q message=%q", html.ErrorCode(), html.Message())
	}
	plain := NewHTTPError(502, "codex", "bad gateway "+refresh)
	if strings.Contains(plain.Message(), refresh) || strings.Contains(plain.Error(), refresh) || !strings.Contains(plain.Message(), "bad gateway") {
		t.Fatalf("plain error: %q", plain.Error())
	}
}
