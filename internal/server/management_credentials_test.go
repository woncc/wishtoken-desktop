package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xxx-holic/wishtoken-desktop/internal/account"
	"github.com/xxx-holic/wishtoken-desktop/internal/config"
)

func TestManagementOmitsOAuthAndRejectsRemote(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	f := newFixture(t, cfg, testAccount("acct_one", "one@example.test"))
	acc := f.srv.Store.List()[0]
	if err := f.srv.Store.Update(acc.ID, func(stored *account.Account) {
		stored.LastError = "refresh failed for " + stored.RefreshToken + " / " + stored.AccessToken
	}); err != nil {
		t.Fatal(err)
	}
	token := acc.AccessToken
	refresh := acc.RefreshToken

	export, body := getRaw(t, f, "/api/accounts/export?format=codex")
	if export != http.StatusForbidden || strings.Contains(body, token) || strings.Contains(body, refresh) || strings.Contains(body, cfg.APIKey) {
		t.Fatalf("export leaked or was served: %d %s", export, body)
	}
	accounts, body := getRaw(t, f, "/api/accounts")
	if accounts != http.StatusOK || strings.Contains(body, token) || strings.Contains(body, refresh) || !strings.Contains(body, "[redacted]") {
		t.Fatalf("account view leaked: %d %s", accounts, body)
	}
	snippets, body := getRaw(t, f, "/api/snippets")
	if snippets != http.StatusOK || strings.Contains(body, cfg.APIKey) || !strings.Contains(body, "${GPTBRIDGE_API_KEY}") {
		t.Fatalf("snippets leaked the local key: %d %s", snippets, body)
	}
	for _, route := range []string{"/api/status", "/api/settings", "/api/logs"} {
		status, body := getRaw(t, f, route)
		if status != http.StatusOK || strings.Contains(body, token) || strings.Contains(body, refresh) || strings.Contains(body, cfg.APIKey) {
			t.Fatalf("%s leaked: %d %s", route, status, body)
		}
	}

	remote := httptest.NewRequest(http.MethodGet, "/api/accounts/export", nil)
	remote.RemoteAddr = "203.0.113.9:4242"
	remote.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, remote)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), token) || strings.Contains(rec.Body.String(), cfg.APIKey) {
		t.Fatalf("remote management accepted: %d %s", rec.Code, rec.Body.String())
	}
	for _, addr := range []string{"", "203.0.113.9", "localhost:9"} {
		req := httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
		req.RemoteAddr = addr
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		got := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(got, req)
		if got.Code != http.StatusForbidden {
			t.Fatalf("peer %q status %d", addr, got.Code)
		}
	}

	model := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-6-astra","input":"ping"}`))
	model.RemoteAddr = "203.0.113.9:9"
	model.Host = "203.0.113.9:8791"
	model.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	model.Header.Set("Content-Type", "application/json")
	exposed := *cfg
	exposed.AllowRemote = true
	exposed.Listen = "0.0.0.0:8791"
	f.srv.setConfig(&exposed)
	modelRec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(modelRec, model)
	if modelRec.Code != http.StatusOK || strings.Contains(modelRec.Body.String(), token) {
		t.Fatalf("explicit remote model API should still answer without OAuth material: %d %s", modelRec.Code, modelRec.Body.String())
	}
	again := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(again, remote)
	if again.Code != http.StatusForbidden {
		t.Fatalf("allow_remote opened management: %d %s", again.Code, again.Body.String())
	}
}

func TestReboundLoopbackHostCannotReachManagement(t *testing.T) {
	cfg := config.Default()
	cfg.AllowRemote = true
	cfg.Listen = "0.0.0.0:8791"
	cfg.APIKey = "synthetic-local-management-key"
	f := newFixture(t, cfg, testAccount("acct_one", "one@example.test"))
	token := f.srv.Store.List()[0].AccessToken

	rebound := httptest.NewRequest(http.MethodPost, "/api/shutdown", nil)
	rebound.RemoteAddr = "127.0.0.1:9"
	rebound.Host = "rebind.example:8791"
	rebound.Header.Set("Origin", "http://rebind.example:8791")
	rebound.Header.Set("Sec-Fetch-Site", "same-origin")
	reboundRec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(reboundRec, rebound)
	if reboundRec.Code != http.StatusForbidden || strings.Contains(reboundRec.Body.String(), token) {
		t.Fatalf("rebound shutdown: %d %s", reboundRec.Code, reboundRec.Body.String())
	}

	for _, host := range []string{"evil.localhost:8791", "127.0.0.1.rebind.example:8791", "localhost.example:8791", "localhost%evil.example:8791", "127.0.0.1%evil:8791"} {
		req := httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
		req.RemoteAddr = "[::1]:9"
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		got := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(got, req)
		if got.Code != http.StatusForbidden || strings.Contains(got.Body.String(), token) {
			t.Fatalf("host %q status %d body %s", host, got.Code, got.Body.String())
		}
	}

	for _, tc := range []struct{ remote, host string }{
		{"127.0.0.1:9", "localhost:8791"},
		{"[::1]:9", "localhost.:8791"},
		{"[::1%lo]:9", "[::1%lo]:8791"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
		req.RemoteAddr = tc.remote
		req.Host = tc.host
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		got := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(got, req)
		if got.Code != http.StatusOK || strings.Contains(got.Body.String(), token) {
			t.Fatalf("loopback %s host %s: %d %s", tc.remote, tc.host, got.Code, got.Body.String())
		}
	}

	spoof := httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
	spoof.RemoteAddr = "203.0.113.9:9"
	spoof.Host = "127.0.0.1:8791"
	spoof.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	spoofRec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(spoofRec, spoof)
	if spoofRec.Code != http.StatusForbidden || strings.Contains(spoofRec.Body.String(), token) {
		t.Fatalf("remote peer with loopback host: %d %s", spoofRec.Code, spoofRec.Body.String())
	}
}

func TestRedactKeepsProxyWhenAPIKeyIsSeparate(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	f := newFixture(t, cfg, testAccount("acct_one", "one@example.test"))
	acc := f.srv.Store.List()[0]
	body := []byte(`{"access_token":"` + acc.AccessToken + `","note":"see ` + acc.RefreshToken + `","api_key":"` + cfg.APIKey + `","proxy_url":"http://user:` + cfg.APIKey + `@127.0.0.1:7890"}`)
	out := string(f.srv.redactManagementBody(body))
	if strings.Contains(out, acc.AccessToken) || strings.Contains(out, acc.RefreshToken) || strings.Contains(out, `"api_key":"`+cfg.APIKey+`"`) {
		t.Fatalf("credential field survived: %s", out)
	}
	if !strings.Contains(out, "http://user:"+cfg.APIKey+"@127.0.0.1:7890") {
		t.Fatalf("proxy URL was rewritten: %s", out)
	}
}

func TestListenAndServeRefusesNonLoopbackBeforeBind(t *testing.T) {
	cfg := config.Default()
	cfg.Listen = "203.0.113.10:1"
	f := newFixture(t, nil)
	f.srv.setConfig(cfg)
	err := f.srv.ListenAndServe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "refusing to bind") {
		t.Fatalf("expected refusal before bind, got %v", err)
	}
	cfg.Listen = ""
	f.srv.setConfig(cfg)
	err = f.srv.ListenAndServe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty") || !strings.Contains(err.Error(), "refusing to bind") {
		t.Fatalf("empty listen: %v", err)
	}
}

func getRaw(t *testing.T, f *fixture, route string) (int, string) {
	t.Helper()
	resp, err := http.Get(f.api.URL + route)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

func TestManagementHidesEmbeddedDisplayCredentials(t *testing.T) {
	const refresh = "rt_display_123456789"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.Name = "note " + refresh
	acc.LastError = "rejected " + refresh
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	if status != http.StatusOK || strings.Contains(body, refresh) || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") {
		t.Fatalf("embedded display credential: %d %s", status, body)
	}
}

func TestManagementHidesCredentialsSplitBySpacingMarks(t *testing.T) {
	const refresh = "rt_display_123456789"
	vowel := "rt_\u093edisplay_123456789"
	tone := "rt_display_\u302e123456789"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.Name = "note " + vowel
	acc.Tags = []string{"team", tone}
	acc.LastError = "rejected " + vowel
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	for _, leaked := range []string{refresh, vowel, tone, "display_123456789"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "team") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestRedactHidesSecretsSplitBySpacingMarks(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	f := newFixture(t, cfg, testAccount("acct_one", "one@example.test"))
	acc := f.srv.Store.List()[0]
	refresh := acc.RefreshToken
	if len(refresh) < 12 {
		t.Fatal("fixture refresh token is too short")
	}
	split := refresh[:4] + "\u093e" + refresh[4:]
	encoded := refresh[:4] + "%E0%A4%BE" + refresh[4:]
	body := []byte(`{"note":"see ` + split + ` and ` + encoded + `","access_token":"` + acc.AccessToken + `"}`)
	out := string(f.srv.redactManagementBody(body))
	for _, leaked := range []string{refresh, split, encoded, acc.AccessToken} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesJSONEscapedOAuthSecrets(t *testing.T) {
	refresh := "rt_quote\"x<secret\\value\nzzTAIL99"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = refresh
	acc.Name = "note " + refresh
	acc.LastError = "rejected " + refresh[:8] + "\u093e" + refresh[8:]
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	if status != http.StatusOK || !json.Valid([]byte(body)) {
		t.Fatalf("accounts: %d %s", status, body)
	}
	for _, leaked := range []string{refresh, "zzTAIL99", "x<secret", "quote\\\"x", "secret\\\\value"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q in %s", leaked, body)
		}
	}
	if !strings.Contains(body, "one@example.test") || !strings.Contains(body, "note") || !strings.Contains(body, "rejected") {
		t.Fatalf("context lost: %s", body)
	}

	note := "see " + refresh[:6] + "\u093e" + refresh[6:]
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]string{"error": note}); err != nil {
		t.Fatal(err)
	}
	out := string(f.srv.redactManagementBody(buf.Bytes()))
	if !json.Valid([]byte(out)) {
		t.Fatalf("redacted log is not json: %s", out)
	}
	for _, leaked := range []string{"zzTAIL99", "x<secret", "\\\"x<secret", "secret\\\\value", refresh} {
		if strings.Contains(out, leaked) {
			t.Fatalf("log leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, "see") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("log context lost: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHyphens(t *testing.T) {
	refresh := "rt_display-123456789"
	hyphen := "rt_display\u2010" + "123456789"
	encoded := "rt_display%E2%80%91123456789"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = refresh
	acc.Name = "note " + hyphen
	acc.LastError = "rejected " + hyphen
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	for _, leaked := range []string{refresh, hyphen, "display-123456789", "123456789"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	bodyBytes := []byte(`{"note":"see ` + hyphen + ` and ` + encoded + `","access_token":"` + acc.AccessToken + `"}`)
	out := string(f.srv.redactManagementBody(bodyBytes))
	for _, leaked := range []string{refresh, hyphen, encoded, acc.AccessToken, "123456789"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") {
		t.Fatalf("note was rewritten: %s", out)
	}
}
