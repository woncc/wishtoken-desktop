package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func TestManagementHidesSecretsSplitByEmDashes(t *testing.T) {
	refresh := "rt_display-123456789"
	em := "rt_display\u2014" + "123456789"
	bar := "rt_display\u2015" + "123456789"
	vertical := "rt_display\ufe31" + "123456789"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = refresh
	acc.Name = "note " + em
	acc.LastError = "rejected " + bar
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	for _, leaked := range []string{refresh, em, bar, vertical, "display-123456789", "123456789"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	bodyBytes := []byte(`{"note":"see ` + vertical + `","access_token":"` + acc.AccessToken + `"}`)
	out := string(f.srv.redactManagementBody(bodyBytes))
	for _, leaked := range []string{refresh, vertical, acc.AccessToken, "123456789"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByScriptHyphens(t *testing.T) {
	refresh := "rt_display-123456789"
	armenian := "rt_display" + "\u058a" + "123456789"
	mongolian := "rt_display" + "\u1806" + "123456789"
	yezidi := "rt_display" + "\U00010ead" + "123456789"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = refresh
	acc.Name = "note " + armenian
	acc.LastError = "rejected " + mongolian
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	for _, leaked := range []string{refresh, armenian, mongolian, "display-123456789", "123456789"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	bodyBytes := []byte(`{"note":"see ` + yezidi + `","access_token":"` + acc.AccessToken + `"}`)
	out := string(f.srv.redactManagementBody(bodyBytes))
	for _, leaked := range []string{refresh, yezidi, acc.AccessToken, "123456789"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLongAndWaveDashes(t *testing.T) {
	refresh := "rt_display-123456789"
	two := "rt_display" + "\u2e3a" + "123456789"
	three := "rt_display" + "\u2e3b" + "123456789"
	wave := "rt_display" + "\u301c" + "123456789"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = refresh
	acc.Name = "note " + two
	acc.LastError = "rejected " + three
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	for _, leaked := range []string{refresh, two, three, "display-123456789", "123456789"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	bodyBytes := []byte(`{"note":"see ` + wave + `","access_token":"` + acc.AccessToken + `"}`)
	out := string(f.srv.redactManagementBody(bodyBytes))
	for _, leaked := range []string{refresh, wave, acc.AccessToken, "123456789"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCompatibilityHyphens(t *testing.T) {
	refresh := "rt_display-123456789"
	super := "rt_display" + "\u207b" + "123456789"
	sub := "rt_display" + "\u208b" + "123456789"
	vertical := "rt_display" + "\ufe32" + "123456789"
	small := "rt_display" + "\ufe63" + "123456789"
	full := "rt_display" + "\uff0d" + "123456789"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = refresh
	acc.Name = "note " + super
	acc.LastError = "rejected " + sub
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	for _, leaked := range []string{refresh, super, sub, "display-123456789", "123456789"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	bodyBytes := []byte(`{"note":"see ` + vertical + ` ` + small + ` ` + full + `","access_token":"` + acc.AccessToken + `"}`)
	out := string(f.srv.redactManagementBody(bodyBytes))
	for _, leaked := range []string{refresh, vertical, small, full, acc.AccessToken, "123456789"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCompatibilityFullStops(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	full := strings.ReplaceAll(acc.AccessToken, ".", "\uff0e")
	leader := strings.ReplaceAll(acc.AccessToken, ".", "\u2024")
	small := strings.ReplaceAll(acc.AccessToken, ".", "\ufe52")
	vertical := strings.ReplaceAll(acc.AccessToken, ".", "\ufe12")
	half := strings.ReplaceAll(acc.AccessToken, ".", "\uff61")
	acc.Name = "note " + full
	acc.LastError = "rejected " + leader
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, full, leader, payload, "eyJ"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	bodyBytes := []byte(`{"note":"see ` + small + ` ` + vertical + ` ` + half + `","access_token":"` + acc.AccessToken + `"}`)
	out := string(f.srv.redactManagementBody(bodyBytes))
	for _, leaked := range []string{acc.AccessToken, small, vertical, half, payload, "eyJ"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByOtherFullStops(t *testing.T) {
	stops := []rune{
		'\u3002', '\u06d4', '\u0701', '\u0702', '\u1362', '\u166e',
		'\u1803', '\u1809', '\u2cf9', '\u2cfe', '\u2e3c', '\ua4ff', '\ua60e', '\ua6f3',
		'\U00016af5', '\U00016e98', '\U0001bc9f', '\U0001da88',
		'\ua4f8', '\U00010a50', '\ua4fa',
		'\u0660', '\u06f0', '\U0001ecae',
		'\uabec', '\U0001d16d',
	}
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qRefresh_7f3a"
	ideographic := strings.ReplaceAll(acc.AccessToken, ".", "\u3002")
	arabic := strings.ReplaceAll(acc.AccessToken, ".", "\u06d4")
	acc.Name = "note " + ideographic
	acc.LastError = "rejected " + arabic
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, ideographic, arabic, payload, "eyJ", acc.RefreshToken} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	var notes []string
	var leaked []string
	for _, r := range stops {
		marked := strings.ReplaceAll(acc.AccessToken, ".", string(r))
		notes = append(notes, marked)
		leaked = append(leaked, marked)
	}
	inserted := "rt_Zz9q\U0001d16dRefresh_7f3a"
	notes = append(notes, inserted)
	raw := `{"note":"see ` + strings.Join(notes, " ") + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, item := range append([]string{acc.AccessToken, acc.RefreshToken, inserted, payload, "eyJ", "Zz9qRefresh"}, leaked...) {
		if strings.Contains(out, item) {
			t.Fatalf("leaked %q in %s", item, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByFullwidthLetters(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qRefresh_7f3a"
	idx := strings.IndexByte(acc.AccessToken, 'e')
	if idx < 0 {
		t.Fatal("synthetic token has no e")
	}
	marked := acc.AccessToken[:idx] + "\uff45" + acc.AccessToken[idx+1:]
	refreshMarked := "rt_\uff3a9qRefresh_7f3a"
	acc.Name = "note " + marked
	acc.LastError = "rejected " + refreshMarked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, marked, acc.RefreshToken, refreshMarked, payload, "eyJ", "Zz9qRefresh"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.Replace(acc.AccessToken, "e", "%EF%BD%85", 1)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, encoded, payload, "eyJ"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMathLetters(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qRefresh_7f3a"
	idx := strings.IndexByte(acc.AccessToken, 'e')
	if idx < 0 {
		t.Fatal("synthetic token has no e")
	}
	marked := acc.AccessToken[:idx] + "\U0001D41E" + acc.AccessToken[idx+1:]
	refreshMarked := "rt_\U0001D4199qRefresh_7f3a"
	acc.Name = "note " + marked
	acc.LastError = "rejected " + refreshMarked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, marked, acc.RefreshToken, refreshMarked, payload, "eyJ", "Zz9qRefresh"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	hole := strings.Replace(acc.AccessToken, "h", "\u210E", 1)
	encoded := strings.Replace(acc.AccessToken, "e", "%F0%9D%90%9E", 1)
	raw := `{"note":"see ` + hole + " " + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, hole, encoded, payload, "eyJ"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByEnclosedLetters(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qRefresh_7f3a"
	idx := strings.IndexByte(acc.AccessToken, 'e')
	if idx < 0 {
		t.Fatal("synthetic token has no e")
	}
	marked := acc.AccessToken[:idx] + "\u24d4" + acc.AccessToken[idx+1:]
	refreshMarked := "rt_\U0001F1499qRefresh_7f3a"
	acc.Name = "note " + marked
	acc.LastError = "rejected " + refreshMarked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, marked, acc.RefreshToken, refreshMarked, payload, "eyJ", "Zz9qRefresh"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.Replace(acc.AccessToken, "e", "%E2%93%94", 1)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, encoded, payload, "eyJ"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySuperSubLetters(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qRefresh_7f3a"
	idx := strings.IndexByte(acc.AccessToken, 'e')
	if idx < 0 {
		t.Fatal("synthetic token has no e")
	}
	marked := acc.AccessToken[:idx] + "\u2091" + acc.AccessToken[idx+1:]
	refreshMarked := "rt_Zz9qRefresh_\u2077f3a"
	acc.Name = "note " + marked
	acc.LastError = "rejected " + refreshMarked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, marked, acc.RefreshToken, refreshMarked, payload, "eyJ", "Zz9qRefresh"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.Replace(acc.AccessToken, "e", "%E2%82%91", 1)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, encoded, payload, "eyJ"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByModifierLetters(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Kz9qRefresh_7f3a"
	idx := strings.IndexByte(acc.AccessToken, 'e')
	if idx < 0 {
		t.Fatal("synthetic token has no e")
	}
	marked := acc.AccessToken[:idx] + "\u1d49" + acc.AccessToken[idx+1:]
	refreshMarked := "rt_\u212az9qRefresh_7f3a"
	acc.Name = "note " + marked
	acc.LastError = "rejected " + refreshMarked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, marked, acc.RefreshToken, refreshMarked, payload, "eyJ", "Kz9qRefresh"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.Replace(acc.AccessToken, "e", "%E1%B5%89", 1)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, encoded, payload, "eyJ"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySegmentedDigits(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qRefresh_7f3a"
	idx := strings.IndexByte(acc.AccessToken, '2')
	if idx < 0 {
		t.Fatal("synthetic token has no 2")
	}
	marked := acc.AccessToken[:idx] + "\U0001fbf2" + acc.AccessToken[idx+1:]
	refreshMarked := "rt_Zz9qRefresh_\U0001fbf7f3a"
	acc.Name = "note " + marked
	acc.LastError = "rejected " + refreshMarked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, marked, acc.RefreshToken, refreshMarked, payload, "eyJ", "Zz9qRefresh"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.Replace(acc.AccessToken, "2", "%F0%9F%AF%B2", 1)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, encoded, payload, "eyJ"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByRomanNumerals(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Cz9qRefresh_7f3a"
	idx := strings.IndexByte(acc.AccessToken, 'i')
	if idx < 0 {
		t.Fatal("synthetic token has no i")
	}
	marked := acc.AccessToken[:idx] + "\u2170" + acc.AccessToken[idx+1:]
	refreshMarked := "rt_\u216dz9qRefresh_7f3a"
	acc.Name = "note " + marked
	acc.LastError = "rejected " + refreshMarked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, marked, acc.RefreshToken, refreshMarked, payload, "eyJ", "z9qRefresh"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.Replace(acc.AccessToken, "i", "%E2%85%B0", 1)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, encoded, payload, "eyJ"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLongS(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_sessionTok_7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, "s", "\u017f")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + marked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, payload, "eyJ", "sessionTok"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.Replace(acc.RefreshToken, "s", "%C5%BF", 1)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "sessionTok"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByPlusEqualsSigns(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q+Refresh=7f3a"
	marked := strings.NewReplacer("+", "\u207a", "=", "\u208c").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + marked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("+", "%E2%81%BA", "=", "%E2%81%BC").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowLines(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_sessionTok_7f3a"
	marked := "rt_sessionTok\ufe4d7f3a"
	acc.Name = "note " + marked
	acc.LastError = "rejected " + marked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, payload, "eyJ", "sessionTok", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.Replace(acc.RefreshToken, "_", "%EF%B9%8D", 1)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "sessionTok"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySolidusAndTilde(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh~7f3a"
	marked := strings.NewReplacer("/", "\uff0f", "~", "\uff5e").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + marked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("/", "%EF%BC%8F", "~", "%EF%BD%9E").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByParentheses(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q(Refresh)7f3a"
	marked := strings.NewReplacer("(", "\uff08", ")", "\uff09").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + marked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("(", "%EF%BC%88", ")", "%EF%BC%89").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesCompatibilityPercentSecrets(t *testing.T) {
	refresh := "rt_submitted_123456"
	encoded := strings.ReplaceAll(encodeEveryByte(refresh), "%", "\uFF05")
	small := strings.ReplaceAll(encodeEveryByte(refresh), "%", "\uFE6A")
	hexed := fullwidthHexEscapes(encodeEveryByte(refresh))
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = refresh
	acc.Name = "note " + encoded
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	for _, leaked := range []string{refresh, encoded, small, hexed, acc.AccessToken, "submitted", "123456"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	raw := `{"note":"see ` + hexed + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{refresh, hexed, acc.AccessToken, "submitted", "123456"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func fullwidthHexEscapes(encoded string) string {
	var b strings.Builder
	for _, r := range encoded {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(0xFF10 + (r - '0'))
		case r >= 'A' && r <= 'F':
			b.WriteRune(0xFF21 + (r - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestManagementHidesSecretsSplitByExclamation(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q!Refresh!7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, "!", "\uFF01")
	small := strings.ReplaceAll(acc.RefreshToken, "!", "\uFE57")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "!", "%EF%BC%81")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByReverseSolidus(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, "\\", "\uFF3C")
	small := strings.ReplaceAll(acc.RefreshToken, "\\", "\uFE68")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "\\", "%EF%BC%BC")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByNumberSign(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q#Refresh#7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, "#", "\uFF03")
	small := strings.ReplaceAll(acc.RefreshToken, "#", "\uFE5F")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "#", "%EF%BC%83")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByDollarSign(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q$Refresh$7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, "$", "\uFF04")
	small := strings.ReplaceAll(acc.RefreshToken, "$", "\uFE69")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "$", "%EF%BC%84")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByAmpersand(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q&Refresh&7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, "&", "\uFF06")
	small := strings.ReplaceAll(acc.RefreshToken, "&", "\uFE60")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "&", "%EF%BC%86")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByAsterisk(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q*Refresh*7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, "*", "\uFF0A")
	small := strings.ReplaceAll(acc.RefreshToken, "*", "\uFE61")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "*", "%EF%BC%8A")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByQuestionMark(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q?Refresh?7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, "?", "\uFF1F")
	small := strings.ReplaceAll(acc.RefreshToken, "?", "\uFE56")
	vertical := strings.ReplaceAll(acc.RefreshToken, "?", "\uFE16")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small + " " + vertical
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, vertical, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "?", "%EF%BC%9F")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySemicolon(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q;Refresh;7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, ";", "\uFF1B")
	small := strings.ReplaceAll(acc.RefreshToken, ";", "\uFE54")
	greek := strings.ReplaceAll(acc.RefreshToken, ";", "\u037E")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small + " " + greek
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, greek, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, ";", "%EF%BC%9B")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByComma(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q,Refresh,7f3a"
	marked := strings.ReplaceAll(acc.RefreshToken, ",", "\uFF0C")
	small := strings.ReplaceAll(acc.RefreshToken, ",", "\uFE50")
	vertical := strings.ReplaceAll(acc.RefreshToken, ",", "\uFE10")
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small + " " + vertical
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, vertical, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, ",", "%EF%BC%8C")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCurlyBrackets(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q{Refresh}7f3a"
	marked := strings.NewReplacer("{", "\uFF5B", "}", "\uFF5D").Replace(acc.RefreshToken)
	small := strings.NewReplacer("{", "\uFE5B", "}", "\uFE5C").Replace(acc.RefreshToken)
	vertical := strings.NewReplacer("{", "\uFE37", "}", "\uFE38").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small + " " + vertical
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, vertical, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("{", "%EF%BD%9B", "}", "%EF%BD%9D").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySquareBrackets(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q[Refresh]7f3a"
	marked := strings.NewReplacer("[", "\uFF3B", "]", "\uFF3D").Replace(acc.RefreshToken)
	vertical := strings.NewReplacer("[", "\uFE47", "]", "\uFE48").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + vertical
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, vertical, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("[", "%EF%BC%BB", "]", "%EF%BC%BD").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLessGreaterSigns(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q<Refresh>7f3a"
	marked := strings.NewReplacer("<", "\uFF1C", ">", "\uFF1E").Replace(acc.RefreshToken)
	small := strings.NewReplacer("<", "\uFE64", ">", "\uFE65").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, small, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("<", "%EF%BC%9C", ">", "%EF%BC%9E").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByGraveAccents(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q`Refresh`7f3a"
	marked := strings.NewReplacer("`", "\uFF40").Replace(acc.RefreshToken)
	varia := strings.NewReplacer("`", "\u1FEF").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + varia
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, varia, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("`", "%EF%BD%80").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCircumflexAccents(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q^Refresh^7f3a"
	marked := strings.NewReplacer("^", "\uFF3E").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + marked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("^", "%EF%BC%BE").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByVerticalLines(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q|Refresh|7f3a"
	marked := strings.NewReplacer("|", "\uFF5C").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + marked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("|", "%EF%BD%9C").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByApostrophes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q'Refresh'7f3a"
	marked := strings.NewReplacer("'", "\uFF07").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + marked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("'", "%EF%BC%87").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByQuotationMarks(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q\"Refresh\"7f3a"
	marked := strings.NewReplacer("\"", "\uFF02").Replace(acc.RefreshToken)
	acc.Name = "note " + marked
	acc.LastError = "rejected " + marked
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, marked, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("\"", "%EF%BC%82").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByColons(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q:Refresh:7f3a"
	full := strings.NewReplacer(":", "\uFF1A").Replace(acc.RefreshToken)
	small := strings.NewReplacer(":", "\uFE55").Replace(acc.RefreshToken)
	acc.Name = "note " + full
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, full, small, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer(":", "%EF%BC%9A").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCommercialAt(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q@Refresh@7f3a"
	full := strings.NewReplacer("@", "\uFF20").Replace(acc.RefreshToken)
	small := strings.NewReplacer("@", "\uFE6B").Replace(acc.RefreshToken)
	acc.Name = "note " + full
	acc.LastError = "rejected " + small
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, full, small, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("@", "%EF%BC%A0").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCompatibilitySpaces(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q Refresh 7f3a"
	nbsp := strings.NewReplacer(" ", "\u00A0").Replace(acc.RefreshToken)
	ideo := strings.NewReplacer(" ", "\u3000").Replace(acc.RefreshToken)
	acc.Name = "note " + nbsp
	acc.LastError = "rejected " + ideo
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, nbsp, ideo, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer(" ", "%C2%A0").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLatinLigatures(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qstaff7f3a"
	st := strings.NewReplacer("st", "\uFB06").Replace(acc.RefreshToken)
	longST := strings.NewReplacer("st", "\uFB05").Replace(acc.RefreshToken)
	acc.Name = "note " + st
	acc.LastError = "rejected " + longST
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, st, longST, payload, "eyJ", "Zz9q", "staff", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer("st", "%EF%AC%86").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "staff"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByAdditiveRoman(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qVII7f3a"
	seven := strings.NewReplacer("VII", "\u2166").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("VII", "%E2%85%A6").Replace(acc.RefreshToken)
	acc.Name = "note " + seven
	acc.LastError = "rejected " + encoded
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, seven, payload, "eyJ", "Zz9q", "VII", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	if strings.Contains(body, encoded) {
		t.Fatalf("encoded numeral leaked: %s", body)
	}
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "VII"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByDoublePunctuation(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q!!7f3a"
	bang := strings.NewReplacer("!!", "\u203C").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("!!", "%E2%80%BC").Replace(acc.RefreshToken)
	acc.Name = "note " + bang
	acc.LastError = "rejected " + encoded
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, bang, encoded, payload, "eyJ", "Zz9q", "!!", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "!!"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByVulgarFractions(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q1/27f3a"
	half := strings.NewReplacer("1/2", "\u00BD").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("1/2", "%C2%BD").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, payload, "eyJ", "Zz9q", "1/2", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "1/2"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySquareDivisionSlashes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qm/s7f3a"
	half := strings.NewReplacer("m/s", "\u33A7").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("m/s", "%E3%8E%A7").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, payload, "eyJ", "Zz9q", "m/s", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "m/s"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByTagPunctuation(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/ab7f3a"
	half := strings.NewReplacer("/", "\U000E002F").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("/", "%F3%A0%80%AF").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByTagSpace(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q ab7f3a"
	half := strings.NewReplacer(" ", "\U000E0020").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer(" ", "%F3%A0%80%A0").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagLetter(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qab7f3a"
	half := strings.NewReplacer("q", "\U000E0071").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("q", "%F3%A0%81%B1").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("Z", "\U000E005A", "a", "\U000E0061").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagDigit(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qab7f3a"
	half := strings.NewReplacer("9", "\U000E0039").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("3", "%F3%A0%80%B3").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("q", "\U000E0071", "3", "\U000E0033").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagLowLine(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9qab7f3a"
	half := strings.NewReplacer("_", "\U000E005F").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("_", "%F3%A0%81%9F").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("_", "\U000E005F", "9", "\U000E0039").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagPlus(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt+Zz9qab7f3a"
	half := strings.NewReplacer("+", "\U000E002B").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("+", "%F3%A0%80%AB").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("+", "\U000E002B", "9", "\U000E0039").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagEquals(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt=Zz9qab7f3a"
	half := strings.NewReplacer("=", "\U000E003D").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("=", "%F3%A0%80%BD").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("=", "\U000E003D", "9", "\U000E0039").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagPercent(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q%ab7f3a"
	half := strings.NewReplacer("%", "\U000E0025").Replace(acc.RefreshToken)
	encoded := strings.ReplaceAll(encodeEveryByte(acc.RefreshToken), "%", "\U000E0025")
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagCommercialAt(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt@Zz9qab7f3a"
	half := strings.NewReplacer("@", "\U000E0040").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("@", "%F3%A0%81%80").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("@", "\U000E0040", "9", "\U000E0039").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagQuotation(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt@\"Zz9qab7f3a"
	half := strings.NewReplacer("\"", "\U000E0022").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("\"", "%F3%A0%80%A2").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("\"", "\U000E0022", "@", "\U000E0040").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagApostrophe(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt'\"Zz9qab7f3a"
	half := strings.NewReplacer("'", "\U000E0027").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("'", "%F3%A0%80%A7").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("'", "\U000E0027", "\"", "\U000E0022").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagVerticalLine(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt|'Zz9qab7f3a"
	half := strings.NewReplacer("|", "\U000E007C").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("|", "%F3%A0%81%BC").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("|", "\U000E007C", "'", "\U000E0027").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagCircumflex(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt^|Zz9qab7f3a"
	half := strings.NewReplacer("^", "\U000E005E").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("^", "%F3%A0%81%9E").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("^", "\U000E005E", "|", "\U000E007C").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagGrave(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt`^Zz9qab7f3a"
	half := strings.NewReplacer("`", "\U000E0060").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("`", "%F3%A0%81%A0").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("`", "\U000E0060", "^", "\U000E005E").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagLessThan(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt<`Zz9qab7f3a"
	half := strings.NewReplacer("<", "\U000E003C").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("<", "%F3%A0%80%BC").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("<", "\U000E003C", "`", "\U000E0060").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagGreaterThan(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt><Zz9qab7f3a"
	half := strings.NewReplacer(">", "\U000E003E").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer(">", "%F3%A0%80%BE").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer(">", "\U000E003E", "<", "\U000E003C").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagLeftSquareBracket(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt[>Zz9qab7f3a"
	half := strings.NewReplacer("[", "\U000E005B").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("[", "%F3%A0%81%9B").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("[", "\U000E005B", ">", "\U000E003E").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagRightSquareBracket(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt][Zz9qab7f3a"
	half := strings.NewReplacer("]", "\U000E005D").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("]", "%F3%A0%81%9D").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("]", "\U000E005D", "[", "\U000E005B").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagLeftCurlyBracket(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt{]Zz9qab7f3a"
	half := strings.NewReplacer("{", "\U000E007B").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("{", "%F3%A0%81%BB").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("{", "\U000E007B", "]", "\U000E005D").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagRightCurlyBracket(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt}{Zz9qab7f3a"
	half := strings.NewReplacer("}", "\U000E007D").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("}", "%F3%A0%81%BD").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("}", "\U000E007D", "{", "\U000E007B").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagComma(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt,}Zz9qab7f3a"
	half := strings.NewReplacer(",", "\U000E002C").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer(",", "%F3%A0%80%AC").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer(",", "\U000E002C", "}", "\U000E007D").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagSemicolon(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt;,Zz9qab7f3a"
	half := strings.NewReplacer(";", "\U000E003B").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer(";", "%F3%A0%80%BB").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer(";", "\U000E003B", ",", "\U000E002C").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagQuestionMark(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt?;Zz9qab7f3a"
	half := strings.NewReplacer("?", "\U000E003F").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("?", "%F3%A0%80%BF").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("?", "\U000E003F", ";", "\U000E003B").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagAsterisk(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt*?Zz9qab7f3a"
	half := strings.NewReplacer("*", "\U000E002A").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("*", "%F3%A0%80%AA").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("*", "\U000E002A", "?", "\U000E003F").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagAmpersand(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt&*Zz9qab7f3a"
	half := strings.NewReplacer("&", "\U000E0026").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("&", "%F3%A0%80%A6").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("&", "\U000E0026", "*", "\U000E002A").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagDollar(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt$&Zz9qab7f3a"
	half := strings.NewReplacer("$", "\U000E0024").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("$", "%F3%A0%80%A4").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("$", "\U000E0024", "&", "\U000E0026").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagNumberSign(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt#$Zz9qab7f3a"
	half := strings.NewReplacer("#", "\U000E0023").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("#", "%F3%A0%80%A3").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("#", "\U000E0023", "$", "\U000E0024").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagExclamation(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt!#Zz9qab7f3a"
	half := strings.NewReplacer("!", "\U000E0021").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("!", "%F3%A0%80%A1").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("!", "\U000E0021", "#", "\U000E0023").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagLeftParenthesis(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt(!Zz9qab7f3a"
	half := strings.NewReplacer("(", "\U000E0028").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("(", "%F3%A0%80%A8").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("(", "\U000E0028", "!", "\U000E0021").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagRightParenthesis(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt)(Zz9qab7f3a"
	half := strings.NewReplacer(")", "\U000E0029").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer(")", "%F3%A0%80%A9").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer(")", "\U000E0029", "(", "\U000E0028").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByTagTilde(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt~)Zz9qab7f3a"
	half := strings.NewReplacer("~", "\U000E007E").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer("~", "%F3%A0%81%BE").Replace(acc.RefreshToken)
	mixed := strings.NewReplacer("~", "\U000E007E", ")", "\U000E0029").Replace(acc.RefreshToken)
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, mixed, payload, "eyJ", "Zz9q", "ab7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByColonLookalikes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q:Refresh:7f3a"
	ratio := strings.NewReplacer(":", "\u2236").Replace(acc.RefreshToken)
	mod := strings.NewReplacer(":", "\u02d0").Replace(acc.RefreshToken)
	mixed := strings.Replace(ratio, "\u2236", "\u0903", 1)
	acc.Name = "note " + ratio
	acc.LastError = "rejected " + mod + " " + mixed
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, ratio, mod, mixed, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.NewReplacer(":", "%E2%88%B6").Replace(acc.RefreshToken)
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByVisarga(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q:Refresh:7f3a"
	half := strings.NewReplacer(":", "\u0903").Replace(acc.RefreshToken)
	encoded := strings.NewReplacer(":", "%E0%A4%83").Replace(acc.RefreshToken)
	inserted := "rt_Zz9q:Ref\u0903resh:7f3a"
	acc.Name = "note " + half
	acc.LastError = "rejected " + encoded + " " + inserted
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, half, encoded, inserted, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitBySlashLookalikes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	division := strings.ReplaceAll(acc.RefreshToken, "/", "\u2215")
	fraction := strings.ReplaceAll(acc.RefreshToken, "/", "\u2044")
	acc.Name = "note " + division
	acc.LastError = "rejected " + fraction
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, division, fraction, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%88%95")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}

	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	yen := strings.ReplaceAll(back.RefreshToken, "\\", "\u00a5")
	set := strings.ReplaceAll(back.RefreshToken, "\\", "\u2216")
	back.Name = "note " + yen
	back.LastError = "rejected " + set
	fb := newFixture(t, cfg, back)
	status, body = getRaw(t, fb, "/api/accounts")
	payload = strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, yen, set, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encodedYen := strings.ReplaceAll(back.RefreshToken, "\\", "%C2%A5")
	raw = `{"note":"see ` + encodedYen + `","access_token":"` + back.AccessToken + `"}`
	out = string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encodedYen, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("yen escaped leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("yen note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByDiagonalSlashes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	box := strings.ReplaceAll(acc.RefreshToken, "/", "\u2571")
	rising := strings.ReplaceAll(acc.RefreshToken, "/", "\u27cb")
	acc.Name = "note " + box
	acc.LastError = "rejected " + rising
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, box, rising, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%95%B1")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}

	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	falling := strings.ReplaceAll(back.RefreshToken, "\\", "\u2572")
	heavy := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001f67d")
	back.Name = "note " + falling
	back.LastError = "rejected " + heavy
	fb := newFixture(t, cfg, back)
	status, body = getRaw(t, fb, "/api/accounts")
	payload = strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, falling, heavy, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByGreekNotationSlashes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	vocal := strings.ReplaceAll(acc.RefreshToken, "\\", "\U0001d20f")
	inst47 := strings.ReplaceAll(acc.RefreshToken, "\\", "\U0001d23a")
	acc.Name = "note " + vocal
	acc.LastError = "rejected " + inst47
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, vocal, inst47, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "\\", "%F0%9D%88%BB")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByKanaRepeatSlashes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	upper := strings.ReplaceAll(acc.RefreshToken, "/", "\u3033")
	voiced := strings.ReplaceAll(acc.RefreshToken, "/", "\u3034")
	acc.Name = "note " + upper
	acc.LastError = "rejected " + voiced
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, upper, voiced, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E3%80%B4")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}

	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	lower := strings.ReplaceAll(back.RefreshToken, "\\", "\u3035")
	back.Name = "note " + lower
	back.LastError = "rejected " + lower
	fb := newFixture(t, cfg, back)
	status, body = getRaw(t, fb, "/api/accounts")
	payload = strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, lower, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByRadicalIdeographs(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	slash := strings.ReplaceAll(acc.RefreshToken, "/", "\u4e3f")
	acc.Name = "note " + slash
	acc.LastError = "rejected " + slash
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, slash, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E4%B8%BF")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}

	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	dot := strings.ReplaceAll(back.RefreshToken, "\\", "\u4e36")
	back.Name = "note " + dot
	back.LastError = "rejected " + dot
	fb := newFixture(t, cfg, back)
	status, body = getRaw(t, fb, "/api/accounts")
	payload = strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, dot, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByKatakanaNoAndCopticEsh(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	kana := strings.ReplaceAll(acc.RefreshToken, "/", "\u30ce")
	half := strings.ReplaceAll(acc.RefreshToken, "/", "\uff89")
	acc.Name = "note " + kana
	acc.LastError = "rejected " + half
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, kana, half, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	capital := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%B3%86")
	small := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%B3%87")
	raw := `{"note":"see ` + capital + ` ` + small + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, capital, small, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCircledKatakanaNo(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	circled := strings.ReplaceAll(acc.RefreshToken, "/", "\u32e8")
	nano := strings.ReplaceAll(acc.RefreshToken, "/", "\u3328")
	acc.Name = "note " + circled
	acc.LastError = "rejected " + nano
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, circled, nano, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	notto := strings.ReplaceAll(acc.RefreshToken, "/", "%E3%8C%A9")
	raw := `{"note":"see ` + notto + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, notto, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySyllabicSlashes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	superset := strings.ReplaceAll(acc.RefreshToken, "/", "\u27c9")
	acc.Name = "note " + superset
	acc.LastError = "rejected " + superset
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, superset, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%9F%89")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}

	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	subset := strings.ReplaceAll(back.RefreshToken, "\\", "\u27c8")
	back.Name = "note " + subset
	back.LastError = "rejected " + subset
	fb := newFixture(t, cfg, back)
	status, body = getRaw(t, fb, "/api/accounts")
	payload = strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, subset, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByAPLSlashBars(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	bar := strings.ReplaceAll(acc.RefreshToken, "/", "\u233f")
	acc.Name = "note " + bar
	acc.LastError = "rejected " + bar
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, bar, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%8C%BF")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}

	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	aplBack := strings.ReplaceAll(back.RefreshToken, "\\", "\u2340")
	back.Name = "note " + aplBack
	back.LastError = "rejected " + aplBack
	fb := newFixture(t, cfg, back)
	status, body = getRaw(t, fb, "/api/accounts")
	payload = strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, aplBack, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByQuadSlashes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	quad := strings.ReplaceAll(acc.RefreshToken, "/", "\u2341")
	acc.Name = "note " + quad
	acc.LastError = "rejected " + quad
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, quad, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%8D%81")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}

	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	quadBack := strings.ReplaceAll(back.RefreshToken, "\\", "\u2342")
	back.Name = "note " + quadBack
	back.LastError = "rejected " + quadBack
	fb := newFixture(t, cfg, back)
	status, body = getRaw(t, fb, "/api/accounts")
	payload = strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, quadBack, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByCircledSlashes(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	circled := strings.ReplaceAll(acc.RefreshToken, "/", "\u2298")
	acc.Name = "note " + circled
	acc.LastError = "rejected " + circled
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, circled, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%8A%98")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}

	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	circledBack := strings.ReplaceAll(back.RefreshToken, "\\", "\u29b8")
	back.Name = "note " + circledBack
	back.LastError = "rejected " + circledBack
	fb := newFixture(t, cfg, back)
	status, body = getRaw(t, fb, "/api/accounts")
	payload = strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, circledBack, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByAPLCircleBackslash(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	circled := strings.ReplaceAll(back.RefreshToken, "\\", "\u2349")
	back.Name = "note " + circled
	back.LastError = "rejected " + circled
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, circled, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%E2%8D%89")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortDiagonals(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	rising := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001fba0")
	acc.Name = "note " + rising
	acc.LastError = "rejected " + rising
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, rising, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%A0")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}

	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	falling := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001fba1")
	back.Name = "note " + falling
	back.LastError = "rejected " + falling
	fb := newFixture(t, cfg, back)
	status, body = getRaw(t, fb, "/api/accounts")
	payload = strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, falling, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
}

func TestManagementHidesSecretsSplitByBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB66")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%A6")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByWiderBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB65")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%A5")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMiddleBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB67")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%A7")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByInnerBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB64")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%A4")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByTopBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB63")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%A3")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortTopBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB62")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%A2")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerCentreBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB56")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%96")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByOuterBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB55")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%95")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortLowerUpperLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB5D")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%9D")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerUpperLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB5E")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%9E")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortLowerCentreUpperLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB5F")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%9F")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByOuterUpperLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB60")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%A0")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerCentreUpperLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB61")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%A1")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortLowerLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB47")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%87")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB48")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%88")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortLowerCentreLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB49")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%89")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByOuterLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB4A")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%8A")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerCentreLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB4B")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%8B")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortTopLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB41")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%81")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByTopLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB42")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%82")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByInnerLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB43")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%83")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMiddleLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB46")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%86")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByWiderLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB44")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%84")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerRightBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB45")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%85")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortLowerLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB3C")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AC%BC")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB3D")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AC%BD")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortLowerCentreLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB3E")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AC%BE")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByOuterLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB3F")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AC%BF")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerCentreLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB40")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%80")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortTopLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB4C")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%8C")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByTopLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB4D")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%8D")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByInnerLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB4E")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%8E")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMiddleLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB51")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%91")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByWiderLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB4F")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%8F")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerLeftBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB50")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%90")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByUpperRightToLowerLeftFill(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB99")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%99")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySquareUpperRightToLowerLeftFill(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u25A8")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%96%A8")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySquareDiagonalCrosshatch(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u25A9")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%96%A9")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalCross(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2573")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%95%B3")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalCorner(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBA4")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%A4")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalRightCorner(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBA5")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%A5")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalLowerCorner(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBA6")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%A6")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalTopCorner(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBA7")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%A7")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalPairedRise(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBA8")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%A8")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalPairedFall(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FBA9")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, back.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AE%A9")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, back.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalLongRightPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBAA")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%AA")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalLongLeftPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBAB")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%AB")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalLongUpperPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBAC")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%AC")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalLongRightUpperPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBAD")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%AD")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightDiagonalDiamondPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBAE")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%AE")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByNegativeDiagonalDiamondPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBBF")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%BF")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByNegativeDiagonalCrossPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBBD")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%BD")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMultiplicationSignInDoubleCirclePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2A37")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%A8%B7")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCircledMultiplicationSignWithCircumflexPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2A36")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%A8%B6")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMultiplicationSignInRightHalfCirclePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2A35")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%A8%B5")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMultiplicationSignInLeftHalfCirclePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2A34")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%A8%B4")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMultiplicationSignWithUnderbarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2A31")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%A8%B1")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMultiplicationSignWithDotAbovePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2A30")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%A8%B0")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByVectorOrCrossProductPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2A2F")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%A8%AF")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMultiplicationSignPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u00D7")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%C3%97")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCancellationXPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F5D9")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%97%99")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByNegativeSquaredCrossMarkPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u274E")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%9D%8E")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCrossMarkPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u274C")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%9D%8C")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavyBallotXPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2718")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%9C%98")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByBallotXPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2717")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%9C%97")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavyMultiplicationXPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2716")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%9C%96")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMultiplicationXPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2715")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%9C%95")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByNinePointedWhiteStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D9")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%99")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByNegativeCircledSquarePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D8")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%98")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCircledSquarePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D7")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%97")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByNegativeCircledTrianglePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D6")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%96")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByCircledTrianglePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D5")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%95")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavyTwelvePointedPinwheelStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D4")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%94")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavyTwelvePointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D3")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%93")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightTwelvePointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D2")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%92")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavyEightPointedPinwheelStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D1")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%91")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByVeryHeavyEightPointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7D0")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%90")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavyEightPointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7CF")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%8F")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMediumEightPointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7CE")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%8E")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySixPointedPinwheelStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7CD")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%8D")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavySixPointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7CC")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%8C")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMediumSixPointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7CB")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%8B")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavyFivePointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7CA")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%8A")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightFivePointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C9")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%89")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByReverseLightFourPointedPinwheelStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C8")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%88")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMediumFourPointedPinwheelStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C7")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%87")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByFourPointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C6")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%86")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMediumFourPointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C5")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%85")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightFourPointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C4")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%84")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMediumThreePointedPinwheelStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C3")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%83")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByThreePointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C2")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%82")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMediumThreePointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C1")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%81")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightThreePointedBlackStarPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7C0")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9F%80")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByEightSpokedAsteriskPaths(t *testing.T) {
	marks := []rune{'\U0001F7BB', '\U0001F7BC', '\U0001F7BD', '\U0001F7BE', '\U0001F7BF'}
	for _, mark := range marks {
		cfg := config.Default()
		cfg.APIKey = "synthetic-local-management-key"
		acc := testAccount("acct_one", "one@example.test")
		acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
		block := strings.ReplaceAll(acc.RefreshToken, "/", string(mark))
		acc.Name = "note " + block
		acc.LastError = "rejected " + block
		f := newFixture(t, cfg, acc)
		status, body := getRaw(t, f, "/api/accounts")
		payload := strings.Split(acc.AccessToken, ".")[1]
		for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
			if strings.Contains(body, leaked) {
				t.Fatalf("U+%04X leaked %q: %d %s", mark, leaked, status, body)
			}
		}
		if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
			t.Fatalf("U+%04X display context lost: %d %s", mark, status, body)
		}
		var bytes []string
		for _, b := range []byte(string(mark)) {
			bytes = append(bytes, fmt.Sprintf("%%%02X", b))
		}
		encoded := strings.ReplaceAll(acc.RefreshToken, "/", strings.Join(bytes, ""))
		raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
		out := string(f.srv.redactManagementBody([]byte(raw)))
		for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
			if strings.Contains(out, leaked) {
				t.Fatalf("U+%04X leaked %q in %s", mark, leaked, out)
			}
		}
		if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
			t.Fatalf("U+%04X note was rewritten: %s", mark, out)
		}
	}
}

func TestManagementHidesSecretsSplitByExtremelyHeavySixSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7BA")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%BA")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByVeryHeavySixSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B9")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B9")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavySixSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B8")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B8")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByBoldSixSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B7")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B7")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMediumSixSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B6")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B6")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightSixSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B5")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B5")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByExtremelyHeavyFiveSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B4")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B4")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByVeryHeavyFiveSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B3")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B3")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavyFiveSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B2")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B2")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByBoldFiveSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B1")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B1")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMediumFiveSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7B0")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%B0")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightFiveSpokedAsteriskPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7AF")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%AF")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavyCircledSaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2B59")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%AD%99")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySquaredSaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u26DD")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%9B%9D")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySaltireMarkPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\u2613")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%E2%98%93")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByExtremelyHeavySaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7AE")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%AE")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByVeryHeavySaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7AD")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%AD")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByHeavySaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7AC")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%AC")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByBoldSaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7AB")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%AB")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMediumSaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7AA")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%AA")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLightSaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7A9")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%A9")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByThinSaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001F7A8")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%9E%A8")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByWhiteUpPointingChevronPath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBCA")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AF%8A")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByWhiteHeavySaltirePath(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FBC0")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AF%80")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitBySquareUpperLeftToLowerRightFill(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\u25A7")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, back.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%E2%96%A7")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, back.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByUpperLeftToLowerRightFill(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB98")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, back.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AE%98")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, back.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortLowerBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB52")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%92")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByLowerBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB53")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%93")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortLowerCentreBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	back := testAccount("acct_one", "one@example.test")
	back.RefreshToken = "rt_Zz9q\\Refresh\\7f3a"
	block := strings.ReplaceAll(back.RefreshToken, "\\", "\U0001FB54")
	back.Name = "note " + block
	back.LastError = "rejected " + block
	fb := newFixture(t, cfg, back)
	status, body := getRaw(t, fb, "/api/accounts")
	payload := strings.Split(back.AccessToken, ".")[1]
	for _, leaked := range []string{back.AccessToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("backslash leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("backslash context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(back.RefreshToken, "\\", "%F0%9F%AD%94")
	raw := `{"note":"see ` + encoded + `","access_token":"` + back.AccessToken + `"}`
	out := string(fb.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{back.AccessToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByRisingBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB5B")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%9B")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByWiderRisingBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB5A")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%9A")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByMiddleRisingBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB5C")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%9C")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByInnerRisingBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB59")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%99")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByTopRisingBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB58")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%98")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByShortTopRisingBlockDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	block := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001FB57")
	acc.Name = "note " + block
	acc.LastError = "rejected " + block
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, block, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AD%97")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByModifierDotSlash(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	dot := strings.ReplaceAll(acc.RefreshToken, "/", "\uA718")
	acc.Name = "note " + dot
	acc.LastError = "rejected " + dot
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, dot, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%EA%9C%98")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}

func TestManagementHidesSecretsSplitByNegativeDiagonal(t *testing.T) {
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.RefreshToken = "rt_Zz9q/Refresh/7f3a"
	neg := strings.ReplaceAll(acc.RefreshToken, "/", "\U0001fbbe")
	acc.Name = "note " + neg
	acc.LastError = "rejected " + neg
	f := newFixture(t, cfg, acc)
	status, body := getRaw(t, f, "/api/accounts")
	payload := strings.Split(acc.AccessToken, ".")[1]
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, neg, payload, "eyJ", "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("leaked %q: %d %s", leaked, status, body)
		}
	}
	if status != http.StatusOK || !strings.Contains(body, "note") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "one@example.test") || !strings.Contains(body, "rejected") {
		t.Fatalf("display context lost: %d %s", status, body)
	}
	encoded := strings.ReplaceAll(acc.RefreshToken, "/", "%F0%9F%AE%BE")
	raw := `{"note":"see ` + encoded + `","access_token":"` + acc.AccessToken + `"}`
	out := string(f.srv.redactManagementBody([]byte(raw)))
	for _, leaked := range []string{acc.AccessToken, acc.RefreshToken, encoded, payload, "eyJ", "Zz9q", "Refresh"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"note"`) || !strings.Contains(out, "[redacted]") || !strings.Contains(out, "see") {
		t.Fatalf("note was rewritten: %s", out)
	}
}
