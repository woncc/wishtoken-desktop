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
