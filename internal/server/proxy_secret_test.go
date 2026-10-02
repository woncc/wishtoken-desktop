package server

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/account"
	"github.com/xxx-holic/wishtoken-desktop/internal/config"
	"github.com/xxx-holic/wishtoken-desktop/internal/httpx"
)

func TestManagementHidesProxyPasswords(t *testing.T) {
	const password = "s3cret-proxy"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	cfg.ProxyURL = "user:" + password + "@127.0.0.1:7890"
	f := newFixture(t, cfg, testAccount("acct_one", "one@example.test"))
	acc := f.srv.Store.List()[0]
	if err := f.srv.Store.Update(acc.ID, func(stored *account.Account) {
		stored.ProxyURL = "http://user:" + password + "@127.0.0.1:7890"
	}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/api/status", "/api/accounts", "/api/settings"} {
		status, body := getRaw(t, f, route)
		if status != http.StatusOK || strings.Contains(body, password) {
			t.Fatalf("%s leaked: %d %s", route, status, body)
		}
	}

	redacted := httpx.Redact(cfg.ProxyURL)
	status, body := putJSON(t, f, "/api/settings", `{"proxy_url":"`+redacted+`"}`)
	if status != http.StatusOK || strings.Contains(body, password) || f.srv.Config().ProxyURL != cfg.ProxyURL {
		t.Fatalf("redacted save: %d %s stored %q", status, body, f.srv.Config().ProxyURL)
	}
	status, body = putJSON(t, f, "/api/settings", `{"proxy_url":"http://user:`+password+`@"}`)
	if status == http.StatusOK || strings.Contains(body, password) || f.srv.Config().ProxyURL != cfg.ProxyURL {
		t.Fatalf("invalid proxy: %d %s stored %q", status, body, f.srv.Config().ProxyURL)
	}

	viewRedacted := httpx.Redact("http://user:" + password + "@127.0.0.1:7890")
	status, body = putJSON(t, f, "/api/accounts/"+acc.ID, `{"proxy_url":"`+viewRedacted+`"}`)
	if status != http.StatusOK || strings.Contains(body, password) {
		t.Fatalf("account save: %d %s", status, body)
	}
	stored, ok := f.srv.Store.Get(acc.ID)
	if !ok || stored.ProxyURL != "http://user:"+password+"@127.0.0.1:7890" {
		t.Fatalf("account proxy changed: %+v", stored.ProxyURL)
	}
}

func TestManagementHidesUnparseableProxyPasswords(t *testing.T) {
	const password = "s3cret%zz"
	const spaced = "s3cret proxy"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	cfg.ProxyURL = "http://user:" + password + "@127.0.0.1:7890"
	f := newFixture(t, cfg, testAccount("acct_one", "one@example.test"))
	acc := f.srv.Store.List()[0]
	if err := f.srv.Store.Update(acc.ID, func(stored *account.Account) {
		stored.ProxyURL = "http://user:" + spaced + "@127.0.0.1:7890"
	}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/api/status", "/api/accounts", "/api/settings"} {
		status, body := getRaw(t, f, route)
		if status != http.StatusOK || strings.Contains(body, password) || strings.Contains(body, spaced) {
			t.Fatalf("%s leaked unparseable proxy: %d %s", route, status, body)
		}
	}
	redacted := httpx.Redact(cfg.ProxyURL)
	status, body := putJSON(t, f, "/api/settings", `{"proxy_url":"`+redacted+`"}`)
	if status != http.StatusOK || strings.Contains(body, password) || f.srv.Config().ProxyURL != cfg.ProxyURL {
		t.Fatalf("redacted malformed save: %d %s stored %q", status, body, f.srv.Config().ProxyURL)
	}
}

func putJSON(t *testing.T, f *fixture, route, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, f.api.URL+route, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

func TestManagementHidesProxyPasswordInDisplayFields(t *testing.T) {
	const password = "s3cret-proxy"
	proxyURL := "http://user:" + password + "@127.0.0.1:7890"
	malformed := "http://user:" + password + "%zz@127.0.0.1:7890"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	acc := testAccount("acct_one", "one@example.test")
	acc.Name = "note " + proxyURL
	acc.PlanType = proxyURL
	acc.Source = malformed
	acc.Tags = []string{"team", malformed}
	acc.LastError = "dial " + malformed
	acc.ProxyURL = proxyURL
	f := newFixture(t, cfg, acc)
	stored := f.srv.Store.List()[0]
	f.srv.Pool.ReportRateLimited(stored.ID, time.Minute, "dial "+malformed)
	resp, err := http.Get(f.api.URL + "/api/accounts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode != http.StatusOK || strings.Contains(body, password) {
		t.Fatalf("display fields leaked: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "xxxxx") || !strings.Contains(body, "one@example.test") {
		t.Fatalf("redacted account lost context: %s", body)
	}
}

func TestManagementHidesEncodedProxyPassword(t *testing.T) {
	const password = "s3cret-proxy"
	var encoded strings.Builder
	for i := 0; i < len(password); i++ {
		fmt.Fprintf(&encoded, "%%%02X", password[i])
	}
	proxyURL := "http://user:" + password + "@127.0.0.1:7890?q=" + encoded.String()
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	cfg.ProxyURL = proxyURL
	acc := testAccount("acct_one", "one@example.test")
	acc.ProxyURL = proxyURL
	acc.LastError = "dial " + proxyURL
	f := newFixture(t, cfg, acc)
	for _, route := range []string{"/api/status", "/api/accounts", "/api/settings"} {
		status, body := getRaw(t, f, route)
		if status != http.StatusOK || strings.Contains(body, password) || strings.Contains(body, encoded.String()) {
			t.Fatalf("%s leaked encoded proxy password: %d %s", route, status, body)
		}
	}
}

func TestManagementHidesCompatibilityProxyColon(t *testing.T) {
	const password = "s3cret-proxy"
	proxyURL := "http://user\uff1a" + password + "@127.0.0.1:7890"
	encoded := "http://user%EF%BC%9A" + password + "@127.0.0.1:7890"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	cfg.ProxyURL = proxyURL
	acc := testAccount("acct_one", "one@example.test")
	acc.ProxyURL = encoded
	acc.Name = "note " + proxyURL
	acc.LastError = "dial " + encoded
	f := newFixture(t, cfg, acc)
	for _, route := range []string{"/api/status", "/api/accounts", "/api/settings"} {
		status, body := getRaw(t, f, route)
		if status != http.StatusOK || strings.Contains(body, password) || strings.Contains(body, "%EF%BC%9A"+password) {
			t.Fatalf("%s leaked compatibility proxy colon: %d %s", route, status, body)
		}
	}
}

func TestManagementHidesRemainingProxyColonLookalikes(t *testing.T) {
	const password = "s3cret-proxy"
	proxyURL := "http://user\u0705" + password + "@127.0.0.1:7890"
	encodedColon := encodeEveryByte("\u1365")
	encoded := "http://user" + encodedColon + password + "@127.0.0.1:7890"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	cfg.ProxyURL = proxyURL
	acc := testAccount("acct_one", "one@example.test")
	acc.ProxyURL = encoded
	acc.Name = "note " + proxyURL
	acc.LastError = "dial " + encoded
	f := newFixture(t, cfg, acc)
	for _, route := range []string{"/api/status", "/api/accounts", "/api/settings"} {
		status, body := getRaw(t, f, route)
		if status != http.StatusOK || strings.Contains(body, password) || strings.Contains(body, encodedColon+password) || strings.Contains(body, "\u0705"+password) {
			t.Fatalf("%s leaked colon lookalike: %d %s", route, status, body)
		}
	}
	redacted := httpx.Redact(cfg.ProxyURL)
	status, body := putJSON(t, f, "/api/settings", `{"proxy_url":"`+redacted+`"}`)
	if status != http.StatusOK || strings.Contains(body, password) || f.srv.Config().ProxyURL != cfg.ProxyURL {
		t.Fatalf("redacted save: %d %s stored %q", status, body, f.srv.Config().ProxyURL)
	}
}

func encodeEveryByte(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

func TestManagementHidesScriptColonProxyPasswords(t *testing.T) {
	const password = "s3cret-proxy"
	proxyURL := "http://user\u1804" + password + "@127.0.0.1:7890"
	encodedColon := encodeEveryByte("\ua6f4")
	encoded := "http://user" + encodedColon + password + "@127.0.0.1:7890"
	hiddenAt := "http://user\ua6f4" + password + "\uFF20127.0.0.1:7890"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	cfg.ProxyURL = proxyURL
	acc := testAccount("acct_one", "one@example.test")
	acc.ProxyURL = encoded
	acc.Name = "note " + hiddenAt
	acc.LastError = "dial " + encoded
	f := newFixture(t, cfg, acc)
	for _, route := range []string{"/api/status", "/api/accounts", "/api/settings"} {
		status, body := getRaw(t, f, route)
		if status != http.StatusOK || strings.Contains(body, password) || strings.Contains(body, encodedColon+password) || strings.Contains(body, "\u1804"+password) || strings.Contains(body, "\ua6f4"+password) {
			t.Fatalf("%s leaked script colon: %d %s", route, status, body)
		}
	}
	redacted := httpx.Redact(cfg.ProxyURL)
	status, body := putJSON(t, f, "/api/settings", `{"proxy_url":"`+redacted+`"}`)
	if status != http.StatusOK || strings.Contains(body, password) || f.srv.Config().ProxyURL != cfg.ProxyURL {
		t.Fatalf("redacted save: %d %s stored %q", status, body, f.srv.Config().ProxyURL)
	}
}

func TestManagementHidesSuperscriptColonProxyPasswords(t *testing.T) {
	const password = "s3cret-proxy"
	proxyURL := "http://user\U00010781" + password + "@127.0.0.1:7890"
	encodedColon := encodeEveryByte("\U00010782")
	encoded := "http://user" + encodedColon + password + "@127.0.0.1:7890"
	hiddenAt := "http://user\U00010782" + password + "\uFF20127.0.0.1:7890"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	cfg.ProxyURL = proxyURL
	acc := testAccount("acct_one", "one@example.test")
	acc.ProxyURL = encoded
	acc.Name = "note " + hiddenAt
	acc.LastError = "dial " + encoded
	f := newFixture(t, cfg, acc)
	for _, route := range []string{"/api/status", "/api/accounts", "/api/settings"} {
		status, body := getRaw(t, f, route)
		if status != http.StatusOK || strings.Contains(body, password) || strings.Contains(body, encodedColon+password) || strings.Contains(body, "\U00010781"+password) || strings.Contains(body, "\U00010782"+password) {
			t.Fatalf("%s leaked superscript colon: %d %s", route, status, body)
		}
	}
	redacted := httpx.Redact(cfg.ProxyURL)
	status, body := putJSON(t, f, "/api/settings", `{"proxy_url":"`+redacted+`"}`)
	if status != http.StatusOK || strings.Contains(body, password) || f.srv.Config().ProxyURL != cfg.ProxyURL {
		t.Fatalf("redacted save: %d %s stored %q", status, body, f.srv.Config().ProxyURL)
	}
}

func TestManagementHidesAtSignProxyPasswords(t *testing.T) {
	const password = "s3cret-proxy"
	proxyURL := "http://user:" + password + "\uFF20127.0.0.1:7890"
	encoded := "http://user:" + password + "%2540127.0.0.1:7890"
	cfg := config.Default()
	cfg.APIKey = "synthetic-local-management-key"
	cfg.ProxyURL = proxyURL
	acc := testAccount("acct_one", "one@example.test")
	acc.ProxyURL = encoded
	acc.Name = "note " + proxyURL
	acc.LastError = "dial " + encoded + " failed"
	f := newFixture(t, cfg, acc)
	for _, route := range []string{"/api/status", "/api/accounts", "/api/settings"} {
		status, body := getRaw(t, f, route)
		if status != http.StatusOK || strings.Contains(body, password) || strings.Contains(body, "%2540"+password) {
			t.Fatalf("%s leaked at-sign lookalike: %d %s", route, status, body)
		}
	}
	redacted := httpx.Redact(cfg.ProxyURL)
	status, body := putJSON(t, f, "/api/settings", `{"proxy_url":"`+redacted+`"}`)
	if status != http.StatusOK || strings.Contains(body, password) || f.srv.Config().ProxyURL != cfg.ProxyURL {
		t.Fatalf("redacted save: %d %s stored %q", status, body, f.srv.Config().ProxyURL)
	}
}
