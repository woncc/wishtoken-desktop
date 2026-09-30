package server

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

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
