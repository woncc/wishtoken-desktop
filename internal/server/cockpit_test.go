package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/config"
	"github.com/xxx-holic/wishtoken-desktop/internal/testutil"
)

func TestCockpitOAuthPinAndMemoryIsolation(t *testing.T) {
	cfg := config.Default()
	cfg.CockpitKey = "test-capability"
	f := newFixture(t, cfg, testAccount("unrelated", "unrelated@example.com"))
	before, _ := os.ReadFile(f.srv.Store.Path())
	for _, email := range []string{"one@example.com", "two@example.com"} {
		a := testAccount("shared-team", email)
		claims := testutil.ChatGPTClaims(email, "shared-team", "team", time.Now().Add(time.Hour))
		claims["https://api.openai.com/auth"].(map[string]any)["chatgpt_user_id"] = email
		a.AccessToken = testutil.MakeJWT(claims)
		h := map[string]string{"X-GPTBridge-Cockpit": cfg.CockpitKey, "Authorization": "Bearer " + a.AccessToken, "Chatgpt-Account-Id": a.AccountID, "X-GPTBridge-Account": "unrelated"}
		resp, body := post(t, f.api.URL+"/cockpit/v1/responses", object{"input": "ping", "model": "gpt-6-astra"}, h)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		sent := f.bpsHdr.Load().(http.Header)
		if sent.Get("Authorization") != "Bearer "+a.AccessToken || sent.Get("Chatgpt-Account-Id") != a.AccountID || sent.Get("X-GPTBridge-Cockpit") != "" {
			t.Fatal("wrong upstream identity")
		}
	}
	if f.srv.cockpitStore.Count() != 2 || f.codexHit.Load() != 0 {
		t.Fatal("members merged or native fallback used")
	}
	for _, a := range f.srv.cockpitStore.List() {
		if a.RefreshToken != "" || a.IDToken != "" {
			t.Fatal("extra credential retained")
		}
	}
	after, _ := os.ReadFile(f.srv.Store.Path())
	if string(before) != string(after) {
		t.Fatal("Cockpit token persisted")
	}
	f.bpsMode.Store("deny")
	a := testAccount("shared-team", "one@example.com")
	claims := testutil.ChatGPTClaims(a.Email, "shared-team", "team", time.Now().Add(time.Hour))
	claims["https://api.openai.com/auth"].(map[string]any)["chatgpt_user_id"] = a.Email
	a.AccessToken = testutil.MakeJWT(claims)
	h := map[string]string{"X-GPTBridge-Cockpit": cfg.CockpitKey, "Authorization": "Bearer " + a.AccessToken}
	n := f.bpsHits.Load()
	r, _ := post(t, f.api.URL+"/cockpit/v1/responses", object{"input": "ping", "model": "gpt-6-astra"}, h)
	if r.StatusCode == 200 || f.bpsHits.Load() != n+1 || f.codexHit.Load() != 0 {
		t.Fatal("denied account was substituted")
	}
}

func TestCockpitRejectsUntrustedRequests(t *testing.T) {
	cfg := config.Default()
	cfg.CockpitKey = "test-capability"
	f := newFixture(t, cfg)
	for _, h := range []map[string]string{nil, {"X-GPTBridge-Cockpit": "wrong"}, {"X-GPTBridge-Cockpit": cfg.CockpitKey}, {"X-GPTBridge-Cockpit": cfg.CockpitKey, "Sec-Fetch-Site": "cross-site"}, {"X-GPTBridge-Cockpit": cfg.CockpitKey, "Authorization": "Bearer malformed"}} {
		r, _ := post(t, f.api.URL+"/cockpit/v1/responses", object{"input": "ping"}, h)
		if r.StatusCode < 400 {
			t.Fatal("untrusted request accepted")
		}
	}
	for _, path := range []string{"/cockpit-auth/wrong/v1/user-auth-credential/whoami", "/cockpit-auth/test-capability/arbitrary"} {
		r, e := http.Get(f.api.URL + path)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != 401 {
			t.Fatal("identity path not restricted")
		}
	}
	if f.bpsHits.Load() != 0 || f.codexHit.Load() != 0 {
		t.Fatal("untrusted request reached upstream")
	}
}

type identityTransport func(*http.Request) (*http.Response, error)

func (f identityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCockpitMetadataRequiresUpstreamValidation(t *testing.T) {
	claims := testutil.ChatGPTClaims("one@example.com", "workspace", "team", time.Now().Add(time.Hour))
	claims["https://api.openai.com/auth"].(map[string]any)["chatgpt_user_id"] = "member"
	token := testutil.MakeJWT(claims)
	for _, status := range []int{200, 401, 403, 429, 500} {
		called := false
		client := &http.Client{Transport: identityTransport(func(r *http.Request) (*http.Response, error) {
			called = true
			if r.URL.Host != "chatgpt.com" || r.URL.Path != "/backend-api/wham/usage" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Chatgpt-Account-Id") != "workspace" {
				t.Fatal("incorrect verification request")
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"plan_type":"team","rate_limit":{}}`)), Header: make(http.Header)}, nil
		})}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "http://localhost/", nil)
		serveCockpitIdentity(w, r, client, token)
		if !called {
			t.Fatal("unverified metadata")
		}
		if status == 200 {
			var result object
			_ = json.Unmarshal(w.Body.Bytes(), &result)
			if w.Code != 200 || result["chatgpt_user_id"] != "member" || result["chatgpt_account_id"] != "workspace" {
				t.Fatal("invalid metadata")
			}
		} else if w.Code < 400 {
			t.Fatal("failed upstream accepted")
		}
	}
}
