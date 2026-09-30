package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xxx-holic/wishtoken-desktop/internal/config"
)

func TestDesktopScopePinsAccountAndChannel(t *testing.T) {
	cfg := config.Default()
	cfg.DesktopMode = true
	cfg.APIKey = "synthetic-local-key"
	f := newFixture(t, cfg, testAccount("team-one", "one@example.test"), testAccount("team-two", "two@example.test"))
	accounts := f.srv.Store.List()
	id := accounts[0].ID
	endpoint := "/desktop-api/" + desktopScope(cfg.APIKey, id, "codex") + "/" + id + "/codex/v1/responses"
	body := object{"model": "gpt-6-astra", "input": "fixture", "stream": true}
	resp, raw := post(t, f.api.URL+endpoint, body, map[string]string{"X-GPTBridge-Account": accounts[1].ID, "X-GPTBridge-Channel": "bps", "Authorization": "Bearer untrusted-input"})
	if resp.StatusCode != 200 || f.codexHit.Load() != 1 || f.bpsHits.Load() != 0 {
		t.Fatalf("route mismatch: %d %s", resp.StatusCode, raw)
	}
	if f.codexHdr.Load().(http.Header).Get("Chatgpt-Account-Id") != accounts[0].AccountID {
		t.Fatal("account pin was overridden")
	}
	for _, route := range []string{strings.Replace(endpoint, "/codex/", "/bps/", 1), strings.Replace(endpoint, id, accounts[1].ID, 1), strings.Replace(endpoint, "/desktop-api/", "/desktop-api/tampered", 1)} {
		denied, _ := post(t, f.api.URL+route, body, nil)
		if denied.StatusCode != 401 {
			t.Fatalf("tampered capability accepted: %d", denied.StatusCode)
		}
	}
	denied, _ := post(t, f.api.URL+endpoint, body, map[string]string{"Origin": "https://example.test"})
	if denied.StatusCode != 401 {
		t.Fatal("browser origin accepted")
	}
	probe, err := http.Get(f.api.URL + endpoint)
	if err != nil {
		t.Fatal(err)
	}
	probe.Body.Close()
	if probe.StatusCode != 426 {
		t.Fatalf("websocket probe status %d", probe.StatusCode)
	}
	req := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader("{}"))
	req.RemoteAddr = "203.0.113.1:1234"
	recorder := httptest.NewRecorder()
	f.srv.handleDesktopAPI(recorder, req)
	if recorder.Code != 401 {
		t.Fatal("remote request accepted")
	}
	f.srv.cfgMu.Lock()
	f.srv.cfg.DesktopMode = false
	f.srv.cfgMu.Unlock()
	denied, _ = post(t, f.api.URL+endpoint, body, nil)
	if denied.StatusCode != 401 {
		t.Fatal("non-desktop server accepted capability")
	}
}
