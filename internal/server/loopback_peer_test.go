package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/config"
	"github.com/xxx-holic/wishtoken-desktop/internal/testutil"
)

func TestPrivilegedRoutesRequireLoopbackPeer(t *testing.T) {
	cfg := config.Default()
	cfg.DesktopMode = true
	cfg.APIKey = "synthetic-local-key"
	cfg.CockpitKey = "synthetic-cockpit-key"
	account := testAccount("team-one", "one@example.test")
	f := newFixture(t, cfg, account)
	stored := f.srv.Store.List()[0]
	desktopPath := "/desktop-api/" + desktopScope(cfg.APIKey, stored.ID, "codex") + "/" + stored.ID + "/codex/v1/responses"
	body := `{"model":"gpt-6-astra","input":"fixture","stream":true}`
	cockpitHeaders := map[string]string{
		"X-GPTBridge-Cockpit": cfg.CockpitKey,
		"Authorization":       "Bearer " + stored.AccessToken,
		"Chatgpt-Account-Id":  stored.AccountID,
	}

	rejected := []string{"", "localhost:9", "localhost", "203.0.113.8:9", "[::]:9", "0.0.0.0:9"}
	for _, addr := range rejected {
		desktop := callPrivileged(f, http.MethodPost, desktopPath, body, addr, nil)
		if desktop.Code != http.StatusUnauthorized || f.codexHit.Load() != 0 {
			t.Fatalf("desktop peer %q status %d body %s", addr, desktop.Code, desktop.Body.String())
		}
		cockpit := callPrivileged(f, http.MethodPost, "/cockpit/v1/responses", body, addr, cockpitHeaders)
		if cockpit.Code != http.StatusUnauthorized || f.bpsHits.Load() != 0 {
			t.Fatalf("cockpit peer %q status %d body %s", addr, cockpit.Code, cockpit.Body.String())
		}
	}

	for _, addr := range []string{"127.0.0.1:9", "[::1]:9", "[::ffff:127.0.0.1]:9", "[::1%lo]:9"} {
		before := f.codexHit.Load()
		desktop := callPrivileged(f, http.MethodPost, desktopPath, body, addr, nil)
		if desktop.Code == http.StatusUnauthorized || f.codexHit.Load() != before+1 {
			t.Fatalf("desktop loopback %q status %d hits %d body %s", addr, desktop.Code, f.codexHit.Load(), desktop.Body.String())
		}
		beforeBPS := f.bpsHits.Load()
		cockpit := callPrivileged(f, http.MethodPost, "/cockpit/v1/responses", body, addr, cockpitHeaders)
		if cockpit.Code == http.StatusUnauthorized || f.bpsHits.Load() != beforeBPS+1 {
			t.Fatalf("cockpit loopback %q status %d hits %d body %s", addr, cockpit.Code, f.bpsHits.Load(), cockpit.Body.String())
		}
	}

	// A bad proxy makes a skipped peer check fail inside the client instead of
	// returning the authentication error. It must not be dialed.
	f.srv.cfgMu.Lock()
	f.srv.cfg.ProxyURL = "ftp://127.0.0.1:9"
	f.srv.cfgMu.Unlock()
	identityPath := "/cockpit-auth/" + cfg.CockpitKey + "/v1/user-auth-credential/whoami"
	claims := testutil.ChatGPTClaims("one@example.test", "team-one", "team", time.Now().Add(time.Hour))
	for _, addr := range rejected {
		identity := callPrivileged(f, http.MethodGet, identityPath, "", addr, map[string]string{
			"Authorization": "Bearer " + testutil.MakeJWT(claims),
		})
		if identity.Code != http.StatusUnauthorized {
			t.Fatalf("identity peer %q status %d body %s", addr, identity.Code, identity.Body.String())
		}
	}
}

func callPrivileged(f *fixture, method, path, body, remote string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	switch {
	case strings.HasPrefix(path, "/desktop-api/"):
		f.srv.handleDesktopAPI(rec, req)
	case strings.HasPrefix(path, "/cockpit-auth/"):
		f.srv.handleCockpitIdentity(rec, req)
	default:
		f.srv.handleCockpit(rec, req)
	}
	return rec
}
