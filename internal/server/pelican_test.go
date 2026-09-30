package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/xxx-holic/wishtoken-desktop/internal/config"
)

func TestPelicanPinningAndSelection(t *testing.T) {
	cfg := config.Default()
	cfg.RoutePolicy = config.PolicyBPSOnly
	cfg.NativeFallback = false
	f := newFixture(t, cfg, testAccount("acct_one", "first@example.test"), testAccount("acct_two", "second@example.test"))
	id := ""
	for _, a := range f.srv.Store.List() {
		if a.AccountID == "acct_two" {
			id = a.ID
		}
	}
	response, _ := post(t, f.api.URL+"/api/codex/select", object{"account_id": id}, nil)
	if response.StatusCode != 200 || f.srv.Config().ActiveAccountID != id {
		t.Fatal("selection failed")
	}
	response, body := post(t, f.api.URL+"/api/pelican/generate", object{"account_id": id, "model": "gpt-6-astra", "effort": "high", "prompt": "Draw a pelican"}, nil)
	if response.StatusCode != 200 || !strings.Contains(body, "pong from bps") {
		t.Fatalf("%d %s", response.StatusCode, body)
	}
	if f.bpsHdr.Load().(http.Header).Get("Chatgpt-Account-Id") != "acct_two" {
		t.Fatal("benchmark used wrong account")
	}
	if f.codexHit.Load() != 0 {
		t.Fatal("unexpected fallback")
	}
	for _, bad := range []object{{"account_id": ""}, {"account_id": id, "model": "gpt-6-astra", "effort": "max", "prompt": "test"}} {
		r, _ := post(t, f.api.URL+"/api/pelican/generate", bad, nil)
		if r.StatusCode != 400 {
			t.Fatal("invalid benchmark accepted")
		}
	}
}

func TestPelicanRejectsIncompleteAndPolicyDenial(t *testing.T) {
	for _, mode := range []string{"incomplete", "policy_denied"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.Default()
			cfg.RoutePolicy = config.PolicyBPSOnly
			cfg.NativeFallback = false
			f := newFixture(t, cfg, testAccount("acct_one", "first@example.test"))
			f.bpsMode.Store(mode)
			id := f.srv.Store.List()[0].ID
			response, body := post(t, f.api.URL+"/api/pelican/generate", object{"account_id": id, "model": "gpt-6-astra", "effort": "high", "prompt": "Draw HTML"}, nil)
			if response.StatusCode == 200 {
				t.Fatal("incomplete/refused generation accepted")
			}
			if mode == "policy_denied" {
				if response.StatusCode != 403 || !strings.Contains(body, "basispoints_access_restricted") {
					t.Fatalf("wrong denial: %s", body)
				}
				a, _ := f.srv.Store.Get(id)
				if !strings.HasPrefix(a.LastError, "bps_access_restricted:") {
					t.Fatal("lost account status")
				}
			}
			if f.codexHit.Load() != 0 {
				t.Fatal("silent native fallback")
			}
		})
	}
}

func TestDesktopExplicitChannels(t *testing.T) {
	cfg := config.Default()
	cfg.DesktopMode, cfg.APIKey = true, "local-test-key"
	f := newFixture(t, cfg, testAccount("acct_one", "one@example.test"), testAccount("acct_two", "two@example.test"))
	id := f.srv.Store.List()[1].ID
	account, _ := f.srv.Store.Get(id)
	headers := map[string]string{"Authorization": "Bearer local-test-key"}
	body := object{"account_id": id, "model": "gpt-5.6-terra", "channel": "codex", "effort": "high", "prompt": "Draw HTML"}
	resp, text := post(t, f.api.URL+"/api/pelican/generate", body, headers)
	if resp.StatusCode != 200 || !strings.Contains(text, "pong from codex") || f.bpsHits.Load() != 0 {
		t.Fatalf("explicit native failed: %d %s", resp.StatusCode, text)
	}
	if f.codexHdr.Load().(http.Header).Get("Chatgpt-Account-Id") != account.AccountID {
		t.Fatal("wrong native account")
	}
	native := f.codexBody.Load().(object)
	if native["model"] != "gpt-5.6-terra" || len(native["input"].([]any)) != 1 {
		t.Fatal("model substituted or input not normalized")
	}
	// BPS denial does not trigger native, and native denial does not trigger BPS.
	body["model"], body["channel"] = "gpt-6-astra", "bps"
	f.bpsMode.Store("policy_denied")
	resp, _ = post(t, f.api.URL+"/api/pelican/generate", body, headers)
	if resp.StatusCode != 403 || f.codexHit.Load() != 1 {
		t.Fatal("BPS silently fell back")
	}
	body["channel"] = "codex"
	f.codexMode.Store("deny")
	resp, _ = post(t, f.api.URL+"/api/pelican/generate", body, headers)
	if resp.StatusCode != 403 || f.bpsHits.Load() != 1 {
		t.Fatal("native silently fell back")
	}
	for _, channel := range []string{"invalid", "bps"} {
		body["channel"], body["model"] = channel, "gpt-5.6-terra"
		resp, _ = post(t, f.api.URL+"/api/pelican/generate", body, headers)
		if resp.StatusCode != 400 {
			t.Fatal("invalid channel/model accepted")
		}
	}
}

func TestDesktopProfileChannelPinAndDefault(t *testing.T) {
	cfg := config.Default()
	cfg.DesktopMode, cfg.APIKey = true, "local-test-key"
	f := newFixture(t, cfg, testAccount("acct_one", "one@example.test"))
	headers := map[string]string{"Authorization": "Bearer local-test-key"}
	body := object{"model": "gpt-6-astra", "input": "ping", "stream": false}
	r, _ := post(t, f.api.URL+"/v1/responses", body, headers)
	if r.StatusCode != 200 || f.bpsHits.Load() != 1 || f.codexHit.Load() != 0 {
		t.Fatal("default must stay BPS")
	}
	headers["X-GPTBridge-Channel"] = "codex"
	r, _ = post(t, f.api.URL+"/v1/responses", body, headers)
	if r.StatusCode != 200 || f.codexHit.Load() != 1 {
		t.Fatal("profile header not respected")
	}
	body["model"] = "gpt-6-astra:bps"
	r, _ = post(t, f.api.URL+"/v1/responses", body, headers)
	if r.StatusCode != 400 || f.bpsHits.Load() != 1 {
		t.Fatal("profile can silently change channel")
	}
}
