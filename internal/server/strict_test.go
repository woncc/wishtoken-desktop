package server

import (
	"net/http"
	"testing"
)

func TestStrictRouteAndEffortNeverDowngrade(t *testing.T) {
	f := newFixture(t, nil, testAccount("team", "member@example.com"))
	for _, model := range []string{"gpt-6-astra:codex", "gpt-6-astra(max)", "gpt-6-astra-ultra"} {
		r, _ := post(t, f.api.URL+"/v1/responses", object{"model": model, "input": "ping"}, nil)
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("accepted %s", model)
		}
	}
	for _, effort := range []string{"max", "ultra", "bogus"} {
		r, _ := post(t, f.api.URL+"/v1/responses", object{"model": "gpt-6-astra", "reasoning": object{"effort": effort}, "input": "ping"}, nil)
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("accepted %s", effort)
		}
	}
	if f.codexHit.Load() != 0 || f.bpsHits.Load() != 0 {
		t.Fatal("rejected requests reached upstream")
	}
}

func TestPinnedAccountNeverChangesOnSwitchOrFailure(t *testing.T) {
	f := newFixture(t, nil, testAccount("acct_one", "one@example.com"), testAccount("acct_two", "two@example.com"))
	ids := map[string]string{}
	for _, a := range f.srv.Store.List() {
		ids[a.AccountID] = a.ID
	}
	cfg := *f.srv.Config()
	cfg.ActiveAccountID = ids["acct_one"]
	f.srv.setConfig(&cfg)
	request := object{"model": "gpt-6-astra", "input": "ping"}
	resp, _ := post(t, f.api.URL+"/v1/responses", request, nil)
	if resp.StatusCode != 200 || f.bpsHdr.Load().(http.Header).Get("Chatgpt-Account-Id") != "acct_one" {
		t.Fatal("active account not used")
	}
	resp, _ = post(t, f.api.URL+"/v1/responses", request, map[string]string{"X-GPTBridge-Account": ids["acct_two"]})
	if resp.StatusCode != 200 || f.bpsHdr.Load().(http.Header).Get("Chatgpt-Account-Id") != "acct_two" {
		t.Fatal("instance pin ignored")
	}
	f.bpsMode.Store("rate_first")
	before := f.bpsHits.Load()
	resp, _ = post(t, f.api.URL+"/v1/responses", request, nil)
	if resp.StatusCode != 429 || f.bpsHits.Load() != before+1 {
		t.Fatal("rate-limited pinned account silently changed")
	}
	resp, _ = post(t, f.api.URL+"/v1/responses", request, map[string]string{"X-GPTBridge-Account": "missing"})
	if resp.StatusCode != 503 || f.bpsHits.Load() != before+1 {
		t.Fatal("unknown account silently changed")
	}
}
