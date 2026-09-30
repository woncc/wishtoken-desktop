package localcodex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccountIdentityAndSpeed(t *testing.T) {
	root := t.TempDir()
	o := Options{Home: filepath.Join(root, "profile"), Directory: root, BaseURL: "http://127.0.0.1:8792", Model: "gpt-6-astra", Effort: "high", Channel: "codex", Speed: "fast", AccountID: "acc-test", AccessToken: "real-token-sentinel", AuthAPIURL: "http://127.0.0.1:8792/cockpit-auth/private-key"}
	o, err := Prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(o.Home, "config.toml"))
	for _, want := range []string{`service_tier = "priority"`, `default-service-tier = "priority"`, `requires_openai_auth = true`, `env_key = "GPTBRIDGE_CODEX_KEY"`, `"X-GPTBridge-Account" = "acc-test"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(string(raw), o.AccessToken) {
		t.Fatal("token leaked into config")
	}
	auth, _ := os.ReadFile(filepath.Join(o.Home, "auth.json"))
	var doc map[string]any
	if json.Unmarshal(auth, &doc) != nil || doc["personal_access_token"] != o.AccessToken || len(doc) != 2 {
		t.Fatal("auth projection changed or refresh token included")
	}
	if !strings.Contains(strings.Join(Environment(o), ";"), "CODEX_AUTHAPI_BASE_URL="+o.AuthAPIURL) {
		t.Fatal("identity adapter unavailable to CLI")
	}
	o.Speed = "standard"
	if _, err = Prepare(o); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(o.Home, "config.toml"))
	if strings.Contains(string(raw), "priority") || !strings.Contains(string(raw), `service_tier = "default"`) {
		t.Fatal("fast setting persisted after standard selection")
	}
	o.Channel = "bps"
	o.Speed = "fast"
	if _, err = Prepare(o); err == nil {
		t.Fatal("BPS silently accepted unsupported speed")
	}
}

func TestIsolatedConfig(t *testing.T) {
	root := t.TempDir()
	global := filepath.Join(root, "existing-codex")
	if err := os.MkdirAll(global, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(global, "config.toml"), []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", global)
	o, err := Prepare(Options{Home: filepath.Join(root, "bridge", "codex-home"), BaseURL: "http://127.0.0.1:8790", Model: "gpt-6-astra", Effort: "xhigh", APIKey: "secret-local-key", Directory: root})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(o.Home, "config.toml"))
	for _, want := range []string{`model = "gpt-6-astra"`, `model_reasoning_effort = "xhigh"`, `wire_api = "responses"`, `supports_websockets = false`, `env_key = "GPTBRIDGE_CODEX_KEY"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(string(raw), o.APIKey) {
		t.Fatal("key persisted in config")
	}
	original, _ := os.ReadFile(filepath.Join(global, "config.toml"))
	if string(original) != "sentinel" || os.Getenv("CODEX_HOME") != global {
		t.Fatal("global Codex configuration changed")
	}
	env := Environment(o)
	count := 0
	for _, s := range env {
		if strings.HasPrefix(s, "CODEX_HOME=") {
			count++
			if s != "CODEX_HOME="+o.Home {
				t.Fatal("wrong isolated home")
			}
		}
	}
	if count != 1 {
		t.Fatal("duplicate CODEX_HOME")
	}
	o.Effort = "ultra"
	if _, err := Prepare(o); err == nil {
		t.Fatal("effort was silently changed")
	}
}
