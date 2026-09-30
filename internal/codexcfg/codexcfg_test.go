package codexcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `model = "gpt-5.5"
model_provider = "other"

[projects."C:\\x"]
trust_level = "trusted"

[model_providers.other]
name = "Other"
base_url = "https://other.example/v1"
wire_api = "responses"
`

func TestApplyInspectRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	backup, err := Apply(path, Projection{BaseURL: "http://127.0.0.1:8790/v1", Model: "gpt-6-astra", Effort: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if backup == "" {
		t.Fatal("expected a backup path")
	}
	raw, _ := os.ReadFile(path)
	content := string(raw)
	for _, needle := range []string{`model_provider = "gptbridge"`, `model = "gpt-6-astra"`, `model_reasoning_effort = "high"`, "[model_providers.gptbridge]", `base_url = "http://127.0.0.1:8790/v1"`, "[model_providers.other]", `[projects."C:\\x"]`} {
		if !strings.Contains(content, needle) {
			t.Fatalf("missing %s in:\n%s", needle, content)
		}
	}
	if strings.Contains(content, `model_provider = "other"`) || strings.Count(content, "model_provider =") != 1 {
		t.Fatalf("old provider not replaced:\n%s", content)
	}
	st := Inspect(path)
	if !st.BridgeActive || st.Model != "gpt-6-astra" || st.BaseURL != "http://127.0.0.1:8790/v1" {
		t.Fatalf("inspect: %+v", st)
	}
	// Applying twice must not duplicate the block.
	if _, err := Apply(path, Projection{BaseURL: "http://127.0.0.1:9999/v1"}); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if strings.Count(string(raw), "[model_providers.gptbridge]") != 1 || !strings.Contains(string(raw), ":9999/v1") {
		t.Fatalf("duplicate or stale block:\n%s", raw)
	}
	if _, err := Remove(path); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), "gptbridge") {
		t.Fatalf("remove left traces:\n%s", raw)
	}
	if !strings.Contains(string(raw), "[model_providers.other]") {
		t.Fatalf("remove damaged other provider:\n%s", raw)
	}
}

func TestApplyCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.toml")
	backup, err := Apply(path, Projection{BaseURL: "http://127.0.0.1:8790/v1", Model: "gpt-5.6-sol", APIKey: "secret"})
	if err != nil || backup != "" {
		t.Fatalf("create: %v backup=%q", err, backup)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `experimental_bearer_token = "secret"`) || !strings.HasPrefix(string(raw), `model = "gpt-5.6-sol"`) {
		t.Fatalf("content:\n%s", raw)
	}
}
