package codexcfg

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestApplyReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	dir := t.TempDir()
	stolen := filepath.Join(dir, "stolen.toml")
	if err := os.WriteFile(stolen, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.Symlink(stolen, path); err != nil {
		t.Skip(err)
	}
	fixed := time.Date(2026, 10, 1, 3, 4, 5, 0, time.UTC)
	previous := backupClock
	backupClock = func() time.Time { return fixed }
	t.Cleanup(func() { backupClock = previous })
	backup := path + ".bak-" + fixed.Format("20060102-150405")
	if err := os.Symlink(stolen, backup); err != nil {
		t.Skip(err)
	}
	const key = "synthetic-local-key"
	gotBackup, err := Apply(path, Projection{BaseURL: "http://127.0.0.1:8790/v1", Model: "gpt-6-astra", APIKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if gotBackup != backup {
		t.Fatalf("backup path %q", gotBackup)
	}
	kept, err := os.ReadFile(stolen)
	if err != nil || string(kept) != "keep" || strings.Contains(string(kept), key) {
		t.Fatalf("config write followed a symlink: %q %v", kept, err)
	}
	for _, name := range []string{path, backup} {
		info, err := os.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s remained a symlink", name)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode %o", name, info.Mode().Perm())
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), key) || !strings.Contains(string(raw), "keep") {
		t.Fatalf("replacement config: %q %v", raw, err)
	}
	braw, err := os.ReadFile(backup)
	if err != nil || string(braw) != "keep" {
		t.Fatalf("backup content: %q %v", braw, err)
	}
}
