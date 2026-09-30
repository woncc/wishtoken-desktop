package cockpit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxx-holic/wishtoken-desktop/internal/config"
)

func TestInstallPreservesCockpitAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "bridge")
	data := filepath.Join(root, "cockpit")
	_ = os.MkdirAll(data, 0700)
	exe := filepath.Join(root, "cockpit-tools.exe")
	_ = os.WriteFile(exe, []byte("test"), 0600)
	path := filepath.Join(data, "codex_instances.json")
	original := []byte(`{"defaultSettings":{"bindAccountId":"existing","lastPid":123,"future":true},"futureRoot":42,"instances":[{"id":"existing","name":"original"}]}`)
	_ = os.WriteFile(path, original, 0600)
	cfg := config.Default()
	ins, err := Install(home, data, exe, "http://127.0.0.1:8791", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	raw, _ := os.ReadFile(path)
	_ = json.Unmarshal(raw, &result)
	if len(result["instances"].([]any)) != 2 || result["futureRoot"].(float64) != 42 || result["defaultSettings"].(map[string]any)["bindAccountId"] != "existing" {
		t.Fatal("existing state lost")
	}
	backups, _ := filepath.Glob(path + ".gptbridge-backup-*")
	if len(backups) != 1 {
		t.Fatal("backup missing")
	}
	b, _ := os.ReadFile(backups[0])
	if string(b) != string(original) {
		t.Fatal("incorrect backup")
	}
	profile := filepath.Join(ins.Profile, "config.toml")
	p, _ := os.ReadFile(profile)
	if !strings.Contains(string(p), "requires_openai_auth = true") || strings.Contains(string(p), "experimental_bearer_token") {
		t.Fatal("OAuth replaced with API card")
	}
	auth := filepath.Join(ins.Profile, "auth.json")
	_ = os.WriteFile(auth, []byte("user auth"), 0600)
	_ = os.WriteFile(profile, []byte("user config"), 0600)
	second, err := Install(home, data, exe, "http://127.0.0.1:8791", cfg)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) || second.InstanceID != ins.InstanceID {
		t.Fatal("reinstall changed registry")
	}
	for name, want := range map[string]string{auth: "user auth", profile: "user config"} {
		b, _ := os.ReadFile(name)
		if string(b) != want {
			t.Fatal("user file overwritten")
		}
	}
}
