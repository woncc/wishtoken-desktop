// Package cockpit configures a user-owned OAuth instance in unmodified Cockpit.
package cockpit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/config"
	"github.com/xxx-holic/wishtoken-desktop/internal/localcodex"
	"github.com/xxx-holic/wishtoken-desktop/internal/ownerfile"
)

type Installation struct {
	InstanceID  string `json:"instance_id"`
	Profile     string `json:"profile"`
	CockpitData string `json:"cockpit_data"`
	CockpitExe  string `json:"cockpit_exe"`
}

func randomKey() (string, error) {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}

func Install(home, data, exe, base string, cfg *config.Config) (*Installation, error) {
	if !config.IsLoopback(cfg.Listen) {
		return nil, fmt.Errorf("Cockpit OAuth 接入仅允许本机回环地址")
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		return nil, err
	}
	statePath := filepath.Join(home, "cockpit-integration.json")
	var ins Installation
	if b, e := os.ReadFile(statePath); e == nil {
		if e = json.Unmarshal(b, &ins); e != nil {
			return nil, e
		}
	}
	if ins.InstanceID == "" {
		id, e := randomKey()
		if e != nil {
			return nil, e
		}
		ins.InstanceID = "gptbridge-" + id[:16]
	}
	if data != "" {
		ins.CockpitData = data
	}
	if ins.CockpitData == "" {
		user, e := os.UserHomeDir()
		if e != nil {
			return nil, e
		}
		ins.CockpitData = filepath.Join(user, ".antigravity_cockpit")
	}
	if exe != "" {
		ins.CockpitExe = exe
	}
	if ins.CockpitExe == "" {
		return nil, fmt.Errorf("请使用 --exe 指定 Cockpit Tools 的可执行文件")
	}
	if st, e := os.Stat(ins.CockpitExe); e != nil || st.IsDir() {
		return nil, fmt.Errorf("Cockpit 程序不存在：%s", ins.CockpitExe)
	}
	ins.Profile = filepath.Join(home, "cockpit-profile")
	if cfg.CockpitKey == "" {
		key, e := randomKey()
		if e != nil {
			return nil, e
		}
		cfg.CockpitKey = key
	}
	if err := cfg.Save(filepath.Join(home, "config.json")); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(ins.Profile, 0700); err != nil {
		return nil, err
	}
	profile := fmt.Sprintf(`model_provider = "gptbridge_bps"
model = "gpt-6-astra"
model_reasoning_effort = "xhigh"
model_catalog_json = %s
model_context_window = 272000
model_auto_compact_token_limit = 200000
web_search = "disabled"
approval_policy = "on-request"
sandbox_mode = "workspace-write"

[windows]
sandbox = "unelevated"

[model_providers.gptbridge_bps]
name = "GPTBridge BPS"
base_url = %s
wire_api = "responses"
requires_openai_auth = true
supports_websockets = false
request_max_retries = 2
stream_max_retries = 2
stream_idle_timeout_ms = 600000
http_headers = { "X-GPTBridge-Cockpit" = %s }
`, strconv.Quote(filepath.Join(ins.Profile, "models.json")), strconv.Quote(strings.TrimRight(base, "/")+"/cockpit/v1"), strconv.Quote(cfg.CockpitKey))
	// Never overwrite the user's model settings, OAuth auth.json, or sessions.
	if e := writeNew(filepath.Join(ins.Profile, "config.toml"), []byte(profile)); e != nil {
		return nil, e
	}
	if e := writeNew(filepath.Join(ins.Profile, "models.json"), localcodex.Catalog()); e != nil {
		return nil, e
	}
	if err := registerInstance(&ins); err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(ins, "", "  ")
	if e := atomicWrite(statePath, b); e != nil {
		return nil, e
	}
	return &ins, nil
}

func writeNew(path string, raw []byte) error {
	// A planted symlink must not remain in place and must not be followed.
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

func atomicWrite(path string, b []byte) error {
	return ownerfile.Write(path, b)
}

func registerInstance(ins *Installation) error {
	path := filepath.Join(ins.CockpitData, "codex_instances.json")
	if e := os.MkdirAll(ins.CockpitData, 0700); e != nil {
		return e
	}
	original, e := os.ReadFile(path)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	var document map[string]any
	if len(original) > 0 {
		if e = json.Unmarshal(original, &document); e != nil {
			return fmt.Errorf("Cockpit 实例文件无效，未修改：%w", e)
		}
	}
	if document == nil {
		document = map[string]any{"instances": []any{}}
	}
	entries, ok := document["instances"].([]any)
	if !ok && document["instances"] != nil {
		return fmt.Errorf("Cockpit instances 字段格式不兼容，未修改")
	}
	for _, v := range entries {
		row, _ := v.(map[string]any)
		if row["id"] == ins.InstanceID {
			return nil
		}
	}
	document["instances"] = append(entries, map[string]any{
		"id": ins.InstanceID, "name": "GPTBridge BPS · Team", "userDataDir": ins.Profile,
		"workingDir": nil, "extraArgs": "", "bindAccountId": nil, "launchMode": "app", "appSpeed": "standard",
		"createdAt": time.Now().UnixMilli(), "lastLaunchedAt": nil, "lastPid": nil,
	})
	raw, e := json.MarshalIndent(document, "", "  ")
	if e != nil {
		return e
	}
	latest, _ := os.ReadFile(path)
	if !bytes.Equal(latest, original) {
		return fmt.Errorf("Cockpit 正在修改实例列表，请稍后重试")
	}
	if len(original) > 0 {
		backup := path + ".gptbridge-backup-" + time.Now().Format("20060102-150405.000")
		if e := writeNew(backup, original); e != nil {
			return e
		}
	}
	return atomicWrite(path, raw)
}
