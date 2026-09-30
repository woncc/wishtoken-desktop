// Package localcodex launches Codex with an isolated provider configuration.
package localcodex

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/xxx-holic/wishtoken-desktop/internal/ownerfile"
)

//go:embed models.json
var modelCatalog []byte

//go:embed native-models.json
var nativeCatalog []byte

func Channel(value string) (string, error) {
	if value == "" {
		return "bps", nil
	}
	if value != "bps" && value != "codex" {
		return "", fmt.Errorf("请选择 BPS 或原生通道")
	}
	return value, nil
}

func NativeModels() []map[string]any {
	var manifest struct {
		Models []map[string]any `json:"models"`
	}
	_ = json.Unmarshal(nativeCatalog, &manifest)
	models := []map[string]any{}
	for _, m := range manifest.Models {
		models = append(models, map[string]any{"id": m["slug"], "display_name": m["display_name"], "context_window": m["context_window"]})
	}
	return models
}

func NativeModelAllowed(model string) bool {
	for _, m := range NativeModels() {
		if m["id"] == model {
			return true
		}
	}
	return false
}

// Catalog returns the route-compatible native Codex model manifest.
func Catalog() []byte { return append([]byte(nil), modelCatalog...) }

func ChannelCatalog(channel string) []byte {
	if channel == "codex" {
		return append([]byte(nil), nativeCatalog...)
	}
	return Catalog()
}

type Options struct {
	Home          string
	BaseURL       string
	APIKey        string
	Model         string
	Effort        string
	Directory     string
	AccountID     string
	Channel       string
	Speed         string
	AccessToken   string
	AuthAPIURL    string
	ContextWindow int
	CompactLimit  int
	Resume        bool
}

func Binary() (string, error) {
	if explicit := strings.TrimSpace(os.Getenv("GPTBRIDGE_CODEX_BIN")); explicit != "" {
		if filepath.IsAbs(explicit) {
			if st, err := os.Stat(explicit); err == nil && !st.IsDir() {
				return explicit, nil
			}
		}
		return "", fmt.Errorf("指定的 Codex CLI 文件不存在")
	}
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("codex.cmd"); err == nil {
			return p, nil
		}
	}
	p, err := exec.LookPath("codex")
	if err != nil {
		if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
			home, _ := os.UserHomeDir()
			for _, candidate := range []string{"/opt/homebrew/bin/codex", "/usr/local/bin/codex", filepath.Join(home, ".local", "bin", "codex"), filepath.Join(home, ".npm-global", "bin", "codex")} {
				if st, e := os.Stat(candidate); e == nil && !st.IsDir() && st.Mode()&0111 != 0 {
					return candidate, nil
				}
			}
		}
		return "", fmt.Errorf("未找到 Codex CLI，请先运行 npm install -g @openai/codex，再重启 GPTBridge")
	}
	return p, nil
}

// Prepare writes only GPTBridge's private CODEX_HOME; never ~/.codex.
func Prepare(o Options) (Options, error) {
	channel, channelErr := Channel(o.Channel)
	if channelErr != nil {
		return o, channelErr
	}
	o.Channel = channel
	if o.Speed == "" {
		o.Speed = "standard"
	}
	if o.Speed != "standard" && o.Speed != "fast" {
		return o, fmt.Errorf("请选择标准或快速模式")
	}
	if o.Channel == "bps" && o.Speed != "standard" {
		return o, fmt.Errorf("BPS 暂不支持快速模式，请选择标准速度或原生通道")
	}
	u, err := url.Parse(o.BaseURL)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") {
		return o, fmt.Errorf("Codex provider must use the local bridge")
	}
	if o.Model == "" {
		return o, fmt.Errorf("model is required")
	}
	switch o.Effort {
	case "low", "medium", "high", "xhigh":
	default:
		return o, fmt.Errorf("请选择 low / medium / high / xhigh；BPS 当前不支持 max")
	}
	if o.ContextWindow == 0 {
		o.ContextWindow = 272000
	}
	if o.CompactLimit == 0 {
		o.CompactLimit = 200000
		if o.ContextWindow < 272000 {
			o.CompactLimit = o.ContextWindow * 3 / 4
		}
	}
	if o.ContextWindow < 32000 || o.ContextWindow > 272000 || o.CompactLimit < 8000 || o.CompactLimit >= o.ContextWindow {
		return o, fmt.Errorf("上下文须为 32000–272000，压缩阈值须大于等于 8000 且小于上下文窗口")
	}
	if o.Directory == "" {
		o.Directory, _ = os.UserHomeDir()
	}
	o.Directory, err = filepath.Abs(o.Directory)
	if err != nil {
		return o, err
	}
	st, err := os.Stat(o.Directory)
	if err != nil || !st.IsDir() {
		return o, fmt.Errorf("工作目录不存在: %s", o.Directory)
	}
	o.Home, err = filepath.Abs(o.Home)
	if err != nil {
		return o, err
	}
	if err := os.MkdirAll(o.Home, 0700); err != nil {
		return o, err
	}
	// Identity is used only for App account/quota UI. Model requests retain the
	// bridge env_key and pinned account/channel. Never share refresh-token ownership.
	identity := o.AccessToken != "" && o.AuthAPIURL != ""
	if identity {
		auth, _ := json.Marshal(map[string]any{"OPENAI_API_KEY": nil, "personal_access_token": o.AccessToken})
		if err := ownerfile.Write(filepath.Join(o.Home, "auth.json"), auth); err != nil {
			return o, err
		}
		meta, _ := json.Marshal(map[string]string{"auth_api_url": o.AuthAPIURL})
		if err := os.WriteFile(filepath.Join(o.Home, "bridge-identity.json"), meta, 0600); err != nil {
			return o, err
		}
	}
	// env_key avoids embedding a local API key in generated configuration.
	tier := "default"
	if o.Speed == "fast" {
		tier = "priority"
	}
	data := fmt.Sprintf(`service_tier = %s
model_provider = "gptbridge"
model = %s
model_reasoning_effort = %s
model_catalog_json = %s
model_context_window = %d
model_auto_compact_token_limit = %d
web_search = "disabled"
sandbox_mode = "workspace-write"
approval_policy = "on-request"

[windows]
sandbox = "unelevated"

[model_providers.gptbridge]
name = "GPTBridge Team"
base_url = %s
env_key = "GPTBRIDGE_CODEX_KEY"
requires_openai_auth = %t
wire_api = "responses"
supports_websockets = false
request_max_retries = 2
stream_max_retries = 2
stream_idle_timeout_ms = 600000
http_headers = { "X-GPTBridge-Account" = %s, "X-GPTBridge-Channel" = %s }
`, strconv.Quote(tier), strconv.Quote(o.Model), strconv.Quote(o.Effort), strconv.Quote(filepath.Join(o.Home, "models.json")), o.ContextWindow, o.CompactLimit, strconv.Quote(strings.TrimRight(o.BaseURL, "/")+"/v1"), identity, strconv.Quote(o.AccountID), strconv.Quote(o.Channel))
	if o.Speed == "fast" {
		data += "\n[desktop]\ndefault-service-tier = \"priority\"\n"
	}
	catalog := modelCatalog
	if o.Channel == "codex" {
		catalog = nativeCatalog
	}
	if err := os.WriteFile(filepath.Join(o.Home, "models.json"), catalog, 0600); err != nil {
		return o, err
	}
	return o, ownerfile.Write(filepath.Join(o.Home, "config.toml"), []byte(data))
}

func Environment(o Options) []string {
	env := []string{}
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if !strings.EqualFold(k, "CODEX_HOME") && !strings.EqualFold(k, "GPTBRIDGE_CODEX_KEY") && !strings.EqualFold(k, "CODEX_AUTHAPI_BASE_URL") {
			env = append(env, v)
		}
	}
	key := o.APIKey
	if o.AuthAPIURL != "" {
		env = append(env, "CODEX_AUTHAPI_BASE_URL="+o.AuthAPIURL)
	}
	if key == "" {
		key = "gptbridge-local"
	}
	return append(env, "CODEX_HOME="+o.Home, "GPTBRIDGE_CODEX_KEY="+key)
}
