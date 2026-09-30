// Package codexcfg projects the bridge as a model provider into the Codex
// CLI / Codex Desktop configuration file (~/.codex/config.toml) without a
// TOML dependency: edits are line based and always preceded by a backup.
package codexcfg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/httpx"
	"github.com/xxx-holic/wishtoken-desktop/internal/ownerfile"
)

// ProviderID is the model_providers key written by the bridge.
const ProviderID = "gptbridge"

// Projection describes the provider block to write.
type Projection struct {
	BaseURL string // e.g. http://127.0.0.1:8790/v1
	Model   string // optional top-level model
	Effort  string // optional model_reasoning_effort
	APIKey  string // optional bearer token the bridge requires
}

// ConfigPath returns the Codex configuration file path.
func ConfigPath() string {
	if home := strings.TrimSpace(os.Getenv("CODEX_HOME")); home != "" {
		return filepath.Join(home, "config.toml")
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, ".codex", "config.toml")
}

// Block renders the provider table.
func Block(p Projection) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[model_providers.%s]\n", ProviderID)
	sb.WriteString("name = \"GPTBridge (local, Basispoints)\"\n")
	fmt.Fprintf(&sb, "base_url = %q\n", p.BaseURL)
	sb.WriteString("wire_api = \"responses\"\n")
	sb.WriteString("requires_openai_auth = false\n")
	sb.WriteString("supports_websockets = false\n")
	if strings.TrimSpace(p.APIKey) != "" {
		fmt.Fprintf(&sb, "experimental_bearer_token = %q\n", p.APIKey)
	}
	return sb.String()
}

// Snippet renders the complete configuration a user can paste manually.
func Snippet(p Projection) string {
	var sb strings.Builder
	if p.Model != "" {
		fmt.Fprintf(&sb, "model = %q\n", p.Model)
	}
	if p.Effort != "" {
		fmt.Fprintf(&sb, "model_reasoning_effort = %q\n", p.Effort)
	}
	fmt.Fprintf(&sb, "model_provider = %q\n\n", ProviderID)
	sb.WriteString(Block(p))
	return sb.String()
}

var tableHeader = regexp.MustCompile(`^\s*\[`)

// backupClock is the timestamp used in backup filenames.
var backupClock = time.Now

// Apply rewrites path so Codex uses the bridge. It returns the backup path
// (empty when the file did not exist before). A symlink at the config path
// or the backup path is replaced; it is not followed.
func Apply(path string, p Projection) (string, error) {
	if path == "" {
		return "", errors.New("codex config path is unknown")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	var lines []string
	backup := ""
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		backup = path + ".bak-" + backupClock().Format("20060102-150405")
		if err := ownerfile.Write(backup, raw); err != nil {
			return "", fmt.Errorf("write backup: %w", err)
		}
		lines = strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	case errors.Is(err, os.ErrNotExist):
	default:
		return "", err
	}
	lines = removeTable(lines, "model_providers."+ProviderID)
	if p.Model != "" {
		lines = setTopLevel(lines, "model", fmt.Sprintf("%q", p.Model))
	}
	if p.Effort != "" {
		lines = setTopLevel(lines, "model_reasoning_effort", fmt.Sprintf("%q", p.Effort))
	}
	lines = setTopLevel(lines, "model_provider", fmt.Sprintf("%q", ProviderID))
	// Ensure the [model_providers] parent table exists before our sub-table
	// only if the file uses that style; TOML accepts the dotted header alone.
	content := strings.TrimRight(strings.Join(lines, "\n"), "\n")
	if content != "" {
		content += "\n\n"
	}
	content += Block(p)
	if err := ownerfile.Write(path, []byte(content)); err != nil {
		return backup, err
	}
	return backup, nil
}

// Remove deletes the bridge provider and clears model_provider when it
// pointed at the bridge. The previous provider is not restored automatically;
// use the backup file for that.
func Remove(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backup := path + ".bak-" + backupClock().Format("20060102-150405")
	if err := ownerfile.Write(backup, raw); err != nil {
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	lines = removeTable(lines, "model_providers."+ProviderID)
	out := lines[:0]
	for _, line := range lines {
		if key, value := parseKey(line); key == "model_provider" && strings.Trim(value, "\"'") == ProviderID {
			continue
		}
		out = append(out, line)
	}
	return backup, ownerfile.Write(path, []byte(strings.Join(out, "\n")))
}

// Status reports whether the bridge is the active provider.
type Status struct {
	Path             string `json:"path"`
	Exists           bool   `json:"exists"`
	ActiveProvider   string `json:"active_provider"`
	BridgeConfigured bool   `json:"bridge_configured"`
	BridgeActive     bool   `json:"bridge_active"`
	BaseURL          string `json:"base_url,omitempty"`
	Model            string `json:"model,omitempty"`
}

// Inspect reads the current provider status.
func Inspect(path string) Status {
	st := Status{Path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		return st
	}
	st.Exists = true
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	inBridge := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if tableHeader.MatchString(trimmed) {
			inBridge = trimmed == "[model_providers."+ProviderID+"]"
			if inBridge {
				st.BridgeConfigured = true
			}
			continue
		}
		key, value := parseKey(line)
		if key == "" {
			continue
		}
		value = strings.Trim(value, "\"'")
		if inBridge && key == "base_url" {
			st.BaseURL = httpx.Redact(value)
		}
	}
	// Top-level keys only.
	for _, line := range lines {
		if tableHeader.MatchString(strings.TrimSpace(line)) {
			break
		}
		key, value := parseKey(line)
		switch key {
		case "model_provider":
			st.ActiveProvider = strings.Trim(value, "\"'")
		case "model":
			st.Model = strings.Trim(value, "\"'")
		}
	}
	st.BridgeActive = st.ActiveProvider == ProviderID && st.BridgeConfigured
	return st
}

func parseKey(line string) (string, string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
		return "", ""
	}
	key, value, ok := strings.Cut(trimmed, "=")
	if !ok {
		return "", ""
	}
	return strings.TrimSpace(key), strings.TrimSpace(value)
}

func removeTable(lines []string, name string) []string {
	out := make([]string, 0, len(lines))
	skipping := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if tableHeader.MatchString(trimmed) {
			skipping = trimmed == "["+name+"]"
			if skipping {
				continue
			}
		}
		if skipping {
			continue
		}
		out = append(out, line)
	}
	// Drop trailing blank lines left behind.
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}

func setTopLevel(lines []string, key, value string) []string {
	firstTable := len(lines)
	for i, line := range lines {
		if tableHeader.MatchString(strings.TrimSpace(line)) {
			firstTable = i
			break
		}
	}
	for i := 0; i < firstTable; i++ {
		if k, _ := parseKey(lines[i]); k == key {
			lines[i] = key + " = " + value
			return lines
		}
	}
	insert := key + " = " + value
	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:firstTable]...)
	if firstTable > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
		out = append(out, insert)
	} else if firstTable > 0 {
		out = append(out[:len(out)-1], insert, "")
	} else {
		out = append(out, insert, "")
	}
	out = append(out, lines[firstTable:]...)
	return out
}
