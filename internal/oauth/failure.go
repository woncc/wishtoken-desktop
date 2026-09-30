package oauth

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/xxx-holic/wishtoken-desktop/internal/httpx"
)

func safeOAuthCode(code string) string {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 48 || strings.ContainsAny(code, " \t\r\n\"'\\/") {
		return ""
	}
	for _, r := range code {
		if r > 127 || !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return ""
		}
	}
	if httpx.SanitizeFailure(code) != code {
		return ""
	}
	return code
}

func limitFailure(s string, n int) string {
	if s == "" || n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	i := 0
	for idx := range s {
		if i == n {
			return s[:idx] + "..."
		}
		i++
	}
	return s
}

func formSecrets(form url.Values) []string {
	var out []string
	for _, key := range []string{"refresh_token", "code", "code_verifier"} {
		if v := strings.TrimSpace(form.Get(key)); len(v) >= 8 {
			out = append(out, v)
		}
	}
	return out
}

func usageFailureDetail(body string, secrets ...string) string {
	body = strings.TrimSpace(body)
	if body == "" || !json.Valid([]byte(body)) {
		return ""
	}
	var payload map[string]any
	if json.Unmarshal([]byte(body), &payload) != nil {
		return ""
	}
	var parts []string
	addCode := func(v any) {
		if c := safeOAuthCode(asString(v)); c != "" {
			parts = addUnique(parts, c)
		}
	}
	addText := func(v any) {
		s := httpx.SanitizeFailure(asString(v), secrets...)
		if s != "" {
			parts = addUnique(parts, s)
		}
	}
	switch errObj := payload["error"].(type) {
	case string:
		if c := safeOAuthCode(errObj); c != "" {
			parts = addUnique(parts, c)
		} else {
			addText(errObj)
		}
	case map[string]any:
		addCode(errObj["code"])
		addCode(errObj["type"])
		addText(errObj["message"])
	}
	addCode(payload["code"])
	addCode(payload["type"])
	addText(payload["message"])
	switch detail := payload["detail"].(type) {
	case string:
		if c := safeOAuthCode(detail); c != "" && !strings.Contains(detail, " ") {
			parts = addUnique(parts, c)
		} else {
			addText(detail)
		}
	case map[string]any:
		addCode(detail["code"])
		addText(detail["message"])
	}
	if len(parts) > 4 {
		parts = parts[:4]
	}
	return limitFailure(httpx.SanitizeFailure(strings.Join(parts, ": "), secrets...), 160)
}

func asString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func addUnique(parts []string, s string) []string {
	for _, existing := range parts {
		if existing == s {
			return parts
		}
	}
	return append(parts, s)
}
