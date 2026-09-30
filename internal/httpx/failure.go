package httpx

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	jwtPattern      = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	bearerPattern   = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*`)
	prefixedPattern = regexp.MustCompile(`(?i)(?:sk-(?:proj-)?|rk-|rt_|github_pat_|gh[pousr]_)[A-Za-z0-9_-]{8,}`)
	opaquePattern   = regexp.MustCompile(`[A-Za-z0-9_+/=\-]{32,}`)
)

// SanitizeFailure removes credential-shaped material from an operator-facing
// failure string. Ordinary sentences and error codes stay. Known secrets are
// removed even when they are too short for the generic patterns, including
// their query-escaped form.
func SanitizeFailure(detail string, secrets ...string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if len(secret) < 8 {
			continue
		}
		detail = strings.ReplaceAll(detail, secret, "[redacted]")
		if esc := url.QueryEscape(secret); esc != secret {
			detail = strings.ReplaceAll(detail, esc, "[redacted]")
		}
	}
	detail = jwtPattern.ReplaceAllString(detail, "[redacted]")
	detail = bearerPattern.ReplaceAllString(detail, "[redacted]")
	detail = prefixedPattern.ReplaceAllString(detail, "[redacted]")
	detail = opaquePattern.ReplaceAllStringFunc(detail, func(run string) string {
		if opaqueCredential(run) {
			return "[redacted]"
		}
		return run
	})
	detail = strings.Join(strings.Fields(detail), " ")
	for strings.Contains(detail, "[redacted] [redacted]") {
		detail = strings.ReplaceAll(detail, "[redacted] [redacted]", "[redacted]")
	}
	if !failureTextRemains(detail) {
		return ""
	}
	return detail
}

func opaqueCredential(run string) bool {
	var upper, lower, digit bool
	for _, r := range run {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	if !upper || !lower || !digit {
		return false
	}
	// Long snake_case reasons are operator text, not tokens.
	if strings.Count(run, "_") >= 2 && !strings.ContainsAny(run, "+/=") {
		return false
	}
	return true
}

func failureTextRemains(detail string) bool {
	stripped := strings.ReplaceAll(detail, "[redacted]", "")
	stripped = strings.Trim(stripped, " \t()[]{}:;,./*-_\"'")
	return stripped != ""
}
