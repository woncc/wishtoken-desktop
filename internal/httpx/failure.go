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
// their query-escaped and percent-encoded forms. Generic token shapes are
// checked again after percent-decoding, so a double-encoded callback value
// does not survive query parsing.
func SanitizeFailure(detail string, secrets ...string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	// Proxy userinfo is not a token shape. Mask it before the generic patterns,
	// including colon lookalikes that url.Parse otherwise rejects.
	detail = Redact(detail)
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if len(secret) < 8 {
			continue
		}
		detail = maskEncodedSecret(detail, secret, "[redacted]")
		if esc := url.QueryEscape(secret); esc != secret {
			detail = strings.ReplaceAll(detail, esc, "[redacted]")
		}
	}
	detail = maskCredentialPatterns(detail)
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

func maskCredentialPatterns(detail string) string {
	pieces := rawPieces(detail)
	var spans [][2]int
	for layer := 0; layer < 5; layer++ {
		spans = append(spans, credentialPatternSpans(renderPieces(pieces), pieces)...)
		if dropped := dropMarkPieces(pieces); len(dropped) != len(pieces) {
			spans = append(spans, credentialPatternSpans(renderPieces(dropped), dropped)...)
		}
		next := decodePieces(pieces)
		if len(next) == len(pieces) {
			break
		}
		pieces = next
	}
	return applySecretSpans(detail, spans, "[redacted]")
}

func credentialPatternSpans(rendered string, pieces []secretPiece) [][2]int {
	if rendered == "" || len(pieces) != len(rendered) {
		return nil
	}
	var spans [][2]int
	add := func(start, end int) {
		if start < 0 || end > len(pieces) || start >= end {
			return
		}
		spans = append(spans, [2]int{pieces[start].start, pieces[end-1].end})
	}
	for _, pattern := range []*regexp.Regexp{jwtPattern, bearerPattern, prefixedPattern} {
		for _, loc := range pattern.FindAllStringIndex(rendered, -1) {
			add(loc[0], loc[1])
		}
	}
	for _, loc := range opaquePattern.FindAllStringIndex(rendered, -1) {
		if opaqueCredential(rendered[loc[0]:loc[1]]) {
			add(loc[0], loc[1])
		}
	}
	return spans
}
