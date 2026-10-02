package httpx

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	jwtPattern    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	bearerPattern = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*`)
	// Used only after Unicode spaces have been removed. The ordinary bearer
	// pattern still requires a real space, so "BearerAuth" is left alone.
	bearerGluedPattern = regexp.MustCompile(`(?i)\bbearer[A-Za-z0-9._~+/-]+=*`)
	prefixedPattern    = regexp.MustCompile(`(?i)(?:sk-(?:proj-)?|rk-|rt_|github_pat_|gh[pousr]_)[A-Za-z0-9_-]{8,}`)
	opaquePattern      = regexp.MustCompile(`[A-Za-z0-9_+/=\-]{32,}`)
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
		detail = MaskEncodedSecret(detail, secret, "[redacted]")
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
		// Fold hyphen lookalikes before the ASCII token classes run, and
		// before marks are dropped. A non-breaking hyphen is not itself a
		// mark, but a spacing mark shaped like one has to become '-' first.
		folded := foldHyphenPieces(pieces)
		spans = append(spans, credentialPatternSpans(renderPieces(folded), folded)...)
		if dropped := dropMarkPieces(folded); len(dropped) != len(folded) {
			rendered := renderPieces(dropped)
			spans = append(spans, credentialPatternSpans(rendered, dropped)...)
			spans = append(spans, gluedBearerSpans(rendered, dropped)...)
		}
		next := decodePieces(pieces)
		if len(next) == len(pieces) {
			break
		}
		pieces = next
	}
	return applySecretSpans(detail, spans, "[redacted]")
}

func gluedBearerSpans(rendered string, pieces []secretPiece) [][2]int {
	if rendered == "" || len(pieces) != len(rendered) {
		return nil
	}
	var spans [][2]int
	for _, loc := range bearerGluedPattern.FindAllStringIndex(rendered, -1) {
		if loc[0] < 0 || loc[1] > len(pieces) || loc[0]+6 >= loc[1] {
			continue
		}
		// "BearerAuth" plus a later dropped space must not count. A space or
		// mark has to have been removed immediately after the word bearer.
		if pieces[loc[0]+5].end == pieces[loc[0]+6].start {
			continue
		}
		spans = append(spans, [2]int{pieces[loc[0]].start, pieces[loc[1]-1].end})
	}
	return spans
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
