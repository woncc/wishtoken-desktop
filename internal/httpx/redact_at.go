package httpx

import (
	"sort"
	"strings"
	"unicode/utf8"
)

type hiddenPW struct {
	start  int
	end    int
	secret string
}

// maskHiddenProxyPasswords redacts a password whose terminator is not an ASCII
// at-sign. url.Parse and scrubProxyUserinfo only split on '@', so U+FE6B,
// U+FF20, and nested percent-encoding of those marks would otherwise keep the
// secret. An ASCII at-sign is left to redactParsed.
func maskHiddenProxyPasswords(raw string) (string, bool) {
	var found []hiddenPW
	for i := 0; i < len(raw); {
		n, ok := hiddenAtSpan(raw[i:])
		if !ok {
			i++
			continue
		}
		if start, end, ok := hiddenPasswordSpan(raw, i); ok {
			found = append(found, hiddenPW{start: start, end: end, secret: raw[start:end]})
		}
		i += n
	}
	found = maximalPasswords(found)
	if len(found) == 0 {
		return "", false
	}
	spans := make([][2]int, len(found))
	for i, item := range found {
		spans[i] = [2]int{item.start, item.end}
	}
	out := applySecretSpans(raw, spans, "xxxxx")
	secrets := make([]string, len(found))
	for i, item := range found {
		secrets[i] = item.secret
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, secret := range secrets {
		if len(secret) < 8 {
			continue
		}
		out = maskEncodedSecret(out, secret, "xxxxx")
	}
	if out == raw {
		return "", false
	}
	return out, true
}

func maximalPasswords(in []hiddenPW) []hiddenPW {
	kept := make([]hiddenPW, 0, len(in))
	for i, span := range in {
		covered := false
		for j, other := range in {
			if i == j {
				continue
			}
			if other.start <= span.start && other.end >= span.end && (other.start < span.start || other.end > span.end) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, span)
		}
	}
	return kept
}

func hiddenPasswordSpan(raw string, atStart int) (int, int, bool) {
	head := raw[:atStart]
	searchFrom := 0
	if i := strings.LastIndex(head, "://"); i >= 0 {
		searchFrom = i + 3
	}
	rest := head[searchFrom:]
	pwStart := -1
	for i := 0; i < len(rest); {
		n, ok := separatorSpan(rest[i:], isColonSeparator)
		if !ok {
			i++
			continue
		}
		abs := searchFrom + i
		absEnd := abs + n
		if usernameBefore(head, abs) && !strings.Contains(raw[absEnd:atStart], "@") && strings.TrimSpace(raw[absEnd:atStart]) != "" {
			pwStart = absEnd
		}
		i += n
	}
	if pwStart < 0 {
		return 0, 0, false
	}
	return pwStart, atStart, true
}

func usernameBefore(s string, colonStart int) bool {
	if colonStart <= 0 || colonStart > len(s) {
		return false
	}
	j := colonStart
	for j > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:j])
		if size <= 0 || !isUserRune(r) {
			break
		}
		j -= size
	}
	if j == colonStart {
		return false
	}
	if j == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:j])
	return !isColonSeparator(r) && r != '@' && !isHiddenAt(r)
}

func isUserRune(r rune) bool {
	switch r {
	case utf8.RuneError, '@', '/', '?', '#', ' ', '\t', '\n', '\r':
		return false
	}
	return !isColonSeparator(r) && !isHiddenAt(r)
}

func isColonSeparator(r rune) bool {
	switch r {
	case ':', '\ufe13', '\ufe55', '\uff1a', '\u2236', '\u02d0', '\u02d1', '\ua789', '\u02f8',
		'\u0703', '\u0704', '\u0705', '\u0706', '\u0707', '\u0708', '\u0709',
		'\u0589', '\u05c3', '\u1361', '\u1365', '\u1366', '\u205a',
		'\u1804', '\ua6f4':
		return true
	default:
		return false
	}
}

func isHiddenAt(r rune) bool {
	return r == '\ufe6b' || r == '\uff20'
}

func hiddenAtSpan(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	r, size := utf8.DecodeRuneInString(s)
	if isHiddenAt(r) {
		return size, true
	}
	return encodedSeparatorSpan(s, func(r rune) bool { return r == '@' || isHiddenAt(r) })
}

func separatorSpan(s string, match func(rune) bool) (int, bool) {
	if s == "" {
		return 0, false
	}
	r, size := utf8.DecodeRuneInString(s)
	if match(r) {
		return size, true
	}
	return encodedSeparatorSpan(s, match)
}

func encodedSeparatorSpan(s string, match func(rune) bool) (int, bool) {
	if s == "" || s[0] != '%' {
		return 0, false
	}
	max := 0
	for max < len(s) && max < 48 && (s[max] == '%' || isHex(s[max])) {
		max++
	}
	for end := 3; end <= max; end++ {
		if decodesToSeparator(s[:end], match) {
			return end, true
		}
	}
	return 0, false
}

func decodesToSeparator(s string, match func(rune) bool) bool {
	cur := s
	for layer := 0; layer < 4; layer++ {
		next := lenientUnescape(cur)
		if next == cur {
			return false
		}
		cur = next
		r, size := utf8.DecodeRuneInString(cur)
		if size == len(cur) && match(r) {
			return true
		}
	}
	return false
}
