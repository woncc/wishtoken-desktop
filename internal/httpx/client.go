// Package httpx builds outbound HTTP clients with optional proxies.
package httpx

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Options tunes a client.
type Options struct {
	// ProxyURL routes traffic through http://, https:// or socks5:// proxies.
	// Empty means the standard HTTPS_PROXY / NO_PROXY environment applies.
	ProxyURL string
	// ResponseHeaderTimeout bounds the wait for response headers. Zero means
	// unbounded, which streaming reasoning responses require.
	ResponseHeaderTimeout time.Duration
	// Timeout is the whole-request timeout (zero for streaming clients).
	Timeout time.Duration
}

var (
	cacheMu sync.Mutex
	cache   = map[string]*http.Client{}
)

// NewClient returns a client honouring opts. Clients are cached per option
// set so connection pools are reused.
func NewClient(opts Options) (*http.Client, error) {
	key := fmt.Sprintf("%s|%d|%d", opts.ProxyURL, opts.ResponseHeaderTimeout, opts.Timeout)
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if c, ok := cache[key]; ok {
		return c, nil
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
	if raw := strings.TrimSpace(opts.ProxyURL); raw != "" {
		parsed, err := ParseProxyURL(raw)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	c := &http.Client{Transport: transport, Timeout: opts.Timeout}
	cache[key] = c
	return c, nil
}

// ParseProxyURL validates a proxy URL. socks5h is mapped to socks5, which the
// Go transport resolves remotely as well.
func ParseProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid proxy url")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5":
	case "socks5h":
		parsed.Scheme = "socks5"
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https or socks5)", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("proxy url has no host")
	}
	return parsed, nil
}

// Redact hides credentials embedded in a proxy URL for logging and management
// responses. A schemeless user:password@host value is recognized too.
// A space or bad percent escape makes url.Parse fail; those passwords are
// scrubbed instead of returned unchanged. A fullwidth or small commercial at,
// and a percent-encoded at-sign, still ends a password when url.Parse never
// sees a userinfo separator.
func Redact(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	redacted, _ := redactParsed(raw)
	if next, ok := maskHiddenProxyPasswords(redacted); ok {
		return next
	}
	return redacted
}

func redactParsed(raw string) (string, bool) {
	candidate := raw
	restore := ""
	if !strings.Contains(raw, "://") {
		if strings.HasPrefix(raw, "//") {
			// Prepending "http://" would produce "http:////user..." and hide userinfo.
			candidate = "http:" + raw
			restore = "//"
		} else {
			candidate = "http://" + raw
			restore = "schemeless"
		}
	}
	parsed, err := url.Parse(candidate)
	if err == nil && parsed.User != nil {
		// A percent-encoded colon is decoded into the username, so Password()
		// stays empty while the secret is still visible.
		if _, ok := parsed.User.Password(); !ok {
			if name, secret, found := splitEncodedPassword(parsed.User.Username()); found {
				parsed.User = url.UserPassword(name, secret)
			}
		}
		if pass, ok := parsed.User.Password(); ok {
			redacted := maskProxyPassword(parsed.Redacted(), pass)
			switch restore {
			case "schemeless":
				redacted = strings.TrimPrefix(redacted, "http://")
			case "//":
				redacted = "//" + strings.TrimPrefix(redacted, "http://")
			}
			return redacted, true
		}
	}
	if scrubbed, ok := scrubProxyUserinfo(raw); ok {
		return scrubbed, true
	}
	return raw, false
}

// splitEncodedPassword finds a colon hidden by one or more layers of percent
// encoding, including a compatibility colon or another colon lookalike.
// The decoded username and password are returned separately.
func splitEncodedPassword(userinfo string) (string, string, bool) {
	decoded := userinfo
	for i := 0; i < 4; i++ {
		next := lenientUnescape(decoded)
		if next == decoded {
			break
		}
		decoded = next
	}
	name, secret, found := strings.Cut(foldUserinfoColons(decoded), ":")
	if !found || secret == "" {
		return "", "", false
	}
	return name, secret, true
}

// foldUserinfoColons maps colon characters that can conceal a proxy password.
// NFKC folds the three compatibility colons to ASCII ':'. Superscript
// triangular colons fold to the modifier colons, and double colon equal
// expands to '::='. The remaining lookalikes do not fold at all, including
// cuneiform colon punctuation and the SignWriting colon. A vertical
// two-dot leader NFKC-folds to ".." rather than ':', and runic multiple
// punctuation, Samaritan afsaaq, Manichaean two dots, the Khojki word
// separator, and Lisu mya jeu do not fold to ':'. Visarga signs, including
// Bengali visarga and the marks confusable with it, do not fold to ':'
// either. Ethiopic short rikrik, musical repeat dots, and Tolong Siki
// sela are the same kind of unmapped sign. Proportion and squared
// four-dot punctuation are confusable with "::" and do not fold to ':'.
// Mongolian full stop and Manchu full stop are skeletoned as colons too;
// the public-path check keeps them as dots so a private extension still matches.
// url.Parse rejects every one of them as invalid userinfo, so an unlisted
// character would otherwise be returned with its password intact. The Go
// core has no Unicode normalization dependency, so each one is listed.
func foldUserinfoColons(s string) string {
	const lookalikes = "\ufe13\ufe55\uff1a\u2236\u02d0\u02d1\U00010781\U00010782\ua789\u02f8\u0703\u0704\u0705\u0706\u0707\u0708\u0709\u0589\u05c3\u1361\u1365\u1366\u205a\u205d\u1804\ua6f4\u2a74\u2254\u2255\u2982\u2af6\U00012471\U00012472\U00012473\U00012474\U0001DA8A\ufe30\u16ec\u0831\U00010af5\U0001123a\ua4fd\u0903\u0a83\U00011002\U00011082\U00011182\U000115BE\U000116AC\U00011838\u0983\u0a03\u0c03\u0c83\u0d03\u0d83\u0f7f\u1038\u17c7\U00011303\U000114C1\U000119DF\U00011A39\U00011C3E\u1393\U0001D108\U00011DD9\u2237\u2e2c\u1803\u1809"
	if !strings.ContainsAny(s, lookalikes) {
		return s
	}
	return strings.NewReplacer(
		"\ufe13", ":",
		"\ufe55", ":",
		"\uff1a", ":",
		"\u2236", ":",
		"\u02d0", ":",
		"\u02d1", ":",
		"\U00010781", ":",
		"\U00010782", ":",
		"\ua789", ":",
		"\u02f8", ":",
		"\u0703", ":",
		"\u0704", ":",
		"\u0705", ":",
		"\u0706", ":",
		"\u0707", ":",
		"\u0708", ":",
		"\u0709", ":",
		"\u0589", ":",
		"\u05c3", ":",
		"\u1361", ":",
		"\u1365", ":",
		"\u1366", ":",
		"\u205a", ":",
		"\u1804", ":",
		"\ua6f4", ":",
		"\u2a74", ":",
		"\u205d", ":",
		"\u2254", ":",
		"\u2255", ":",
		"\u2982", ":",
		"\u2af6", ":",
		"\U00012471", ":",
		"\U00012472", ":",
		"\U00012473", ":",
		"\U00012474", ":",
		"\U0001DA8A", ":",
		"\ufe30", ":",
		"\u16ec", ":",
		"\u0831", ":",
		"\U00010af5", ":",
		"\U0001123a", ":",
		"\ua4fd", ":",
		"\u0903", ":",
		"\u0a83", ":",
		"\U00011002", ":",
		"\U00011082", ":",
		"\U00011182", ":",
		"\U000115BE", ":",
		"\U000116AC", ":",
		"\U00011838", ":",
		"\u0983", ":",
		"\u0a03", ":",
		"\u0c03", ":",
		"\u0c83", ":",
		"\u0d03", ":",
		"\u0d83", ":",
		"\u0f7f", ":",
		"\u1038", ":",
		"\u17c7", ":",
		"\U00011303", ":",
		"\U000114C1", ":",
		"\U000119DF", ":",
		"\U00011A39", ":",
		"\U00011C3E", ":",
		"\u1393", ":",
		"\U0001D108", ":",
		"\U00011DD9", ":",
		"\u2237", ":",
		"\u2e2c", ":",
		"\u1803", ":",
		"\u1809", ":",
	).Replace(s)
}

func lenientUnescape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func maskProxyPassword(redacted, password string) string {
	if len(password) < 8 {
		return redacted
	}
	// url.URL.Redacted keeps RawQuery and RawFragment. A password hidden there
	// by one or more layers of percent-encoding must not survive either.
	redacted = MaskEncodedSecret(redacted, password, "xxxxx")
	if esc := url.QueryEscape(password); esc != password {
		redacted = strings.ReplaceAll(redacted, esc, "xxxxx")
	}
	return redacted
}

// MaskEncodedSecret replaces secret even when some or all of its bytes are
// percent-encoded, including nested escapes such as %2573 for 's'. Marks that
// do not add a base letter are ignored while matching, and the surrounding
// text is not reformatted.
func MaskEncodedSecret(s, secret, repl string) string {
	if secret == "" || s == "" || repl == "" {
		return s
	}
	pieces := rawPieces(s)
	var spans [][2]int
	for layer := 0; layer < 5; layer++ {
		spans = append(spans, findSecretSpans(pieces, secret)...)
		next := decodePieces(pieces)
		if len(next) == len(pieces) {
			break
		}
		pieces = next
	}
	return applySecretSpans(s, spans, repl)
}

func renderPieces(pieces []secretPiece) string {
	var text strings.Builder
	text.Grow(len(pieces))
	for _, piece := range pieces {
		text.WriteByte(piece.b)
	}
	return text.String()
}

type secretPiece struct {
	b     byte
	start int
	end   int
}

func rawPieces(s string) []secretPiece {
	out := make([]secretPiece, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = secretPiece{b: s[i], start: i, end: i + 1}
	}
	return out
}

func decodePieces(in []secretPiece) []secretPiece {
	out := make([]secretPiece, 0, len(in))
	for i := 0; i < len(in); {
		if in[i].b == '%' && i+2 < len(in) && isHex(in[i+1].b) && isHex(in[i+2].b) {
			v, err := strconv.ParseUint(string([]byte{in[i+1].b, in[i+2].b}), 16, 8)
			if err == nil {
				out = append(out, secretPiece{b: byte(v), start: in[i].start, end: in[i+2].end})
				i += 3
				continue
			}
		}
		out = append(out, in[i])
		i++
	}
	return out
}

func findSecretSpans(pieces []secretPiece, secret string) [][2]int {
	// A hyphen lookalike is not ignorable: dropping it would glue the token
	// together and miss the stored ASCII hyphen. Fold first, then drop marks.
	needle := foldHyphenString(secret)
	folded := foldHyphenPieces(pieces)
	spans := exactSecretSpans(folded, needle)
	// Soft hyphen is a format character, so the drop pass below removes it.
	// That joins a hyphenated token and misses the stored '-'. Folding it to
	// '-' is a separate reading; the drop reading still runs.
	if soft, ok := foldSoftHyphenPieces(folded); ok {
		spans = append(spans, exactSecretSpans(soft, foldSoftHyphenString(needle))...)
	}
	dropped := dropMarkPieces(folded)
	if len(dropped) != len(folded) {
		spans = append(spans, exactSecretSpans(dropped, needle)...)
	}
	return spans
}

func exactSecretSpans(pieces []secretPiece, secret string) [][2]int {
	if len(secret) == 0 || len(pieces) < len(secret) {
		return nil
	}
	rendered := renderPieces(pieces)
	var spans [][2]int
	from := 0
	for {
		i := strings.Index(rendered[from:], secret)
		if i < 0 {
			return spans
		}
		i += from
		spans = append(spans, [2]int{pieces[i].start, pieces[i+len(secret)-1].end})
		from = i + len(secret)
	}
}

// foldHyphenPieces maps hyphen confusables to ASCII '-'. None of these
// NFKC-fold to hyphen-minus. Non-breaking hyphen folds to U+2010, and small
// em dash folds to an em dash, so both have to be listed. The em dash and
// the horizontal bar do not fold. Vertical em dash folds to an em dash, and
// this pass does not run NFKC, so that form is listed too. Script hyphens,
// including maqaf and the Yezidi hyphenation mark, do not fold either.
// Arabic full stop
// stays a dot elsewhere in this codebase and is not a hyphen here. Spacing
// marks that skeleton to a hyphen are folded before dropMarkPieces, or the
// stored hyphen would disappear and the token would no longer match. One
// output piece covers the original rune so the redaction span stays on the
// caller's bytes.
func foldHyphenPieces(in []secretPiece) []secretPiece {
	if len(in) == 0 {
		return in
	}
	buf := renderPieces(in)
	out := make([]secretPiece, 0, len(in))
	changed := false
	for i := 0; i < len(in); {
		r, size := utf8.DecodeRuneInString(buf[i:])
		if size <= 0 {
			break
		}
		if hyphenLike(r) {
			out = append(out, secretPiece{b: '-', start: in[i].start, end: in[i+size-1].end})
			changed = true
			i += size
			continue
		}
		out = append(out, in[i:i+size]...)
		i += size
	}
	if !changed {
		return in
	}
	return out
}

func foldHyphenString(s string) string {
	if !hyphenFolded(s) {
		return s
	}
	return renderPieces(foldHyphenPieces(rawPieces(s)))
}

func hyphenFolded(s string) bool {
	for _, r := range s {
		if hyphenLike(r) {
			return true
		}
	}
	return false
}

func foldSoftHyphenPieces(in []secretPiece) ([]secretPiece, bool) {
	if len(in) == 0 {
		return in, false
	}
	buf := renderPieces(in)
	out := make([]secretPiece, 0, len(in))
	changed := false
	for i := 0; i < len(in); {
		r, size := utf8.DecodeRuneInString(buf[i:])
		if size <= 0 {
			break
		}
		if r == '\u00ad' {
			out = append(out, secretPiece{b: '-', start: in[i].start, end: in[i+size-1].end})
			changed = true
			i += size
			continue
		}
		out = append(out, in[i:i+size]...)
		i += size
	}
	if !changed {
		return in, false
	}
	return out, true
}

func foldSoftHyphenString(s string) string {
	if !strings.ContainsRune(s, '\u00ad') {
		return s
	}
	folded, _ := foldSoftHyphenPieces(rawPieces(s))
	return renderPieces(folded)
}

func hyphenLike(r rune) bool {
	switch r {
	case '\u2010', '\u2011', '\u2012', '\u2013', '\ufe58',
		'\u2014', '\u2015', '\ufe31',
		'\u058a', '\u05be', '\u1400', '\u1806',
		'\u2e17', '\u2e1a', '\u2e40', '\u2e5d', '\u30a0', '\U00010ead',
		'\u2043', '\u02d7', '\u2212', '\u2796', '\U00010191',
		'\u2cba', '\u2cbb', '\u174d', '\u1bf3', '\uaa7d':
		return true
	default:
		return false
	}
}

// dropMarkPieces removes characters that do not add a base letter: variation
// selectors, nonspacing and enclosing marks, spacing combining marks such as
// vowel signs and Hangul tone marks, format characters such as zero-width
// spaces, controls other than ordinary spacing, blank fillers,
// and Unicode spaces other than ASCII space. Hangul fillers and the braille
// blank pattern have no ink. U+3164 and U+FFA0 fold to U+1160 under NFKC and
// stay letters, so a category check never drops them. Ogham space is a real
// space separator that does not NFKC-fold. Tab, newline, carriage return, and
// ASCII space still separate operator text. The original byte range of a match
// still covers a dropped character that was sitting inside the secret.
func dropMarkPieces(in []secretPiece) []secretPiece {
	if len(in) == 0 {
		return in
	}
	buf := renderPieces(in)
	out := make([]secretPiece, 0, len(in))
	for i := 0; i < len(in); {
		r, size := utf8.DecodeRuneInString(buf[i:])
		if size <= 0 {
			break
		}
		if ignorableCredentialRune(r) {
			i += size
			continue
		}
		out = append(out, in[i:i+size]...)
		i += size
	}
	return out
}

func ignorableCredentialRune(r rune) bool {
	if r == utf8.RuneError {
		return false
	}
	// Spacing combining marks sit beside a letter without becoming one.
	// Visarga is also a colon lookalike, but proxy redaction folds that shape
	// before this pass. Left in place, a vowel sign hides the token.
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Cf, r) {
		return true
	}
	if unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
		return true
	}
	// ASCII space still separates words. The other space separators, including
	// Ogham space which does not NFKC-fold, have to come out before a token is
	// matched or they hide the secret.
	if r != ' ' && unicode.Is(unicode.Zs, r) {
		return true
	}
	if unicode.Is(unicode.Cc, r) && !unicode.IsSpace(r) {
		return true
	}
	switch r {
	case '\u115f', '\u1160', '\u3164', '\uffa0', '\u2800':
		return true
	default:
		return false
	}
}

func applySecretSpans(s string, spans [][2]int, repl string) string {
	if len(spans) == 0 {
		return s
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i][0] == spans[j][0] {
			return spans[i][1] > spans[j][1]
		}
		return spans[i][0] < spans[j][0]
	})
	merged := [][2]int{spans[0]}
	for _, span := range spans[1:] {
		last := &merged[len(merged)-1]
		if span[0] >= last[1] {
			merged = append(merged, span)
			continue
		}
		if span[1] > last[1] {
			last[1] = span[1]
		}
	}
	for i := len(merged) - 1; i >= 0; i-- {
		start, end := merged[i][0], merged[i][1]
		if start < 0 || end > len(s) || start >= end {
			continue
		}
		s = s[:start] + repl + s[end:]
	}
	return s
}

// scrubProxyUserinfo replaces a password in user:password@host when url.Parse
// rejects the string. Username-only values are left unchanged.
func scrubProxyUserinfo(raw string) (string, bool) {
	at := strings.LastIndex(raw, "@")
	if at <= 0 {
		return "", false
	}
	head, tail := raw[:at], raw[at:]
	prefix, userinfo := "", head
	if i := strings.Index(head, "://"); i >= 0 {
		prefix = head[:i+3]
		userinfo = head[i+3:]
	} else if strings.HasPrefix(head, "//") {
		prefix = "//"
		userinfo = head[2:]
	}
	name, secret, found := splitEncodedPassword(userinfo)
	if !found {
		return "", false
	}
	return maskProxyPassword(prefix+name+":xxxxx"+tail, secret), true
}

// PreserveProxy returns current when incoming is empty of changes or is only
// the redacted form of current. Callers can show Redact(current) in an editor
// and accept it back without storing the mask as the password.
func PreserveProxy(current, incoming string) string {
	incoming = strings.TrimSpace(incoming)
	current = strings.TrimSpace(current)
	if incoming == "" || current == "" {
		return incoming
	}
	if incoming == current || incoming == Redact(current) {
		return current
	}
	return incoming
}
