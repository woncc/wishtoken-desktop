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
	// Fold only percent signs and hex digits. A full credential fold would
	// turn a Mongolian full stop into '.', and the colon split below would
	// miss the password. The result is only used to find a hidden colon.
	folded := foldEscapeString(s)
	var b strings.Builder
	b.Grow(len(folded))
	for i := 0; i < len(folded); {
		if folded[i] == '%' && i+2 < len(folded) && isHex(folded[i+1]) && isHex(folded[i+2]) {
			v, err := strconv.ParseUint(folded[i+1:i+3], 16, 8)
			if err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(folded[i])
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
		// Decode the folded bytes. A small or fullwidth percent, and hex
		// digits written with compatibility characters, still open the next
		// layer. Spans keep the original indexes, so the surrounding text
		// is not rewritten.
		folded := foldCredentialPieces(pieces)
		next := decodePieces(folded)
		if len(next) == len(folded) {
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
	// A hyphen or full stop is not ignorable: dropping it would glue the
	// token together and miss the stored ASCII byte. Fold the credential
	// alphabet, including a compatibility percent sign, before matching.
	// Then drop marks. Spacing marks shaped like full stops keep both readings.
	needle := foldCredentialString(secret)
	folded := foldCredentialPieces(pieces)
	spans := exactSecretSpans(folded, needle)
	// Soft hyphen is a format character, so the drop pass below removes it.
	// That joins a hyphenated token and misses the stored '-'. Folding it to
	// '-' is a separate reading; the drop reading still runs.
	if soft, ok := foldSoftHyphenPieces(folded); ok {
		spans = append(spans, exactSecretSpans(soft, foldSoftHyphenString(needle))...)
	}
	if spacing, ok := foldSpacingStopPieces(folded); ok {
		needleStop := foldSpacingStopString(needle)
		spans = append(spans, exactSecretSpans(spacing, needleStop)...)
		if droppedStops := dropMarkPieces(spacing); len(droppedStops) != len(spacing) {
			spans = append(spans, exactSecretSpans(droppedStops, needleStop)...)
		}
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

// foldHyphenPieces maps hyphen confusables to ASCII '-'. Most of these do
// not NFKC-fold to hyphen-minus. Non-breaking hyphen folds to U+2010, and
// small em dash folds to an em dash, so both have to be listed. The em dash
// and the horizontal bar do not fold. Vertical em dash folds to an em dash,
// and this pass does not run NFKC, so that form is listed too. Superscript
// minus and subscript minus fold to U+2212, vertical en dash folds to an en
// dash, and small hyphen-minus and fullwidth hyphen-minus fold to '-'.
// Those raw forms are listed because this pass does not run NFKC. Script
// hyphens, including maqaf and the Yezidi hyphenation mark, do not fold
// either. Two-em dash, three-em dash, wave dash, and wavy dash do not fold
// either.
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
		'\u2e3a', '\u2e3b', '\u301c', '\u3030',
		'\u207b', '\u208b', '\ufe32', '\ufe63', '\uff0d',
		'\u2043', '\u02d7', '\u2212', '\u2796', '\U00010191',
		'\u2cba', '\u2cbb', '\u174d', '\u1bf3', '\uaa7d':
		return true
	default:
		return false
	}
}

// foldFullwidthPieces maps fullwidth letters and digits to ASCII.
// NFKC folds them, and this pass does not run NFKC, so a stored token or a
// JWT written with those forms would stay visible. Fullwidth punctuation is
// left to the separator folds. One output piece covers the original rune.
func foldFullwidthPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := fullwidthASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldFullwidthString(s string) string {
	if !fullwidthFolded(s) {
		return s
	}
	return renderPieces(foldFullwidthPieces(rawPieces(s)))
}

func fullwidthFolded(s string) bool {
	for _, r := range s {
		if _, ok := fullwidthASCII(r); ok {
			return true
		}
	}
	return false
}

func fullwidthASCII(r rune) (byte, bool) {
	switch {
	case r >= '\uff10' && r <= '\uff19', r >= '\uff21' && r <= '\uff3a', r >= '\uff41' && r <= '\uff5a':
		return byte(r - 0xfee0), true
	default:
		return 0, false
	}
}

// foldMathPieces maps mathematical alphanumeric symbols to ASCII.
// NFKC folds them, and this pass does not run NFKC, so a stored token or a
// JWT written with those forms would stay visible. Greek mathematical
// letters fold to Greek, not ASCII, and stay out. The same alphabets left
// holes for letters that already lived in the letterlike block, including
// Planck's constant for italic h. Those holes, and the few double-struck
// italic letters, are listed here. Kelvin sign and information source also
// fold to one ASCII letter, but they are not mathematical letters, so the
// modifier fold lists them. One output piece covers the original rune.
func foldMathPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := mathASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldMathString(s string) string {
	if !mathFolded(s) {
		return s
	}
	return renderPieces(foldMathPieces(rawPieces(s)))
}

func mathFolded(s string) bool {
	for _, r := range s {
		if _, ok := mathASCII(r); ok {
			return true
		}
	}
	return false
}

func mathASCII(r rune) (byte, bool) {
	switch {
	case r >= 0x1D400 && r <= 0x1D419:
		return byte(r - 0x1D400 + 'A'), true
	case r >= 0x1D41A && r <= 0x1D433:
		return byte(r - 0x1D41A + 'a'), true
	case r >= 0x1D434 && r <= 0x1D44D:
		return byte(r - 0x1D434 + 'A'), true
	case r >= 0x1D44E && r <= 0x1D454:
		return byte(r - 0x1D44E + 'a'), true
	case r >= 0x1D456 && r <= 0x1D467:
		return byte(r - 0x1D456 + 'i'), true
	case r >= 0x1D468 && r <= 0x1D481:
		return byte(r - 0x1D468 + 'A'), true
	case r >= 0x1D482 && r <= 0x1D49B:
		return byte(r - 0x1D482 + 'a'), true
	case r == 0x1D49C:
		return 'A', true
	case r >= 0x1D49E && r <= 0x1D49F:
		return byte(r - 0x1D49E + 'C'), true
	case r == 0x1D4A2:
		return 'G', true
	case r >= 0x1D4A5 && r <= 0x1D4A6:
		return byte(r - 0x1D4A5 + 'J'), true
	case r >= 0x1D4A9 && r <= 0x1D4AC:
		return byte(r - 0x1D4A9 + 'N'), true
	case r >= 0x1D4AE && r <= 0x1D4B5:
		return byte(r - 0x1D4AE + 'S'), true
	case r >= 0x1D4B6 && r <= 0x1D4B9:
		return byte(r - 0x1D4B6 + 'a'), true
	case r == 0x1D4BB:
		return 'f', true
	case r >= 0x1D4BD && r <= 0x1D4C3:
		return byte(r - 0x1D4BD + 'h'), true
	case r >= 0x1D4C5 && r <= 0x1D4CF:
		return byte(r - 0x1D4C5 + 'p'), true
	case r >= 0x1D4D0 && r <= 0x1D4E9:
		return byte(r - 0x1D4D0 + 'A'), true
	case r >= 0x1D4EA && r <= 0x1D503:
		return byte(r - 0x1D4EA + 'a'), true
	case r >= 0x1D504 && r <= 0x1D505:
		return byte(r - 0x1D504 + 'A'), true
	case r >= 0x1D507 && r <= 0x1D50A:
		return byte(r - 0x1D507 + 'D'), true
	case r >= 0x1D50D && r <= 0x1D514:
		return byte(r - 0x1D50D + 'J'), true
	case r >= 0x1D516 && r <= 0x1D51C:
		return byte(r - 0x1D516 + 'S'), true
	case r >= 0x1D51E && r <= 0x1D537:
		return byte(r - 0x1D51E + 'a'), true
	case r >= 0x1D538 && r <= 0x1D539:
		return byte(r - 0x1D538 + 'A'), true
	case r >= 0x1D53B && r <= 0x1D53E:
		return byte(r - 0x1D53B + 'D'), true
	case r >= 0x1D540 && r <= 0x1D544:
		return byte(r - 0x1D540 + 'I'), true
	case r == 0x1D546:
		return 'O', true
	case r >= 0x1D54A && r <= 0x1D550:
		return byte(r - 0x1D54A + 'S'), true
	case r >= 0x1D552 && r <= 0x1D56B:
		return byte(r - 0x1D552 + 'a'), true
	case r >= 0x1D56C && r <= 0x1D585:
		return byte(r - 0x1D56C + 'A'), true
	case r >= 0x1D586 && r <= 0x1D59F:
		return byte(r - 0x1D586 + 'a'), true
	case r >= 0x1D5A0 && r <= 0x1D5B9:
		return byte(r - 0x1D5A0 + 'A'), true
	case r >= 0x1D5BA && r <= 0x1D5D3:
		return byte(r - 0x1D5BA + 'a'), true
	case r >= 0x1D5D4 && r <= 0x1D5ED:
		return byte(r - 0x1D5D4 + 'A'), true
	case r >= 0x1D5EE && r <= 0x1D607:
		return byte(r - 0x1D5EE + 'a'), true
	case r >= 0x1D608 && r <= 0x1D621:
		return byte(r - 0x1D608 + 'A'), true
	case r >= 0x1D622 && r <= 0x1D63B:
		return byte(r - 0x1D622 + 'a'), true
	case r >= 0x1D63C && r <= 0x1D655:
		return byte(r - 0x1D63C + 'A'), true
	case r >= 0x1D656 && r <= 0x1D66F:
		return byte(r - 0x1D656 + 'a'), true
	case r >= 0x1D670 && r <= 0x1D689:
		return byte(r - 0x1D670 + 'A'), true
	case r >= 0x1D68A && r <= 0x1D6A3:
		return byte(r - 0x1D68A + 'a'), true
	case r >= 0x1D7CE && r <= 0x1D7D7:
		return byte(r - 0x1D7CE + '0'), true
	case r >= 0x1D7D8 && r <= 0x1D7E1:
		return byte(r - 0x1D7D8 + '0'), true
	case r >= 0x1D7E2 && r <= 0x1D7EB:
		return byte(r - 0x1D7E2 + '0'), true
	case r >= 0x1D7EC && r <= 0x1D7F5:
		return byte(r - 0x1D7EC + '0'), true
	case r >= 0x1D7F6 && r <= 0x1D7FF:
		return byte(r - 0x1D7F6 + '0'), true
	}
	switch r {
	case 0x2102:
		return 'C', true
	case 0x210A:
		return 'g', true
	case 0x210B:
		return 'H', true
	case 0x210C:
		return 'H', true
	case 0x210D:
		return 'H', true
	case 0x210E:
		return 'h', true
	case 0x2110:
		return 'I', true
	case 0x2111:
		return 'I', true
	case 0x2112:
		return 'L', true
	case 0x2113:
		return 'l', true
	case 0x2115:
		return 'N', true
	case 0x2119:
		return 'P', true
	case 0x211A:
		return 'Q', true
	case 0x211B:
		return 'R', true
	case 0x211C:
		return 'R', true
	case 0x211D:
		return 'R', true
	case 0x2124:
		return 'Z', true
	case 0x2128:
		return 'Z', true
	case 0x212C:
		return 'B', true
	case 0x212D:
		return 'C', true
	case 0x212F:
		return 'e', true
	case 0x2130:
		return 'E', true
	case 0x2131:
		return 'F', true
	case 0x2133:
		return 'M', true
	case 0x2134:
		return 'o', true
	case 0x2145:
		return 'D', true
	case 0x2146:
		return 'd', true
	case 0x2147:
		return 'e', true
	case 0x2148:
		return 'i', true
	case 0x2149:
		return 'j', true
	default:
		return 0, false
	}
}

// foldPercentPieces maps small and fullwidth percent signs to ASCII '%'.
// NFKC folds them, and this pass does not run NFKC, so an escape written
// with those signs would never be decoded. Arabic percent, per mille, and
// the commercial minus sign do not fold to '%', so they stay out. One
// output piece covers the original rune.
func foldPercentPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := percentASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldPercentString(s string) string {
	if !percentFolded(s) {
		return s
	}
	return renderPieces(foldPercentPieces(rawPieces(s)))
}

func percentFolded(s string) bool {
	for _, r := range s {
		if _, ok := percentASCII(r); ok {
			return true
		}
	}
	return false
}

func percentASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE6A, 0xFF05:
		return '%', true
	default:
		return 0, false
	}
}

// foldEscapePieces maps a compatibility percent sign, and compatibility
// hex digits, to ASCII. Other credential folds stay out: a Mongolian full
// stop is a colon to the proxy splitter and a dot to path checks, so this
// pass must not turn it into '.'. One output piece covers the original rune.
func foldEscapePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := escapeASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldEscapeString(s string) string {
	if !escapeFolded(s) {
		return s
	}
	return renderPieces(foldEscapePieces(rawPieces(s)))
}

func escapeFolded(s string) bool {
	for _, r := range s {
		if _, ok := escapeASCII(r); ok {
			return true
		}
	}
	return false
}

func escapeASCII(r rune) (byte, bool) {
	if b, ok := percentASCII(r); ok {
		return b, true
	}
	if b, ok := fullwidthASCII(r); ok && isHex(b) {
		return b, true
	}
	if b, ok := mathASCII(r); ok && isHex(b) {
		return b, true
	}
	if b, ok := longSASCII(r); ok && isHex(b) {
		return b, true
	}
	if b, ok := romanASCII(r); ok && isHex(b) {
		return b, true
	}
	if b, ok := segmentedASCII(r); ok && isHex(b) {
		return b, true
	}
	if b, ok := modifierASCII(r); ok && isHex(b) {
		return b, true
	}
	if b, ok := superSubASCII(r); ok && isHex(b) {
		return b, true
	}
	if b, ok := enclosedASCII(r); ok && isHex(b) {
		return b, true
	}
	return 0, false
}

// foldCredentialPieces maps compatibility letters, digits, and token
// punctuation, including the percent sign and exclamation mark, to ASCII.
// Credential redaction does not run NFKC. The percent fold is part of this
// result because the decode loop consumes it: a compatibility percent or hex
// digit still starts the next escape layer. Marks are not dropped here.
func foldCredentialPieces(in []secretPiece) []secretPiece {
	return foldExclamationPieces(foldPercentPieces(foldDotPieces(foldHyphenPieces(foldFullwidthPieces(foldMathPieces(foldEnclosedPieces(foldSuperSubPieces(foldModifierPieces(foldSegmentedPieces(foldRomanPieces(foldLongSPieces(foldPlusEqualsPieces(foldLowLinePieces(foldSolidusTildePieces(foldParenPieces(in))))))))))))))))
}

func foldCredentialString(s string) string {
	return foldExclamationString(foldPercentString(foldDotString(foldHyphenString(foldFullwidthString(foldMathString(foldEnclosedString(foldSuperSubString(foldModifierString(foldSegmentedString(foldRomanString(foldLongSString(foldPlusEqualsString(foldLowLineString(foldSolidusTildeString(foldParenString(s))))))))))))))))
}

// foldExclamationPieces maps exclamation marks to ASCII '!'.
// NFKC folds them, and this pass does not run NFKC, so a stored secret
// written with those forms would stay visible. A double exclamation mark
// expands to "!!", and an exclamation question mark expands to "!?".
// Inverted exclamation, the retroflex click, and heavy exclamation
// ornaments do not fold to '!', so they stay out. One output piece covers
// the original rune.
func foldExclamationPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := exclamationASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldExclamationString(s string) string {
	if !exclamationFolded(s) {
		return s
	}
	return renderPieces(foldExclamationPieces(rawPieces(s)))
}

func exclamationFolded(s string) bool {
	for _, r := range s {
		if _, ok := exclamationASCII(r); ok {
			return true
		}
	}
	return false
}

func exclamationASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE15, 0xFE57, 0xFF01:
		return '!', true
	default:
		return 0, false
	}
}

// foldParenPieces maps parentheses to ASCII. NFKC folds them, and this
// pass does not run NFKC, so a stored secret written with those forms would
// stay visible. Parenthesized digits and parenthesized hangul expand to more
// than one character. Flattened, white, double, and ornament parentheses do
// not fold to ASCII, so they stay out. One output piece covers the original
// rune.
func foldParenPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := parenASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldParenString(s string) string {
	if !parenFolded(s) {
		return s
	}
	return renderPieces(foldParenPieces(rawPieces(s)))
}

func parenFolded(s string) bool {
	for _, r := range s {
		if _, ok := parenASCII(r); ok {
			return true
		}
	}
	return false
}

func parenASCII(r rune) (byte, bool) {
	switch r {
	case 0x207D, 0x208D, 0xFE35, 0xFE59, 0xFF08:
		return '(', true
	case 0x207E, 0x208E, 0xFE36, 0xFE5A, 0xFF09:
		return ')', true
	default:
		return 0, false
	}
}

// foldSolidusTildePieces maps fullwidth solidus and fullwidth tilde to ASCII.
// NFKC folds them, and this pass does not run NFKC, so a bearer token, an
// opaque token, or a stored secret written with those forms would stay
// visible. Division slash, fraction slash, and big solidus do not fold to
// '/', and a reverse solidus folds to a backslash. Tilde operator, swung
// dash, and wave dash do not fold to '~'. Small tilde expands to a space
// plus a mark, so it stays out. One output piece covers the original rune.
func foldSolidusTildePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := solidusTildeASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldSolidusTildeString(s string) string {
	if !solidusTildeFolded(s) {
		return s
	}
	return renderPieces(foldSolidusTildePieces(rawPieces(s)))
}

func solidusTildeFolded(s string) bool {
	for _, r := range s {
		if _, ok := solidusTildeASCII(r); ok {
			return true
		}
	}
	return false
}

func solidusTildeASCII(r rune) (byte, bool) {
	switch r {
	case 0xFF0F:
		return '/', true
	case 0xFF5E:
		return '~', true
	default:
		return 0, false
	}
}

// foldLowLinePieces maps low lines to ASCII '_'.
// NFKC folds them, and this pass does not run NFKC, so a JWT or an opaque
// token written with those forms would stay visible. A double low line
// expands to a space plus a mark, and a low macron does not fold to '_',
// so those stay out. One output piece covers the original rune.
func foldLowLinePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := lowLineASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldLowLineString(s string) string {
	if !lowLineFolded(s) {
		return s
	}
	return renderPieces(foldLowLinePieces(rawPieces(s)))
}

func lowLineFolded(s string) bool {
	for _, r := range s {
		if _, ok := lowLineASCII(r); ok {
			return true
		}
	}
	return false
}

func lowLineASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE33, 0xFE34, 0xFE4D, 0xFE4E, 0xFE4F, 0xFF3F:
		return '_', true
	default:
		return 0, false
	}
}

// foldPlusEqualsPieces maps plus and equals signs to ASCII.
// NFKC folds them, and this pass does not run NFKC, so an opaque token
// written with those forms would stay visible. Plus-minus, superscript
// minus, and not-equal do not become one ASCII plus or equals, so they
// stay out. One output piece covers the original rune.
func foldPlusEqualsPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := plusEqualsASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldPlusEqualsString(s string) string {
	if !plusEqualsFolded(s) {
		return s
	}
	return renderPieces(foldPlusEqualsPieces(rawPieces(s)))
}

func plusEqualsFolded(s string) bool {
	for _, r := range s {
		if _, ok := plusEqualsASCII(r); ok {
			return true
		}
	}
	return false
}

func plusEqualsASCII(r rune) (byte, bool) {
	switch r {
	case 0x207A, 0x208A, 0xFB29, 0xFE62, 0xFF0B:
		return '+', true
	case 0x207C, 0x208C, 0xFE66, 0xFF1D:
		return '=', true
	default:
		return 0, false
	}
}

// foldLongSPieces maps latin small letter long s to ASCII s.
// NFKC folds it, and this pass does not run NFKC, so a stored token or a
// JWT written with that form would stay visible. Long s with a dot or a
// stroke stays a phonetic letter, and the long s t ligature expands to two
// letters, so those stay out. One output piece covers the original rune.
func foldLongSPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := longSASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldLongSString(s string) string {
	if !longSFolded(s) {
		return s
	}
	return renderPieces(foldLongSPieces(rawPieces(s)))
}

func longSFolded(s string) bool {
	for _, r := range s {
		if _, ok := longSASCII(r); ok {
			return true
		}
	}
	return false
}

func longSASCII(r rune) (byte, bool) {
	if r == 0x017F {
		return 's', true
	}
	return 0, false
}

// foldRomanPieces maps roman numerals to ASCII when NFKC folds them
// to one letter. Credential redaction does not run NFKC, so a stored token
// or a JWT written with those forms would stay visible. Two, three, four,
// and the other additive numerals expand to more than one letter. The
// archaic thousand signs do not fold to ASCII. Those stay out. One output
// piece covers the original rune.
func foldRomanPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := romanASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldRomanString(s string) string {
	if !romanFolded(s) {
		return s
	}
	return renderPieces(foldRomanPieces(rawPieces(s)))
}

func romanFolded(s string) bool {
	for _, r := range s {
		if _, ok := romanASCII(r); ok {
			return true
		}
	}
	return false
}

func romanASCII(r rune) (byte, bool) {
	switch r {
	case 0x2160:
		return 'I', true
	case 0x2164:
		return 'V', true
	case 0x2169:
		return 'X', true
	case 0x216C:
		return 'L', true
	case 0x216D:
		return 'C', true
	case 0x216E:
		return 'D', true
	case 0x216F:
		return 'M', true
	case 0x2170:
		return 'i', true
	case 0x2174:
		return 'v', true
	case 0x2179:
		return 'x', true
	case 0x217C:
		return 'l', true
	case 0x217D:
		return 'c', true
	case 0x217E:
		return 'd', true
	case 0x217F:
		return 'm', true
	default:
		return 0, false
	}
}

// foldSegmentedPieces maps segmented digits to ASCII.
// NFKC folds them, and this pass does not run NFKC, so a stored token or a
// JWT written with those forms would stay visible. Circled, parenthesized,
// and full-stop digits expand to more than one character or are already
// covered by another fold, so they stay out. One output piece covers the
// original rune.
func foldSegmentedPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := segmentedASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldSegmentedString(s string) string {
	if !segmentedFolded(s) {
		return s
	}
	return renderPieces(foldSegmentedPieces(rawPieces(s)))
}

func segmentedFolded(s string) bool {
	for _, r := range s {
		if _, ok := segmentedASCII(r); ok {
			return true
		}
	}
	return false
}

func segmentedASCII(r rune) (byte, bool) {
	if r >= 0x1FBF0 && r <= 0x1FBF9 {
		return byte(r - 0x1FBF0 + '0'), true
	}
	return 0, false
}

// foldModifierPieces maps modifier letters to ASCII when NFKC folds
// them to one letter. Latin subscript letters in the same phonetic blocks
// do the same, so they are listed too. Kelvin sign and information source
// are the letterlike symbols with that one-letter fold. Long s, roman
// numerals, segmented digits, and modifier letters that stay phonetic or
// expand past one character stay out. This pass does not run NFKC, so a
// stored token or a JWT written with these forms would stay visible. One
// output piece covers the original rune.
func foldModifierPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := modifierASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldModifierString(s string) string {
	if !modifierFolded(s) {
		return s
	}
	return renderPieces(foldModifierPieces(rawPieces(s)))
}

func modifierFolded(s string) bool {
	for _, r := range s {
		if _, ok := modifierASCII(r); ok {
			return true
		}
	}
	return false
}

func modifierASCII(r rune) (byte, bool) {
	switch r {
	case 0x02B0:
		return 'h', true
	case 0x02B2:
		return 'j', true
	case 0x02B3:
		return 'r', true
	case 0x02B7:
		return 'w', true
	case 0x02B8:
		return 'y', true
	case 0x02E1:
		return 'l', true
	case 0x02E2:
		return 's', true
	case 0x02E3:
		return 'x', true
	case 0x1D2C:
		return 'A', true
	case 0x1D2E:
		return 'B', true
	case 0x1D30:
		return 'D', true
	case 0x1D31:
		return 'E', true
	case 0x1D33:
		return 'G', true
	case 0x1D34:
		return 'H', true
	case 0x1D35:
		return 'I', true
	case 0x1D36:
		return 'J', true
	case 0x1D37:
		return 'K', true
	case 0x1D38:
		return 'L', true
	case 0x1D39:
		return 'M', true
	case 0x1D3A:
		return 'N', true
	case 0x1D3C:
		return 'O', true
	case 0x1D3E:
		return 'P', true
	case 0x1D3F:
		return 'R', true
	case 0x1D40:
		return 'T', true
	case 0x1D41:
		return 'U', true
	case 0x1D42:
		return 'W', true
	case 0x1D43:
		return 'a', true
	case 0x1D47:
		return 'b', true
	case 0x1D48:
		return 'd', true
	case 0x1D49:
		return 'e', true
	case 0x1D4D:
		return 'g', true
	case 0x1D4F:
		return 'k', true
	case 0x1D50:
		return 'm', true
	case 0x1D52:
		return 'o', true
	case 0x1D56:
		return 'p', true
	case 0x1D57:
		return 't', true
	case 0x1D58:
		return 'u', true
	case 0x1D5B:
		return 'v', true
	case 0x1D62:
		return 'i', true
	case 0x1D63:
		return 'r', true
	case 0x1D64:
		return 'u', true
	case 0x1D65:
		return 'v', true
	case 0x1D9C:
		return 'c', true
	case 0x1DA0:
		return 'f', true
	case 0x1DBB:
		return 'z', true
	case 0x2C7C:
		return 'j', true
	case 0x2C7D:
		return 'V', true
	case 0xA7F2:
		return 'C', true
	case 0xA7F3:
		return 'F', true
	case 0xA7F4:
		return 'Q', true
	case 0x107A5:
		return 'q', true
	case 0x212A:
		return 'K', true
	case 0x2139:
		return 'i', true
	default:
		return 0, false
	}
}

// foldSuperSubPieces maps superscript and subscript letters and digits
// to ASCII. NFKC folds them, and this pass does not run NFKC, so a stored
// token or a JWT written with those forms would stay visible. The feminine
// and masculine ordinals are superscript a and o. Superscript and subscript
// minus are already hyphen folds. Plus and equals are their own fold, and
// parentheses are their own fold. Subscript schwa does not become an ASCII
// letter, so it stays out. One output piece covers the original rune.
func foldSuperSubPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := superSubASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldSuperSubString(s string) string {
	if !superSubFolded(s) {
		return s
	}
	return renderPieces(foldSuperSubPieces(rawPieces(s)))
}

func superSubFolded(s string) bool {
	for _, r := range s {
		if _, ok := superSubASCII(r); ok {
			return true
		}
	}
	return false
}

func superSubASCII(r rune) (byte, bool) {
	switch r {
	case 0x00AA:
		return 'a', true
	case 0x00BA:
		return 'o', true
	case 0x00B2:
		return '2', true
	case 0x00B3:
		return '3', true
	case 0x00B9:
		return '1', true
	case 0x2070:
		return '0', true
	case 0x2071:
		return 'i', true
	case 0x207F:
		return 'n', true
	}
	switch {
	case r >= 0x2074 && r <= 0x2079:
		return byte(r - 0x2074 + '4'), true
	case r >= 0x2080 && r <= 0x2089:
		return byte(r - 0x2080 + '0'), true
	case r >= 0x2090 && r <= 0x2093:
		return "aeox"[r-0x2090], true
	case r >= 0x2095 && r <= 0x209C:
		return "hklmnpst"[r-0x2095], true
	default:
		return 0, false
	}
}

// foldEnclosedPieces maps circled and squared Latin letters and digits to
// ASCII. NFKC folds them, and this pass does not run NFKC, so a stored
// token or a JWT written with those forms would stay visible. Circled
// italic C and R are the only circled italic letters. Parenthesized
// letters, circled numbers from ten up, digit full stops, negative circled
// letters, and squared digraphs such as HV expand to more than one
// character or do not fold, so they stay out. One output piece covers the
// original rune.
func foldEnclosedPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := enclosedASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldEnclosedString(s string) string {
	if !enclosedFolded(s) {
		return s
	}
	return renderPieces(foldEnclosedPieces(rawPieces(s)))
}

func enclosedFolded(s string) bool {
	for _, r := range s {
		if _, ok := enclosedASCII(r); ok {
			return true
		}
	}
	return false
}

func enclosedASCII(r rune) (byte, bool) {
	switch {
	case r >= 0x2460 && r <= 0x2468:
		return byte(r - 0x2460 + '1'), true
	case r >= 0x24B6 && r <= 0x24CF:
		return byte(r - 0x24B6 + 'A'), true
	case r >= 0x24D0 && r <= 0x24E9:
		return byte(r - 0x24D0 + 'a'), true
	case r == 0x24EA:
		return '0', true
	case r == 0x1F12B:
		return 'C', true
	case r == 0x1F12C:
		return 'R', true
	case r >= 0x1F130 && r <= 0x1F149:
		return byte(r - 0x1F130 + 'A'), true
	default:
		return 0, false
	}
}

// foldDotPieces maps full stops to ASCII '.'. Compatibility forms NFKC-fold
// to '.' or to U+3002, and the other full stops do not NFKC-fold at all.
// This pass does not run NFKC, so a JWT split by any of them would miss both
// the stored token and the JWT pattern. Mongolian full stop and Manchu full
// stop are colon lookalikes in proxy userinfo; a dotted token still reads
// them as dots. One output piece covers the original rune.
func foldDotPieces(in []secretPiece) []secretPiece {
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
		if dotLike(r) {
			out = append(out, secretPiece{b: '.', start: in[i].start, end: in[i+size-1].end})
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

func foldDotString(s string) string {
	if !dotFolded(s) {
		return s
	}
	return renderPieces(foldDotPieces(rawPieces(s)))
}

func dotFolded(s string) bool {
	for _, r := range s {
		if dotLike(r) {
			return true
		}
	}
	return false
}

func dotLike(r rune) bool {
	switch r {
	case '\u2024', '\ufe52', '\uff0e', '\ufe12', '\uff61',
		'\u3002', '\u06d4', '\u0701', '\u0702', '\u1362', '\u166e',
		'\u1803', '\u1809', '\u2cf9', '\u2cfe', '\u2e3c', '\ua4ff', '\ua60e', '\ua6f3',
		'\U00016af5', '\U00016e98', '\U0001bc9f', '\U0001da88',
		'\ua4f8', '\U00010a50', '\ua4fa',
		'\u0660', '\u06f0', '\U0001ecae':
		return true
	default:
		return false
	}
}

// foldSpacingStopPieces maps spacing marks that are full stops to ASCII '.'.
// Meetei Mayek lum iyek and the musical augmentation dot do not NFKC-fold to
// '.'. Folding them is a separate reading: dropMarkPieces still has to remove
// an inserted mark, or a dotless token would no longer match. A following
// drop on this reading removes any other mark that was sitting beside the
// stop. One output piece covers the original rune.
func foldSpacingStopPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if spacingStop(r) {
			out = append(out, secretPiece{b: '.', start: in[i].start, end: in[i+size-1].end})
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

func foldSpacingStopString(s string) string {
	if !spacingStopFolded(s) {
		return s
	}
	folded, _ := foldSpacingStopPieces(rawPieces(s))
	return renderPieces(folded)
}

func spacingStopFolded(s string) bool {
	for _, r := range s {
		if spacingStop(r) {
			return true
		}
	}
	return false
}

func spacingStop(r rune) bool {
	return r == '\uabec' || r == '\U0001d16d'
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
