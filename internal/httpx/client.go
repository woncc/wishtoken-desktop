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
// Tag colon is a format character and does not NFKC-fold. url.Parse rejects
// every one of them as invalid userinfo, so an unlisted character would
// otherwise be returned with its password intact. The Go core has no Unicode
// normalization dependency, so each one is listed.
func foldUserinfoColons(s string) string {
	const lookalikes = "\ufe13\ufe55\uff1a\u2236\u02d0\u02d1\U00010781\U00010782\ua789\u02f8\u0703\u0704\u0705\u0706\u0707\u0708\u0709\u0589\u05c3\u1361\u1365\u1366\u205a\u205d\u1804\ua6f4\u2a74\u2254\u2255\u2982\u2af6\U00012471\U00012472\U00012473\U00012474\U0001DA8A\ufe30\u16ec\u0831\U00010af5\U0001123a\ua4fd\u0903\u0a83\U00011002\U00011082\U00011182\U000115BE\U000116AC\U00011838\u0983\u0a03\u0c03\u0c83\u0d03\u0d83\u0f7f\u1038\u17c7\U00011303\U000114C1\U000119DF\U00011A39\U00011C3E\u1393\U0001D108\U00011DD9\u2237\u2e2c\u1803\u1809\U000E003A"
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
		"\U000E003A", ":",
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
		next := decodePieces(foldTagPercentDecode(folded))
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
	// Tag space, hyphen, full stop, solidus, colon, and reverse solidus are
	// format characters, so the drop pass below removes them. That joins a
	// token and misses the stored byte. Folding those six is a separate
	// reading; the drop reading still runs, so an inserted tag cannot hide a
	// token that has no such mark. Language tag and cancel tag are not ASCII copies.
	needleTag := foldTagPunctuationString(needle)
	if tagged, ok := foldTagPunctuationPieces(folded); ok {
		spans = append(spans, exactSecretSpans(tagged, needleTag)...)
	} else if needleTag != needle {
		// The stored secret uses a tag and the response already has ASCII.
		spans = append(spans, exactSecretSpans(folded, needleTag)...)
	}
	// Tag letters copy A-Z and a-z and do not NFKC-fold. They are format
	// characters, so the drop pass below removes them. That deletes the
	// stored letter and misses the token. Folding them is a separate reading.
	// It runs on the tag-punctuation reading so one secret can use both a tag
	// slash and a tag letter. The drop reading still runs, so an inserted tag
	// letter cannot hide a token that has no tag letter. Digits, the language
	// tag, and cancel tag are not letters; digits have their own reading.
	letterBase := folded
	if tagged, ok := foldTagPunctuationPieces(folded); ok {
		letterBase = tagged
	}
	needleLetters := foldTagLetterString(needleTag)
	if lettered, ok := foldTagLetterPieces(letterBase); ok {
		spans = append(spans, exactSecretSpans(lettered, needleLetters)...)
	} else if needleLetters != needleTag {
		spans = append(spans, exactSecretSpans(letterBase, needleLetters)...)
	}
	// Tag digits copy 0-9 and do not NFKC-fold. They are format characters, so
	// the drop pass below removes them. That deletes the stored digit and
	// misses the token. Folding them is a separate reading. It runs on the
	// tag-letter reading so one secret can use a tag letter and a tag digit.
	// The drop reading still runs, so an inserted tag digit cannot hide a
	// token that has no tag digit. The language tag and cancel tag stay out.
	digitBase := letterBase
	if lettered, ok := foldTagLetterPieces(letterBase); ok {
		digitBase = lettered
	}
	needleDigits := foldTagDigitString(needleLetters)
	if digited, ok := foldTagDigitPieces(digitBase); ok {
		spans = append(spans, exactSecretSpans(digited, needleDigits)...)
	} else if needleDigits != needleLetters {
		spans = append(spans, exactSecretSpans(digitBase, needleDigits)...)
	}
	// Tag low line copies '_' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That joins id_rsa and
	// misses the stored underscore. Folding it is a separate reading. It runs
	// on the tag-digit reading so one secret can use a tag letter, digit, and
	// low line. The drop reading still runs, so an inserted tag low line
	// cannot hide a token that has no underscore.
	lowLineBase := digitBase
	if digited, ok := foldTagDigitPieces(digitBase); ok {
		lowLineBase = digited
	}
	needleLowLine := foldTagLowLineString(needleDigits)
	if lowered, ok := foldTagLowLinePieces(lowLineBase); ok {
		spans = append(spans, exactSecretSpans(lowered, needleLowLine)...)
	} else if needleLowLine != needleDigits {
		spans = append(spans, exactSecretSpans(lowLineBase, needleLowLine)...)
	}
	// Tag plus copies '+' and does not NFKC-fold. It is a format character,
	// so the drop pass below removes it. That joins a base64 or PKCE token
	// and misses the stored plus. Folding it is a separate reading. It runs
	// on the tag-low-line reading so one secret can use a tag low line and a
	// tag plus. The drop reading still runs, so an inserted tag plus cannot
	// hide a token that has no plus.
	plusBase := lowLineBase
	if lowered, ok := foldTagLowLinePieces(lowLineBase); ok {
		plusBase = lowered
	}
	needlePlus := foldTagPlusString(needleLowLine)
	if plused, ok := foldTagPlusPieces(plusBase); ok {
		spans = append(spans, exactSecretSpans(plused, needlePlus)...)
	} else if needlePlus != needleLowLine {
		spans = append(spans, exactSecretSpans(plusBase, needlePlus)...)
	}
	// Tag equals copies '=' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That drops base64
	// padding and misses the stored equals. Folding it is a separate
	// reading. It runs on the tag-plus reading so one secret can use a tag
	// plus and a tag equals. The drop reading still runs, so an inserted tag
	// equals cannot hide a token that has no equals.
	equalsBase := plusBase
	if plused, ok := foldTagPlusPieces(plusBase); ok {
		equalsBase = plused
	}
	needleEquals := foldTagEqualsString(needlePlus)
	if equaled, ok := foldTagEqualsPieces(equalsBase); ok {
		spans = append(spans, exactSecretSpans(equaled, needleEquals)...)
	} else if needleEquals != needlePlus {
		spans = append(spans, exactSecretSpans(equalsBase, needleEquals)...)
	}
	// Tag percent copies '%' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That misses a stored
	// percent. Folding it is a separate reading and is not part of
	// foldCredentialPieces: that fold is what the drop reading sees, and an
	// inserted tag percent must still disappear instead of becoming '%'.
	// Decode applies the same map to a copy so an escape written with a tag
	// percent still opens the next layer.
	percentBase := equalsBase
	if equaled, ok := foldTagEqualsPieces(equalsBase); ok {
		percentBase = equaled
	}
	needlePercent := foldTagPercentString(needleEquals)
	if percented, ok := foldTagPercentPieces(percentBase); ok {
		spans = append(spans, exactSecretSpans(percented, needlePercent)...)
	} else if needlePercent != needleEquals {
		spans = append(spans, exactSecretSpans(percentBase, needlePercent)...)
	}
	// Tag commercial at copies '@' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits an address
	// or token and misses the stored at sign. Folding it is a separate
	// reading. It runs on the tag-percent reading so one secret can use both.
	// The drop reading still runs, so an inserted tag at sign cannot hide a
	// token that has no at sign.
	atBase := percentBase
	if percented, ok := foldTagPercentPieces(percentBase); ok {
		atBase = percented
	}
	needleAt := foldTagCommercialAtString(needlePercent)
	if ated, ok := foldTagCommercialAtPieces(atBase); ok {
		spans = append(spans, exactSecretSpans(ated, needleAt)...)
	} else if needleAt != needlePercent {
		spans = append(spans, exactSecretSpans(atBase, needleAt)...)
	}
	// Tag quotation mark copies '"' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a quoted
	// token and misses the stored quotation mark. Folding it is a separate
	// reading. It runs on the tag-commercial-at reading so one secret can
	// use both. The drop reading still runs, so an inserted tag quotation
	// mark cannot hide a token that has no quotation mark.
	quoteBase := atBase
	if ated, ok := foldTagCommercialAtPieces(atBase); ok {
		quoteBase = ated
	}
	needleQuote := foldTagQuotationString(needleAt)
	if quoted, ok := foldTagQuotationPieces(quoteBase); ok {
		spans = append(spans, exactSecretSpans(quoted, needleQuote)...)
	} else if needleQuote != needleAt {
		spans = append(spans, exactSecretSpans(quoteBase, needleQuote)...)
	}
	// Tag apostrophe copies '\'' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored apostrophe. Folding it is a separate reading. It
	// runs on the tag-quotation reading so one secret can use both. The
	// drop reading still runs, so an inserted tag apostrophe cannot hide a
	// token that has no apostrophe.
	aposBase := quoteBase
	if quoted, ok := foldTagQuotationPieces(quoteBase); ok {
		aposBase = quoted
	}
	needleApos := foldTagApostropheString(needleQuote)
	if apostrophed, ok := foldTagApostrophePieces(aposBase); ok {
		spans = append(spans, exactSecretSpans(apostrophed, needleApos)...)
	} else if needleApos != needleQuote {
		spans = append(spans, exactSecretSpans(aposBase, needleApos)...)
	}
	// Tag vertical line copies '|' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored vertical line. Folding it is a separate reading. It
	// runs on the tag-apostrophe reading so one secret can use both. The
	// drop reading still runs, so an inserted tag vertical line cannot hide
	// a token that has no vertical line.
	barBase := aposBase
	if apostrophed, ok := foldTagApostrophePieces(aposBase); ok {
		barBase = apostrophed
	}
	needleBar := foldTagVerticalLineString(needleApos)
	if barred, ok := foldTagVerticalLinePieces(barBase); ok {
		spans = append(spans, exactSecretSpans(barred, needleBar)...)
	} else if needleBar != needleApos {
		spans = append(spans, exactSecretSpans(barBase, needleBar)...)
	}
	// Tag circumflex accent copies '^' and does not NFKC-fold. It is a
	// format character, so the drop pass below removes it. That splits a
	// token and misses the stored circumflex. Folding it is a separate
	// reading. It runs on the tag-vertical-line reading so one secret can
	// use both. The drop reading still runs, so an inserted tag circumflex
	// cannot hide a token that has no circumflex.
	caretBase := barBase
	if barred, ok := foldTagVerticalLinePieces(barBase); ok {
		caretBase = barred
	}
	needleCaret := foldTagCircumflexString(needleBar)
	if careted, ok := foldTagCircumflexPieces(caretBase); ok {
		spans = append(spans, exactSecretSpans(careted, needleCaret)...)
	} else if needleCaret != needleBar {
		spans = append(spans, exactSecretSpans(caretBase, needleCaret)...)
	}
	// Tag grave accent copies '`' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored grave accent. Folding it is a separate reading. It
	// runs on the tag-circumflex reading so one secret can use both. The
	// drop reading still runs, so an inserted tag grave accent cannot hide
	// a token that has no grave accent.
	graveBase := caretBase
	if careted, ok := foldTagCircumflexPieces(caretBase); ok {
		graveBase = careted
	}
	needleGrave := foldTagGraveString(needleCaret)
	if graved, ok := foldTagGravePieces(graveBase); ok {
		spans = append(spans, exactSecretSpans(graved, needleGrave)...)
	} else if needleGrave != needleCaret {
		spans = append(spans, exactSecretSpans(graveBase, needleGrave)...)
	}
	// Tag less-than sign copies '<' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored less-than sign. Folding it is a separate reading. It
	// runs on the tag-grave reading so one secret can use both. The drop
	// reading still runs, so an inserted tag less-than sign cannot hide a
	// token that has no less-than sign.
	lessBase := graveBase
	if graved, ok := foldTagGravePieces(graveBase); ok {
		lessBase = graved
	}
	needleLess := foldTagLessThanString(needleGrave)
	if lessed, ok := foldTagLessThanPieces(lessBase); ok {
		spans = append(spans, exactSecretSpans(lessed, needleLess)...)
	} else if needleLess != needleGrave {
		spans = append(spans, exactSecretSpans(lessBase, needleLess)...)
	}
	// Tag greater-than sign copies '>' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored greater-than sign. Folding it is a separate reading.
	// It runs on the tag-less-than reading so one secret can use both. The
	// drop reading still runs, so an inserted tag greater-than sign cannot
	// hide a token that has no greater-than sign.
	greaterBase := lessBase
	if lessed, ok := foldTagLessThanPieces(lessBase); ok {
		greaterBase = lessed
	}
	needleGreater := foldTagGreaterThanString(needleLess)
	if greatered, ok := foldTagGreaterThanPieces(greaterBase); ok {
		spans = append(spans, exactSecretSpans(greatered, needleGreater)...)
	} else if needleGreater != needleLess {
		spans = append(spans, exactSecretSpans(greaterBase, needleGreater)...)
	}
	// Tag left square bracket copies '[' and does not NFKC-fold. It is a
	// format character, so the drop pass below removes it. That splits a
	// token and misses the stored left square bracket. Folding it is a
	// separate reading. It runs on the tag-greater-than reading so one secret
	// can use both. The drop reading still runs, so an inserted tag left
	// square bracket cannot hide a token that has no left square bracket.
	leftBracketBase := greaterBase
	if greatered, ok := foldTagGreaterThanPieces(greaterBase); ok {
		leftBracketBase = greatered
	}
	needleLeftBracket := foldTagLeftSquareBracketString(needleGreater)
	if bracketed, ok := foldTagLeftSquareBracketPieces(leftBracketBase); ok {
		spans = append(spans, exactSecretSpans(bracketed, needleLeftBracket)...)
	} else if needleLeftBracket != needleGreater {
		spans = append(spans, exactSecretSpans(leftBracketBase, needleLeftBracket)...)
	}
	// Tag right square bracket copies ']' and does not NFKC-fold. It is a
	// format character, so the drop pass below removes it. That splits a
	// token and misses the stored right square bracket. Folding it is a
	// separate reading. It runs on the tag-left-square-bracket reading so one
	// secret can use both. The drop reading still runs, so an inserted tag
	// right square bracket cannot hide a token that has no right square bracket.
	rightBracketBase := leftBracketBase
	if bracketed, ok := foldTagLeftSquareBracketPieces(leftBracketBase); ok {
		rightBracketBase = bracketed
	}
	needleRightBracket := foldTagRightSquareBracketString(needleLeftBracket)
	if closed, ok := foldTagRightSquareBracketPieces(rightBracketBase); ok {
		spans = append(spans, exactSecretSpans(closed, needleRightBracket)...)
	} else if needleRightBracket != needleLeftBracket {
		spans = append(spans, exactSecretSpans(rightBracketBase, needleRightBracket)...)
	}
	// Tag left curly bracket copies '{' and does not NFKC-fold. It is a
	// format character, so the drop pass below removes it. That splits a
	// token and misses the stored left curly bracket. Folding it is a
	// separate reading. It runs on the tag-right-square-bracket reading so
	// one secret can use both. The drop reading still runs, so an inserted
	// tag left curly bracket cannot hide a token that has no left curly bracket.
	leftCurlyBase := rightBracketBase
	if closed, ok := foldTagRightSquareBracketPieces(rightBracketBase); ok {
		leftCurlyBase = closed
	}
	needleLeftCurly := foldTagLeftCurlyBracketString(needleRightBracket)
	if curled, ok := foldTagLeftCurlyBracketPieces(leftCurlyBase); ok {
		spans = append(spans, exactSecretSpans(curled, needleLeftCurly)...)
	} else if needleLeftCurly != needleRightBracket {
		spans = append(spans, exactSecretSpans(leftCurlyBase, needleLeftCurly)...)
	}
	// Tag right curly bracket copies '}' and does not NFKC-fold. It is a
	// format character, so the drop pass below removes it. That splits a
	// token and misses the stored right curly bracket. Folding it is a
	// separate reading. It runs on the tag-left-curly-bracket reading so one
	// secret can use both. The drop reading still runs, so an inserted tag
	// right curly bracket cannot hide a token that has no right curly bracket.
	rightCurlyBase := leftCurlyBase
	if curled, ok := foldTagLeftCurlyBracketPieces(leftCurlyBase); ok {
		rightCurlyBase = curled
	}
	needleRightCurly := foldTagRightCurlyBracketString(needleLeftCurly)
	if closed, ok := foldTagRightCurlyBracketPieces(rightCurlyBase); ok {
		spans = append(spans, exactSecretSpans(closed, needleRightCurly)...)
	} else if needleRightCurly != needleLeftCurly {
		spans = append(spans, exactSecretSpans(rightCurlyBase, needleRightCurly)...)
	}
	// Tag comma copies ',' and does not NFKC-fold. It is a format character,
	// so the drop pass below removes it. That splits a token and misses the
	// stored comma. Folding it is a separate reading. It runs on the
	// tag-right-curly-bracket reading so one secret can use both. The drop
	// reading still runs, so an inserted tag comma cannot hide a token that
	// has no comma.
	commaBase := rightCurlyBase
	if closed, ok := foldTagRightCurlyBracketPieces(rightCurlyBase); ok {
		commaBase = closed
	}
	needleComma := foldTagCommaString(needleRightCurly)
	if commaed, ok := foldTagCommaPieces(commaBase); ok {
		spans = append(spans, exactSecretSpans(commaed, needleComma)...)
	} else if needleComma != needleRightCurly {
		spans = append(spans, exactSecretSpans(commaBase, needleComma)...)
	}
	// Tag semicolon copies ';' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored semicolon. Folding it is a separate reading. It runs
	// on the tag-comma reading so one secret can use both. The drop reading
	// still runs, so an inserted tag semicolon cannot hide a token that has
	// no semicolon.
	semiBase := commaBase
	if commaed, ok := foldTagCommaPieces(commaBase); ok {
		semiBase = commaed
	}
	needleSemi := foldTagSemicolonString(needleComma)
	if semied, ok := foldTagSemicolonPieces(semiBase); ok {
		spans = append(spans, exactSecretSpans(semied, needleSemi)...)
	} else if needleSemi != needleComma {
		spans = append(spans, exactSecretSpans(semiBase, needleSemi)...)
	}
	// Tag question mark copies '?' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored question mark. Folding it is a separate reading. It
	// runs on the tag-semicolon reading so one secret can use both. The drop
	// reading still runs, so an inserted tag question mark cannot hide a token
	// that has no question mark.
	questionBase := semiBase
	if semied, ok := foldTagSemicolonPieces(semiBase); ok {
		questionBase = semied
	}
	needleQuestion := foldTagQuestionMarkString(needleSemi)
	if questioned, ok := foldTagQuestionMarkPieces(questionBase); ok {
		spans = append(spans, exactSecretSpans(questioned, needleQuestion)...)
	} else if needleQuestion != needleSemi {
		spans = append(spans, exactSecretSpans(questionBase, needleQuestion)...)
	}
	// Tag asterisk copies '*' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored asterisk. Folding it is a separate reading. It runs
	// on the tag-question-mark reading so one secret can use both. The drop
	// reading still runs, so an inserted tag asterisk cannot hide a token that
	// has no asterisk.
	asteriskBase := questionBase
	if questioned, ok := foldTagQuestionMarkPieces(questionBase); ok {
		asteriskBase = questioned
	}
	needleAsterisk := foldTagAsteriskString(needleQuestion)
	if asterisked, ok := foldTagAsteriskPieces(asteriskBase); ok {
		spans = append(spans, exactSecretSpans(asterisked, needleAsterisk)...)
	} else if needleAsterisk != needleQuestion {
		spans = append(spans, exactSecretSpans(asteriskBase, needleAsterisk)...)
	}
	// Tag ampersand copies '&' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored ampersand. Folding it is a separate reading. It runs
	// on the tag-asterisk reading so one secret can use both. The drop reading
	// still runs, so an inserted tag ampersand cannot hide a token that has no
	// ampersand.
	ampersandBase := asteriskBase
	if asterisked, ok := foldTagAsteriskPieces(asteriskBase); ok {
		ampersandBase = asterisked
	}
	needleAmpersand := foldTagAmpersandString(needleAsterisk)
	if amped, ok := foldTagAmpersandPieces(ampersandBase); ok {
		spans = append(spans, exactSecretSpans(amped, needleAmpersand)...)
	} else if needleAmpersand != needleAsterisk {
		spans = append(spans, exactSecretSpans(ampersandBase, needleAmpersand)...)
	}
	// Tag dollar sign copies '$' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored dollar sign. Folding it is a separate reading. It runs
	// on the tag-ampersand reading so one secret can use both. The drop
	// reading still runs, so an inserted tag dollar sign cannot hide a token
	// that has no dollar sign.
	dollarBase := ampersandBase
	if amped, ok := foldTagAmpersandPieces(ampersandBase); ok {
		dollarBase = amped
	}
	needleDollar := foldTagDollarString(needleAmpersand)
	if dollared, ok := foldTagDollarPieces(dollarBase); ok {
		spans = append(spans, exactSecretSpans(dollared, needleDollar)...)
	} else if needleDollar != needleAmpersand {
		spans = append(spans, exactSecretSpans(dollarBase, needleDollar)...)
	}
	// Tag number sign copies '#' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored number sign. Folding it is a separate reading. It runs
	// on the tag-dollar-sign reading so one secret can use both. The drop
	// reading still runs, so an inserted tag number sign cannot hide a token
	// that has no number sign.
	numberBase := dollarBase
	if dollared, ok := foldTagDollarPieces(dollarBase); ok {
		numberBase = dollared
	}
	needleNumber := foldTagNumberSignString(needleDollar)
	if numbered, ok := foldTagNumberSignPieces(numberBase); ok {
		spans = append(spans, exactSecretSpans(numbered, needleNumber)...)
	} else if needleNumber != needleDollar {
		spans = append(spans, exactSecretSpans(numberBase, needleNumber)...)
	}
	// Tag exclamation mark copies '!' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored exclamation mark. Folding it is a separate reading. It
	// runs on the tag-number-sign reading so one secret can use both. The drop
	// reading still runs, so an inserted tag exclamation mark cannot hide a
	// token that has no exclamation mark.
	exclaimBase := numberBase
	if numbered, ok := foldTagNumberSignPieces(numberBase); ok {
		exclaimBase = numbered
	}
	needleExclaim := foldTagExclamationString(needleNumber)
	if exclaimed, ok := foldTagExclamationPieces(exclaimBase); ok {
		spans = append(spans, exactSecretSpans(exclaimed, needleExclaim)...)
	} else if needleExclaim != needleNumber {
		spans = append(spans, exactSecretSpans(exclaimBase, needleExclaim)...)
	}
	// Tag left parenthesis copies '(' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored left parenthesis. Folding it is a separate reading. It
	// runs on the tag-exclamation-mark reading so one secret can use both. The
	// drop reading still runs, so an inserted tag left parenthesis cannot hide
	// a token that has no left parenthesis.
	leftParenBase := exclaimBase
	if exclaimed, ok := foldTagExclamationPieces(exclaimBase); ok {
		leftParenBase = exclaimed
	}
	needleLeftParen := foldTagLeftParenthesisString(needleExclaim)
	if opened, ok := foldTagLeftParenthesisPieces(leftParenBase); ok {
		spans = append(spans, exactSecretSpans(opened, needleLeftParen)...)
	} else if needleLeftParen != needleExclaim {
		spans = append(spans, exactSecretSpans(leftParenBase, needleLeftParen)...)
	}
	// Tag right parenthesis copies ')' and does not NFKC-fold. It is a format
	// character, so the drop pass below removes it. That splits a token and
	// misses the stored right parenthesis. Folding it is a separate reading.
	// It runs on the tag-left-parenthesis reading so one secret can use both.
	// The drop reading still runs, so an inserted tag right parenthesis cannot
	// hide a token that has no right parenthesis.
	rightParenBase := leftParenBase
	if opened, ok := foldTagLeftParenthesisPieces(leftParenBase); ok {
		rightParenBase = opened
	}
	needleRightParen := foldTagRightParenthesisString(needleLeftParen)
	if closed, ok := foldTagRightParenthesisPieces(rightParenBase); ok {
		spans = append(spans, exactSecretSpans(closed, needleRightParen)...)
	} else if needleRightParen != needleLeftParen {
		spans = append(spans, exactSecretSpans(rightParenBase, needleRightParen)...)
	}
	// Tag tilde copies '~' and does not NFKC-fold. It is a format character,
	// so the drop pass below removes it. That splits a token and misses the
	// stored tilde. Folding it is a separate reading. It runs on the
	// tag-right-parenthesis reading so one secret can use both. The drop
	// reading still runs, so an inserted tag tilde cannot hide a token that
	// has no tilde.
	tildeBase := rightParenBase
	if closed, ok := foldTagRightParenthesisPieces(rightParenBase); ok {
		tildeBase = closed
	}
	needleTilde := foldTagTildeString(needleRightParen)
	if tilded, ok := foldTagTildePieces(tildeBase); ok {
		spans = append(spans, exactSecretSpans(tilded, needleTilde)...)
	} else if needleTilde != needleRightParen {
		spans = append(spans, exactSecretSpans(tildeBase, needleTilde)...)
	}
	// Visarga signs are spacing marks shaped like a colon. The drop pass
	// below removes them, which deletes a stored colon and misses the token.
	// Folding them to ':' is a separate reading. The drop reading still runs,
	// so an inserted visarga cannot hide a token that has no colon.
	needleVisarga := foldVisargaColonString(needle)
	if visarga, ok := foldVisargaColonPieces(folded); ok {
		spans = append(spans, exactSecretSpans(visarga, needleVisarga)...)
	} else if needleVisarga != needle {
		spans = append(spans, exactSecretSpans(folded, needleVisarga)...)
	}
	if spacing, ok := foldSpacingStopPieces(folded); ok {
		needleStop := foldSpacingStopString(needle)
		spans = append(spans, exactSecretSpans(spacing, needleStop)...)
		if droppedStops := dropMarkPieces(spacing); len(droppedStops) != len(spacing) {
			spans = append(spans, exactSecretSpans(droppedStops, needleStop)...)
		}
	}
	// Compatibility spaces NFKC-fold to ASCII space, and this pass does not
	// run NFKC. Dropping one joins a spaced token and misses the stored ' '.
	// Folding it to ' ' is a separate reading; the drop below still runs so
	// an inserted space cannot hide a token that has no space.
	if spaced, ok := foldSpacePieces(folded); ok {
		spans = append(spans, exactSecretSpans(spaced, foldSpaceString(needle))...)
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

// foldTagPunctuationPieces maps Unicode tag space and the five tag
// punctuation characters to the ASCII marks they copy. None of them
// NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes format
// characters, so a stored space, slash, dot, hyphen, colon, or backslash
// written with a tag would stay visible. One output piece covers the
// original rune. The drop reading still runs on the unfolded pieces. Other
// tag characters, including letters and the language and cancel tags, stay out.
func foldTagPunctuationPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if folded, ok := tagPunctuationASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldTagPunctuationString(s string) string {
	if !tagPunctuationFolded(s) {
		return s
	}
	folded, _ := foldTagPunctuationPieces(rawPieces(s))
	return renderPieces(folded)
}

func tagPunctuationFolded(s string) bool {
	for _, r := range s {
		if _, ok := tagPunctuationASCII(r); ok {
			return true
		}
	}
	return false
}

func tagPunctuationASCII(r rune) (byte, bool) {
	switch r {
	case 0xE0020:
		return ' ', true
	case 0xE002D:
		return '-', true
	case 0xE002E:
		return '.', true
	case 0xE002F:
		return '/', true
	case 0xE003A:
		return ':', true
	case 0xE005C:
		return '\\', true
	default:
		return 0, false
	}
}

// foldTagLetterPieces maps Unicode tag letters to the ASCII letters they
// copy. None of them NFKC-fold. This pass does not run NFKC, and
// dropMarkPieces removes format characters, so a stored letter written with
// a tag would stay visible. One output piece covers the original rune. The
// drop reading still runs on the unfolded pieces. Tag digits, tag
// punctuation, the language tag, and cancel tag stay out.
func foldTagLetterPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if folded, ok := tagLetterASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldTagLetterString(s string) string {
	if !tagLetterFolded(s) {
		return s
	}
	folded, _ := foldTagLetterPieces(rawPieces(s))
	return renderPieces(folded)
}

func tagLetterFolded(s string) bool {
	for _, r := range s {
		if _, ok := tagLetterASCII(r); ok {
			return true
		}
	}
	return false
}

func tagLetterASCII(r rune) (byte, bool) {
	switch {
	case r >= 0xE0041 && r <= 0xE005A, r >= 0xE0061 && r <= 0xE007A:
		return byte(r - 0xE0000), true
	default:
		return 0, false
	}
}

// foldTagDigitPieces maps Unicode tag digits to the ASCII digits they copy.
// None of them NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored digit written with a tag would stay
// visible. One output piece covers the original rune. The drop reading still
// runs on the unfolded pieces. Tag letters, tag punctuation, the language
// tag, and cancel tag stay out.
func foldTagDigitPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if folded, ok := tagDigitASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldTagDigitString(s string) string {
	if !tagDigitFolded(s) {
		return s
	}
	folded, _ := foldTagDigitPieces(rawPieces(s))
	return renderPieces(folded)
}

func tagDigitFolded(s string) bool {
	for _, r := range s {
		if _, ok := tagDigitASCII(r); ok {
			return true
		}
	}
	return false
}

func tagDigitASCII(r rune) (byte, bool) {
	if r >= 0xE0030 && r <= 0xE0039 {
		return byte(r - 0xE0000), true
	}
	return 0, false
}

// foldTagLowLinePieces maps the Unicode tag low line to ASCII '_'. It does
// not NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes
// format characters, so a stored underscore written with a tag would stay
// visible. One output piece covers the original rune. The drop reading still
// runs on the unfolded pieces. Other tag characters stay out.
func foldTagLowLinePieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE005F {
			out = append(out, secretPiece{b: '_', start: in[i].start, end: in[i+size-1].end})
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

func foldTagLowLineString(s string) string {
	if !strings.ContainsRune(s, 0xE005F) {
		return s
	}
	folded, _ := foldTagLowLinePieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagPlusPieces maps the Unicode tag plus sign to ASCII '+'. It does
// not NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes
// format characters, so a stored plus written with a tag would stay visible.
// One output piece covers the original rune. The drop reading still runs on
// the unfolded pieces. Other tag characters stay out.
func foldTagPlusPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE002B {
			out = append(out, secretPiece{b: '+', start: in[i].start, end: in[i+size-1].end})
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

func foldTagPlusString(s string) string {
	if !strings.ContainsRune(s, 0xE002B) {
		return s
	}
	folded, _ := foldTagPlusPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagEqualsPieces maps the Unicode tag equals sign to ASCII '='. It does
// not NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes
// format characters, so a stored equals written with a tag would stay
// visible. One output piece covers the original rune. The drop reading still
// runs on the unfolded pieces. Other tag characters stay out.
func foldTagEqualsPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE003D {
			out = append(out, secretPiece{b: '=', start: in[i].start, end: in[i+size-1].end})
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

func foldTagEqualsString(s string) string {
	if !strings.ContainsRune(s, 0xE003D) {
		return s
	}
	folded, _ := foldTagEqualsPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagPercentPieces maps the Unicode tag percent sign to ASCII '%'. It
// does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes
// format characters, so a stored percent written with a tag would stay
// visible. One output piece covers the original rune. The drop reading still
// runs on the unfolded pieces. Other tag characters stay out.
func foldTagPercentPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0025 {
			out = append(out, secretPiece{b: '%', start: in[i].start, end: in[i+size-1].end})
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

func foldTagPercentString(s string) string {
	if !strings.ContainsRune(s, 0xE0025) {
		return s
	}
	folded, _ := foldTagPercentPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagPercentDecode maps tag percent signs for the percent-decoder only.
// The drop reading keeps the original pieces, so an inserted tag percent is
// still removed instead of becoming a literal '%'.
func foldTagPercentDecode(in []secretPiece) []secretPiece {
	if folded, ok := foldTagPercentPieces(in); ok {
		return folded
	}
	return in
}

// foldTagCommercialAtPieces maps the Unicode tag commercial at to ASCII '@'.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored at sign written with a tag would
// stay visible. One output piece covers the original rune. The drop reading
// still runs on the unfolded pieces. Other tag characters stay out.
func foldTagCommercialAtPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0040 {
			out = append(out, secretPiece{b: '@', start: in[i].start, end: in[i+size-1].end})
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

func foldTagCommercialAtString(s string) string {
	if !strings.ContainsRune(s, 0xE0040) {
		return s
	}
	folded, _ := foldTagCommercialAtPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagQuotationPieces maps the Unicode tag quotation mark to ASCII '"'.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored quotation mark written with a tag
// would stay visible. One output piece covers the original rune. The drop
// reading still runs on the unfolded pieces. Other tag characters stay out.
func foldTagQuotationPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0022 {
			out = append(out, secretPiece{b: '"', start: in[i].start, end: in[i+size-1].end})
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

func foldTagQuotationString(s string) string {
	if !strings.ContainsRune(s, 0xE0022) {
		return s
	}
	folded, _ := foldTagQuotationPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagApostrophePieces maps the Unicode tag apostrophe to ASCII '\”.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored apostrophe written with a tag
// would stay visible. One output piece covers the original rune. The drop
// reading still runs on the unfolded pieces. Other tag characters stay out.
func foldTagApostrophePieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0027 {
			out = append(out, secretPiece{b: '\'', start: in[i].start, end: in[i+size-1].end})
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

func foldTagApostropheString(s string) string {
	if !strings.ContainsRune(s, 0xE0027) {
		return s
	}
	folded, _ := foldTagApostrophePieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagVerticalLinePieces maps the Unicode tag vertical line to ASCII '|'.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored vertical line written with a tag
// would stay visible. One output piece covers the original rune. The drop
// reading still runs on the unfolded pieces. Other tag characters stay out.
func foldTagVerticalLinePieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE007C {
			out = append(out, secretPiece{b: '|', start: in[i].start, end: in[i+size-1].end})
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

func foldTagVerticalLineString(s string) string {
	if !strings.ContainsRune(s, 0xE007C) {
		return s
	}
	folded, _ := foldTagVerticalLinePieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagCircumflexPieces maps the Unicode tag circumflex accent to ASCII '^'.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored circumflex written with a tag would
// stay visible. One output piece covers the original rune. The drop reading
// still runs on the unfolded pieces. Other tag characters stay out.
func foldTagCircumflexPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE005E {
			out = append(out, secretPiece{b: '^', start: in[i].start, end: in[i+size-1].end})
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

func foldTagCircumflexString(s string) string {
	if !strings.ContainsRune(s, 0xE005E) {
		return s
	}
	folded, _ := foldTagCircumflexPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagGravePieces maps the Unicode tag grave accent to ASCII '`'.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored grave accent written with a tag would
// stay visible. One output piece covers the original rune. The drop reading
// still runs on the unfolded pieces. Other tag characters stay out.
func foldTagGravePieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0060 {
			out = append(out, secretPiece{b: '`', start: in[i].start, end: in[i+size-1].end})
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

func foldTagGraveString(s string) string {
	if !strings.ContainsRune(s, 0xE0060) {
		return s
	}
	folded, _ := foldTagGravePieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagLessThanPieces maps the Unicode tag less-than sign to ASCII '<'.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored less-than sign written with a tag
// would stay visible. One output piece covers the original rune. The drop
// reading still runs on the unfolded pieces. Other tag characters stay out.
func foldTagLessThanPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE003C {
			out = append(out, secretPiece{b: '<', start: in[i].start, end: in[i+size-1].end})
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

func foldTagLessThanString(s string) string {
	if !strings.ContainsRune(s, 0xE003C) {
		return s
	}
	folded, _ := foldTagLessThanPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagGreaterThanPieces maps the Unicode tag greater-than sign to ASCII '>'.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored greater-than sign written with a tag
// would stay visible. One output piece covers the original rune. The drop
// reading still runs on the unfolded pieces. Other tag characters stay out.
func foldTagGreaterThanPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE003E {
			out = append(out, secretPiece{b: '>', start: in[i].start, end: in[i+size-1].end})
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

func foldTagGreaterThanString(s string) string {
	if !strings.ContainsRune(s, 0xE003E) {
		return s
	}
	folded, _ := foldTagGreaterThanPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagLeftSquareBracketPieces maps the Unicode tag left square bracket to
// ASCII '['. It does not NFKC-fold. This pass does not run NFKC, and
// dropMarkPieces removes format characters, so a stored left square bracket
// written with a tag would stay visible. One output piece covers the original
// rune. The drop reading still runs on the unfolded pieces. Other tag
// characters stay out.
func foldTagLeftSquareBracketPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE005B {
			out = append(out, secretPiece{b: '[', start: in[i].start, end: in[i+size-1].end})
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

func foldTagLeftSquareBracketString(s string) string {
	if !strings.ContainsRune(s, 0xE005B) {
		return s
	}
	folded, _ := foldTagLeftSquareBracketPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagRightSquareBracketPieces maps the Unicode tag right square bracket
// to ASCII ']'. It does not NFKC-fold. This pass does not run NFKC, and
// dropMarkPieces removes format characters, so a stored right square bracket
// written with a tag would stay visible. One output piece covers the original
// rune. The drop reading still runs on the unfolded pieces. Other tag
// characters stay out.
func foldTagRightSquareBracketPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE005D {
			out = append(out, secretPiece{b: ']', start: in[i].start, end: in[i+size-1].end})
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

func foldTagRightSquareBracketString(s string) string {
	if !strings.ContainsRune(s, 0xE005D) {
		return s
	}
	folded, _ := foldTagRightSquareBracketPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagLeftCurlyBracketPieces maps the Unicode tag left curly bracket to
// ASCII '{'. It does not NFKC-fold. This pass does not run NFKC, and
// dropMarkPieces removes format characters, so a stored left curly bracket
// written with a tag would stay visible. One output piece covers the original
// rune. The drop reading still runs on the unfolded pieces. Other tag
// characters stay out.
func foldTagLeftCurlyBracketPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE007B {
			out = append(out, secretPiece{b: '{', start: in[i].start, end: in[i+size-1].end})
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

func foldTagLeftCurlyBracketString(s string) string {
	if !strings.ContainsRune(s, 0xE007B) {
		return s
	}
	folded, _ := foldTagLeftCurlyBracketPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagRightCurlyBracketPieces maps the Unicode tag right curly bracket to
// ASCII '}'. It does not NFKC-fold. This pass does not run NFKC, and
// dropMarkPieces removes format characters, so a stored right curly bracket
// written with a tag would stay visible. One output piece covers the original
// rune. The drop reading still runs on the unfolded pieces. Other tag
// characters stay out.
func foldTagRightCurlyBracketPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE007D {
			out = append(out, secretPiece{b: '}', start: in[i].start, end: in[i+size-1].end})
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

func foldTagRightCurlyBracketString(s string) string {
	if !strings.ContainsRune(s, 0xE007D) {
		return s
	}
	folded, _ := foldTagRightCurlyBracketPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagCommaPieces maps the Unicode tag comma to ASCII ','. It does not
// NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes format
// characters, so a stored comma written with a tag would stay visible. One
// output piece covers the original rune. The drop reading still runs on the
// unfolded pieces. Other tag characters stay out.
func foldTagCommaPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE002C {
			out = append(out, secretPiece{b: ',', start: in[i].start, end: in[i+size-1].end})
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

func foldTagCommaString(s string) string {
	if !strings.ContainsRune(s, 0xE002C) {
		return s
	}
	folded, _ := foldTagCommaPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagSemicolonPieces maps the Unicode tag semicolon to ASCII ';'. It does
// not NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes
// format characters, so a stored semicolon written with a tag would stay
// visible. One output piece covers the original rune. The drop reading still
// runs on the unfolded pieces. Other tag characters stay out.
func foldTagSemicolonPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE003B {
			out = append(out, secretPiece{b: ';', start: in[i].start, end: in[i+size-1].end})
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

func foldTagSemicolonString(s string) string {
	if !strings.ContainsRune(s, 0xE003B) {
		return s
	}
	folded, _ := foldTagSemicolonPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagQuestionMarkPieces maps the Unicode tag question mark to ASCII '?'.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored question mark written with a tag
// would stay visible. One output piece covers the original rune. The drop
// reading still runs on the unfolded pieces. Other tag characters stay out.
func foldTagQuestionMarkPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE003F {
			out = append(out, secretPiece{b: '?', start: in[i].start, end: in[i+size-1].end})
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

func foldTagQuestionMarkString(s string) string {
	if !strings.ContainsRune(s, 0xE003F) {
		return s
	}
	folded, _ := foldTagQuestionMarkPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagAsteriskPieces maps the Unicode tag asterisk to ASCII '*'. It does
// not NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes
// format characters, so a stored asterisk written with a tag would stay
// visible. One output piece covers the original rune. The drop reading still
// runs on the unfolded pieces. Other tag characters stay out.
func foldTagAsteriskPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE002A {
			out = append(out, secretPiece{b: '*', start: in[i].start, end: in[i+size-1].end})
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

func foldTagAsteriskString(s string) string {
	if !strings.ContainsRune(s, 0xE002A) {
		return s
	}
	folded, _ := foldTagAsteriskPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagAmpersandPieces maps the Unicode tag ampersand to ASCII '&'. It does
// not NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes
// format characters, so a stored ampersand written with a tag would stay
// visible. One output piece covers the original rune. The drop reading still
// runs on the unfolded pieces. Other tag characters stay out.
func foldTagAmpersandPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0026 {
			out = append(out, secretPiece{b: '&', start: in[i].start, end: in[i+size-1].end})
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

func foldTagAmpersandString(s string) string {
	if !strings.ContainsRune(s, 0xE0026) {
		return s
	}
	folded, _ := foldTagAmpersandPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagDollarPieces maps the Unicode tag dollar sign to ASCII '$'. It does
// not NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes
// format characters, so a stored dollar sign written with a tag would stay
// visible. One output piece covers the original rune. The drop reading still
// runs on the unfolded pieces. Other tag characters stay out.
func foldTagDollarPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0024 {
			out = append(out, secretPiece{b: '$', start: in[i].start, end: in[i+size-1].end})
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

func foldTagDollarString(s string) string {
	if !strings.ContainsRune(s, 0xE0024) {
		return s
	}
	folded, _ := foldTagDollarPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagNumberSignPieces maps the Unicode tag number sign to ASCII '#'. It
// does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes
// format characters, so a stored number sign written with a tag would stay
// visible. One output piece covers the original rune. The drop reading still
// runs on the unfolded pieces. Other tag characters stay out.
func foldTagNumberSignPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0023 {
			out = append(out, secretPiece{b: '#', start: in[i].start, end: in[i+size-1].end})
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

func foldTagNumberSignString(s string) string {
	if !strings.ContainsRune(s, 0xE0023) {
		return s
	}
	folded, _ := foldTagNumberSignPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagExclamationPieces maps the Unicode tag exclamation mark to ASCII '!'.
// It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored exclamation mark written with a tag
// would stay visible. One output piece covers the original rune. The drop
// reading still runs on the unfolded pieces. Other tag characters stay out.
func foldTagExclamationPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0021 {
			out = append(out, secretPiece{b: '!', start: in[i].start, end: in[i+size-1].end})
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

func foldTagExclamationString(s string) string {
	if !strings.ContainsRune(s, 0xE0021) {
		return s
	}
	folded, _ := foldTagExclamationPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagLeftParenthesisPieces maps the Unicode tag left parenthesis to ASCII
// '('. It does not NFKC-fold. This pass does not run NFKC, and dropMarkPieces
// removes format characters, so a stored left parenthesis written with a tag
// would stay visible. One output piece covers the original rune. The drop
// reading still runs on the unfolded pieces. Other tag characters stay out.
func foldTagLeftParenthesisPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0028 {
			out = append(out, secretPiece{b: '(', start: in[i].start, end: in[i+size-1].end})
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

func foldTagLeftParenthesisString(s string) string {
	if !strings.ContainsRune(s, 0xE0028) {
		return s
	}
	folded, _ := foldTagLeftParenthesisPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagRightParenthesisPieces maps the Unicode tag right parenthesis to
// ASCII ')'. It does not NFKC-fold. This pass does not run NFKC, and
// dropMarkPieces removes format characters, so a stored right parenthesis
// written with a tag would stay visible. One output piece covers the original
// rune. The drop reading still runs on the unfolded pieces. Other tag
// characters stay out.
func foldTagRightParenthesisPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE0029 {
			out = append(out, secretPiece{b: ')', start: in[i].start, end: in[i+size-1].end})
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

func foldTagRightParenthesisString(s string) string {
	if !strings.ContainsRune(s, 0xE0029) {
		return s
	}
	folded, _ := foldTagRightParenthesisPieces(rawPieces(s))
	return renderPieces(folded)
}

// foldTagTildePieces maps the Unicode tag tilde to ASCII '~'. It does not
// NFKC-fold. This pass does not run NFKC, and dropMarkPieces removes format
// characters, so a stored tilde written with a tag would stay visible. One
// output piece covers the original rune. The drop reading still runs on the
// unfolded pieces. Other tag characters stay out.
func foldTagTildePieces(in []secretPiece) ([]secretPiece, bool) {
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
		if r == 0xE007E {
			out = append(out, secretPiece{b: '~', start: in[i].start, end: in[i+size-1].end})
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

func foldTagTildeString(s string) string {
	if !strings.ContainsRune(s, 0xE007E) {
		return s
	}
	folded, _ := foldTagTildePieces(rawPieces(s))
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

// foldFractionPieces maps vulgar fractions to the ASCII digits and slash
// NFKC produces. The compatibility decomposition uses a fraction slash;
// this pass emits the ASCII solidus instead, and it does not run NFKC.
// A stored secret written with a fraction would otherwise stay visible.
// Each output byte keeps the original rune's range. Fraction numerator
// one has no trailing digit and still expands to "1/". Other slashes and
// the letterlike signs stay out.
func foldFractionPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := fractionASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldFractionString(s string) string {
	if !fractionFolded(s) {
		return s
	}
	return renderPieces(foldFractionPieces(rawPieces(s)))
}

func fractionFolded(s string) bool {
	for _, r := range s {
		if _, ok := fractionASCII(r); ok {
			return true
		}
	}
	return false
}

func fractionASCII(r rune) (string, bool) {
	switch r {
	case 0x00BC:
		return "1/4", true
	case 0x00BD:
		return "1/2", true
	case 0x00BE:
		return "3/4", true
	case 0x2150:
		return "1/7", true
	case 0x2151:
		return "1/9", true
	case 0x2152:
		return "1/10", true
	case 0x2153:
		return "1/3", true
	case 0x2154:
		return "2/3", true
	case 0x2155:
		return "1/5", true
	case 0x2156:
		return "2/5", true
	case 0x2157:
		return "3/5", true
	case 0x2158:
		return "4/5", true
	case 0x2159:
		return "1/6", true
	case 0x215A:
		return "5/6", true
	case 0x215B:
		return "1/8", true
	case 0x215C:
		return "3/8", true
	case 0x215D:
		return "5/8", true
	case 0x215E:
		return "7/8", true
	case 0x215F:
		return "1/", true
	case 0x2189:
		return "0/3", true
	default:
		return "", false
	}
}

// foldRupeePieces maps the rupee sign to the ASCII "Rs" NFKC produces.
// This pass does not run NFKC, so a stored secret written with that sign
// would stay visible. Each output byte keeps the original rune's range.
// Other currency signs do not fold to "Rs", so they stay out.
func foldRupeePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := rupeeASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldRupeeString(s string) string {
	if !rupeeFolded(s) {
		return s
	}
	return renderPieces(foldRupeePieces(rawPieces(s)))
}

func rupeeFolded(s string) bool {
	for _, r := range s {
		if _, ok := rupeeASCII(r); ok {
			return true
		}
	}
	return false
}

func rupeeASCII(r rune) (string, bool) {
	if r == 0x20A8 {
		return "Rs", true
	}
	return "", false
}

// foldSquarePieces maps CJK square symbols to the ASCII sequences NFKC
// produces. This pass does not run NFKC, so a stored secret written with
// those forms would stay visible. Each output byte keeps the original
// rune's range. Squares that decompose through a division slash emit an
// ASCII solidus instead. Squares whose remaining decomposition is not
// ASCII stay out. The rupee sign is folded separately. Double colon equal
// and the vertical two-dot leader stay out; the leader is read as a colon
// when a proxy password is split.
func foldSquarePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := squareASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldSquareString(s string) string {
	if !squareFolded(s) {
		return s
	}
	return renderPieces(foldSquarePieces(rawPieces(s)))
}

func squareFolded(s string) bool {
	for _, r := range s {
		if _, ok := squareASCII(r); ok {
			return true
		}
	}
	return false
}

func squareASCII(r rune) (string, bool) {
	switch r {
	case 0x3250:
		return "PTE", true
	case 0x32CC:
		return "Hg", true
	case 0x32CD:
		return "erg", true
	case 0x32CE:
		return "eV", true
	case 0x32CF:
		return "LTD", true
	case 0x3371:
		return "hPa", true
	case 0x3372:
		return "da", true
	case 0x3373:
		return "AU", true
	case 0x3374:
		return "bar", true
	case 0x3375:
		return "oV", true
	case 0x3376:
		return "pc", true
	case 0x3377:
		return "dm", true
	case 0x3378:
		return "dm2", true
	case 0x3379:
		return "dm3", true
	case 0x337A:
		return "IU", true
	case 0x3380:
		return "pA", true
	case 0x3381:
		return "nA", true
	case 0x3383:
		return "mA", true
	case 0x3384:
		return "kA", true
	case 0x3385:
		return "KB", true
	case 0x3386:
		return "MB", true
	case 0x3387:
		return "GB", true
	case 0x3388:
		return "cal", true
	case 0x3389:
		return "kcal", true
	case 0x338A:
		return "pF", true
	case 0x338B:
		return "nF", true
	case 0x338E:
		return "mg", true
	case 0x338F:
		return "kg", true
	case 0x3390:
		return "Hz", true
	case 0x3391:
		return "kHz", true
	case 0x3392:
		return "MHz", true
	case 0x3393:
		return "GHz", true
	case 0x3394:
		return "THz", true
	case 0x3396:
		return "ml", true
	case 0x3397:
		return "dl", true
	case 0x3398:
		return "kl", true
	case 0x3399:
		return "fm", true
	case 0x339A:
		return "nm", true
	case 0x339C:
		return "mm", true
	case 0x339D:
		return "cm", true
	case 0x339E:
		return "km", true
	case 0x339F:
		return "mm2", true
	case 0x33A0:
		return "cm2", true
	case 0x33A1:
		return "m2", true
	case 0x33A2:
		return "km2", true
	case 0x33A3:
		return "mm3", true
	case 0x33A4:
		return "cm3", true
	case 0x33A5:
		return "m3", true
	case 0x33A6:
		return "km3", true
	case 0x33A7:
		return "m/s", true
	case 0x33A8:
		return "m/s2", true
	case 0x33A9:
		return "Pa", true
	case 0x33AA:
		return "kPa", true
	case 0x33AB:
		return "MPa", true
	case 0x33AC:
		return "GPa", true
	case 0x33AD:
		return "rad", true
	case 0x33AE:
		return "rad/s", true
	case 0x33AF:
		return "rad/s2", true
	case 0x33B0:
		return "ps", true
	case 0x33B1:
		return "ns", true
	case 0x33B3:
		return "ms", true
	case 0x33B4:
		return "pV", true
	case 0x33B5:
		return "nV", true
	case 0x33B7:
		return "mV", true
	case 0x33B8:
		return "kV", true
	case 0x33B9:
		return "MV", true
	case 0x33BA:
		return "pW", true
	case 0x33BB:
		return "nW", true
	case 0x33BD:
		return "mW", true
	case 0x33BE:
		return "kW", true
	case 0x33BF:
		return "MW", true
	case 0x33C2:
		return "a.m.", true
	case 0x33C3:
		return "Bq", true
	case 0x33C4:
		return "cc", true
	case 0x33C5:
		return "cd", true
	case 0x33C6:
		return "C/kg", true
	case 0x33C7:
		return "Co.", true
	case 0x33C8:
		return "dB", true
	case 0x33C9:
		return "Gy", true
	case 0x33CA:
		return "ha", true
	case 0x33CB:
		return "HP", true
	case 0x33CC:
		return "in", true
	case 0x33CD:
		return "KK", true
	case 0x33CE:
		return "KM", true
	case 0x33CF:
		return "kt", true
	case 0x33D0:
		return "lm", true
	case 0x33D1:
		return "ln", true
	case 0x33D2:
		return "log", true
	case 0x33D3:
		return "lx", true
	case 0x33D4:
		return "mb", true
	case 0x33D5:
		return "mil", true
	case 0x33D6:
		return "mol", true
	case 0x33D7:
		return "PH", true
	case 0x33D8:
		return "p.m.", true
	case 0x33D9:
		return "PPM", true
	case 0x33DA:
		return "PR", true
	case 0x33DB:
		return "sr", true
	case 0x33DC:
		return "Sv", true
	case 0x33DD:
		return "Wb", true
	case 0x33DE:
		return "V/m", true
	case 0x33DF:
		return "A/m", true
	case 0x33FF:
		return "gal", true
	default:
		return "", false
	}
}

// foldLetterlikePieces maps letterlike signs to the ASCII sequences NFKC
// produces. This pass does not run NFKC, so a stored secret written with
// those forms would stay visible. Each output byte keeps the original
// rune's range. Single-letter forms in this block are folded with the
// mathematical letters. The rupee sign and CJK square units stay out.
func foldLetterlikePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := letterlikeASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldLetterlikeString(s string) string {
	if !letterlikeFolded(s) {
		return s
	}
	return renderPieces(foldLetterlikePieces(rawPieces(s)))
}

func letterlikeFolded(s string) bool {
	for _, r := range s {
		if _, ok := letterlikeASCII(r); ok {
			return true
		}
	}
	return false
}

func letterlikeASCII(r rune) (string, bool) {
	switch r {
	case 0x2100:
		return "a/c", true
	case 0x2101:
		return "a/s", true
	case 0x2105:
		return "c/o", true
	case 0x2106:
		return "c/u", true
	case 0x2116:
		return "No", true
	case 0x2120:
		return "SM", true
	case 0x2121:
		return "TEL", true
	case 0x2122:
		return "TM", true
	case 0x213B:
		return "FAX", true
	default:
		return "", false
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
// modifier fold lists them. Letterlike signs that expand to more than one
// character are folded separately. One output piece covers the original rune.
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
	// Tag percent is a format character. It stays out of percentASCII so the
	// credential drop reading can still remove an inserted one. This fold is
	// only used to find a percent-encoded colon in proxy userinfo.
	if r == 0xE0025 {
		return '%', true
	}
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

// foldCredentialPieces maps compatibility letters, digits, latin
// ligatures, circled numbers, digit full stops, digit commas, parenthesized numbers, parenthesized letters, enclosed abbreviations, letterlike signs, square symbols, the rupee sign, vulgar fractions, and token punctuation, including the percent sign, exclamation
// mark, consecutive equals signs, dot leaders, reverse solidus, number sign, dollar sign,
// ampersand, asterisk, question mark,
// semicolon, comma, curly brackets, square brackets, less-than and
// greater-than signs, the grave accent, the circumflex accent, the vertical
// line, the apostrophe, the quotation mark, the colon, and the commercial
// at, to ASCII. Credential redaction does not run NFKC.
// The percent fold is part of this result because the decode loop consumes
// it: a compatibility percent or hex digit still starts the next escape
// layer. Marks are not dropped here.
func foldCredentialPieces(in []secretPiece) []secretPiece {
	return foldCommercialAtPieces(foldColonPieces(foldQuotationPieces(foldApostrophePieces(foldVerticalLinePieces(foldCircumflexPieces(foldGravePieces(foldLessGreaterPieces(foldBracketPieces(foldBracePieces(foldCommaPieces(foldSemicolonPieces(foldQuestionPieces(foldAsteriskPieces(foldAmpersandPieces(foldDollarPieces(foldNumberSignPieces(foldReverseSolidusPieces(foldEqualsRunPieces(foldDoublePunctuationPieces(foldExclamationPieces(foldPercentPieces(foldDotLeaderPieces(foldDotPieces(foldHyphenPieces(foldFullwidthPieces(foldSquarePieces(foldFractionPieces(foldRupeePieces(foldLetterlikePieces(foldMathPieces(foldParenLetterPieces(foldParenNumberPieces(foldDigitCommaPieces(foldDigitStopPieces(foldCircledNumberPieces(foldEnclosedAbbrevPieces(foldEnclosedPieces(foldSuperSubPieces(foldModifierPieces(foldSegmentedPieces(foldAdditiveRomanPieces(foldRomanPieces(foldLigaturePieces(foldLongSPieces(foldPlusEqualsPieces(foldLowLinePieces(foldSolidusTildePieces(foldParenPieces(in)))))))))))))))))))))))))))))))))))))))))))))))))
}

func foldCredentialString(s string) string {
	return foldCommercialAtString(foldColonString(foldQuotationString(foldApostropheString(foldVerticalLineString(foldCircumflexString(foldGraveString(foldLessGreaterString(foldBracketString(foldBraceString(foldCommaString(foldSemicolonString(foldQuestionString(foldAsteriskString(foldAmpersandString(foldDollarString(foldNumberSignString(foldReverseSolidusString(foldEqualsRunString(foldDoublePunctuationString(foldExclamationString(foldPercentString(foldDotLeaderString(foldDotString(foldHyphenString(foldFullwidthString(foldSquareString(foldFractionString(foldRupeeString(foldLetterlikeString(foldMathString(foldParenLetterString(foldParenNumberString(foldDigitCommaString(foldDigitStopString(foldCircledNumberString(foldEnclosedAbbrevString(foldEnclosedString(foldSuperSubString(foldModifierString(foldSegmentedString(foldAdditiveRomanString(foldRomanString(foldLigatureString(foldLongSString(foldPlusEqualsString(foldLowLineString(foldSolidusTildeString(foldParenString(s)))))))))))))))))))))))))))))))))))))))))))))))))
}

// foldCommercialAtPieces maps the small and fullwidth commercial at to
// ASCII '@'. NFKC folds them, and this pass does not run NFKC, so a stored
// secret written with those forms would stay visible. This pass does not
// decide where a proxy password ends. No other character NFKC-folds to '@',
// so at-shaped marks stay out. One output piece covers the original rune.
func foldCommercialAtPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := commercialAtASCII(r); ok {
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

func foldCommercialAtString(s string) string {
	if !commercialAtFolded(s) {
		return s
	}
	return renderPieces(foldCommercialAtPieces(rawPieces(s)))
}

func commercialAtFolded(s string) bool {
	for _, r := range s {
		if _, ok := commercialAtASCII(r); ok {
			return true
		}
	}
	return false
}

func commercialAtASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE6B, 0xFF20:
		return '@', true
	default:
		return 0, false
	}
}

// foldSpacePieces maps compatibility spaces to ASCII ' '. NFKC folds them,
// and this pass does not run NFKC, so a stored secret written with those
// spaces would stay visible. This is a separate reading from dropMarkPieces:
// dropping the space would join the token and miss the stored ' '. Ogham
// space does not NFKC-fold to ' ', and neither do tab, line separators, or
// zero-width spaces, so they stay out. This pass does not decide where a
// proxy password ends. One output piece covers the original rune.
func foldSpacePieces(in []secretPiece) ([]secretPiece, bool) {
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
		if folded, ok := spaceASCII(r); ok {
			out = append(out, secretPiece{b: folded, start: in[i].start, end: in[i+size-1].end})
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

func foldSpaceString(s string) string {
	if !spaceFolded(s) {
		return s
	}
	folded, _ := foldSpacePieces(rawPieces(s))
	return renderPieces(folded)
}

func spaceFolded(s string) bool {
	for _, r := range s {
		if _, ok := spaceASCII(r); ok {
			return true
		}
	}
	return false
}

func spaceASCII(r rune) (byte, bool) {
	switch r {
	case 0x00A0, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
		0x2007, 0x2008, 0x2009, 0x200A, 0x202F, 0x205F, 0x3000:
		return ' ', true
	default:
		return 0, false
	}
}

// foldColonPieces maps colon lookalikes to ASCII ':'. Compatibility
// vertical, small, and fullwidth colons NFKC-fold to ':'. Ratio, modifier
// colons, and the other non-mark lookalikes do not, but a management
// response can still hide a stored colon with them. This pass does not run
// NFKC. Visarga signs are spacing marks and stay on a separate reading so
// an inserted visarga can still be dropped. Mongolian and Manchu full stops
// stay dots. Tag colon stays on the tag-punctuation reading. One output
// piece covers the original rune.
func foldColonPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := colonASCII(r); ok {
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

func foldColonString(s string) string {
	if !colonFolded(s) {
		return s
	}
	return renderPieces(foldColonPieces(rawPieces(s)))
}

func colonFolded(s string) bool {
	for _, r := range s {
		if _, ok := colonASCII(r); ok {
			return true
		}
	}
	return false
}

func colonASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE13, 0xFE55, 0xFF1A,
		0x2236, 0x02D0, 0x02D1, 0x10781, 0x10782, 0xA789, 0x02F8,
		0x0703, 0x0704, 0x0705, 0x0706, 0x0707, 0x0708, 0x0709,
		0x0589, 0x05C3, 0x1361, 0x1365, 0x1366, 0x205A, 0x205D,
		0x1804, 0xA6F4, 0x2A74, 0x2254, 0x2255, 0x2982, 0x2AF6,
		0x12471, 0x12472, 0x12473, 0x12474, 0x1DA8A,
		0xFE30, 0x16EC, 0x0831, 0x10AF5, 0x1123A, 0xA4FD,
		0x1393, 0x1D108, 0x11DD9, 0x2237, 0x2E2C:
		return ':', true
	default:
		return 0, false
	}
}

// foldVisargaColonPieces maps visarga signs to ASCII ':'. They are spacing
// marks, so the drop reading still removes an inserted visarga. Folding is
// separate: dropping the mark would delete a stored colon and the token
// would no longer match. One output piece covers the original rune.
func foldVisargaColonPieces(in []secretPiece) ([]secretPiece, bool) {
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
		if visargaColon(r) {
			out = append(out, secretPiece{b: ':', start: in[i].start, end: in[i+size-1].end})
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

func foldVisargaColonString(s string) string {
	if !visargaColonFolded(s) {
		return s
	}
	folded, _ := foldVisargaColonPieces(rawPieces(s))
	return renderPieces(folded)
}

func visargaColonFolded(s string) bool {
	for _, r := range s {
		if visargaColon(r) {
			return true
		}
	}
	return false
}

func visargaColon(r rune) bool {
	switch r {
	case 0x0903, 0x0983, 0x0A03, 0x0A83, 0x0C03, 0x0C83, 0x0D03, 0x0D83,
		0x0F7F, 0x1038, 0x17C7,
		0x11002, 0x11082, 0x11182, 0x11303, 0x114C1, 0x115BE, 0x116AC,
		0x11838, 0x119DF, 0x11A39, 0x11C3E:
		return true
	default:
		return false
	}
}

// foldQuotationPieces maps the fullwidth quotation mark to ASCII quotation mark.
// NFKC folds it, and this pass does not run NFKC, so a stored secret written
// with that form would stay visible. Curly double quotes, the double prime,
// and quotation ornaments do not fold to a quotation mark, so they stay out.
// One output piece covers the original rune.
func foldQuotationPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := quotationASCII(r); ok {
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

func foldQuotationString(s string) string {
	if !quotationFolded(s) {
		return s
	}
	return renderPieces(foldQuotationPieces(rawPieces(s)))
}

func quotationFolded(s string) bool {
	for _, r := range s {
		if _, ok := quotationASCII(r); ok {
			return true
		}
	}
	return false
}

func quotationASCII(r rune) (byte, bool) {
	switch r {
	case 0xFF02:
		return '"', true
	default:
		return 0, false
	}
}

// foldApostrophePieces maps the fullwidth apostrophe to ASCII apostrophe.
// NFKC folds it, and this pass does not run NFKC, so a stored secret written
// with that form would stay visible. Curly single quotes, the modifier
// apostrophe, prime, and the Armenian apostrophe do not fold to apostrophe,
// so they stay out. One output piece covers the original rune.
func foldApostrophePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := apostropheASCII(r); ok {
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

func foldApostropheString(s string) string {
	if !apostropheFolded(s) {
		return s
	}
	return renderPieces(foldApostrophePieces(rawPieces(s)))
}

func apostropheFolded(s string) bool {
	for _, r := range s {
		if _, ok := apostropheASCII(r); ok {
			return true
		}
	}
	return false
}

func apostropheASCII(r rune) (byte, bool) {
	switch r {
	case 0xFF07:
		return '\'', true
	default:
		return 0, false
	}
}

// foldVerticalLinePieces maps the fullwidth vertical line to ASCII '|'.
// NFKC folds it, and this pass does not run NFKC, so a stored secret written
// with that form would stay visible. Broken bar, divides, the dental click,
// and box-drawing verticals do not fold to '|', so they stay out. One output
// piece covers the original rune.
func foldVerticalLinePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := verticalLineASCII(r); ok {
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

func foldVerticalLineString(s string) string {
	if !verticalLineFolded(s) {
		return s
	}
	return renderPieces(foldVerticalLinePieces(rawPieces(s)))
}

func verticalLineFolded(s string) bool {
	for _, r := range s {
		if _, ok := verticalLineASCII(r); ok {
			return true
		}
	}
	return false
}

func verticalLineASCII(r rune) (byte, bool) {
	switch r {
	case 0xFF5C:
		return '|', true
	default:
		return 0, false
	}
}

// foldCircumflexPieces maps the fullwidth circumflex accent to ASCII '^'.
// NFKC folds it, and this pass does not run NFKC, so a stored secret written
// with that form would stay visible. Modifier letter circumflex, the caret,
// the up arrowhead, and combining circumflex do not fold to '^', so they stay
// out. One output piece covers the original rune.
func foldCircumflexPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := circumflexASCII(r); ok {
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

func foldCircumflexString(s string) string {
	if !circumflexFolded(s) {
		return s
	}
	return renderPieces(foldCircumflexPieces(rawPieces(s)))
}

func circumflexFolded(s string) bool {
	for _, r := range s {
		if _, ok := circumflexASCII(r); ok {
			return true
		}
	}
	return false
}

func circumflexASCII(r rune) (byte, bool) {
	switch r {
	case 0xFF3E:
		return '^', true
	default:
		return 0, false
	}
}

// foldGravePieces maps Greek varia and the fullwidth grave accent to ASCII
// '`'. NFKC folds them, and this pass does not run NFKC, so a stored secret
// written with those forms would stay visible. Modifier letter grave accent,
// combining grave, acute accent, and Greek psili do not fold to '`', so they
// stay out. One output piece covers the original rune.
func foldGravePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := graveASCII(r); ok {
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

func foldGraveString(s string) string {
	if !graveFolded(s) {
		return s
	}
	return renderPieces(foldGravePieces(rawPieces(s)))
}

func graveFolded(s string) bool {
	for _, r := range s {
		if _, ok := graveASCII(r); ok {
			return true
		}
	}
	return false
}

func graveASCII(r rune) (byte, bool) {
	switch r {
	case 0x1FEF, 0xFF40:
		return '`', true
	default:
		return 0, false
	}
}

// foldLessGreaterPieces maps small and fullwidth less-than and greater-than
// signs to ASCII '<' and '>'. NFKC folds them, and this pass does not run
// NFKC, so a stored secret written with those forms would stay visible.
// Angle brackets, guillemets, and less-than-or-equal signs do not fold to
// '<' or '>', so they stay out. One output piece covers the original rune.
func foldLessGreaterPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := lessGreaterASCII(r); ok {
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

func foldLessGreaterString(s string) string {
	if !lessGreaterFolded(s) {
		return s
	}
	return renderPieces(foldLessGreaterPieces(rawPieces(s)))
}

func lessGreaterFolded(s string) bool {
	for _, r := range s {
		if _, ok := lessGreaterASCII(r); ok {
			return true
		}
	}
	return false
}

func lessGreaterASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE64, 0xFF1C:
		return '<', true
	case 0xFE65, 0xFF1E:
		return '>', true
	default:
		return 0, false
	}
}

// foldBracketPieces maps vertical and fullwidth square brackets to ASCII
// '[' and ']'. NFKC folds them, and this pass does not run NFKC, so a
// stored secret written with those forms would stay visible. Quilled,
// mathematical, lenticular, and white square brackets do not fold to
// '[' or ']', so they stay out. One output piece covers the original rune.
func foldBracketPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := bracketASCII(r); ok {
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

func foldBracketString(s string) string {
	if !bracketFolded(s) {
		return s
	}
	return renderPieces(foldBracketPieces(rawPieces(s)))
}

func bracketFolded(s string) bool {
	for _, r := range s {
		if _, ok := bracketASCII(r); ok {
			return true
		}
	}
	return false
}

func bracketASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE47, 0xFF3B:
		return '[', true
	case 0xFE48, 0xFF3D:
		return ']', true
	default:
		return 0, false
	}
}

// foldBracePieces maps vertical, small, and fullwidth curly brackets to
// ASCII '{' and '}'. NFKC folds them, and this pass does not run NFKC, so a
// stored secret written with those forms would stay visible. Tortoise shell
// brackets, white curly brackets, and curly bracket ornaments do not fold
// to '{' or '}', so they stay out. One output piece covers the original rune.
func foldBracePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := braceASCII(r); ok {
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

func foldBraceString(s string) string {
	if !braceFolded(s) {
		return s
	}
	return renderPieces(foldBracePieces(rawPieces(s)))
}

func braceFolded(s string) bool {
	for _, r := range s {
		if _, ok := braceASCII(r); ok {
			return true
		}
	}
	return false
}

func braceASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE37, 0xFE5B, 0xFF5B:
		return '{', true
	case 0xFE38, 0xFE5C, 0xFF5D:
		return '}', true
	default:
		return 0, false
	}
}

// foldCommaPieces maps vertical, small, and fullwidth commas to ASCII ','.
// NFKC folds them, and this pass does not run NFKC, so a stored secret
// written with those forms would stay visible. Arabic, ideographic, reversed,
// and medieval commas do not fold to ','. Digit commas expand to a digit and
// a comma and are folded separately. One output piece covers the original rune.
func foldCommaPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := commaASCII(r); ok {
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

func foldCommaString(s string) string {
	if !commaFolded(s) {
		return s
	}
	return renderPieces(foldCommaPieces(rawPieces(s)))
}

func commaFolded(s string) bool {
	for _, r := range s {
		if _, ok := commaASCII(r); ok {
			return true
		}
	}
	return false
}

func commaASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE10, 0xFE50, 0xFF0C:
		return ',', true
	default:
		return 0, false
	}
}

// foldSemicolonPieces maps the Greek question mark and vertical, small, and
// fullwidth semicolons to ASCII ';'. NFKC folds them, and this pass does not
// run NFKC, so a stored secret written with those forms would stay visible.
// Arabic, Ethiopic, reversed, and turned semicolons do not fold to ';', so
// they stay out. One output piece covers the original rune.
func foldSemicolonPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := semicolonASCII(r); ok {
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

func foldSemicolonString(s string) string {
	if !semicolonFolded(s) {
		return s
	}
	return renderPieces(foldSemicolonPieces(rawPieces(s)))
}

func semicolonFolded(s string) bool {
	for _, r := range s {
		if _, ok := semicolonASCII(r); ok {
			return true
		}
	}
	return false
}

func semicolonASCII(r rune) (byte, bool) {
	switch r {
	case 0x037E, 0xFE14, 0xFE54, 0xFF1B:
		return ';', true
	default:
		return 0, false
	}
}

// foldQuestionPieces maps vertical, small, and fullwidth question marks to
// ASCII '?'. NFKC folds them, and this pass does not run NFKC, so a stored
// secret written with those forms would stay visible. A double question mark
// expands to "??", and a question exclamation mark expands to "?!". Those two
// are folded with the doubled exclamation marks. Inverted and Arabic question
// marks, the interrobang, and question-mark ornaments do not fold to '?'.
// The Greek question mark folds to ';', so it stays out. One output piece
// covers the original rune.
func foldQuestionPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := questionASCII(r); ok {
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

func foldQuestionString(s string) string {
	if !questionFolded(s) {
		return s
	}
	return renderPieces(foldQuestionPieces(rawPieces(s)))
}

func questionFolded(s string) bool {
	for _, r := range s {
		if _, ok := questionASCII(r); ok {
			return true
		}
	}
	return false
}

func questionASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE16, 0xFE56, 0xFF1F:
		return '?', true
	default:
		return 0, false
	}
}

// foldAsteriskPieces maps small and fullwidth asterisks to ASCII '*'.
// NFKC folds them, and this pass does not run NFKC, so a stored secret
// written with those forms would stay visible. A low asterisk, the asterisk
// operator, and heavy or spoked asterisk ornaments do not fold to '*', so
// they stay out. One output piece covers the original rune.
func foldAsteriskPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := asteriskASCII(r); ok {
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

func foldAsteriskString(s string) string {
	if !asteriskFolded(s) {
		return s
	}
	return renderPieces(foldAsteriskPieces(rawPieces(s)))
}

func asteriskFolded(s string) bool {
	for _, r := range s {
		if _, ok := asteriskASCII(r); ok {
			return true
		}
	}
	return false
}

func asteriskASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE61, 0xFF0A:
		return '*', true
	default:
		return 0, false
	}
}

// foldAmpersandPieces maps small and fullwidth ampersands to ASCII '&'.
// NFKC folds them, and this pass does not run NFKC, so a stored secret
// written with those forms would stay visible. A turned ampersand and
// heavy or swash ampersand ornaments do not fold to '&', so they stay out.
// One output piece covers the original rune.
func foldAmpersandPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := ampersandASCII(r); ok {
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

func foldAmpersandString(s string) string {
	if !ampersandFolded(s) {
		return s
	}
	return renderPieces(foldAmpersandPieces(rawPieces(s)))
}

func ampersandFolded(s string) bool {
	for _, r := range s {
		if _, ok := ampersandASCII(r); ok {
			return true
		}
	}
	return false
}

func ampersandASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE60, 0xFF06:
		return '&', true
	default:
		return 0, false
	}
}

// foldDollarPieces maps small and fullwidth dollar signs to ASCII '$'.
// NFKC folds them, and this pass does not run NFKC, so a stored secret
// written with those forms would stay visible. A heavy dollar sign and
// other currency signs do not fold to '$', so they stay out. One output
// piece covers the original rune.
func foldDollarPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := dollarASCII(r); ok {
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

func foldDollarString(s string) string {
	if !dollarFolded(s) {
		return s
	}
	return renderPieces(foldDollarPieces(rawPieces(s)))
}

func dollarFolded(s string) bool {
	for _, r := range s {
		if _, ok := dollarASCII(r); ok {
			return true
		}
	}
	return false
}

func dollarASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE69, 0xFF04:
		return '$', true
	default:
		return 0, false
	}
}

// foldNumberSignPieces maps small and fullwidth number signs to ASCII '#'.
// NFKC folds them, and this pass does not run NFKC, so a stored secret
// written with those forms would stay visible. Music sharp, viewdata
// square, and the reference mark do not fold to '#', so they stay out.
// One output piece covers the original rune.
func foldNumberSignPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := numberSignASCII(r); ok {
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

func foldNumberSignString(s string) string {
	if !numberSignFolded(s) {
		return s
	}
	return renderPieces(foldNumberSignPieces(rawPieces(s)))
}

func numberSignFolded(s string) bool {
	for _, r := range s {
		if _, ok := numberSignASCII(r); ok {
			return true
		}
	}
	return false
}

func numberSignASCII(r rune) (byte, bool) {
	switch r {
	case 0xFE5F, 0xFF03:
		return '#', true
	default:
		return 0, false
	}
}

// foldReverseSolidusPieces maps reverse-solidus characters to ASCII.
// NFKC folds the small and fullwidth forms. Yen, won, set minus, the reverse
// solidus operator, the stroked form, big reverse solidus, and the OCR double
// backslash do not, but a management response can still hide a stored
// backslash with them. Falling diagonals do not either: the box drawing, the
// short box drawings from upper centre to middle right and from middle left
// to lower centre, the mathematical falling diagonal, the squared falling
// diagonal, CJK stroke D,
// the dot radical, the very heavy reverse solidus, the upper right
// block diagonals, the Greek notation slashes, and the kana repeat
// lower half. This pass does not run NFKC.
// Forward solidus lookalikes fold to '/'. The dot radical's ideograph
// folds here too. Reverse solidus preceding subset expands to a backslash
// plus a syllabic letter and does not NFKC-fold to a backslash. It stays
// one backslash so that letter cannot glue the token back together.
// The syllabic letter itself stays out. APL backslash bar is a backslash
// with a bar and does not NFKC-fold to a backslash. It stays one
// backslash. Quad backslash is that bar inside a square and does not
// NFKC-fold to a backslash either. It stays one backslash so the square
// cannot glue the token back together. Circled reverse solidus is a
// backslash inside a circle and does not NFKC-fold to a backslash either.
// It stays one backslash so the circle cannot glue the token back together.
// APL circle backslash is that same slash inside an APL circle and does
// not NFKC-fold to a backslash either. It stays one backslash so the
// circle cannot glue the token back together. The circled division sign
// and the combining enclosing circle backslash stay out. The diagonal
// cross, the chevron diagonals, and the negative diamond stay out. The
// negative short diagonal folds to a slash. The upper right block
// diagonal from upper centre to lower right is that falling stroke as a
// narrow block and does not NFKC-fold to a backslash. It stays one
// backslash. The upper right block diagonal from upper left to lower
// middle right is that same falling stroke as a wider block and does
// not NFKC-fold to a backslash either. It stays one backslash. The
// upper right block diagonal from upper middle left to lower middle
// right is that falling stroke across the middle and does not NFKC-fold
// to a backslash either. It stays one backslash. The upper right block
// diagonal from upper centre to lower middle right is that falling
// stroke stopped before the corner and does not NFKC-fold to a
// backslash either. It stays one backslash. The upper right block
// diagonal from upper left to upper middle right is that falling
// stroke along the top and does not NFKC-fold to a backslash either.
// It stays one backslash. The upper right block diagonal from upper
// centre to upper middle right is that shorter falling stroke along
// the top and does not NFKC-fold to a backslash either. It stays one
// backslash. The upper right block diagonal from upper left to lower
// centre is that wider falling stroke stopped at the lower centre and
// does not NFKC-fold to a backslash either. It stays one backslash.
// The upper right block diagonal from upper middle left to lower right
// is that falling stroke continued to the corner and does not NFKC-fold
// to a backslash either. It stays one backslash. The upper right block
// diagonal from upper middle left to lower centre is that shorter falling
// stroke stopped at the lower centre and does not NFKC-fold to a
// backslash either. It stays one backslash. The upper right block
// diagonal from lower middle left to lower right is that short falling
// stroke along the lower edge and does not NFKC-fold to a backslash
// either. It stays one backslash. The upper right block diagonal from
// lower middle left to lower centre is that shorter falling stroke
// stopped before the corner and does not NFKC-fold to a backslash
// either. It stays one backslash. The lower left block diagonal from
// upper centre to lower right is that falling stroke as a narrow block
// and does not NFKC-fold to a backslash. It stays one backslash. The
// lower left block diagonal from upper left to lower middle right is
// that same falling stroke as a wider block and does not NFKC-fold to
// a backslash either. It stays one backslash. The lower left block
// diagonal from upper middle left to lower middle right is that falling
// stroke across the middle and does not NFKC-fold to a backslash either.
// It stays one backslash. The lower left block diagonal from upper
// centre to lower middle right is that falling stroke stopped before
// the corner and does not NFKC-fold to a backslash either. It stays one
// backslash. The lower left block diagonal from upper left to upper
// middle right is that falling stroke along the top and does not
// NFKC-fold to a backslash either. It stays one backslash. The lower
// left block diagonal from upper centre to upper middle right is that
// shorter falling stroke along the top and does not NFKC-fold to a
// backslash either. It stays one backslash. The lower left block
// diagonal from upper left to lower centre is that wider falling stroke
// stopped at the lower centre and does not NFKC-fold to a backslash
// either. It stays one backslash. The lower left block diagonal from
// upper middle left to lower right is that falling stroke continued to
// the corner and does not NFKC-fold to a backslash either. It stays one
// backslash. The other wider lower-left block diagonals stay out.
// Other letters and ideographs stay out.
// One output piece covers the original rune.
func foldReverseSolidusPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := reverseSolidusASCII(r); ok {
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

func foldReverseSolidusString(s string) string {
	if !reverseSolidusFolded(s) {
		return s
	}
	return renderPieces(foldReverseSolidusPieces(rawPieces(s)))
}

func reverseSolidusFolded(s string) bool {
	for _, r := range s {
		if _, ok := reverseSolidusASCII(r); ok {
			return true
		}
	}
	return false
}

func reverseSolidusASCII(r rune) (byte, bool) {
	switch r {
	case 0x00A5, 0x20A9, 0x2216, 0x2340, 0x2342, 0x2349, 0x244A, 0x2572, 0x27C8, 0x27CD, 0x29B8, 0x29C5, 0x29F5, 0x29F7, 0x29F9, 0x2F02, 0x3035, 0x31D4, 0x4E36, 0xFE68, 0xFF3C, 0x1D20F, 0x1D23A, 0x1D23B, 0x1F67D, 0x1FBA1, 0x1FBA2, 0x1FB3F, 0x1FB40, 0x1FB4C, 0x1FB4D, 0x1FB4E, 0x1FB4F, 0x1FB50, 0x1FB51, 0x1FB52, 0x1FB53, 0x1FB54, 0x1FB55, 0x1FB56, 0x1FB62, 0x1FB63, 0x1FB64, 0x1FB65, 0x1FB66, 0x1FB67:
		return '\\', true
	default:
		return 0, false
	}
}

// foldEqualsRunPieces maps two and three consecutive equals signs to the
// ASCII runs NFKC produces. This pass does not run NFKC, so a stored secret
// written with those forms would stay visible. Each output byte keeps the
// original rune's range. A single equals sign is folded with the plus signs.
// Double colon equal expands to "::=" and is a colon lookalike, so it stays
// out. Not-equal and identical-to do not fold to ASCII equals signs.
func foldEqualsRunPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := equalsRunASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldEqualsRunString(s string) string {
	if !equalsRunFolded(s) {
		return s
	}
	return renderPieces(foldEqualsRunPieces(rawPieces(s)))
}

func equalsRunFolded(s string) bool {
	for _, r := range s {
		if _, ok := equalsRunASCII(r); ok {
			return true
		}
	}
	return false
}

func equalsRunASCII(r rune) (string, bool) {
	switch r {
	case 0x2A75:
		return "==", true
	case 0x2A76:
		return "===", true
	default:
		return "", false
	}
}

// foldDoublePunctuationPieces maps the doubled question and exclamation
// marks to the ASCII pairs NFKC produces. This pass does not run NFKC, so a
// stored secret written with those marks would stay visible. Each output
// byte keeps the original rune's range. Consecutive equals signs expand
// to "==" or "===" and are folded separately. Two-dot leaders and ellipses
// expand to repeated dots and are folded separately. The interrobang and
// inverted marks are not these four marks, so they stay out.
func foldDoublePunctuationPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := doublePunctuationASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldDoublePunctuationString(s string) string {
	if !doublePunctuationFolded(s) {
		return s
	}
	return renderPieces(foldDoublePunctuationPieces(rawPieces(s)))
}

func doublePunctuationFolded(s string) bool {
	for _, r := range s {
		if _, ok := doublePunctuationASCII(r); ok {
			return true
		}
	}
	return false
}

func doublePunctuationASCII(r rune) (string, bool) {
	switch r {
	case 0x203C:
		return "!!", true
	case 0x2047:
		return "??", true
	case 0x2048:
		return "?!", true
	case 0x2049:
		return "!?", true
	default:
		return "", false
	}
}

// foldExclamationPieces maps exclamation marks to ASCII '!'.
// NFKC folds them, and this pass does not run NFKC, so a stored secret
// written with those forms would stay visible. A double exclamation mark
// expands to "!!", and an exclamation question mark expands to "!?". Those
// two are folded with the doubled question marks. Inverted exclamation, the
// retroflex click, and heavy exclamation ornaments do not fold to '!', so
// they stay out. One output piece covers the original rune.
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
// stay visible. Parenthesized digits expand to parentheses and digits and
// are folded separately. Parenthesized hangul expands to more than one
// character. Flattened, white, double, and ornament parentheses do not fold
// to ASCII, so they stay out. One output piece covers the original rune.
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

// foldSolidusTildePieces maps solidus and tilde characters to ASCII.
// NFKC folds fullwidth solidus and fullwidth tilde. Division slash, fraction
// slash, solidus with overbar, and big solidus do not, but a management
// response can still hide a stored slash with them. Diagonal symbols do not
// either: Philippine punctuation, the caret insertion point, box drawings,
// the short box drawings from upper centre to middle left and from middle
// right to lower centre, a rising mathematical diagonal, dotted and heavy
// solidi, the modifier letter dot slash, the upper left block diagonals, squared rising diagonal, CJK strokes P and SP, the slash radical, the double and
// triple solidus operators, the kana repeat upper halves, the slash
// radical's ideograph, katakana no, and both Old Coptic esh letters.
// Halfwidth katakana no and circled katakana no NFKC-fold to katakana no
// rather than '/', so both are listed. Square nano and square notto
// expand to kana around that letter and do not NFKC-fold to a slash
// either. Each of those stays one slash, so an expanded form cannot
// glue the token back together. Other non-ASCII squares stay out.
// This pass does not run NFKC.
// A reverse solidus folds to a backslash on its own pass, including the
// Greek notation slashes and the kana repeat lower half. The full vertical
// kana repeat stays out. Katakana no and Old Coptic esh fold to '/'.
// Hiragana no stays out. Coptic old Nubian full stop expands to two
// reverse solidi, so it stays out. Superset preceding solidus expands
// to a syllabic letter plus a slash and stays one slash. The syllabic
// letters stay out. APL slash bar is a slash with a bar and does not
// NFKC-fold to a slash. It stays one slash. Quad slash is that bar
// inside a square and does not NFKC-fold to a slash either. It stays
// one slash so the square cannot glue the token back together. Circled
// division slash is a slash inside a circle and does not NFKC-fold to a
// slash either. It stays one slash so the circle cannot glue the token
// back together. APL circle backslash is a backslash inside a circle.
// It folds to a backslash on its own pass. The circled division sign
// stays out. The negative short diagonal, from middle right to lower
// centre, is that same rising stroke in negative and does not NFKC-fold
// to a slash. It stays one slash. The diagonal cross, the chevron
// diagonals, and the negative diamond stay out. The modifier letter dot
// slash is that dotted stroke in small form and does not NFKC-fold to a
// slash. It stays one slash. The dot vertical bar and the dot horizontal
// bar stay out. The upper left block diagonal from lower left to upper
// centre is that rising stroke as a narrow block and does not NFKC-fold
// to a slash. It stays one slash. The upper left block diagonal from
// lower middle left to upper right is that same rising stroke as a wider
// block and does not NFKC-fold to a slash either. It stays one slash.
// The upper left block diagonal from lower middle left to upper middle
// right is that rising stroke across the middle and does not NFKC-fold
// to a slash either. It stays one slash. The upper left block diagonal
// from lower middle left to upper centre is that rising stroke stopped
// at the centre and does not NFKC-fold to a slash either. It stays one
// slash. The upper left block diagonal from upper middle left to upper
// right is that rising stroke along the top and does not NFKC-fold to a
// slash either. It stays one slash. The upper left block diagonal from
// upper middle left to upper centre is that shorter rising stroke along
// the top and does not NFKC-fold to a slash either. It stays one slash.
// The other wider upper-left block diagonals stay out. Other letters stay out.
// Tilde operator, swung dash, and wave dash do not fold to '~'. Small tilde
// expands to a space plus a mark, so it stays out. One output piece covers
// the original rune.
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
	case 0x1735, 0x2041, 0x2044, 0x2215, 0x2298, 0x233F, 0x2341, 0x2571, 0x27C9, 0x27CB, 0x29C4, 0x29F6, 0x29F8, 0x2AFB, 0x2AFD, 0x2CC6, 0x2CC7, 0x2E4A, 0xA718, 0x2F03, 0x3033, 0x3034, 0x30CE, 0x31D2, 0x31D3, 0x32E8, 0x3328, 0x3329, 0x4E3F, 0xFF0F, 0xFF89, 0x1F67C, 0x1FBA0, 0x1FBA3, 0x1FB57, 0x1FB58, 0x1FB59, 0x1FB5A, 0x1FB5B, 0x1FB5C, 0x1FBBE:
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
// stay out. Two and three consecutive equals signs expand to more than one
// character and are folded separately. One output piece covers the original
// rune.
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

// foldLigaturePieces maps latin ligatures and compatibility digraphs to
// the ASCII letters NFKC produces. This pass does not run NFKC, so a stored
// token or a JWT written with those forms would stay visible. Each output
// byte keeps the original rune's range, so redaction removes the whole
// character. Roman numerals that expand to more than one letter, squared
// unit symbols, and the trademark sign are not latin ligatures, so they
// stay out.
func foldLigaturePieces(in []secretPiece) []secretPiece {
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
		if folded, ok := ligatureASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldLigatureString(s string) string {
	if !ligatureFolded(s) {
		return s
	}
	return renderPieces(foldLigaturePieces(rawPieces(s)))
}

func ligatureFolded(s string) bool {
	for _, r := range s {
		if _, ok := ligatureASCII(r); ok {
			return true
		}
	}
	return false
}

func ligatureASCII(r rune) (string, bool) {
	switch r {
	case 0x0132:
		return "IJ", true
	case 0x0133:
		return "ij", true
	case 0x01C7:
		return "LJ", true
	case 0x01C8:
		return "Lj", true
	case 0x01C9:
		return "lj", true
	case 0x01CA:
		return "NJ", true
	case 0x01CB:
		return "Nj", true
	case 0x01CC:
		return "nj", true
	case 0x01F1:
		return "DZ", true
	case 0x01F2:
		return "Dz", true
	case 0x01F3:
		return "dz", true
	case 0xFB00:
		return "ff", true
	case 0xFB01:
		return "fi", true
	case 0xFB02:
		return "fl", true
	case 0xFB03:
		return "ffi", true
	case 0xFB04:
		return "ffl", true
	case 0xFB05, 0xFB06:
		return "st", true
	default:
		return "", false
	}
}

// foldLongSPieces maps latin small letter long s to ASCII s.
// NFKC folds it, and this pass does not run NFKC, so a stored token or a
// JWT written with that form would stay visible. Long s with a dot or a
// stroke stays a phonetic letter. The long s t ligature expands to "st" and
// is folded with the other latin ligatures. One output piece covers the
// original rune.
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
// and the other additive numerals expand to more than one letter and are
// folded separately. The archaic thousand signs do not fold to ASCII.
// Those stay out. One output piece covers the original rune.
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

// foldAdditiveRomanPieces maps roman numerals that NFKC expands to more
// than one ASCII letter. This pass does not run NFKC, so a stored token or
// a JWT written with those forms would stay visible. Each output byte keeps
// the original rune's range. Single-letter numerals are folded elsewhere.
// Archaic thousand signs and late or early forms do not fold to ASCII
// letters, so they stay out. Vulgar fractions expand to digits around a
// slash and are folded separately.
func foldAdditiveRomanPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := additiveRomanASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldAdditiveRomanString(s string) string {
	if !additiveRomanFolded(s) {
		return s
	}
	return renderPieces(foldAdditiveRomanPieces(rawPieces(s)))
}

func additiveRomanFolded(s string) bool {
	for _, r := range s {
		if _, ok := additiveRomanASCII(r); ok {
			return true
		}
	}
	return false
}

func additiveRomanASCII(r rune) (string, bool) {
	switch r {
	case 0x2161:
		return "II", true
	case 0x2162:
		return "III", true
	case 0x2163:
		return "IV", true
	case 0x2165:
		return "VI", true
	case 0x2166:
		return "VII", true
	case 0x2167:
		return "VIII", true
	case 0x2168:
		return "IX", true
	case 0x216A:
		return "XI", true
	case 0x216B:
		return "XII", true
	case 0x2171:
		return "ii", true
	case 0x2172:
		return "iii", true
	case 0x2173:
		return "iv", true
	case 0x2175:
		return "vi", true
	case 0x2176:
		return "vii", true
	case 0x2177:
		return "viii", true
	case 0x2178:
		return "ix", true
	case 0x217A:
		return "xi", true
	case 0x217B:
		return "xii", true
	default:
		return "", false
	}
}

// foldSegmentedPieces maps segmented digits to ASCII.
// NFKC folds them, and this pass does not run NFKC, so a stored token or a
// JWT written with those forms would stay visible. Circled and full-stop
// digits expand to more than one character or are already covered by another
// fold, so they stay out. Parenthesized numbers are folded separately. One
// output piece covers the original rune.
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

// foldCircledNumberPieces maps circled numbers from ten through fifty to
// the two ASCII digits NFKC produces. This pass does not run NFKC, so a
// stored token or a JWT written with those forms would stay visible. Each
// output byte keeps the original rune's range. Circled digits below ten are
// one character and are folded with the other enclosed letters. Negative
// circled numbers and numbers on black squares do not fold to ASCII digits,
// so they stay out. Parenthesized numbers are folded separately. Digit full
// stops expand to a number and a full stop and are folded separately.
func foldCircledNumberPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := circledNumberASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldCircledNumberString(s string) string {
	if !circledNumberFolded(s) {
		return s
	}
	return renderPieces(foldCircledNumberPieces(rawPieces(s)))
}

func circledNumberFolded(s string) bool {
	for _, r := range s {
		if _, ok := circledNumberASCII(r); ok {
			return true
		}
	}
	return false
}

func circledNumberASCII(r rune) (string, bool) {
	switch {
	case r >= 0x2469 && r <= 0x2473:
		n := int(r-0x2469) + 10
		return string([]byte{byte('0' + n/10), byte('0' + n%10)}), true
	case r >= 0x3251 && r <= 0x325F:
		n := int(r-0x3251) + 21
		return string([]byte{byte('0' + n/10), byte('0' + n%10)}), true
	case r >= 0x32B1 && r <= 0x32BF:
		n := int(r-0x32B1) + 36
		return string([]byte{byte('0' + n/10), byte('0' + n%10)}), true
	default:
		return "", false
	}
}

// foldDigitStopPieces maps digit full stops to the ASCII number and full
// stop NFKC produces. This pass does not run NFKC, so a stored token or a
// JWT written with those forms would stay visible. Each output byte keeps
// the original rune's range. Digit zero full stop is the only supplementary
// form. Digit commas and parenthesized numbers are folded separately.
// Circled numbers do not fold to a trailing full stop, so they stay out.
func foldDigitStopPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := digitStopASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldDigitStopString(s string) string {
	if !digitStopFolded(s) {
		return s
	}
	return renderPieces(foldDigitStopPieces(rawPieces(s)))
}

func digitStopFolded(s string) bool {
	for _, r := range s {
		if _, ok := digitStopASCII(r); ok {
			return true
		}
	}
	return false
}

func digitStopASCII(r rune) (string, bool) {
	switch r {
	case 0x1F100:
		return "0.", true
	}
	switch {
	case r >= 0x2488 && r <= 0x2490:
		n := int(r-0x2488) + 1
		return string([]byte{byte('0' + n), '.'}), true
	case r >= 0x2491 && r <= 0x249B:
		n := int(r-0x2491) + 10
		return string([]byte{byte('0' + n/10), byte('0' + n%10), '.'}), true
	default:
		return "", false
	}
}

// foldDigitCommaPieces maps digit commas to the ASCII digit and comma NFKC
// produces. This pass does not run NFKC, so a stored secret written with
// those forms would stay visible. Each output byte keeps the original rune's
// range. Only the ten supplementary digit commas fold. Compatibility commas,
// digit full stops, and ideographic commas do not fold to a trailing comma
// here, so they stay out.
func foldDigitCommaPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := digitCommaASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldDigitCommaString(s string) string {
	if !digitCommaFolded(s) {
		return s
	}
	return renderPieces(foldDigitCommaPieces(rawPieces(s)))
}

func digitCommaFolded(s string) bool {
	for _, r := range s {
		if _, ok := digitCommaASCII(r); ok {
			return true
		}
	}
	return false
}

func digitCommaASCII(r rune) (string, bool) {
	if r < 0x1F101 || r > 0x1F10A {
		return "", false
	}
	return string([]byte{byte('0' + (r - 0x1F101)), ','}), true
}

// foldParenNumberPieces maps parenthesized numbers from one through twenty
// to the ASCII parentheses and digits NFKC produces. This pass does not run
// NFKC, so a stored secret written with those forms would stay visible. Each
// output byte keeps the original rune's range. Parenthesized letters are
// folded separately. Parenthesized hangul do not fold to ASCII digits, so
// they stay out.
func foldParenNumberPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := parenNumberASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldParenNumberString(s string) string {
	if !parenNumberFolded(s) {
		return s
	}
	return renderPieces(foldParenNumberPieces(rawPieces(s)))
}

func parenNumberFolded(s string) bool {
	for _, r := range s {
		if _, ok := parenNumberASCII(r); ok {
			return true
		}
	}
	return false
}

func parenNumberASCII(r rune) (string, bool) {
	switch {
	case r >= 0x2474 && r <= 0x247C:
		n := int(r-0x2474) + 1
		return string([]byte{'(', byte('0' + n), ')'}), true
	case r >= 0x247D && r <= 0x2487:
		n := int(r-0x247D) + 10
		return string([]byte{'(', byte('0' + n/10), byte('0' + n%10), ')'}), true
	default:
		return "", false
	}
}

// foldParenLetterPieces maps parenthesized Latin letters to the ASCII
// parentheses and letter NFKC produces. This pass does not run NFKC, so a
// stored secret written with those forms would stay visible. Each output
// byte keeps the original rune's range. Parenthesized numbers and
// parenthesized hangul do not fold to ASCII letters, so they stay out.
func foldParenLetterPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := parenLetterASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldParenLetterString(s string) string {
	if !parenLetterFolded(s) {
		return s
	}
	return renderPieces(foldParenLetterPieces(rawPieces(s)))
}

func parenLetterFolded(s string) bool {
	for _, r := range s {
		if _, ok := parenLetterASCII(r); ok {
			return true
		}
	}
	return false
}

func parenLetterASCII(r rune) (string, bool) {
	switch {
	case r >= 0x249C && r <= 0x24B5:
		return string([]byte{'(', byte('a' + (r - 0x249C)), ')'}), true
	case r >= 0x1F110 && r <= 0x1F129:
		return string([]byte{'(', byte('A' + (r - 0x1F110)), ')'}), true
	default:
		return "", false
	}
}

// foldEnclosedAbbrevPieces maps circled, squared, and raised Latin
// abbreviations to the ASCII letters NFKC produces. This pass does not run
// NFKC, so a stored secret written with those forms would stay visible.
// Each output byte keeps the original rune's range. Single enclosed letters
// are folded separately. CJK square units, letterlike signs, and negative
// circled letters do not fold here.
func foldEnclosedAbbrevPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := enclosedAbbrevASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldEnclosedAbbrevString(s string) string {
	if !enclosedAbbrevFolded(s) {
		return s
	}
	return renderPieces(foldEnclosedAbbrevPieces(rawPieces(s)))
}

func enclosedAbbrevFolded(s string) bool {
	for _, r := range s {
		if _, ok := enclosedAbbrevASCII(r); ok {
			return true
		}
	}
	return false
}

func enclosedAbbrevASCII(r rune) (string, bool) {
	switch r {
	case 0x1F12D:
		return "CD", true
	case 0x1F12E:
		return "WZ", true
	case 0x1F14A:
		return "HV", true
	case 0x1F14B:
		return "MV", true
	case 0x1F14C:
		return "SD", true
	case 0x1F14D:
		return "SS", true
	case 0x1F14E:
		return "PPV", true
	case 0x1F14F:
		return "WC", true
	case 0x1F16A:
		return "MC", true
	case 0x1F16B:
		return "MD", true
	case 0x1F16C:
		return "MR", true
	case 0x1F190:
		return "DJ", true
	default:
		return "", false
	}
}

// foldEnclosedPieces maps circled and squared Latin letters and digits to
// ASCII. NFKC folds them, and this pass does not run NFKC, so a stored
// token or a JWT written with those forms would stay visible. Circled
// italic C and R are the only circled italic letters. Circled numbers
// from ten through fifty expand to two digits and are folded separately.
// Parenthesized letters expand to parentheses plus a letter and are folded
// separately. Squared and circled abbreviations such as HV expand to more
// than one letter and are folded separately. Negative circled letters do
// not fold to ASCII, so they stay out. Digit full stops expand to a number
// and a full stop and are folded separately. One output piece covers the
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

// foldDotLeaderPieces maps the two-dot leader and horizontal ellipses to
// the repeated ASCII dots NFKC produces. This pass does not run NFKC, so a
// stored secret written with those forms would stay visible. Each output
// byte keeps the original rune's range. One dot leader is a single full
// stop and is folded with the other dots. The vertical two-dot leader
// NFKC-folds to "..", but proxy userinfo reads it as a colon, so it stays
// out of this pass. Midline ellipsis does not fold to ASCII dots.
func foldDotLeaderPieces(in []secretPiece) []secretPiece {
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
		if folded, ok := dotLeaderASCII(r); ok {
			start := in[i].start
			end := in[i+size-1].end
			for j := 0; j < len(folded); j++ {
				out = append(out, secretPiece{b: folded[j], start: start, end: end})
			}
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

func foldDotLeaderString(s string) string {
	if !dotLeaderFolded(s) {
		return s
	}
	return renderPieces(foldDotLeaderPieces(rawPieces(s)))
}

func dotLeaderFolded(s string) bool {
	for _, r := range s {
		if _, ok := dotLeaderASCII(r); ok {
			return true
		}
	}
	return false
}

func dotLeaderASCII(r rune) (string, bool) {
	switch r {
	case 0x2025:
		return "..", true
	case 0x2026, 0xFE19:
		return "...", true
	default:
		return "", false
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
	// matched or they hide the secret. Compatibility spaces that do NFKC-fold
	// to ASCII space also have a fold reading in findSecretSpans; this drop
	// still removes them so an inserted space cannot split a token.
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
