package httpx

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestRedactHidesProxyPassword(t *testing.T) {
	const password = "s3cret-proxy"
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890",
		"user:" + password + "@127.0.0.1:7890",
		"socks5://user:" + password + "@127.0.0.1:1080",
		"http://:" + password + "@127.0.0.1:7890",
		"http://user:" + password + "@",
		"http://user%3A" + password + "@127.0.0.1:7890",
		"http://user%3a" + password + "@127.0.0.1:7890",
		"user%3A" + password + "@127.0.0.1:7890",
		"http://user%253A" + password + "@127.0.0.1:7890",
		"http://user\uFF053A" + password + "@127.0.0.1:7890",
		"http://user\uFE6A3a" + password + "@127.0.0.1:7890",
		"http://user%\uFF13\uFF21" + password + "@127.0.0.1:7890",
		"http://user\uFF05253A" + password + "@127.0.0.1:7890",
		"http://user%3A" + password + "%zz@127.0.0.1:7890",
		"http://user%3A" + password + " proxy@127.0.0.1:1",
		"http://user:" + password + "@127.0.0.1:7890/path?" + password + "=1",
	}
	for _, in := range cases {
		got := Redact(in)
		if strings.Contains(got, password) || got == in {
			t.Fatalf("redact %q -> %q", in, got)
		}
	}
	if Redact("http://127.0.0.1:7890") != "http://127.0.0.1:7890" || Redact("") != "" || Redact("http://user@127.0.0.1:7890") != "http://user@127.0.0.1:7890" {
		t.Fatal("proxy without credentials changed")
	}
	unparsed := []string{
		"http://user:" + password + " proxy@127.0.0.1:7890",
		"http://user:" + password + "%zz@127.0.0.1:7890",
		"http://user:" + password + "\n" + "proxy@127.0.0.1:1",
		"//user:" + password + "@127.0.0.1:7890",
		"user:" + password + " proxy@127.0.0.1:7890",
	}
	for _, in := range unparsed {
		got := Redact(in)
		if strings.Contains(got, password) || got == in {
			t.Fatalf("unparsed redact %q -> %q", in, got)
		}
		if again := Redact(got); strings.Contains(again, password) {
			t.Fatalf("second redact leaked: %q", again)
		}
	}
	malformed := "http://user:" + password + "%zz@127.0.0.1:7890"
	if got := PreserveProxy(malformed, Redact(malformed)); got != malformed {
		t.Fatalf("malformed preserve %q", got)
	}
	again := Redact(Redact("user:" + password + "@127.0.0.1:7890"))
	if strings.Contains(again, password) {
		t.Fatalf("second redact leaked: %q", again)
	}
}

func TestParseProxyURLDoesNotEchoPassword(t *testing.T) {
	const password = "s3cret-proxy"
	_, err := ParseProxyURL("http://user:" + password + "@")
	if err == nil || strings.Contains(err.Error(), password) || strings.Contains(err.Error(), "user:") {
		t.Fatalf("missing host echoed credentials: %v", err)
	}
	_, err = ParseProxyURL("ftp://user:" + password + "@127.0.0.1:9")
	if err == nil || strings.Contains(err.Error(), password) {
		t.Fatalf("scheme error echoed credentials: %v", err)
	}
	parsed, err := ParseProxyURL("user:" + password + "@127.0.0.1:7890")
	if err != nil || parsed.Hostname() != "127.0.0.1" {
		t.Fatalf("schemeless proxy: %v", err)
	}
	got, _ := parsed.User.Password()
	if got != password {
		t.Fatalf("password not preserved for dialing: %q", got)
	}
}

func TestPreserveProxyKeepsSecretWhenEditorReturnsRedaction(t *testing.T) {
	const password = "s3cret-proxy"
	current := "http://user:" + password + "@127.0.0.1:7890"
	if got := PreserveProxy(current, Redact(current)); got != current || strings.Contains(Redact(current), password) {
		t.Fatalf("preserve %q redact %q", got, Redact(current))
	}
	encoded := "http://user%3A" + password + "@127.0.0.1:7890"
	if got := PreserveProxy(encoded, Redact(encoded)); got != encoded || strings.Contains(Redact(encoded), password) {
		t.Fatalf("encoded preserve %q redact %q", got, Redact(encoded))
	}
	schemeless := "user:" + password + "@127.0.0.1:7890"
	if got := PreserveProxy(schemeless, "  "+Redact(schemeless)+"  "); got != schemeless {
		t.Fatalf("schemeless preserve %q", got)
	}
	next := "http://127.0.0.1:1"
	if got := PreserveProxy(current, next); got != next {
		t.Fatalf("replace %q", got)
	}
	if PreserveProxy(current, "  ") != "" {
		t.Fatal("clear did not remove the proxy")
	}
}

func TestRedactHidesPercentEncodedProxyPassword(t *testing.T) {
	const password = "s3cret-proxy"
	encoded := encodeEveryByte(password)
	nested := encodeEveryByte(encoded)
	spaced := "s3cret proxy"
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
		"http://user:" + password + "@127.0.0.1:7890?q=" + strings.ToLower(encoded),
		"http://user:" + password + "@127.0.0.1:7890#" + encoded,
		"http://user:" + password + "@127.0.0.1:7890?q=" + nested,
		"http://user:" + password + "@127.0.0.1:7890?q=" + strings.ReplaceAll(encoded, "%", "\uFF05"),
		"http://user:" + password + "@127.0.0.1:7890?q=" + strings.ReplaceAll(encoded, "%", "\uFE6A"),
		"http://user:" + password + "@127.0.0.1:7890?q=s3cret-" + encodeEveryByte("proxy"),
		"http://user:" + password + "%zz@127.0.0.1:7890?q=" + encodeEveryByte(password+"%zz"),
		"http://user:" + url.PathEscape(spaced) + "@127.0.0.1:7890?q=" + url.QueryEscape(spaced),
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, encoded, nested, spaced, url.QueryEscape(spaced), url.PathEscape(spaced)} {
			if leaked != "" && strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if again := Redact(got); strings.Contains(again, password) || strings.Contains(again, encoded) {
			t.Fatalf("second redact leaked: %q", again)
		}
		if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
			t.Fatalf("preserve %q -> %q", in, kept)
		}
	}
	untouched := "http://user@127.0.0.1:7890?keep=%31%32&q=" + encoded
	if Redact(untouched) != untouched {
		t.Fatalf("username-only query changed: %q", Redact(untouched))
	}
	withQuery := "http://user:" + password + "@127.0.0.1:7890?keep=%31%32&q=" + encoded
	if got := Redact(withQuery); !strings.Contains(got, "keep=%31%32") || strings.Contains(got, encoded) {
		t.Fatalf("query context lost: %q", got)
	}
}

func encodeEveryByte(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

func TestRedactHidesCompatibilityColon(t *testing.T) {
	const password = "s3cret-proxy"
	encodedColon := "%EF%BC%9A"
	nestedColon := "%25EF%25BC%259A"
	cases := []string{
		"http://user" + "\uff1a" + password + "@127.0.0.1:7890",
		"http://user" + "\ufe55" + password + "@127.0.0.1:7890",
		"http://user" + "\ufe13" + password + "@127.0.0.1:7890",
		"user" + "\uff1a" + password + "@127.0.0.1:7890",
		"http://user" + encodedColon + password + "@127.0.0.1:7890",
		"http://user" + nestedColon + password + "@127.0.0.1:7890",
		"http://user" + "\uff1a" + password + "%zz@127.0.0.1:7890",
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, encodedColon + password, nestedColon + password} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "xxxxx") {
			t.Fatalf("redact %q did not mask password: %q", in, got)
		}
		if again := Redact(got); strings.Contains(again, password) {
			t.Fatalf("second redact leaked: %q", again)
		}
		if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
			t.Fatalf("preserve %q -> %q", in, kept)
		}
	}
	short := Redact("http://user\uff1aname@127.0.0.1:7890")
	if strings.Contains(short, "\uff1a") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a compatibility colon: %q", short)
	}
}

func TestRedactHidesColonLookalikes(t *testing.T) {
	const password = "s3cret-proxy"
	// UTF-8 for U+2236 RATIO, then that sequence percent-encoded again.
	encodedColon := "%E2%88%B6"
	nestedColon := "%25E2%2588%25B6"
	cases := []string{
		"http://user" + "\u2236" + password + "@127.0.0.1:7890",
		"http://user" + "\u02d0" + password + "@127.0.0.1:7890",
		"http://user" + "\ua789" + password + "@127.0.0.1:7890",
		"http://user" + "\u02f8" + password + "@127.0.0.1:7890",
		"http://user" + "\u0703" + password + "@127.0.0.1:7890",
		"http://user" + "\u0704" + password + "@127.0.0.1:7890",
		"http://user" + "\u0589" + password + "@127.0.0.1:7890",
		"user" + "\u2236" + password + "@127.0.0.1:7890",
		"http://user" + encodedColon + password + "@127.0.0.1:7890",
		"http://user" + nestedColon + password + "@127.0.0.1:7890",
		"http://user" + "\ua789" + password + "%zz@127.0.0.1:7890",
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, encodedColon + password, nestedColon + password} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "xxxxx") {
			t.Fatalf("redact %q did not mask password: %q", in, got)
		}
		if again := Redact(got); strings.Contains(again, password) {
			t.Fatalf("second redact leaked: %q", again)
		}
		if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
			t.Fatalf("preserve %q -> %q", in, kept)
		}
	}
	short := Redact("http://user\u2236name@127.0.0.1:7890")
	if strings.Contains(short, "\u2236") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a colon lookalike: %q", short)
	}
}

func TestRedactHidesRemainingColonLookalikes(t *testing.T) {
	const password = "s3cret-proxy"
	// Half triangular colon, the rest of the Syriac colon block, Hebrew sof
	// pasuq, Ethiopic wordspace and colons, and two-dot punctuation.
	runes := []rune{'\u02d1', '\u0705', '\u0706', '\u0707', '\u0708', '\u0709', '\u05c3', '\u1361', '\u1365', '\u1366', '\u205a'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\u0705name@127.0.0.1:7890")
	if strings.Contains(short, "\u0705") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a colon lookalike: %q", short)
	}
	if Redact("http://user\u0705@127.0.0.1:7890") != "http://user\u0705@127.0.0.1:7890" {
		t.Fatal("lookalike without a password was rewritten")
	}
}

func TestRedactHidesScriptColons(t *testing.T) {
	const password = "s3cret-proxy"
	// Mongolian colon and Bamum colon do not NFKC-fold to ASCII ':'.
	runes := []rune{'\u1804', '\ua6f4'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
			"http://user" + raw + password + "\uFF20127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\u1804name@127.0.0.1:7890")
	if strings.Contains(short, "\u1804") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a script colon: %q", short)
	}
	if Redact("http://user\ua6f4@127.0.0.1:7890") != "http://user\ua6f4@127.0.0.1:7890" {
		t.Fatal("script colon without a password was rewritten")
	}
}

func TestRedactHidesSuperscriptColons(t *testing.T) {
	const password = "s3cret-proxy"
	// These NFKC-fold to the modifier colons, not to ASCII ':'.
	runes := []rune{'\U00010781', '\U00010782'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
			"http://user" + raw + password + "\uFF20127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\U00010781name@127.0.0.1:7890")
	if strings.Contains(short, "\U00010781") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a superscript colon: %q", short)
	}
	if Redact("http://user\U00010782@127.0.0.1:7890") != "http://user\U00010782@127.0.0.1:7890" {
		t.Fatal("superscript colon without a password was rewritten")
	}
}

func TestRedactHidesDoubleColonEqual(t *testing.T) {
	const password = "s3cret-proxy"
	// U+2A74 NFKC-folds to "::=", so a raw colon search never sees the password.
	raw := "\u2a74"
	encoded := encodeEveryByte(raw)
	nested := encodeEveryByte(encoded)
	cases := []string{
		"http://user" + raw + password + "@127.0.0.1:7890",
		"user" + raw + password + "@127.0.0.1:7890",
		"http://user" + encoded + password + "@127.0.0.1:7890",
		"http://user" + nested + password + "@127.0.0.1:7890",
		"http://user" + raw + password + "%zz@127.0.0.1:7890",
		"http://user" + raw + password + "\uFF20127.0.0.1:7890",
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, raw + password, encoded + password, nested + password, "::=" + password} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "xxxxx") {
			t.Fatalf("redact %q did not mask password: %q", in, got)
		}
		if again := Redact(got); strings.Contains(again, password) {
			t.Fatalf("second redact leaked: %q", again)
		}
		if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
			t.Fatalf("preserve %q -> %q", in, kept)
		}
	}
	short := Redact("http://user\u2a74name@127.0.0.1:7890")
	if strings.Contains(short, "\u2a74") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept double colon equal: %q", short)
	}
	if Redact("http://user\u2a74@127.0.0.1:7890") != "http://user\u2a74@127.0.0.1:7890" {
		t.Fatal("double colon equal without a password was rewritten")
	}
}

func TestRedactHidesColonOperators(t *testing.T) {
	const password = "s3cret-proxy"
	// Tricolon, colon-equals, equals-colon, Z notation type colon, and the
	// triple colon operator do not NFKC-fold to ASCII ':'.
	runes := []rune{'\u205d', '\u2254', '\u2255', '\u2982', '\u2af6'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
			"http://user" + raw + password + "\uFF20127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\u2254name@127.0.0.1:7890")
	if strings.Contains(short, "\u2254") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a colon operator: %q", short)
	}
	if Redact("http://user\u205d@127.0.0.1:7890") != "http://user\u205d@127.0.0.1:7890" {
		t.Fatal("colon operator without a password was rewritten")
	}
}

func TestRedactHidesHistoricColons(t *testing.T) {
	const password = "s3cret-proxy"
	// Cuneiform colon punctuation and the SignWriting colon do not NFKC-fold
	// to ASCII ':'.
	runes := []rune{'\U00012471', '\U00012472', '\U00012473', '\U00012474', '\U0001DA8A'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
			"http://user" + raw + password + "\uFF20127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\U00012471name@127.0.0.1:7890")
	if strings.Contains(short, "\U00012471") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a historic colon: %q", short)
	}
	if Redact("http://user\U0001DA8A@127.0.0.1:7890") != "http://user\U0001DA8A@127.0.0.1:7890" {
		t.Fatal("historic colon without a password was rewritten")
	}
}

func TestRedactHidesTwoDotColons(t *testing.T) {
	const password = "s3cret-proxy"
	// Vertical two-dot leader NFKC-folds to "..". Runic multiple punctuation,
	// Samaritan afsaaq, Manichaean two dots, the Khojki word separator, and
	// Lisu mya jeu do not NFKC-fold to ASCII ':'.
	runes := []rune{'\ufe30', '\u16ec', '\u0831', '\U00010af5', '\U0001123a', '\ua4fd'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
			"http://user" + raw + password + "\uFF20127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\ufe30name@127.0.0.1:7890")
	if strings.Contains(short, "\ufe30") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a two-dot colon: %q", short)
	}
	if Redact("http://user\u16ec@127.0.0.1:7890") != "http://user\u16ec@127.0.0.1:7890" {
		t.Fatal("two-dot colon without a password was rewritten")
	}
}

func TestRedactHidesVisarga(t *testing.T) {
	const password = "s3cret-proxy"
	// Visarga signs do not NFKC-fold to ASCII ':'. Bengali visarga is the
	// confusable prototype for the other script forms, Tibetan rnam bcad,
	// and Khmer reahmuk.
	runes := []rune{'\u0903', '\u0a83', '\U00011002', '\U00011082', '\U00011182', '\U000115BE', '\U000116AC', '\U00011838', '\u0983', '\u0a03', '\u0c03', '\u0c83', '\u0d03', '\u0d83', '\u0f7f', '\u1038', '\u17c7', '\U00011303', '\U000114C1', '\U000119DF', '\U00011A39', '\U00011C3E'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
			"http://user" + raw + password + "\uFF20127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\u0983name@127.0.0.1:7890")
	if strings.Contains(short, "\u0983") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a visarga: %q", short)
	}
	if Redact("http://user\u0903@127.0.0.1:7890") != "http://user\u0903@127.0.0.1:7890" {
		t.Fatal("visarga without a password was rewritten")
	}
}

func TestRedactHidesSignColons(t *testing.T) {
	const password = "s3cret-proxy"
	// Ethiopic short rikrik, musical repeat dots, and Tolong Siki sela do
	// not NFKC-fold to ASCII ':'.
	runes := []rune{'\u1393', '\U0001D108', '\U00011DD9'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
			"http://user" + raw + password + "\uFF20127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\u1393name@127.0.0.1:7890")
	if strings.Contains(short, "\u1393") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a sign colon: %q", short)
	}
	if Redact("http://user\U0001D108@127.0.0.1:7890") != "http://user\U0001D108@127.0.0.1:7890" {
		t.Fatal("sign colon without a password was rewritten")
	}
}

func TestRedactHidesDoubleColonConfusables(t *testing.T) {
	const password = "s3cret-proxy"
	// Proportion and squared four-dot punctuation are confusable with "::"
	// and do not NFKC-fold to ASCII ':'.
	runes := []rune{'\u2237', '\u2e2c'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
			"http://user" + raw + password + "\uFF20127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\u2237name@127.0.0.1:7890")
	if strings.Contains(short, "\u2237") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a double-colon confusable: %q", short)
	}
	if Redact("http://user\u2e2c@127.0.0.1:7890") != "http://user\u2e2c@127.0.0.1:7890" {
		t.Fatal("double-colon confusable without a password was rewritten")
	}
}

func TestRedactHidesMongolianFullStops(t *testing.T) {
	const password = "s3cret-proxy"
	// Mongolian full stop and Manchu full stop are confusable with ':' and
	// do not NFKC-fold to it. The path check keeps both as dots.
	runes := []rune{'\u1803', '\u1809'}
	for _, r := range runes {
		raw := string(r)
		encoded := encodeEveryByte(raw)
		nested := encodeEveryByte(encoded)
		cases := []string{
			"http://user" + raw + password + "@127.0.0.1:7890",
			"user" + raw + password + "@127.0.0.1:7890",
			"http://user" + encoded + password + "@127.0.0.1:7890",
			"http://user" + nested + password + "@127.0.0.1:7890",
			"http://user" + raw + password + "%zz@127.0.0.1:7890",
			"http://user" + raw + password + "\uFF20127.0.0.1:7890",
		}
		for _, in := range cases {
			got := Redact(in)
			for _, leaked := range []string{password, raw + password, encoded + password, nested + password} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
				}
			}
			if !strings.Contains(got, "xxxxx") {
				t.Fatalf("redact %q did not mask password: %q", in, got)
			}
			if again := Redact(got); strings.Contains(again, password) {
				t.Fatalf("second redact leaked: %q", again)
			}
			if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
				t.Fatalf("preserve %q -> %q", in, kept)
			}
		}
	}
	short := Redact("http://user\u1803name@127.0.0.1:7890")
	if strings.Contains(short, "\u1803") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a Mongolian full stop: %q", short)
	}
	if Redact("http://user\u1809@127.0.0.1:7890") != "http://user\u1809@127.0.0.1:7890" {
		t.Fatal("Mongolian full stop without a password was rewritten")
	}
}

func TestRedactHidesAtSignLookalikes(t *testing.T) {
	const password = "s3cret-proxy"
	const other = "other-secret"
	marks := []string{"\uFE6B", "\uFF20"}
	for _, mark := range marks {
		encoded := encodeEveryByte(mark)
		nested := encodeEveryByte(encoded)
		cases := []struct{ in, want string }{
			{"http://user:" + password + mark + "127.0.0.1:7890", "http://user:xxxxx" + mark + "127.0.0.1:7890"},
			{"user:" + password + mark + "127.0.0.1:7890", "user:xxxxx" + mark + "127.0.0.1:7890"},
			{"http://user:" + password + encoded + "127.0.0.1:7890", "http://user:xxxxx" + encoded + "127.0.0.1:7890"},
			{"http://user:" + password + strings.ToLower(encoded) + "127.0.0.1:7890", "http://user:xxxxx" + strings.ToLower(encoded) + "127.0.0.1:7890"},
			{"http://user:" + password + nested + "127.0.0.1:7890", "http://user:xxxxx" + nested + "127.0.0.1:7890"},
			{"//user:" + password + mark + "[::1]:8792", "//user:xxxxx" + mark + "[::1]:8792"},
			{"socks5://alice:hunter2" + mark + "10.0.0.8:1080", "socks5://alice:xxxxx" + mark + "10.0.0.8:1080"},
		}
		for _, tc := range cases {
			got := Redact(tc.in)
			if got != tc.want || strings.Contains(got, password) || strings.Contains(got, "hunter2") {
				t.Fatalf("redact %q -> %q want %q", tc.in, got, tc.want)
			}
			if again := Redact(got); again != got {
				t.Fatalf("second redact changed %q -> %q", got, again)
			}
			if kept := PreserveProxy(tc.in, " "+got+" "); kept != tc.in {
				t.Fatalf("preserve %q -> %q", tc.in, kept)
			}
		}
	}
	cases := []struct{ in, want string }{
		{"http://user:" + password + "%40127.0.0.1:7890", "http://user:xxxxx%40127.0.0.1:7890"},
		{"http://user:" + password + "%2540127.0.0.1:7890", "http://user:xxxxx%2540127.0.0.1:7890"},
		{"user:" + password + "%252540my-proxy:7890", "user:xxxxx%252540my-proxy:7890"},
		{"http://user:" + password + "%25252540127.0.0.1:7890", "http://user:xxxxx%25252540127.0.0.1:7890"},
		{"http://user%3A" + password + "%40127.0.0.1:7890", "http://user%3Axxxxx%40127.0.0.1:7890"},
		{"http://user\uFF1A" + password + "\uFF20127.0.0.1:7890", "http://user\uFF1Axxxxx\uFF20127.0.0.1:7890"},
		{"http://user:" + password + "/token\uFF20127.0.0.1:7890", "http://user:xxxxx\uFF20127.0.0.1:7890"},
		{"http://user:p%40ss\uFF20127.0.0.1:7890", "http://user:xxxxx\uFF20127.0.0.1:7890"},
		{"http://example.com/?x=user:" + password + "\uFF2010.0.0.8:1080", "http://example.com/?x=user:xxxxx\uFF2010.0.0.8:1080"},
		{"via user:" + password + " proxy\uFF2010.1.1.1:8080 failed", "via user:xxxxx\uFF2010.1.1.1:8080 failed"},
		{"dial http://user:" + password + "@127.0.0.1:1 and http://user:" + other + "\uFF2010.0.0.8:2 failed", "dial http://user:xxxxx@127.0.0.1:1 and http://user:xxxxx\uFF2010.0.0.8:2 failed"},
		{"two user:" + password + "\uFF20127.0.0.1:7890 and user:" + other + "\uFE6B10.0.0.8:1080.", "two user:xxxxx\uFF20127.0.0.1:7890 and user:xxxxx\uFE6B10.0.0.8:1080."},
		{"http://user:" + password + "\uFF20127.0.0.1:7890?q=" + password, "http://user:xxxxx\uFF20127.0.0.1:7890?q=xxxxx"},
		{"http://user:" + password + "\uFF20127.0.0.1:7890?q=" + encodeEveryByte(password), "http://user:xxxxx\uFF20127.0.0.1:7890?q=xxxxx"},
	}
	for _, tc := range cases {
		got := Redact(tc.in)
		if got != tc.want || strings.Contains(got, password) || strings.Contains(got, other) || strings.Contains(got, "p%40ss") || strings.Contains(got, "p@ss") {
			t.Fatalf("redact %q -> %q want %q", tc.in, got, tc.want)
		}
		if again := Redact(got); strings.Contains(again, password) || strings.Contains(again, other) {
			t.Fatalf("second redact leaked: %q", again)
		}
	}
	unchanged := []string{
		"member\uFF20example.test",
		"http://user\uFF20127.0.0.1:7890",
		"http://user%40127.0.0.1:7890",
		"http://user%2540127.0.0.1:7890",
		"note 100%40off sale",
		"note 100%2540off sale",
		"http://user@127.0.0.1:7890",
		"member@example.test",
		"http://user\u0705@127.0.0.1:7890",
		"403: This request was blocked by our usage policy.",
	}
	for _, in := range unchanged {
		if got := Redact(in); got != in {
			t.Fatalf("rewrote %q into %q", in, got)
		}
	}
}

func TestRedactHidesExclamationInProxyPassword(t *testing.T) {
	const password = "s3cret!proxy"
	marked := strings.ReplaceAll(password, "!", "\uFF01")
	small := strings.ReplaceAll(password, "!", "\uFE57")
	vertical := strings.ReplaceAll(password, "!", "\uFE15")
	encoded := strings.ReplaceAll(password, "!", "%EF%BC%81")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + vertical,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, vertical, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
	}
}

func TestRedactHidesReverseSolidusInProxyPassword(t *testing.T) {
	const password = "s3cret\\proxy"
	marked := strings.ReplaceAll(password, "\\", "\uFF3C")
	small := strings.ReplaceAll(password, "\\", "\uFE68")
	encoded := strings.ReplaceAll(password, "\\", "%EF%BC%BC")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
	}
}

func TestRedactHidesNumberSignInProxyPassword(t *testing.T) {
	const password = "s3cret#proxy"
	marked := strings.ReplaceAll(password, "#", "\uFF03")
	small := strings.ReplaceAll(password, "#", "\uFE5F")
	encoded := strings.ReplaceAll(password, "#", "%EF%BC%83")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
	}
}

func TestRedactHidesDollarSignInProxyPassword(t *testing.T) {
	const password = "s3cret$proxy"
	marked := strings.ReplaceAll(password, "$", "\uFF04")
	small := strings.ReplaceAll(password, "$", "\uFE69")
	encoded := strings.ReplaceAll(password, "$", "%EF%BC%84")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesAmpersandInProxyPassword(t *testing.T) {
	const password = "s3cret&proxy"
	marked := strings.ReplaceAll(password, "&", "\uFF06")
	small := strings.ReplaceAll(password, "&", "\uFE60")
	encoded := strings.ReplaceAll(password, "&", "%EF%BC%86")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesAsteriskInProxyPassword(t *testing.T) {
	const password = "s3cret*proxy"
	marked := strings.ReplaceAll(password, "*", "\uFF0A")
	small := strings.ReplaceAll(password, "*", "\uFE61")
	encoded := strings.ReplaceAll(password, "*", "%EF%BC%8A")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesQuestionMarkInProxyPassword(t *testing.T) {
	const password = "s3cret?proxy"
	marked := strings.ReplaceAll(password, "?", "\uFF1F")
	small := strings.ReplaceAll(password, "?", "\uFE56")
	vertical := strings.ReplaceAll(password, "?", "\uFE16")
	encoded := strings.ReplaceAll(password, "?", "%EF%BC%9F")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + vertical,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, vertical, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesSemicolonInProxyPassword(t *testing.T) {
	const password = "s3cret;proxy"
	marked := strings.ReplaceAll(password, ";", "\uFF1B")
	small := strings.ReplaceAll(password, ";", "\uFE54")
	vertical := strings.ReplaceAll(password, ";", "\uFE14")
	greek := strings.ReplaceAll(password, ";", "\u037E")
	encoded := strings.ReplaceAll(password, ";", "%EF%BC%9B")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + vertical,
		"http://user:" + password + "@127.0.0.1:7890?q=" + greek,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, vertical, greek, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesCommaInProxyPassword(t *testing.T) {
	const password = "s3cret,proxy"
	marked := strings.ReplaceAll(password, ",", "\uFF0C")
	small := strings.ReplaceAll(password, ",", "\uFE50")
	vertical := strings.ReplaceAll(password, ",", "\uFE10")
	encoded := strings.ReplaceAll(password, ",", "%EF%BC%8C")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + vertical,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, vertical, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesCurlyBracketInProxyPassword(t *testing.T) {
	const password = "s3cret{proxy}"
	marked := strings.NewReplacer("{", "\uFF5B", "}", "\uFF5D").Replace(password)
	small := strings.NewReplacer("{", "\uFE5B", "}", "\uFE5C").Replace(password)
	vertical := strings.NewReplacer("{", "\uFE37", "}", "\uFE38").Replace(password)
	encoded := strings.NewReplacer("{", "%EF%BD%9B", "}", "%EF%BD%9D").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + vertical,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, vertical, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesSquareBracketInProxyPassword(t *testing.T) {
	const password = "s3cret[proxy]"
	marked := strings.NewReplacer("[", "\uFF3B", "]", "\uFF3D").Replace(password)
	vertical := strings.NewReplacer("[", "\uFE47", "]", "\uFE48").Replace(password)
	encoded := strings.NewReplacer("[", "%EF%BC%BB", "]", "%EF%BC%BD").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + vertical,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, vertical, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesLessGreaterInProxyPassword(t *testing.T) {
	const password = "s3cret<proxy>"
	marked := strings.NewReplacer("<", "\uFF1C", ">", "\uFF1E").Replace(password)
	small := strings.NewReplacer("<", "\uFE64", ">", "\uFE65").Replace(password)
	encoded := strings.NewReplacer("<", "%EF%BC%9C", ">", "%EF%BC%9E").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, small, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesGraveInProxyPassword(t *testing.T) {
	const password = "s3cret`proxy"
	marked := strings.NewReplacer("`", "\uFF40").Replace(password)
	varia := strings.NewReplacer("`", "\u1FEF").Replace(password)
	encoded := strings.NewReplacer("`", "%EF%BD%80").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + varia,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, varia, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesCircumflexInProxyPassword(t *testing.T) {
	const password = "s3cret^proxy"
	marked := strings.NewReplacer("^", "\uFF3E").Replace(password)
	encoded := strings.NewReplacer("^", "%EF%BC%BE").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesVerticalLineInProxyPassword(t *testing.T) {
	const password = "s3cret|proxy"
	marked := strings.NewReplacer("|", "\uFF5C").Replace(password)
	encoded := strings.NewReplacer("|", "%EF%BD%9C").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesApostropheInProxyPassword(t *testing.T) {
	const password = "s3cret'proxy"
	marked := strings.NewReplacer("'", "\uFF07").Replace(password)
	encoded := strings.NewReplacer("'", "%EF%BC%87").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesQuotationInProxyPassword(t *testing.T) {
	const password = "s3cret\"proxy"
	marked := strings.NewReplacer("\"", "\uFF02").Replace(password)
	encoded := strings.NewReplacer("\"", "%EF%BC%82").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + marked,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, marked, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesColonInProxyPassword(t *testing.T) {
	const password = "s3cret:proxy"
	full := strings.NewReplacer(":", "\uFF1A").Replace(password)
	small := strings.NewReplacer(":", "\uFE55").Replace(password)
	vertical := strings.NewReplacer(":", "\uFE13").Replace(password)
	encoded := strings.NewReplacer(":", "%EF%BC%9A").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + full,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + vertical,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, full, small, vertical, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") {
			t.Fatalf("host lost: %q", got)
		}
	}
}

func TestRedactHidesCommercialAtInProxyPassword(t *testing.T) {
	const password = "s3cret@proxy"
	full := strings.NewReplacer("@", "\uFF20").Replace(password)
	small := strings.NewReplacer("@", "\uFE6B").Replace(password)
	encoded := strings.NewReplacer("@", "%EF%BC%A0").Replace(password)
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + full,
		"http://user:" + password + "@127.0.0.1:7890?q=" + small,
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, full, small, encoded} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
}

func TestRedactHidesCompatibilitySpaceInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q Refresh 7f3a"
	nbsp := strings.NewReplacer(" ", "\u00A0").Replace(password)
	ideo := strings.NewReplacer(" ", "\u3000").Replace(password)
	narrow := strings.NewReplacer(" ", "\u202F").Replace(password)
	encoded := strings.NewReplacer(" ", "%C2%A0").Replace(password)
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + nbsp,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + ideo,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + narrow,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, nbsp, ideo, narrow, encoded, "Zz9q", "Refresh", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	plain := "member\u3000example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesLatinLigatureInProxyPassword(t *testing.T) {
	const password = "staffToken12"
	st := strings.NewReplacer("st", "\uFB06").Replace(password)
	longST := strings.NewReplacer("st", "\uFB05").Replace(password)
	encoded := strings.NewReplacer("st", "%EF%AC%86").Replace(password)
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + st,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + longST,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, st, longST, encoded, "staff", "Token12"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	plain := "member\uFB01le.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesAdditiveRomanInProxyPassword(t *testing.T) {
	const password = "rt_Zz9qVII7f3a"
	seven := strings.NewReplacer("VII", "\u2166").Replace(password)
	twelve := strings.NewReplacer("VII", "\u216B").Replace("rt_Zz9qXII7f3a")
	encoded := strings.NewReplacer("VII", "%E2%85%A6").Replace(password)
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + seven,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, seven, encoded, "Zz9q", "VII", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9qXII7f3a"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + twelve)
	for _, leaked := range []string{other, twelve, "XII"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("twelve leaked %q in %q", leaked, got)
		}
	}
	plain := "chapter \u2166"
	if got := Redact(plain); got != plain {
		t.Fatalf("prose changed: %q", got)
	}
}

func TestRedactHidesDoublePunctuationInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q!!7f3a"
	bang := strings.NewReplacer("!!", "\u203C").Replace(password)
	question := strings.NewReplacer("!!", "\u2047").Replace("rt_Zz9q??7f3a")
	encoded := strings.NewReplacer("!!", "%E2%80%BC").Replace(password)
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + bang,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, bang, encoded, "Zz9q", "!!", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9q??7f3a"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + question)
	for _, leaked := range []string{other, question, "??"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("question leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u203Cexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesConsecutiveEqualsInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q==7f3a"
	two := strings.NewReplacer("==", "\u2A75").Replace(password)
	three := strings.NewReplacer("===", "\u2A76").Replace("rt_Zz9q===7f3a")
	encoded := strings.NewReplacer("==", "%E2%A9%B5").Replace(password)
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + two,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, two, encoded, "Zz9q", "==", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9q===7f3a"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + three)
	for _, leaked := range []string{other, three, "==="} {
		if strings.Contains(got, leaked) {
			t.Fatalf("triple leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u2A75example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesCircledNumberInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q10ab7f"
	ten := strings.ReplaceAll(password, "10", "\u2469")
	fifty := strings.ReplaceAll("rt_Zz9q50ab7f", "50", "\u32BF")
	encoded := strings.ReplaceAll(password, "10", "%E2%91%A9")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + ten,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, ten, encoded, "Zz9q", "10", "ab7f"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9q50ab7f"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + fifty)
	for _, leaked := range []string{other, fifty, "50"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("fifty leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u2469example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesDotLeaderInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q..7f3a"
	two := strings.ReplaceAll(password, "..", "\u2025")
	three := strings.ReplaceAll("rt_Zz9q...7f3a", "...", "\u2026")
	encoded := strings.ReplaceAll(password, "..", "%E2%80%A5")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + two,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, two, encoded, "Zz9q", "..", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9q...7f3a"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + three)
	for _, leaked := range []string{other, three, "..."} {
		if strings.Contains(got, leaked) {
			t.Fatalf("ellipsis leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u2026example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesDigitStopInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q1.7f3a"
	one := strings.ReplaceAll(password, "1.", "\u2488")
	twenty := strings.ReplaceAll("rt_Zz9q20.7f3a", "20.", "\u249B")
	encoded := strings.ReplaceAll(password, "1.", "%E2%92%88")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + one,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, one, encoded, "Zz9q", "1.", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9q20.7f3a"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + twenty)
	for _, leaked := range []string{other, twenty, "20."} {
		if strings.Contains(got, leaked) {
			t.Fatalf("twenty leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u2488example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesDigitCommaInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q0,7f3a"
	zero := strings.ReplaceAll(password, "0,", "\U0001F101")
	nine := strings.ReplaceAll("rt_Zz9q9,7f3a", "9,", "\U0001F10A")
	encoded := strings.ReplaceAll(password, "0,", "%F0%9F%84%81")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + zero,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, zero, encoded, "Zz9q", "0,", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9q9,7f3a"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + nine)
	for _, leaked := range []string{other, nine, "9,"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("nine leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U0001F101example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesParenNumberInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q(1)7f3a"
	one := strings.ReplaceAll(password, "(1)", "\u2474")
	twenty := strings.ReplaceAll("rt_Zz9q(20)7f", "(20)", "\u2487")
	encoded := strings.ReplaceAll(password, "(1)", "%E2%91%B4")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + one,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, one, encoded, "Zz9q", "(1)", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9q(20)7f"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + twenty)
	for _, leaked := range []string{other, twenty, "(20)"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("twenty leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u2474example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesParenLetterInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q(a)7f3a"
	small := strings.ReplaceAll(password, "(a)", "\u249C")
	capital := strings.ReplaceAll("rt_Zz9q(Z)7f", "(Z)", "\U0001F129")
	encoded := strings.ReplaceAll(password, "(a)", "%E2%92%9C")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + small,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, small, encoded, "Zz9q", "(a)", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9q(Z)7f"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + capital)
	for _, leaked := range []string{other, capital, "(Z)"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("capital leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u249Cexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesEnclosedAbbrevInProxyPassword(t *testing.T) {
	const password = "rt_Zz9qHV7f3a"
	mark := strings.ReplaceAll(password, "HV", "\U0001F14A")
	otherMark := strings.ReplaceAll("rt_Zz9qPPV7f", "PPV", "\U0001F14E")
	encoded := strings.ReplaceAll(password, "HV", "%F0%9F%85%8A")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + mark,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "HV", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9qPPV7f"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + otherMark)
	for _, leaked := range []string{other, otherMark, "PPV"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("ppv leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U0001F14Aexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesLetterlikeInProxyPassword(t *testing.T) {
	const password = "rt_Zz9qc/o7f3a"
	mark := strings.ReplaceAll(password, "c/o", "\u2105")
	otherMark := strings.ReplaceAll("rt_Zz9qFAX7f", "FAX", "\u213B")
	encoded := strings.ReplaceAll(password, "c/o", "%E2%84%85")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + mark,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "c/o", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9qFAX7f"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + otherMark)
	for _, leaked := range []string{other, otherMark, "FAX"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("fax leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u2105example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesSquareSymbolInProxyPassword(t *testing.T) {
	const password = "rt_Zz9qkg7f3a"
	mark := strings.ReplaceAll(password, "kg", "\u338F")
	otherMark := strings.ReplaceAll("rt_Zz9qgal7f", "gal", "\u33FF")
	encoded := strings.ReplaceAll(password, "kg", "%E3%8E%8F")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + mark,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "kg", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Zz9qgal7f"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + otherMark)
	for _, leaked := range []string{other, otherMark, "gal"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("gal leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u338Fexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesSquareDivisionSlashInProxyPassword(t *testing.T) {
	const password = "rt_Zz9qm/s7f3a"
	mark := strings.ReplaceAll(password, "m/s", "\u33A7")
	otherMark := strings.ReplaceAll("rt_Aa8krad/s2x", "rad/s2", "\u33AF")
	encoded := strings.ReplaceAll(password, "m/s", "%E3%8E%A7")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + mark,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "m/s", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Aa8krad/s2x"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + otherMark)
	for _, leaked := range []string{other, otherMark, "rad/s2"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("rad leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u33A7example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesRupeeSignInProxyPassword(t *testing.T) {
	const password = "rt_Zz9qRs7f3a"
	mark := strings.ReplaceAll(password, "Rs", "\u20A8")
	encoded := strings.ReplaceAll(password, "Rs", "%E2%82%A8")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + mark,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "Rs", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	plain := "member\u20A8example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesVulgarFractionInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q1/27f3a"
	mark := strings.ReplaceAll(password, "1/2", "\u00BD")
	otherMark := strings.ReplaceAll("rt_Aa8k1/10ab", "1/10", "\u2152")
	encoded := strings.ReplaceAll(password, "1/2", "%C2%BD")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + mark,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "1/2", "7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	other := "rt_Aa8k1/10ab"
	got := Redact("http://user:" + url.PathEscape(other) + "@127.0.0.1:7890?q=" + otherMark)
	for _, leaked := range []string{other, otherMark, "1/10"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("tenth leaked %q in %q", leaked, got)
		}
	}
	plain := "member\u00BDexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagColon(t *testing.T) {
	const password = "s3cret-proxy"
	encodedColon := "%F3%A0%80%BA"
	nestedColon := "%25F3%25A0%2580%25BA"
	cases := []string{
		"http://user" + "\U000E003A" + password + "@127.0.0.1:7890",
		"user" + "\U000E003A" + password + "@127.0.0.1:7890",
		"http://user" + encodedColon + password + "@127.0.0.1:7890",
		"http://user" + nestedColon + password + "@127.0.0.1:7890",
		"http://user" + "\U000E003A" + password + "%zz@127.0.0.1:7890",
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, encodedColon + password, nestedColon + password, "\U000E003A"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "xxxxx") {
			t.Fatalf("redact %q did not mask password: %q", in, got)
		}
		if again := Redact(got); strings.Contains(again, password) {
			t.Fatalf("second redact leaked: %q", again)
		}
		if kept := PreserveProxy(in, " "+Redact(in)+" "); kept != in {
			t.Fatalf("preserve %q -> %q", in, kept)
		}
	}
	short := Redact("http://user\U000E003Aname@127.0.0.1:7890")
	if strings.Contains(short, "\U000E003A") || strings.Contains(short, "name") || !strings.Contains(short, "xxxxx") {
		t.Fatalf("short secret kept a tag colon: %q", short)
	}
}

func TestRedactHidesTagSolidusInProxyPassword(t *testing.T) {
	const password = "rt_Zz9q/ab7f3a"
	mark := strings.ReplaceAll(password, "/", "\U000E002F")
	encoded := strings.ReplaceAll(password, "/", "%F3%A0%80%AF")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + mark,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	backslash := "rt_Zz9q\\ab7f3a"
	rev := strings.ReplaceAll(backslash, "\\", "\U000E005C")
	got := Redact("http://user:" + url.PathEscape(backslash) + "@127.0.0.1:7890?q=" + rev)
	for _, leaked := range []string{backslash, rev, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("reverse tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E002Fexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
	spaced := "rt_Zz9q ab7f3a"
	spaceMark := strings.ReplaceAll(spaced, " ", "\U000E0020")
	got = Redact("http://user:" + url.PathEscape(spaced) + "@127.0.0.1:7890?q=" + spaceMark)
	for _, leaked := range []string{spaced, spaceMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("tag space leaked %q in %q", leaked, got)
		}
	}
}

func TestRedactHidesTagLetterInProxyPassword(t *testing.T) {
	const password = "rt_Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "q", "\U000E0071")
	encoded := strings.ReplaceAll(password, "q", "%F3%A0%81%B1")
	upper := strings.ReplaceAll(password, "Z", "\U000E005A")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + mark,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + upper,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, mark, encoded, upper, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt_Zz9q/ab7f3a"
	mixedMark := "rt_Z\U000E007A9q\U000E002Fab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E0061example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagDigitInProxyPassword(t *testing.T) {
	const password = "rt_Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "9", "\U000E0039")
	encoded := strings.ReplaceAll(password, "3", "%F3%A0%80%B3")
	userinfo := url.PathEscape(password)
	cases := []string{
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + mark,
		"http://user:" + userinfo + "@127.0.0.1:7890?q=" + encoded,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt_Zz9q/ab7f3a"
	mixedMark := "rt_Zz\U000E0039q\U000E002F\U000E0061b7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E0039example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagLowLineInProxyPassword(t *testing.T) {
	const password = "rt_Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "_", "\U000E005F")
	encoded := strings.ReplaceAll(password, "_", "%F3%A0%81%9F")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt_Zz9q/ab7f3a"
	mixedMark := "rt\U000E005FZz\U000E0039q\U000E002Fab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E005Fexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagPlusInProxyPassword(t *testing.T) {
	const password = "rt+Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "+", "\U000E002B")
	encoded := strings.ReplaceAll(password, "+", "%F3%A0%80%AB")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt+Zz9q/ab7f3a"
	mixedMark := "rt\U000E002BZz\U000E0039q\U000E002Fab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E002Bexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagEqualsInProxyPassword(t *testing.T) {
	const password = "rt=Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "=", "\U000E003D")
	encoded := strings.ReplaceAll(password, "=", "%F3%A0%80%BD")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt=Zz9q/ab7f3a"
	mixedMark := "rt\U000E003DZz\U000E0039q\U000E002Fab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E003Dexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagPercentInProxyPassword(t *testing.T) {
	const password = "s3cret-proxy"
	encoded := strings.ReplaceAll(encodeEveryByte(password), "%", "\U000E0025")
	literal := "100%done"
	literalMark := strings.ReplaceAll(literal, "%", "\U000E0025")
	cases := []string{
		"http://user:" + password + "@127.0.0.1:7890?q=" + encoded,
		"http://user\U000E00253A" + password + "@127.0.0.1:7890",
		"http://user:" + url.PathEscape(literal) + "@127.0.0.1:7890?q=" + literalMark,
	}
	for _, in := range cases {
		got := Redact(in)
		for _, leaked := range []string{password, encoded, literal, literalMark, "s3cret", "done"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact %q leaked %q in %q", in, leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	plain := "member\U000E0025example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagCommercialAtInProxyPassword(t *testing.T) {
	const password = "rt@Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "@", "\U000E0040")
	encoded := strings.ReplaceAll(password, "@", "%F3%A0%81%80")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt@Zz9q/ab7f3a"
	mixedMark := "rt\U000E0040Zz\U000E0039q\U000E002Fab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E0040example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagQuotationInProxyPassword(t *testing.T) {
	const password = "rt\"Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "\"", "\U000E0022")
	encoded := strings.ReplaceAll(password, "\"", "%F3%A0%80%A2")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt\"Zz9q@ab7f3a"
	mixedMark := "rt\U000E0022Zz\U000E0039q\U000E0040ab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E0022example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagApostropheInProxyPassword(t *testing.T) {
	const password = "rt'Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "'", "\U000E0027")
	encoded := strings.ReplaceAll(password, "'", "%F3%A0%80%A7")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt'Zz9q\"ab7f3a"
	mixedMark := "rt\U000E0027Zz\U000E0039q\U000E0022ab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E0027example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagVerticalLineInProxyPassword(t *testing.T) {
	const password = "rt|Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "|", "\U000E007C")
	encoded := strings.ReplaceAll(password, "|", "%F3%A0%81%BC")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt|Zz9q'ab7f3a"
	mixedMark := "rt\U000E007CZz\U000E0039q\U000E0027ab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E007Cexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagCircumflexInProxyPassword(t *testing.T) {
	const password = "rt^Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "^", "\U000E005E")
	encoded := strings.ReplaceAll(password, "^", "%F3%A0%81%9E")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt^Zz9q|ab7f3a"
	mixedMark := "rt\U000E005EZz\U000E0039q\U000E007Cab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E005Eexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagGraveInProxyPassword(t *testing.T) {
	const password = "rt`Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "`", "\U000E0060")
	encoded := strings.ReplaceAll(password, "`", "%F3%A0%81%A0")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt`Zz9q^ab7f3a"
	mixedMark := "rt\U000E0060Zz\U000E0039q\U000E005Eab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E0060example.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagLessThanInProxyPassword(t *testing.T) {
	const password = "rt<Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "<", "\U000E003C")
	encoded := strings.ReplaceAll(password, "<", "%F3%A0%80%BC")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt<Zz9q`ab7f3a"
	mixedMark := "rt\U000E003CZz\U000E0039q\U000E0060ab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E003Cexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagGreaterThanInProxyPassword(t *testing.T) {
	const password = "rt>Zz9qab7f3a"
	mark := strings.ReplaceAll(password, ">", "\U000E003E")
	encoded := strings.ReplaceAll(password, ">", "%F3%A0%80%BE")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt>Zz9q<ab7f3a"
	mixedMark := "rt\U000E003EZz\U000E0039q\U000E003Cab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E003Eexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}

func TestRedactHidesTagLeftSquareBracketInProxyPassword(t *testing.T) {
	const password = "rt[Zz9qab7f3a"
	mark := strings.ReplaceAll(password, "[", "\U000E005B")
	encoded := strings.ReplaceAll(password, "[", "%F3%A0%81%9B")
	userinfo := url.PathEscape(password)
	for _, query := range []string{mark, encoded} {
		got := Redact("http://user:" + userinfo + "@127.0.0.1:7890?q=" + query)
		for _, leaked := range []string{password, mark, encoded, "Zz9q", "ab7f3a"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("redact leaked %q in %q", leaked, got)
			}
		}
		if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "xxxxx") {
			t.Fatalf("host or mask lost: %q", got)
		}
	}
	mixed := "rt[Zz9q>ab7f3a"
	mixedMark := "rt\U000E005BZz\U000E0039q\U000E003Eab7f3a"
	got := Redact("http://user:" + url.PathEscape(mixed) + "@127.0.0.1:7890?q=" + mixedMark)
	for _, leaked := range []string{mixed, mixedMark, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("mixed tag leaked %q in %q", leaked, got)
		}
	}
	plain := "member\U000E005Bexample.test"
	if got := Redact(plain); got != plain {
		t.Fatalf("address changed: %q", got)
	}
}
