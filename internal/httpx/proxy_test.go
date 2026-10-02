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
