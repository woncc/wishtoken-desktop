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
