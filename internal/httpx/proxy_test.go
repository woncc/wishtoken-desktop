package httpx

import (
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
	}
	for _, in := range cases {
		got := Redact(in)
		if strings.Contains(got, password) || got == in {
			t.Fatalf("redact %q -> %q", in, got)
		}
	}
	if Redact("http://127.0.0.1:7890") != "http://127.0.0.1:7890" || Redact("") != "" {
		t.Fatal("proxy without credentials changed")
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
