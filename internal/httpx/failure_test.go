package httpx

import (
	"net/url"
	"strings"
	"testing"
)

func TestSanitizeFailureKeepsOperatorText(t *testing.T) {
	samples := []string{
		"Refresh token is invalid",
		"403: This request was blocked by our usage policy.",
		"model access changed",
		"basispoints_model_access_changed",
		"session_revoked_because_of_security_event",
		"slow down",
	}
	for _, sample := range samples {
		if got := SanitizeFailure(sample); got != sample {
			t.Fatalf("changed %q into %q", sample, got)
		}
	}
}

func TestSanitizeFailureStripsCredentials(t *testing.T) {
	secret := "code+verifier12"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	refresh := "rt_submitted_123456"
	opaque := "AbCdEf0123456789xyzTOKENVALUEEXTRA"
	text := "rejected " + secret + " " + url.QueryEscape(secret) + " " + jwt + " bearer " + opaque + " " + refresh
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, url.QueryEscape(secret), jwt, "eyJ", opaque, refresh} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") {
		t.Fatalf("lost context: %q", got)
	}
	if SanitizeFailure(secret, secret) != "" {
		t.Fatal("credential-only detail was kept")
	}
}

func TestSanitizeFailureStripsEncodedCredentials(t *testing.T) {
	secret := "code verifier12"
	refresh := "rt_submitted_123456"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	opaque := "AbCdEf0123456789xyzTOKENVALUEEXTRA"
	encodedRefresh := encodeEveryByte(refresh)
	encodedJWT := encodeEveryByte(jwt)
	encodedOpaque := encodeEveryByte(opaque)
	text := "rejected " + url.PathEscape(secret) + " " + encodedRefresh + " " + encodedJWT + " bearer%20" + opaque + " " + encodedOpaque
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, url.PathEscape(secret), refresh, encodedRefresh, jwt, encodedJWT, opaque, encodedOpaque, "eyJ"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") {
		t.Fatalf("lost context: %q", got)
	}
	kept := []string{
		"session_revoked_because_of_security_event",
		"slow%20down",
		encodeEveryByte("session_revoked_because_of_security_event"),
	}
	for _, sample := range kept {
		if got := SanitizeFailure(sample); got != sample {
			t.Fatalf("changed %q into %q", sample, got)
		}
	}
}

func TestSanitizeFailureStripsProxyPasswords(t *testing.T) {
	const password = "s3cret-proxy"
	text := "dial http://user:" + password + "@127.0.0.1:7890 and http://user\u0705" + password + "@127.0.0.1:7890 and http://user\u1804" + password + "@10.0.0.8:1080 and http://user\ua6f4" + password + "\uFF2010.0.0.8:1080 and http://user\U00010781" + password + "@10.0.0.8:1080 and http://user\U00010782" + password + "\uFF2010.0.0.8:1080 and http://user\u2a74" + password + "@10.0.0.8:1080 failed"
	got := SanitizeFailure(text)
	if strings.Contains(got, password) || strings.Contains(got, "\u0705"+password) || strings.Contains(got, "\u1804"+password) || strings.Contains(got, "\ua6f4"+password) || strings.Contains(got, "\U00010781"+password) || strings.Contains(got, "\U00010782"+password) || strings.Contains(got, "\u2a74"+password) || !strings.Contains(got, "dial") || !strings.Contains(got, "failed") || !strings.Contains(got, "xxxxx") {
		t.Fatalf("proxy failure: %q", got)
	}
	plain := "http://127.0.0.1:7890"
	if SanitizeFailure("see "+plain) != "see "+plain {
		t.Fatal("proxy without a password was rewritten")
	}
}

func TestSanitizeFailureStripsColonOperators(t *testing.T) {
	const password = "s3cret-proxy"
	text := "dial http://user\u205d" + password + "@127.0.0.1:7890 and http://user\u2254" + password + "\uFF2010.0.0.8:1080 and http://user\u2af6" + password + "@10.0.0.8:1080 failed"
	got := SanitizeFailure(text)
	if strings.Contains(got, password) || strings.Contains(got, "\u205d"+password) || strings.Contains(got, "\u2254"+password) || strings.Contains(got, "\u2af6"+password) || !strings.Contains(got, "dial") || !strings.Contains(got, "failed") || !strings.Contains(got, "xxxxx") {
		t.Fatalf("proxy failure: %q", got)
	}
}

func TestSanitizeFailureStripsHistoricColons(t *testing.T) {
	const password = "s3cret-proxy"
	text := "dial http://user\U00012471" + password + "@127.0.0.1:7890 and http://user\U00012474" + password + "\uFF2010.0.0.8:1080 and http://user\U0001DA8A" + password + "@10.0.0.8:1080 failed"
	got := SanitizeFailure(text)
	if strings.Contains(got, password) || strings.Contains(got, "\U00012471"+password) || strings.Contains(got, "\U00012474"+password) || strings.Contains(got, "\U0001DA8A"+password) || !strings.Contains(got, "dial") || !strings.Contains(got, "failed") || !strings.Contains(got, "xxxxx") {
		t.Fatalf("proxy failure: %q", got)
	}
}

func TestSanitizeFailureStripsTwoDotColons(t *testing.T) {
	const password = "s3cret-proxy"
	text := "dial http://user\ufe30" + password + "@127.0.0.1:7890 and http://user\u16ec" + password + "\uFF2010.0.0.8:1080 and http://user\ua4fd" + password + "@10.0.0.8:1080 failed"
	got := SanitizeFailure(text)
	if strings.Contains(got, password) || strings.Contains(got, "\ufe30"+password) || strings.Contains(got, "\u16ec"+password) || strings.Contains(got, "\ua4fd"+password) || !strings.Contains(got, "dial") || !strings.Contains(got, "failed") || !strings.Contains(got, "xxxxx") {
		t.Fatalf("proxy failure: %q", got)
	}
}

func TestSanitizeFailureStripsVisarga(t *testing.T) {
	const password = "s3cret-proxy"
	text := "dial http://user\u0903" + password + "@127.0.0.1:7890 and http://user\u0983" + password + "\uFF2010.0.0.8:1080 and http://user\u17c7" + password + "@10.0.0.8:1080 failed"
	got := SanitizeFailure(text)
	if strings.Contains(got, password) || strings.Contains(got, "\u0903"+password) || strings.Contains(got, "\u0983"+password) || strings.Contains(got, "\u17c7"+password) || !strings.Contains(got, "dial") || !strings.Contains(got, "failed") || !strings.Contains(got, "xxxxx") {
		t.Fatalf("proxy failure: %q", got)
	}
}

func TestSanitizeFailureStripsSignColons(t *testing.T) {
	const password = "s3cret-proxy"
	text := "dial http://user\u1393" + password + "@127.0.0.1:7890 and http://user\U0001D108" + password + "\uFF2010.0.0.8:1080 and http://user\U00011DD9" + password + "@10.0.0.8:1080 failed"
	got := SanitizeFailure(text)
	if strings.Contains(got, password) || strings.Contains(got, "\u1393"+password) || strings.Contains(got, "\U0001D108"+password) || strings.Contains(got, "\U00011DD9"+password) || !strings.Contains(got, "dial") || !strings.Contains(got, "failed") || !strings.Contains(got, "xxxxx") {
		t.Fatalf("proxy failure: %q", got)
	}
}

func TestSanitizeFailureStripsDoubleColonConfusables(t *testing.T) {
	const password = "s3cret-proxy"
	text := "dial http://user\u2237" + password + "@127.0.0.1:7890 and http://user\u2e2c" + password + "\uFF2010.0.0.8:1080 failed"
	got := SanitizeFailure(text)
	if strings.Contains(got, password) || strings.Contains(got, "\u2237"+password) || strings.Contains(got, "\u2e2c"+password) || !strings.Contains(got, "dial") || !strings.Contains(got, "failed") || !strings.Contains(got, "xxxxx") {
		t.Fatalf("proxy failure: %q", got)
	}
}

func TestSanitizeFailureStripsAtSignLookalikes(t *testing.T) {
	const password = "s3cret-proxy"
	const other = "other-secret"
	text := "dial http://user:" + password + "\uFF20127.0.0.1:7890 and user:" + other + "\uFE6B10.0.0.8:1080 failed"
	got := SanitizeFailure(text)
	if strings.Contains(got, password) || strings.Contains(got, other) || !strings.Contains(got, "dial") || !strings.Contains(got, "failed") || !strings.Contains(got, "xxxxx") {
		t.Fatalf("failure text: %q", got)
	}
	plain := "member\uFF20example.test kept"
	if SanitizeFailure(plain) != plain {
		t.Fatal("address with a fullwidth at was rewritten")
	}
}
