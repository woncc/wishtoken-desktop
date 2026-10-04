package httpx

import (
	"fmt"
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

func TestSanitizeFailureStripsMongolianFullStops(t *testing.T) {
	const password = "s3cret-proxy"
	text := "dial http://user\u1803" + password + "@127.0.0.1:7890 and http://user\u1809" + password + "\uFF2010.0.0.8:1080 failed"
	got := SanitizeFailure(text)
	if strings.Contains(got, password) || strings.Contains(got, "\u1803"+password) || strings.Contains(got, "\u1809"+password) || !strings.Contains(got, "dial") || !strings.Contains(got, "failed") || !strings.Contains(got, "xxxxx") {
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

func TestSanitizeFailureStripsMarksInsideCredentials(t *testing.T) {
	secret := "code+verifier12"
	markedSecret := "code+\uFE0Everifier12"
	refresh := "rt_submitted_123456"
	markedRefresh := "rt_\uFE0Esubmitted_123456"
	encodedMark := "rt_%EF%B8%8Esubmitted_123456"
	acute := "rt_submi\u0301tted_123456"
	enclosed := "rt_submitted_\u20dd123456"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\uFE0FdXJl"
	text := "rejected " + markedSecret + " " + markedRefresh + " " + encodedMark + " " + acute + " " + enclosed + " " + markedJWT + " later"
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, markedSecret, refresh, markedRefresh, "submitted_123456", jwt, "eyJ", "c2lnbmF0dXJl"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	plain := "slow\uFE0Edown"
	if SanitizeFailure(plain) != plain {
		t.Fatalf("operator text changed: %q", SanitizeFailure(plain))
	}
}

func TestSanitizeFailureStripsFormatCharactersInsideCredentials(t *testing.T) {
	secret := "code+verifier12"
	markedSecret := "code+\u200Bverifier12"
	refresh := "rt_submitted_123456"
	zwsp := "rt_\u200Bsubmitted_123456"
	joiner := "rt_sub\u2060mitted_123456"
	bom := "rt_submitted_\uFEFF123456"
	encoded := "rt_%E2%80%8Bsubmitted_123456"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u200DdXJl"
	text := "rejected " + markedSecret + " " + zwsp + " " + joiner + " " + bom + " " + encoded + " " + markedJWT + " later"
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, markedSecret, refresh, zwsp, joiner, bom, encoded, "submitted_123456", jwt, "eyJ", "c2lnbmF0dXJl"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	plain := "slow\u200Bdown"
	if SanitizeFailure(plain) != plain {
		t.Fatalf("operator text changed: %q", SanitizeFailure(plain))
	}
	snake := "session_revoked_\u200Bbecause_of_security_event"
	if SanitizeFailure(snake) != snake {
		t.Fatalf("operator reason changed: %q", SanitizeFailure(snake))
	}
}

func TestSanitizeFailureStripsControlsInsideCredentials(t *testing.T) {
	secret := "code+verifier12"
	markedSecret := "code+\x00verifier12"
	refresh := "rt_submitted_123456"
	nul := "rt_\x00submitted_123456"
	del := "rt_submitted_\x7f123456"
	line := "rt_sub\u2028mitted_123456"
	encoded := "rt_%00submitted_123456"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u2029dXJl"
	text := "rejected " + markedSecret + " " + nul + " " + del + " " + line + " " + encoded + " " + markedJWT + " later"
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, markedSecret, refresh, nul, del, line, encoded, "submitted_123456", jwt, "eyJ", "c2lnbmF0dXJl"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	plain := "slow\x00down"
	if SanitizeFailure(plain) != plain {
		t.Fatalf("operator text changed: %q", SanitizeFailure(plain))
	}
	kept := "Refresh token is invalid\n403 blocked"
	if got := SanitizeFailure(kept); got != "Refresh token is invalid 403 blocked" {
		t.Fatalf("operator text changed: %q", got)
	}
}

func TestSanitizeFailureStripsBlankFillersInsideCredentials(t *testing.T) {
	secret := "code+verifier12"
	markedSecret := "code+\u3164verifier12"
	refresh := "rt_submitted_123456"
	braille := "rt_\u2800submitted_123456"
	choseong := "rt_sub\u115fmitted_123456"
	encoded := "rt_%EF%BE%A0submitted_123456"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u1160dXJl"
	text := "rejected " + markedSecret + " " + braille + " " + choseong + " " + encoded + " " + markedJWT + " later"
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, markedSecret, refresh, braille, choseong, encoded, "submitted_123456", jwt, "eyJ", "c2lnbmF0dXJl"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	plain := "slow\u3164down"
	if SanitizeFailure(plain) != plain {
		t.Fatalf("operator text changed: %q", SanitizeFailure(plain))
	}
	snake := "session_revoked_\u2800because_of_security_event"
	if SanitizeFailure(snake) != snake {
		t.Fatalf("operator reason changed: %q", SanitizeFailure(snake))
	}
}

func TestSanitizeFailureStripsUnicodeSpacesInsideCredentials(t *testing.T) {
	secret := "code+verifier12"
	markedSecret := "code+\u1680verifier12"
	refresh := "rt_submitted_123456"
	nbsp := "rt_\u00a0submitted_123456"
	ideo := "rt_sub\u3000mitted_123456"
	encoded := "rt_%C2%A0submitted_123456"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u202fdXJl"
	bearer := "bearer\u00a0shortToken1"
	text := "rejected " + markedSecret + " " + nbsp + " " + ideo + " " + encoded + " " + markedJWT + " " + bearer + " later"
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, markedSecret, refresh, nbsp, ideo, encoded, "submitted_123456", jwt, "eyJ", "c2lnbmF0dXJl", "shortToken1", bearer} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	if got := SanitizeFailure("slow\u00a0down"); got != "slow down" {
		t.Fatalf("operator text changed: %q", got)
	}
	if got := SanitizeFailure("BearerAuth"); got != "BearerAuth" {
		t.Fatalf("glued word changed: %q", got)
	}
	if got := SanitizeFailure("BearerAuth\u00a0rejected"); got != "BearerAuth rejected" {
		t.Fatalf("glued word changed: %q", got)
	}
	snake := "session_revoked_\u00a0because_of_security_event"
	if got := SanitizeFailure(snake); got != "session_revoked_ because_of_security_event" {
		t.Fatalf("operator reason changed: %q", got)
	}
}

func TestSanitizeFailureStripsSpacingMarksInsideCredentials(t *testing.T) {
	secret := "code+verifier12"
	markedSecret := "code+\u093everifier12"
	refresh := "rt_submitted_123456"
	vowel := "rt_\u093esubmitted_123456"
	tone := "rt_sub\u302emitted_123456"
	encoded := "rt_%E0%A4%BEsubmitted_123456"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u0bbedXJl"
	bearer := "bearer\u302fshortToken1"
	text := "rejected " + markedSecret + " " + vowel + " " + tone + " " + encoded + " " + markedJWT + " " + bearer + " later"
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, markedSecret, refresh, vowel, tone, encoded, "submitted_123456", jwt, "eyJ", "c2lnbmF0dXJl", "shortToken1", bearer} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	plain := "slow\u093edown"
	if SanitizeFailure(plain) != plain {
		t.Fatalf("operator text changed: %q", SanitizeFailure(plain))
	}
	snake := "session_revoked_\u302ebecause_of_security_event"
	if SanitizeFailure(snake) != snake {
		t.Fatalf("operator reason changed: %q", SanitizeFailure(snake))
	}
}

func TestSanitizeFailureStripsHyphenLookalikes(t *testing.T) {
	secret := "code-verifier12"
	markedSecret := "code\u2010verifier12"
	refresh := "rt_sub-mitted_123456"
	nonBreaking := "rt_sub\u2011mitted_123456"
	minus := "rt_sub\u2212mitted_123456"
	encoded := "rt_sub%E2%80%91mitted_123456"
	spaced := "rt_sub\u2010\u093emitted_123456"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEi.c2ln-bmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEi.c2ln\u2010bmF0dXJl"
	text := "rejected " + markedSecret + " " + nonBreaking + " " + minus + " " + encoded + " " + spaced + " " + markedJWT + " later"
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, markedSecret, refresh, nonBreaking, minus, encoded, spaced, "mitted_123456", jwt, markedJWT, "eyJ", "c2ln-bmF0dXJl", "c2ln\u2010bmF0dXJl"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	if got := SanitizeFailure("re\u2013try later"); got != "re\u2013try later" {
		t.Fatalf("en dash prose changed: %q", got)
	}
	if got := SanitizeFailure("re\u2014try later"); got != "re\u2014try later" {
		t.Fatalf("em dash prose changed: %q", got)
	}
	shy := "code\u00adverifier12"
	got = SanitizeFailure("rejected "+shy+" later", secret)
	if strings.Contains(got, secret) || strings.Contains(got, shy) || strings.Contains(got, "verifier12") {
		t.Fatalf("soft hyphen leaked: %q", got)
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("soft hyphen context lost: %q", got)
	}
	if plain := SanitizeFailure("slow\u00addown"); !strings.Contains(plain, "slow") || !strings.Contains(plain, "down") || strings.Contains(plain, "[redacted]") {
		t.Fatalf("soft hyphen prose changed: %q", plain)
	}
	if got := SanitizeFailure("session_revoked_because_of_security_event"); got != "session_revoked_because_of_security_event" {
		t.Fatalf("operator reason changed: %q", got)
	}
}

func TestSanitizeFailureStripsEmDashes(t *testing.T) {
	secret := "code-verifier12"
	em := "code\u2014verifier12"
	bar := "code\u2015verifier12"
	vertical := "code\ufe31verifier12"
	refresh := "rt_sub-mitted_123456"
	marked := "rt_sub\u2014mitted_123456"
	got := SanitizeFailure("rejected "+em+" "+bar+" "+vertical+" "+marked+" later", secret)
	for _, leaked := range []string{secret, em, bar, vertical, refresh, marked, "verifier12", "mitted_123456"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"re\u2014try later", "re\u2015try later", "re\ufe31try later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("dash prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsScriptHyphens(t *testing.T) {
	secret := "code-verifier12"
	refresh := "rt_sub-mitted_123456"
	hyphens := []rune{'\u058a', '\u05be', '\u1400', '\u1806', '\u2e17', '\u2e1a', '\u2e40', '\u2e5d', '\u30a0', '\U00010ead'}
	var parts []string
	var leaked []string
	for _, r := range hyphens {
		marked := "code" + string(r) + "verifier12"
		token := "rt_sub" + string(r) + "mitted_123456"
		parts = append(parts, marked, token)
		leaked = append(leaked, marked, token)
	}
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secret)
	for _, item := range append([]string{secret, refresh, "verifier12", "mitted_123456"}, leaked...) {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, r := range hyphens {
		prose := "re" + string(r) + "try later"
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("script hyphen prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLongAndWaveDashes(t *testing.T) {
	secret := "code-verifier12"
	refresh := "rt_sub-mitted_123456"
	dashes := []rune{'\u2e3a', '\u2e3b', '\u301c', '\u3030'}
	var parts []string
	var leaked []string
	for _, r := range dashes {
		marked := "code" + string(r) + "verifier12"
		token := "rt_sub" + string(r) + "mitted_123456"
		parts = append(parts, marked, token)
		leaked = append(leaked, marked, token)
	}
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secret)
	for _, item := range append([]string{secret, refresh, "verifier12", "mitted_123456"}, leaked...) {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, r := range dashes {
		prose := "re" + string(r) + "try later"
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("dash prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCompatibilityHyphens(t *testing.T) {
	secret := "code-verifier12"
	refresh := "rt_sub-mitted_123456"
	hyphens := []rune{'\u207b', '\u208b', '\ufe32', '\ufe63', '\uff0d'}
	encodedSecret := "code%EF%BC%8Dverifier12"
	encodedRefresh := "rt_sub%EF%BC%8Dmitted_123456"
	var parts []string
	var leaked []string
	for _, r := range hyphens {
		marked := "code" + string(r) + "verifier12"
		token := "rt_sub" + string(r) + "mitted_123456"
		parts = append(parts, marked, token)
		leaked = append(leaked, marked, token)
	}
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" "+encodedSecret+" "+encodedRefresh+" later", secret)
	for _, item := range append([]string{secret, refresh, encodedSecret, encodedRefresh, "verifier12", "mitted_123456"}, leaked...) {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, r := range hyphens {
		prose := "re" + string(r) + "try later"
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("compatibility hyphen prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCompatibilityFullStops(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	dots := []rune{'\u2024', '\ufe52', '\uff0e', '\ufe12', '\uff61'}
	encoded := strings.ReplaceAll(jwt, ".", "%EF%BC%8E")
	var parts []string
	var leaked []string
	for _, r := range dots {
		marked := strings.ReplaceAll(jwt, ".", string(r))
		parts = append(parts, marked)
		leaked = append(leaked, marked)
	}
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" "+encoded+" later", jwt)
	for _, item := range append([]string{jwt, encoded, "eyJ", "c2lnbmF0dXJl", "eyJzdWIiOiJ1c2VyIn0"}, leaked...) {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see file\u2024txt later", "end\ufe52 next", "version 1\uff0e2 stays", "wait\ufe12 please", "half\uff61width"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("full stop prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsOtherFullStops(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	stops := []rune{
		'\u3002', '\u06d4', '\u0701', '\u0702', '\u1362', '\u166e',
		'\u1803', '\u1809', '\u2cf9', '\u2cfe', '\u2e3c', '\ua4ff', '\ua60e', '\ua6f3',
		'\U00016af5', '\U00016e98', '\U0001bc9f', '\U0001da88',
		'\ua4f8', '\U00010a50', '\ua4fa',
		'\u0660', '\u06f0', '\U0001ecae',
	}
	var parts []string
	var leaked []string
	for _, r := range stops {
		marked := strings.ReplaceAll(jwt, ".", string(r))
		parts = append(parts, marked)
		leaked = append(leaked, marked)
	}
	encoded := strings.ReplaceAll(jwt, ".", "%E3%80%82")
	meetei := strings.ReplaceAll(jwt, ".", "\uabec")
	musical := strings.ReplaceAll(jwt, ".", "\U0001d16d")
	combined := "eyJhbGciOiJub25lIn0\U0001d16deyJzdWIi\u093eOiJ1c2VyIn0.c2lnbmF0dXJl"
	// No stored secret: the JWT pattern has to see the folded stops.
	got := SanitizeFailure("rejected " + strings.Join(parts, " ") + " " + encoded + " " + meetei + " " + musical + " " + combined + " later")
	for _, item := range append([]string{jwt, encoded, meetei, musical, combined, "eyJ", "c2lnbmF0dXJl", "eyJzdWIiOiJ1c2VyIn0"}, leaked...) {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "code.verifier12"
	markedSecret := "code\u3002verifier12"
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	if strings.Contains(got, secret) || strings.Contains(got, markedSecret) || strings.Contains(got, "verifier12") {
		t.Fatalf("short secret leaked: %q", got)
	}
	insertedSecret := "code+verifier12"
	inserted := "code+\U0001d16dverifier12"
	meeteiInserted := "code+\uabecverifier12"
	got = SanitizeFailure("rejected "+inserted+" "+meeteiInserted+" later", insertedSecret)
	for _, item := range []string{insertedSecret, inserted, meeteiInserted, "verifier12"} {
		if strings.Contains(got, item) {
			t.Fatalf("inserted stop leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("inserted stop context lost: %q", got)
	}
	for _, prose := range []string{
		"failed\u3002 later",
		"end\u06d4 next",
		"wait\u1362 please",
		"code \u0660 stays",
		"see \u1803 later",
		"slow\uabecdow",
		"slow\U0001d16ddown",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("full stop prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsFullwidthLetters(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	marked := strings.NewReplacer("e", "\uff45", "J", "\uff2a", "y", "\uff59", "1", "\uff11").Replace(jwt)
	encoded := strings.Replace(jwt, "e", "%EF%BD%85", 1)
	secret := "codeVerifier12"
	markedSecret := "code\uff36erifier\uff11\uff12"
	got := SanitizeFailure("rejected "+marked+" "+encoded+" "+markedSecret+" later", secret)
	for _, item := range []string{jwt, marked, encoded, secret, markedSecret, "eyJ", "c2lnbmF0dXJl", "Verifier12", "erifier"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"\uff48\uff45\uff4c\uff4c\uff4f", "build \uff11 stays", "see \uff21 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("fullwidth prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMathLetters(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	marked := strings.NewReplacer(
		"e", "\U0001D41E",
		"J", "\U0001D43D",
		"1", "\U0001D7CF",
		"h", "\u210E",
		"b", "\u212C",
		"c", "\u2102",
		"d", "\u2146",
	).Replace(jwt)
	encoded := strings.Replace(jwt, "e", "%F0%9D%90%9E", 1)
	// No stored secret: the JWT pattern has to see the folded letters.
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{jwt, marked, encoded, "eyJ", "c2lnbmF0dXJl", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "codeVerifier12"
	markedSecret := strings.NewReplacer(
		"V", "\U0001D415",
		"1", "\U0001D7CF",
		"2", "\U0001D7D0",
		"e", "\u212F",
		"o", "\u2134",
	).Replace(secret)
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, "Verifier12", "erifier"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("short secret context lost: %q", got)
	}
	for _, prose := range []string{
		"\U0001D421\U0001D41E\U0001D425\U0001D425\U0001D428",
		"build \U0001D7CF stays",
		"see \U0001D400 later",
		"see \u210E later",
		"see \U0001D6A8 later",
		"see \u212A later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("math prose changed: %q -> %q", prose, got)
		}
	}
}

func TestMathASCIIFoldsOnlyMathematicalLetters(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x1D400, 'A', true},
		{0x1D419, 'Z', true},
		{0x1D41A, 'a', true},
		{0x1D433, 'z', true},
		{0x1D434, 'A', true},
		{0x1D44D, 'Z', true},
		{0x1D44E, 'a', true},
		{0x1D454, 'g', true},
		{0x1D455, 0, false},
		{0x1D456, 'i', true},
		{0x1D467, 'z', true},
		{0x1D49C, 'A', true},
		{0x1D49D, 0, false},
		{0x1D49E, 'C', true},
		{0x1D4B5, 'Z', true},
		{0x1D4B6, 'a', true},
		{0x1D4B9, 'd', true},
		{0x1D4BA, 0, false},
		{0x1D4BB, 'f', true},
		{0x1D4BC, 0, false},
		{0x1D4BD, 'h', true},
		{0x1D4C3, 'n', true},
		{0x1D4C4, 0, false},
		{0x1D4C5, 'p', true},
		{0x1D4CF, 'z', true},
		{0x1D4D0, 'A', true},
		{0x1D503, 'z', true},
		{0x1D504, 'A', true},
		{0x1D506, 0, false},
		{0x1D507, 'D', true},
		{0x1D51C, 'Y', true},
		{0x1D51D, 0, false},
		{0x1D51E, 'a', true},
		{0x1D537, 'z', true},
		{0x1D538, 'A', true},
		{0x1D53A, 0, false},
		{0x1D546, 'O', true},
		{0x1D547, 0, false},
		{0x1D54A, 'S', true},
		{0x1D550, 'Y', true},
		{0x1D551, 0, false},
		{0x1D552, 'a', true},
		{0x1D56B, 'z', true},
		{0x1D56C, 'A', true},
		{0x1D6A3, 'z', true},
		{0x1D6A4, 0, false},
		{0x1D6A8, 0, false},
		{0x1D7CE, '0', true},
		{0x1D7D7, '9', true},
		{0x1D7D8, '0', true},
		{0x1D7FF, '9', true},
		{0x2102, 'C', true},
		{0x210A, 'g', true},
		{0x210B, 'H', true},
		{0x210C, 'H', true},
		{0x210D, 'H', true},
		{0x210E, 'h', true},
		{0x2110, 'I', true},
		{0x2111, 'I', true},
		{0x2112, 'L', true},
		{0x2113, 'l', true},
		{0x2115, 'N', true},
		{0x2119, 'P', true},
		{0x211A, 'Q', true},
		{0x211B, 'R', true},
		{0x211C, 'R', true},
		{0x211D, 'R', true},
		{0x2124, 'Z', true},
		{0x2128, 'Z', true},
		{0x212A, 0, false},
		{0x212C, 'B', true},
		{0x212D, 'C', true},
		{0x212F, 'e', true},
		{0x2130, 'E', true},
		{0x2131, 'F', true},
		{0x2133, 'M', true},
		{0x2134, 'o', true},
		{0x2139, 0, false},
		{0x2145, 'D', true},
		{0x2146, 'd', true},
		{0x2147, 'e', true},
		{0x2148, 'i', true},
		{0x2149, 'j', true},
		{'A', 0, false},
		{'\uff21', 0, false},
	}
	for _, check := range checks {
		got, ok := mathASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
}

func TestSanitizeFailureStripsEnclosedLetters(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	marked := strings.NewReplacer(
		"e", "\u24d4",
		"J", "\u24bf",
		"1", "\u2460",
		"0", "\u24ea",
		"2", "\u2461",
		"c", "\U0001F12B",
	).Replace(jwt)
	encoded := strings.Replace(jwt, "e", "%E2%93%94", 1)
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{jwt, marked, encoded, "eyJ", "c2lnbmF0dXJl", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "codeVerifier12"
	markedSecret := strings.NewReplacer(
		"V", "\U0001F145",
		"1", "\u2460",
		"2", "\u2461",
		"e", "\u24d4",
	).Replace(secret)
	encodedSecret := strings.Replace(secret, "V", "%F0%9F%85%85", 1)
	got = SanitizeFailure("rejected "+markedSecret+" "+encodedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, encodedSecret, "Verifier12", "erifier"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("short secret context lost: %q", got)
	}
	for _, prose := range []string{
		"\u24d7\u24d4\u24db\u24db\u24de",
		"build \u2460 stays",
		"see \u24b6 later",
		"see \u24ea later",
		"see \u249c later",
		"see \u2469 later",
		"see \U0001F14A later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("enclosed prose changed: %q -> %q", prose, got)
		}
	}
}

func TestEnclosedASCIIFoldsOnlySingleLetters(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x2460, '1', true},
		{0x2468, '9', true},
		{0x2469, 0, false},
		{0x24B6, 'A', true},
		{0x24CF, 'Z', true},
		{0x24B5, 0, false},
		{0x24D0, 'a', true},
		{0x24D4, 'e', true},
		{0x24E9, 'z', true},
		{0x24EA, '0', true},
		{0x24FF, 0, false},
		{0x1F12B, 'C', true},
		{0x1F12C, 'R', true},
		{0x1F12A, 0, false},
		{0x1F12D, 0, false},
		{0x1F130, 'A', true},
		{0x1F145, 'V', true},
		{0x1F149, 'Z', true},
		{0x1F14A, 0, false},
		{0x1F150, 0, false},
		{0x2474, 0, false},
		{0x2488, 0, false},
		{0x249C, 0, false},
	}
	for _, check := range checks {
		got, ok := enclosedASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := enclosedASCII(r); ok {
			n++
		}
	}
	if n != 90 {
		t.Fatalf("enclosed fold count %d", n)
	}
}

func TestSanitizeFailureStripsSuperSubLetters(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	marked := strings.NewReplacer(
		"e", "\u2091",
		"i", "\u2071",
		"n", "\u207f",
		"o", "\u00ba",
		"1", "\u00b9",
		"2", "\u00b2",
		"0", "\u2080",
	).Replace(jwt)
	encoded := strings.Replace(jwt, "e", "%E2%82%91", 1)
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{jwt, marked, encoded, "eyJ", "c2lnbmF0dXJl", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "codeVerifier12"
	markedSecret := strings.NewReplacer(
		"e", "\u2091",
		"i", "\u2071",
		"o", "\u00ba",
		"1", "\u00b9",
		"2", "\u2082",
	).Replace(secret)
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, "Verifier12", "erifier"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("short secret context lost: %q", got)
	}
	for _, prose := range []string{
		"see \u00b2 later",
		"n\u00ba 3",
		"x\u2094 later",
		"a\u207a b",
		"slow\u207bdown",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("superscript prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSuperSubASCIIFoldsOnlyLettersAndDigits(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x00AA, 'a', true},
		{0x00BA, 'o', true},
		{0x00B2, '2', true},
		{0x00B3, '3', true},
		{0x00B9, '1', true},
		{0x2070, '0', true},
		{0x2071, 'i', true},
		{0x2072, 0, false},
		{0x2074, '4', true},
		{0x2079, '9', true},
		{0x207A, 0, false},
		{0x207B, 0, false},
		{0x207F, 'n', true},
		{0x2080, '0', true},
		{0x2089, '9', true},
		{0x208A, 0, false},
		{0x2090, 'a', true},
		{0x2091, 'e', true},
		{0x2093, 'x', true},
		{0x2094, 0, false},
		{0x2095, 'h', true},
		{0x2096, 'k', true},
		{0x209C, 't', true},
	}
	for _, check := range checks {
		got, ok := superSubASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := superSubASCII(r); ok {
			n++
		}
	}
	if n != 36 {
		t.Fatalf("superscript fold count %d", n)
	}
}

func TestSanitizeFailureStripsModifierLetters(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	marked := strings.NewReplacer(
		"e", "\u1d49",
		"i", "\u2139",
		"h", "\u02b0",
		"c", "\u1d9c",
	).Replace(jwt)
	encoded := strings.Replace(jwt, "e", "%E1%B5%89", 1)
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{jwt, marked, encoded, "eyJ", "c2lnbmF0dXJl", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "codeVerifier12"
	markedSecret := strings.NewReplacer(
		"e", "\u1d49",
		"i", "\u1d62",
		"o", "\u1d52",
		"V", "\u2c7d",
		"c", "\u1d9c",
	).Replace(secret)
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, "Verifier12", "erifier"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	kelvin := "bridgeKtoken1"
	markedKelvin := strings.ReplaceAll(kelvin, "K", "\u212a")
	got = SanitizeFailure("rejected "+markedKelvin+" later", kelvin)
	for _, item := range []string{kelvin, markedKelvin, "bridge", "token1"} {
		if strings.Contains(got, item) {
			t.Fatalf("kelvin secret leaked %q in %q", item, got)
		}
	}
	smallQ := "tokenqvalue1"
	markedQ := strings.ReplaceAll(smallQ, "q", "\U000107a5")
	got = SanitizeFailure("rejected "+markedQ+" later", smallQ)
	for _, item := range []string{smallQ, markedQ, "token", "value1"} {
		if strings.Contains(got, item) {
			t.Fatalf("modifier q leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u02b9 later",
		"long \u017f word",
		"chapter \u2160 later",
		"schwa \u1d4a here",
		"digit \U0001fbf0 later",
		"hook \u02b1 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("modifier prose changed: %q -> %q", prose, got)
		}
	}
}

func TestModifierASCIIFoldsOnlySingleLetters(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x02B0, 'h', true},
		{0x02B1, 0, false},
		{0x02B2, 'j', true},
		{0x02B3, 'r', true},
		{0x02B7, 'w', true},
		{0x02B8, 'y', true},
		{0x02B9, 0, false},
		{0x02D7, 0, false},
		{0x02E1, 'l', true},
		{0x02E2, 's', true},
		{0x02E3, 'x', true},
		{0x017F, 0, false},
		{0x1D2C, 'A', true},
		{0x1D2D, 0, false},
		{0x1D2E, 'B', true},
		{0x1D30, 'D', true},
		{0x1D31, 'E', true},
		{0x1D32, 0, false},
		{0x1D33, 'G', true},
		{0x1D34, 'H', true},
		{0x1D35, 'I', true},
		{0x1D36, 'J', true},
		{0x1D37, 'K', true},
		{0x1D38, 'L', true},
		{0x1D39, 'M', true},
		{0x1D3A, 'N', true},
		{0x1D3C, 'O', true},
		{0x1D3E, 'P', true},
		{0x1D3F, 'R', true},
		{0x1D40, 'T', true},
		{0x1D41, 'U', true},
		{0x1D42, 'W', true},
		{0x1D43, 'a', true},
		{0x1D47, 'b', true},
		{0x1D48, 'd', true},
		{0x1D49, 'e', true},
		{0x1D4A, 0, false},
		{0x1D4D, 'g', true},
		{0x1D4F, 'k', true},
		{0x1D50, 'm', true},
		{0x1D52, 'o', true},
		{0x1D56, 'p', true},
		{0x1D57, 't', true},
		{0x1D58, 'u', true},
		{0x1D5B, 'v', true},
		{0x1D5D, 0, false},
		{0x1D62, 'i', true},
		{0x1D63, 'r', true},
		{0x1D64, 'u', true},
		{0x1D65, 'v', true},
		{0x1D9C, 'c', true},
		{0x1DA0, 'f', true},
		{0x1DBB, 'z', true},
		{0x2C7C, 'j', true},
		{0x2C7D, 'V', true},
		{0xA7F2, 'C', true},
		{0xA7F3, 'F', true},
		{0xA7F4, 'Q', true},
		{0xA7F8, 0, false},
		{0xA7F9, 0, false},
		{0x107A5, 'q', true},
		{0x212A, 'K', true},
		{0x2126, 0, false},
		{0x2139, 'i', true},
		{0x2160, 0, false},
		{0x2161, 0, false},
		{0x2170, 0, false},
		{0x1FBF0, 0, false},
	}
	for _, check := range checks {
		got, ok := modifierASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := modifierASCII(r); ok {
			n++
		}
	}
	if n != 53 {
		t.Fatalf("modifier fold count %d", n)
	}
}

func TestSanitizeFailureStripsSegmentedDigits(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	marked := strings.NewReplacer(
		"0", "\U0001fbf0",
		"1", "\U0001fbf1",
		"2", "\U0001fbf2",
		"5", "\U0001fbf5",
	).Replace(jwt)
	encoded := strings.Replace(jwt, "2", "%F0%9F%AF%B2", 1)
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{jwt, marked, encoded, "eyJ", "c2lnbmF0dXJl", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "codeVerifier12"
	markedSecret := strings.NewReplacer(
		"1", "\U0001fbf1",
		"2", "\U0001fbf2",
	).Replace(secret)
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, "Verifier12", "erifier"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \U0001fbf0 later",
		"room \u2469 later",
		"item \u2474 later",
		"rev \u2488 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("segmented prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSegmentedASCIIFoldsOnlyDigits(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x1FBEF, 0, false},
		{0x1FBF0, '0', true},
		{0x1FBF1, '1', true},
		{0x1FBF5, '5', true},
		{0x1FBF9, '9', true},
		{0x1FBFA, 0, false},
		{0x2469, 0, false},
		{0x2474, 0, false},
		{0x2488, 0, false},
		{0x24EA, 0, false},
		{0x24FF, 0, false},
		{0xFF10, 0, false},
		{'5', 0, false},
	}
	for _, check := range checks {
		got, ok := segmentedASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := segmentedASCII(r); ok {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("segmented fold count %d", n)
	}
}

func TestSanitizeFailureStripsRomanNumerals(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	marked := strings.NewReplacer(
		"i", "\u2170",
		"c", "\u217d",
		"d", "\u217e",
		"I", "\u2160",
	).Replace(jwt)
	encoded := strings.Replace(jwt, "i", "%E2%85%B0", 1)
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{jwt, marked, encoded, "eyJ", "c2lnbmF0dXJl", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "codeVerifier12"
	markedSecret := strings.NewReplacer(
		"c", "\u217d",
		"i", "\u2170",
		"d", "\u217e",
		"V", "\u2164",
	).Replace(secret)
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, "Verifier12", "erifier"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2161 later",
		"see \u2163 later",
		"see \u2171 later",
		"archaic \u2180 later",
		"chapter \u2160 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("roman prose changed: %q -> %q", prose, got)
		}
	}
}

func TestRomanASCIIFoldsOnlySingleLetters(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x215F, 0, false},
		{0x2160, 'I', true},
		{0x2161, 0, false},
		{0x2163, 0, false},
		{0x2164, 'V', true},
		{0x2169, 'X', true},
		{0x216C, 'L', true},
		{0x216D, 'C', true},
		{0x216E, 'D', true},
		{0x216F, 'M', true},
		{0x2170, 'i', true},
		{0x2171, 0, false},
		{0x2174, 'v', true},
		{0x2179, 'x', true},
		{0x217C, 'l', true},
		{0x217D, 'c', true},
		{0x217E, 'd', true},
		{0x217F, 'm', true},
		{0x2180, 0, false},
		{0x2183, 0, false},
	}
	for _, check := range checks {
		got, ok := romanASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := romanASCII(r); ok {
			n++
		}
	}
	if n != 14 {
		t.Fatalf("roman fold count %d", n)
	}
}

func TestSanitizeFailureStripsLongS(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.signature12"
	marked := strings.ReplaceAll(jwt, "s", "\u017f")
	encoded := strings.Replace(jwt, "s", "%C5%BF", 1)
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{jwt, marked, encoded, "eyJ", "signature12", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "sessionToken12"
	markedSecret := strings.ReplaceAll(secret, "s", "\u017f")
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, "ession", "Token12"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	opaque := "sessionToken12sessionToken12abcd"
	markedOpaque := strings.ReplaceAll(opaque, "s", "\u017f")
	got = SanitizeFailure("rejected " + markedOpaque + " later")
	for _, item := range []string{opaque, markedOpaque, "sessionToken12", "abcd"} {
		if strings.Contains(got, item) {
			t.Fatalf("opaque leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"long \u017f word",
		"see \ufb05 later",
		"see \u1e9b later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("long s prose changed: %q -> %q", prose, got)
		}
	}
}

func TestLongSASCIIFoldsOnlyLongS(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x017F, 's', true},
		{'s', 0, false},
		{0xFB05, 0, false},
		{0x1E9B, 0, false},
		{0x1E9C, 0, false},
		{0x1E9D, 0, false},
		{0x209B, 0, false},
	}
	for _, check := range checks {
		got, ok := longSASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := longSASCII(r); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("long s fold count %d", n)
	}
}

func TestSanitizeFailureStripsPlusEqualsSigns(t *testing.T) {
	opaque := "tokenValue1tokenValue1tokenVal+="
	marked := strings.NewReplacer("+", "\u207a", "=", "\uff1d").Replace(opaque)
	encoded := strings.NewReplacer("+", "%E2%81%BA", "=", "%E2%81%BC").Replace(opaque)
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{opaque, marked, encoded, "tokenValue", "ValueToken"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "code+verif="
	markedSecret := strings.NewReplacer("+", "\ufb29", "=", "\ufe66").Replace(secret)
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, "code", "verif"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"a\u207a b",
		"see \u00b1 later",
		"see \u2260 later",
		"see \u207b later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("plus prose changed: %q -> %q", prose, got)
		}
	}
}

func TestPlusEqualsASCIIFoldsOnlySigns(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x207A, '+', true},
		{0x208A, '+', true},
		{0xFB29, '+', true},
		{0xFE62, '+', true},
		{0xFF0B, '+', true},
		{0x207C, '=', true},
		{0x208C, '=', true},
		{0xFE66, '=', true},
		{0xFF1D, '=', true},
		{'+', 0, false},
		{'=', 0, false},
		{0x00B1, 0, false},
		{0x207B, 0, false},
		{0x208B, 0, false},
		{0x2260, 0, false},
		{0xFF0D, 0, false},
	}
	for _, check := range checks {
		got, ok := plusEqualsASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := plusEqualsASCII(r); ok {
			n++
		}
	}
	if n != 9 {
		t.Fatalf("plus fold count %d", n)
	}
}

func TestSanitizeFailureStripsLowLines(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl_ab12"
	marked := strings.ReplaceAll(jwt, "_", "\uff3f")
	encoded := strings.Replace(jwt, "_", "%EF%BC%BF", 1)
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{jwt, marked, encoded, "eyJ", "c2lnbmF0dXJl", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	secret := "code_verifier1"
	markedSecret := strings.ReplaceAll(secret, "_", "\ufe4d")
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, "verifier1", "code"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	opaque := "tokenValue1tokenValue1tokenVal_1"
	markedOpaque := strings.ReplaceAll(opaque, "_", "\ufe33")
	got = SanitizeFailure("rejected " + markedOpaque + " later")
	for _, item := range []string{opaque, markedOpaque, "tokenValue1", "tokenVal"} {
		if strings.Contains(got, item) {
			t.Fatalf("opaque leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2017 later",
		"see \u02cd later",
		"low \uff3f line",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("low line prose changed: %q -> %q", prose, got)
		}
	}
}

func TestLowLineASCIIFoldsOnlyLowLines(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE33, '_', true},
		{0xFE34, '_', true},
		{0xFE4D, '_', true},
		{0xFE4E, '_', true},
		{0xFE4F, '_', true},
		{0xFF3F, '_', true},
		{'_', 0, false},
		{0x2017, 0, false},
		{0x02CD, 0, false},
		{0xFF0D, 0, false},
	}
	for _, check := range checks {
		got, ok := lowLineASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := lowLineASCII(r); ok {
			n++
		}
	}
	if n != 6 {
		t.Fatalf("low line fold count %d", n)
	}
}

func TestSanitizeFailureStripsSolidusAndTilde(t *testing.T) {
	opaque := "tokenValue1tokenValue1tokenVal/x"
	marked := strings.ReplaceAll(opaque, "/", "\uff0f")
	encoded := strings.Replace(opaque, "/", "%EF%BC%8F", 1)
	got := SanitizeFailure("rejected " + marked + " " + encoded + " later")
	for _, item := range []string{opaque, marked, encoded, "tokenValue", "tokenVal"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	bearer := "Bearer abc.def~ghi/jkl+mnopqrstuvwxyz01"
	markedBearer := strings.NewReplacer("/", "\uff0f", "~", "\uff5e").Replace(bearer)
	encodedBearer := strings.NewReplacer("/", "%EF%BC%8F", "~", "%EF%BD%9E").Replace(bearer)
	got = SanitizeFailure("rejected " + markedBearer + " " + encodedBearer + " later")
	for _, item := range []string{bearer, markedBearer, encodedBearer, "abc.def", "mnopqrstuvwxyz", "Bearer"} {
		if strings.Contains(got, item) {
			t.Fatalf("bearer leaked %q in %q", item, got)
		}
	}
	secret := "code/ver~1"
	markedSecret := strings.NewReplacer("/", "\uff0f", "~", "\uff5e").Replace(secret)
	got = SanitizeFailure("rejected "+markedSecret+" later", secret)
	for _, item := range []string{secret, markedSecret, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("short secret leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2215 later",
		"see \u2044 later",
		"see \u223c later",
		"see \u301c later",
		"see \u02dc later",
		"path \uff0f file",
		"path \uff5e file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("solidus prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSolidusTildeASCIIFoldsOnlyThose(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFF0F, '/', true},
		{0xFF5E, '~', true},
		{0x2044, '/', true},
		{0x2215, '/', true},
		{0x29F6, '/', true},
		{0x29F8, '/', true},
		{'/', 0, false},
		{'~', 0, false},
		{0x1735, '/', true},
		{0x2041, '/', true},
		{0x2571, '/', true},
		{0x27C9, '/', true},
		{0x27C8, 0, false},
		{0x1450, 0, false},
		{0x233F, '/', true},
		{0x2340, 0, false},
		{0x2341, '/', true},
		{0x2342, 0, false},
		{0x2298, '/', true},
		{0x29B8, 0, false},
		{0x2349, 0, false},
		{0x2A38, '/', true},
		{0x1FBA0, '/', true},
		{0x1FBA3, '/', true},
		{0x1FBA1, 0, false},
		{0x1FBA2, 0, false},
		{0x2573, '/', true},
		{0x1FBA4, '/', true},
		{0x1FBA5, '/', true},
		{0x1FBA6, '/', true},
		{0x1FBA7, '/', true},
		{0x1FBA8, '/', true},
		{0x1FBA9, 0, false},
		{0x1FBAA, '/', true},
		{0x1FBAB, '/', true},
		{0x1FBAC, '/', true},
		{0x1FBAD, '/', true},
		{0x1FBAE, '/', true},
		{0x1FBAF, 0, false},
		{0x1FBBD, '/', true},
		{0x1FBBE, '/', true},
		{0x1FBBF, '/', true},
		{0x1FBC0, '/', true},
		{0x1FBCA, '/', true},
		{0x1F7A8, '/', true},
		{0x1F7A9, '/', true},
		{0x1F7AA, '/', true},
		{0x1F7AB, '/', true},
		{0x1F7AC, '/', true},
		{0x1F7AD, '/', true},
		{0x1F7AE, '/', true},
		{0x2613, '/', true},
		{0x26DD, '/', true},
		{0x2B59, '/', true},
		{0x1F7AF, '/', true},
		{0x1F7B0, '/', true},
		{0x1F7B1, '/', true},
		{0x1F7B2, '/', true},
		{0x1F7B3, '/', true},
		{0x1F7B4, '/', true},
		{0x1F7B5, '/', true},
		{0x1F7B6, '/', true},
		{0x1F7B7, '/', true},
		{0x1F7B8, '/', true},
		{0x1F7B9, '/', true},
		{0x1F7BA, '/', true},
		{0x1F7BB, '/', true},
		{0x1F7BC, '/', true},
		{0x1F7BD, '/', true},
		{0x1F7BE, '/', true},
		{0x1F7BF, '/', true},
		{0x1F7C0, '/', true},
		{0x1F7C1, '/', true},
		{0x1F7C2, '/', true},
		{0x1F7C3, '/', true},
		{0x1F7C4, '/', true},
		{0x1F7C5, '/', true},
		{0x1F7C6, '/', true},
		{0x1F7C7, '/', true},
		{0x1F7C8, '/', true},
		{0x1F7C9, '/', true},
		{0x1F7CA, '/', true},
		{0x1F7CB, '/', true},
		{0x1F7CC, '/', true},
		{0x1F7CD, '/', true},
		{0x1F7CE, '/', true},
		{0x1F7CF, '/', true},
		{0x1F7D0, '/', true},
		{0x1F7D1, '/', true},
		{0x1F7D2, '/', true},
		{0x1F7D3, '/', true},
		{0x1F7D4, '/', true},
		{0x1F7D5, '/', true},
		{0x1F7D6, '/', true},
		{0x1F7D7, '/', true},
		{0x1F7D8, '/', true},
		{0x1F7D9, '/', true},
		{0x2715, '/', true},
		{0x2716, '/', true},
		{0x2717, '/', true},
		{0x2718, '/', true},
		{0x2719, 0, false},
		{0x274C, '/', true},
		{0x274E, '/', true},
		{0x1F5D9, '/', true},
		{0x00D7, '/', true},
		{0x2A2F, '/', true},
		{0x2A30, '/', true},
		{0x2A31, '/', true},
		{0x2A34, '/', true},
		{0x2A35, '/', true},
		{0x2A36, '/', true},
		{0x2A37, '/', true},
		{0x2A3B, '/', true},
		{0x2297, '/', true},
		{0x22A0, '/', true},
		{0x2A33, '/', true},
		{0x29D4, '/', true},
		{0x29D5, '/', true},
		{0x29D6, '/', true},
		{0x29D7, '/', true},
		{0x2A32, 0, false},
		{0x229F, 0, false},
		{0x22A1, 0, false},
		{0x2296, 0, false},
		{0x2299, 0, false},
		{0x2A38, '/', true},
		{0x2A3C, 0, false},
		{0x2714, 0, false},
		{0x1F7A7, 0, false},
		{0x1F7E0, 0, false},
		{0x1FBC1, 0, false},
		{0x1FBC5, 0, false},
		{0x1FBF0, 0, false},
		{0xA718, '/', true},
		{0xA717, 0, false},
		{0xA719, 0, false},
		{0x1FB41, '/', true},
		{0x1FB42, '/', true},
		{0x1FB43, '/', true},
		{0x1FB44, '/', true},
		{0x1FB45, '/', true},
		{0x1FB46, '/', true},
		{0x1FB4B, '/', true},
		{0x1FB4A, '/', true},
		{0x1FB49, '/', true},
		{0x1FB48, '/', true},
		{0x1FB47, '/', true},
		{0x1FB61, '/', true},
		{0x1FB60, '/', true},
		{0x1FB5F, '/', true},
		{0x1FB5E, '/', true},
		{0x1FB5D, '/', true},
		{0x1FB98, 0, false},
		{0x25A7, 0, false},
		{0x25A8, '/', true},
		{0x25A9, '/', true},
		{0x25A6, 0, false},
		{0x1FB99, '/', true},
		{0x1FBA4, '/', true},
		{0x1FB5A, '/', true},
		{0x1FB56, 0, false},
		{0x1FB57, '/', true},
		{0x1FB58, '/', true},
		{0x1FB59, '/', true},
		{0x1FB5B, '/', true},
		{0x1FB5C, '/', true},
		{0x1FB5D, '/', true},
		{0x27CB, '/', true},
		{0x2AFD, '/', true},
		{0x1F67C, '/', true},
		{0x2216, 0, false},
		{0x00A5, 0, false},
		{0x30CE, '/', true},
		{0xFF89, '/', true},
		{0x32E8, '/', true},
		{0x3328, '/', true},
		{0x3329, '/', true},
		{0x306E, 0, false},
		{0x3382, 0, false},
		{0x3033, '/', true},
		{0x3034, '/', true},
		{0x3031, 0, false},
		{0x1D20F, 0, false},
		{0x4E3F, '/', true},
		{0x2CC6, '/', true},
		{0x2CC7, '/', true},
		{0x2CF9, 0, false},
		{0xFF3C, 0, false},
		{0xFE68, 0, false},
		{0x223C, 0, false},
		{0x2053, 0, false},
		{0x301C, 0, false},
		{0x02DC, 0, false},
	}
	for _, check := range checks {
		got, ok := solidusTildeASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := solidusTildeASCII(r); ok {
			n++
		}
	}
	if n != 153 {
		t.Fatalf("solidus tilde fold count %d", n)
	}
}

func TestSanitizeFailureStripsSlashLookalikes(t *testing.T) {
	secret := "code/ver/1"
	division := strings.ReplaceAll(secret, "/", "\u2215")
	fraction := strings.ReplaceAll(secret, "/", "\u2044")
	big := strings.ReplaceAll(secret, "/", "\u29f8")
	over := strings.ReplaceAll(secret, "/", "\u29f6")
	encoded := strings.ReplaceAll(secret, "/", "%E2%88%95")
	got := SanitizeFailure("rejected "+division+" "+encoded+" later", secret)
	for _, item := range []string{secret, division, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	got = SanitizeFailure("rejected "+fraction+" "+big+" "+over+" later", secret)
	for _, item := range []string{secret, fraction, big, over, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("lookalike leaked %q in %q", item, got)
		}
	}
	opaque := "tokenValue1tokenValue1tokenVal/x"
	markedOpaque := strings.ReplaceAll(opaque, "/", "\u2215")
	got = SanitizeFailure("rejected " + markedOpaque + " later")
	for _, item := range []string{opaque, markedOpaque, "tokenValue", "tokenVal"} {
		if strings.Contains(got, item) {
			t.Fatalf("opaque leaked %q in %q", item, got)
		}
	}
	back := "code\\ver\\1"
	yen := strings.ReplaceAll(back, "\\", "\u00a5")
	won := strings.ReplaceAll(back, "\\", "\u20a9")
	set := strings.ReplaceAll(back, "\\", "\u2216")
	op := strings.ReplaceAll(back, "\\", "\u29f5")
	stroke := strings.ReplaceAll(back, "\\", "\u29f7")
	bigBack := strings.ReplaceAll(back, "\\", "\u29f9")
	ocr := strings.ReplaceAll(back, "\\", "\u244a")
	encodedBack := strings.ReplaceAll(back, "\\", "%C2%A5")
	got = SanitizeFailure("rejected "+yen+" "+encodedBack+" "+won+" "+set+" "+op+" "+stroke+" "+bigBack+" "+ocr+" later", back)
	for _, item := range []string{back, yen, won, set, op, stroke, bigBack, ocr, encodedBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("backslash leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2215 later",
		"see \u00a5 later",
		"see \u244a later",
		"see \u30ce later",
		"see \u2571 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("slash prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsDiagonalSlashes(t *testing.T) {
	secret := "code/ver/1"
	box := strings.ReplaceAll(secret, "/", "\u2571")
	rising := strings.ReplaceAll(secret, "/", "\u27cb")
	heavy := strings.ReplaceAll(secret, "/", "\U0001f67c")
	encoded := strings.ReplaceAll(secret, "/", "%E2%95%B1")
	got := SanitizeFailure("rejected "+box+" "+encoded+" "+rising+" "+heavy+" later", secret)
	for _, item := range []string{secret, box, rising, heavy, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	back := "code\\ver\\1"
	falling := strings.ReplaceAll(back, "\\", "\u2572")
	math := strings.ReplaceAll(back, "\\", "\u27cd")
	stroke := strings.ReplaceAll(back, "\\", "\u31d4")
	encodedBack := strings.ReplaceAll(back, "\\", "%E2%95%B2")
	got = SanitizeFailure("rejected "+falling+" "+encodedBack+" "+math+" "+stroke+" later", back)
	for _, item := range []string{back, falling, math, stroke, encodedBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("backslash leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{"see \u2571 later", "see \u3033 later", "see \u30ce later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsGreekNotationSlashes(t *testing.T) {
	secret := "code\\ver\\1"
	vocal := strings.ReplaceAll(secret, "\\", "\U0001d20f")
	inst47 := strings.ReplaceAll(secret, "\\", "\U0001d23a")
	inst48 := strings.ReplaceAll(secret, "\\", "\U0001d23b")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9D%88%8F")
	got := SanitizeFailure("rejected "+vocal+" "+encoded+" "+inst47+" "+inst48+" later", secret)
	for _, item := range []string{secret, vocal, inst47, inst48, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001d20f later", "see \u3035 later", "see \u30ce later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("greek prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsKanaRepeatSlashes(t *testing.T) {
	secret := "code/ver/1"
	upper := strings.ReplaceAll(secret, "/", "\u3033")
	voiced := strings.ReplaceAll(secret, "/", "\u3034")
	encoded := strings.ReplaceAll(secret, "/", "%E3%80%B3")
	got := SanitizeFailure("rejected "+upper+" "+encoded+" "+voiced+" later", secret)
	for _, item := range []string{secret, upper, voiced, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	back := "code\\ver\\1"
	lower := strings.ReplaceAll(back, "\\", "\u3035")
	encodedBack := strings.ReplaceAll(back, "\\", "%E3%80%B5")
	got = SanitizeFailure("rejected "+lower+" "+encodedBack+" later", back)
	for _, item := range []string{back, lower, encodedBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("backslash leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{"see \u3031 later", "see \u3033 later", "see \u30ce later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("kana prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsRadicalIdeographs(t *testing.T) {
	secret := "code/ver/1"
	slash := strings.ReplaceAll(secret, "/", "\u4e3f")
	encoded := strings.ReplaceAll(secret, "/", "%E4%B8%BF")
	got := SanitizeFailure("rejected "+slash+" "+encoded+" later", secret)
	for _, item := range []string{secret, slash, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	back := "code\\ver\\1"
	dot := strings.ReplaceAll(back, "\\", "\u4e36")
	encodedBack := strings.ReplaceAll(back, "\\", "%E4%B8%B6")
	got = SanitizeFailure("rejected "+dot+" "+encodedBack+" later", back)
	for _, item := range []string{back, dot, encodedBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("backslash leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{"see \u4e3f later", "see \u4e36 later", "see \u30ce later", "see \u2cc6 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("ideograph prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsKatakanaNoAndCopticEsh(t *testing.T) {
	secret := "code/ver/1"
	kana := strings.ReplaceAll(secret, "/", "\u30ce")
	half := strings.ReplaceAll(secret, "/", "\uff89")
	capital := strings.ReplaceAll(secret, "/", "\u2cc6")
	small := strings.ReplaceAll(secret, "/", "\u2cc7")
	encoded := strings.ReplaceAll(secret, "/", "%E3%83%8E")
	encodedHalf := strings.ReplaceAll(secret, "/", "%EF%BE%89")
	got := SanitizeFailure("rejected "+kana+" "+encoded+" "+half+" "+encodedHalf+" "+capital+" "+small+" later", secret)
	for _, item := range []string{secret, kana, half, capital, small, encoded, encodedHalf, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u30ce later", "see \uff89 later", "see \u2cc6 later", "see \u306e later", "see \u2cf9 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("kana prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCircledKatakanaNo(t *testing.T) {
	secret := "code/ver/1"
	circled := strings.ReplaceAll(secret, "/", "\u32e8")
	nano := strings.ReplaceAll(secret, "/", "\u3328")
	notto := strings.ReplaceAll(secret, "/", "\u3329")
	encoded := strings.ReplaceAll(secret, "/", "%E3%8B%A8")
	got := SanitizeFailure("rejected "+circled+" "+encoded+" "+nano+" "+notto+" later", secret)
	for _, item := range []string{secret, circled, nano, notto, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u32e8 later", "see \u3328 later", "see \u3329 later", "see \u3382 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circled prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsSyllabicSlashes(t *testing.T) {
	secret := "code/ver/1"
	superset := strings.ReplaceAll(secret, "/", "\u27c9")
	encoded := strings.ReplaceAll(secret, "/", "%E2%9F%89")
	got := SanitizeFailure("rejected "+superset+" "+encoded+" later", secret)
	for _, item := range []string{secret, superset, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	back := "code\\ver\\1"
	subset := strings.ReplaceAll(back, "\\", "\u27c8")
	encodedBack := strings.ReplaceAll(back, "\\", "%E2%9F%88")
	got = SanitizeFailure("rejected "+subset+" "+encodedBack+" later", back)
	for _, item := range []string{back, subset, encodedBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("backslash leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{"see \u27c9 later", "see \u27c8 later", "see \u1450 later", "see \u1455 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("syllabic prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsAPLSlashBars(t *testing.T) {
	secret := "code/ver/1"
	bar := strings.ReplaceAll(secret, "/", "\u233f")
	encoded := strings.ReplaceAll(secret, "/", "%E2%8C%BF")
	got := SanitizeFailure("rejected "+bar+" "+encoded+" later", secret)
	for _, item := range []string{secret, bar, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	back := "code\\ver\\1"
	aplBack := strings.ReplaceAll(back, "\\", "\u2340")
	encodedBack := strings.ReplaceAll(back, "\\", "%E2%8D%80")
	got = SanitizeFailure("rejected "+aplBack+" "+encodedBack+" later", back)
	for _, item := range []string{back, aplBack, encodedBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("backslash leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{"see \u233f later", "see \u2340 later", "see \u2341 later", "see \u2342 later", "see \u2298 later", "see \u29b8 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("APL prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsQuadSlashes(t *testing.T) {
	secret := "code/ver/1"
	quad := strings.ReplaceAll(secret, "/", "\u2341")
	encoded := strings.ReplaceAll(secret, "/", "%E2%8D%81")
	got := SanitizeFailure("rejected "+quad+" "+encoded+" later", secret)
	for _, item := range []string{secret, quad, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	back := "code\\ver\\1"
	quadBack := strings.ReplaceAll(back, "\\", "\u2342")
	encodedBack := strings.ReplaceAll(back, "\\", "%E2%8D%82")
	got = SanitizeFailure("rejected "+quadBack+" "+encodedBack+" later", back)
	for _, item := range []string{back, quadBack, encodedBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("backslash leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{"see \u2341 later", "see \u2342 later", "see \u2349 later", "see \u2298 later", "see \u29b8 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("quad prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCircledSlashes(t *testing.T) {
	secret := "code/ver/1"
	circled := strings.ReplaceAll(secret, "/", "\u2298")
	encoded := strings.ReplaceAll(secret, "/", "%E2%8A%98")
	got := SanitizeFailure("rejected "+circled+" "+encoded+" later", secret)
	for _, item := range []string{secret, circled, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	back := "code\\ver\\1"
	circledBack := strings.ReplaceAll(back, "\\", "\u29b8")
	encodedBack := strings.ReplaceAll(back, "\\", "%E2%A6%B8")
	got = SanitizeFailure("rejected "+circledBack+" "+encodedBack+" later", back)
	for _, item := range []string{back, circledBack, encodedBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("backslash leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{"see \u2298 later", "see \u29b8 later", "see \u2349 later", "see \u2a38 later", "see \u29bc later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circled prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsAPLCircleBackslash(t *testing.T) {
	secret := "code\\ver\\1"
	circled := strings.ReplaceAll(secret, "\\", "\u2349")
	encoded := strings.ReplaceAll(secret, "\\", "%E2%8D%89")
	got := SanitizeFailure("rejected "+circled+" "+encoded+" later", secret)
	for _, item := range []string{secret, circled, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2349 later", "see \u2a38 later", "see \u20e0 later", "see \u2339 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circle backslash prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortDiagonals(t *testing.T) {
	secret := "code/ver/1"
	rising := strings.ReplaceAll(secret, "/", "\U0001fba0")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%A0")
	got := SanitizeFailure("rejected "+rising+" "+encoded+" later", secret)
	for _, item := range []string{secret, rising, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	lower := strings.ReplaceAll(secret, "/", "\U0001fba3")
	got = SanitizeFailure("rejected "+lower+" later", secret)
	for _, item := range []string{secret, lower, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("lower leaked %q in %q", item, got)
		}
	}
	back := "code\\ver\\1"
	falling := strings.ReplaceAll(back, "\\", "\U0001fba1")
	encodedBack := strings.ReplaceAll(back, "\\", "%F0%9F%AE%A1")
	got = SanitizeFailure("rejected "+falling+" "+encodedBack+" later", back)
	for _, item := range []string{back, falling, encodedBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("backslash leaked %q in %q", item, got)
		}
	}
	lowerBack := strings.ReplaceAll(back, "\\", "\U0001fba2")
	got = SanitizeFailure("rejected "+lowerBack+" later", back)
	for _, item := range []string{back, lowerBack, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("lower backslash leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{"see \U0001fba0 later", "see \U0001fba1 later", "see \U0001fba2 later", "see \U0001fba3 later", "see \u2573 later", "see \U0001fba4 later", "see \U0001fbbe later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsNegativeDiagonal(t *testing.T) {
	secret := "code/ver/1"
	neg := strings.ReplaceAll(secret, "/", "\U0001fbbe")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%BE")
	got := SanitizeFailure("rejected "+neg+" "+encoded+" later", secret)
	for _, item := range []string{secret, neg, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001fbbe later", "see \U0001fbbd later", "see \U0001fbbf later", "see \u2573 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("negative diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsModifierDotSlash(t *testing.T) {
	secret := "code/ver/1"
	dot := strings.ReplaceAll(secret, "/", "\uA718")
	encoded := strings.ReplaceAll(secret, "/", "%EA%9C%98")
	got := SanitizeFailure("rejected "+dot+" "+encoded+" later", secret)
	for _, item := range []string{secret, dot, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \uA718 later", "see \uA717 later", "see \uA719 later", "see \u2E4A later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("modifier slash prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB66")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%A6")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB66 later", "see \U0001FB65 later", "see \U0001FB67 later", "see \U0001FBA1 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsWiderBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB65")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%A5")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB65 later", "see \U0001FB64 later", "see \U0001FB67 later", "see \U0001FB66 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("wider block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMiddleBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB67")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%A7")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB67 later", "see \U0001FB68 later", "see \U0001FB64 later", "see \U0001FB66 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("middle block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsInnerBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB64")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%A4")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB64 later", "see \U0001FB63 later", "see \U0001FB68 later", "see \U0001FB66 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("inner block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsTopBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB63")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%A3")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB63 later", "see \U0001FB62 later", "see \U0001FB68 later", "see \U0001FB64 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("top block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortTopBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB62")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%A2")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB62 later", "see \U0001FB56 later", "see \U0001FB68 later", "see \U0001FB63 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short top block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerCentreBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB56")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%96")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB56 later", "see \U0001FB55 later", "see \U0001FB68 later", "see \U0001FB62 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower centre block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsOuterBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB55")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%95")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB55 later", "see \U0001FB54 later", "see \U0001FB68 later", "see \U0001FB56 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("outer block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortLowerUpperLeftBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB5D")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%9D")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB5D later", "see \U0001FBA4 later", "see \U0001FB68 later", "see \U0001FB5E later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short lower upper left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerUpperLeftBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB5E")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%9E")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB5E later", "see \U0001FB5D later", "see \U0001FB68 later", "see \U0001FB5F later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower upper left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortLowerCentreUpperLeftBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB5F")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%9F")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB5F later", "see \U0001FB5E later", "see \U0001FB68 later", "see \U0001FB60 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short lower centre upper left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsOuterUpperLeftBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB60")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%A0")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB60 later", "see \U0001FB5F later", "see \U0001FB68 later", "see \U0001FB61 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("outer upper left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerCentreUpperLeftBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB61")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%A1")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB61 later", "see \U0001FB60 later", "see \U0001FB68 later", "see \U0001FB57 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower centre upper left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortLowerLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB47")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%87")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB47 later", "see \U0001FB61 later", "see \U0001FB68 later", "see \U0001FB48 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short lower lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB48")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%88")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB48 later", "see \U0001FB47 later", "see \U0001FB49 later", "see \U0001FB4A later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortLowerCentreLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB49")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%89")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB49 later", "see \U0001FB48 later", "see \U0001FB47 later", "see \U0001FB4A later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short lower centre lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsOuterLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB4A")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%8A")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB4A later", "see \U0001FB49 later", "see \U0001FB47 later", "see \U0001FB4B later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("outer lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerCentreLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB4B")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%8B")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB4B later", "see \U0001FB4A later", "see \U0001FB47 later", "see \U0001FB41 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower centre lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortTopLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB41")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%81")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB41 later", "see \U0001FB40 later", "see \U0001FB47 later", "see \U0001FB42 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short top lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsTopLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB42")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%82")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB42 later", "see \U0001FB41 later", "see \U0001FB47 later", "see \U0001FB43 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("top lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsInnerLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB43")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%83")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB43 later", "see \U0001FB42 later", "see \U0001FB47 later", "see \U0001FB44 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("inner lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMiddleLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB46")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%86")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB46 later", "see \U0001FB47 later", "see \U0001FB43 later", "see \U0001FB44 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("middle lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsWiderLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB44")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%84")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB44 later", "see \U0001FB43 later", "see \U0001FB46 later", "see \U0001FB45 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("wider lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerRightBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB45")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%85")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB45 later", "see \U0001FB44 later", "see \U0001FB46 later", "see \U0001FB5B later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower right block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortLowerLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB3C")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AC%BC")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB3C later", "see \U0001FB41 later", "see \U0001FB68 later", "see \U0001FB3D later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short lower lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB3D")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AC%BD")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB3D later", "see \U0001FB3C later", "see \U0001FB68 later", "see \U0001FB3E later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortLowerCentreLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB3E")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AC%BE")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB3E later", "see \U0001FB3D later", "see \U0001FB68 later", "see \U0001FB3F later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short lower centre lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsOuterLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB3F")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AC%BF")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB3F later", "see \U0001FB3E later", "see \U0001FB68 later", "see \U0001FB40 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("outer lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerCentreLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB40")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%80")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB40 later", "see \U0001FB3F later", "see \U0001FB68 later", "see \U0001FB4C later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower centre lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortTopLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB4C")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%8C")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB4C later", "see \U0001FB40 later", "see \U0001FB68 later", "see \U0001FB4D later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short top lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsTopLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB4D")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%8D")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB4D later", "see \U0001FB4C later", "see \U0001FB68 later", "see \U0001FB4E later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("top lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsInnerLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB4E")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%8E")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB4E later", "see \U0001FB4D later", "see \U0001FB68 later", "see \U0001FB4F later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("inner lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMiddleLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB51")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%91")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB51 later", "see \U0001FB4E later", "see \U0001FB68 later", "see \U0001FB4F later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("middle lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsWiderLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB4F")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%8F")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB4F later", "see \U0001FB4E later", "see \U0001FB68 later", "see \U0001FB50 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("wider lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerLeftBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB50")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%90")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB50 later", "see \U0001FB4F later", "see \U0001FB68 later", "see \U0001FB52 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower left block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsUpperRightToLowerLeftFill(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB99")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%99")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB99 later", "see \U0001FB98 later", "see \U0001FB68 later", "see \U0001FBA4 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("upper right to lower left fill prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsSquareUpperRightToLowerLeftFill(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u25A8")
	encoded := strings.ReplaceAll(secret, "/", "%E2%96%A8")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u25A8 later", "see \u25A7 later", "see \u25A9 later", "see \U0001FB99 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("square upper right to lower left fill prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsSquareDiagonalCrosshatch(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u25A9")
	encoded := strings.ReplaceAll(secret, "/", "%E2%96%A9")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u25A9 later", "see \u25A8 later", "see \u25A6 later", "see \u2573 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("square diagonal crosshatch prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalCross(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2573")
	encoded := strings.ReplaceAll(secret, "/", "%E2%95%B3")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2573 later", "see \u25A9 later", "see \U0001FBA4 later", "see \u25A6 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light diagonal cross prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalCorner(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBA4")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%A4")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBA4 later", "see \u2573 later", "see \U0001FBA5 later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light diagonal corner prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalRightCorner(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBA5")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%A5")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBA5 later", "see \U0001FBA4 later", "see \U0001FBA6 later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light diagonal right corner prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalLowerCorner(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBA6")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%A6")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBA6 later", "see \U0001FBA5 later", "see \U0001FBA7 later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light diagonal lower corner prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalTopCorner(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBA7")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%A7")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBA7 later", "see \U0001FBA6 later", "see \U0001FBA8 later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light diagonal top corner prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalPairedRise(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBA8")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%A8")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBA8 later", "see \U0001FBA7 later", "see \U0001FBA9 later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("paired rising light diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalPairedFall(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FBA9")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AE%A9")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBA9 later", "see \U0001FBA8 later", "see \U0001FBAA later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("paired falling light diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalLongRightPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBAA")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%AA")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBAA later", "see \U0001FBA9 later", "see \U0001FBAB later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("long right light diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalLongLeftPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBAB")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%AB")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBAB later", "see \U0001FBAA later", "see \U0001FBAC later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("long left light diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalLongUpperPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBAC")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%AC")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBAC later", "see \U0001FBAB later", "see \U0001FBAD later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("long upper light diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalLongRightUpperPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBAD")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%AD")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBAD later", "see \U0001FBAC later", "see \U0001FBAE later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("long right-upper light diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightDiagonalDiamondPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBAE")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%AE")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBAE later", "see \U0001FBAD later", "see \U0001FBAF later", "see \U0001FBBF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light diagonal diamond prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsNegativeDiagonalDiamondPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBBF")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%BF")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBBF later", "see \U0001FBBE later", "see \U0001FBBD later", "see \U0001FBC0 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("negative diagonal diamond prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsNegativeDiagonalCrossPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBBD")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AE%BD")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBBD later", "see \U0001FBBF later", "see \U0001FBC0 later", "see \U0001FBBC later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("negative diagonal cross prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCircledDivisionSignPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A38")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%B8")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A38 later", "see \u2A3C later", "see \u2A32 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circled division sign prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsBlackHourglassPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u29D7")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A7%97")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u29D7 later", "see \u2A38 later", "see \u2A32 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("black hourglass prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsWhiteHourglassPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u29D6")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A7%96")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u29D6 later", "see \u29D7 later", "see \u2A38 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("white hourglass prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsTimesWithRightHalfBlackPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u29D5")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A7%95")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u29D5 later", "see \u29D6 later", "see \u29D7 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("times with right half black prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsTimesWithLeftHalfBlackPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u29D4")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A7%94")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u29D4 later", "see \u29D5 later", "see \u2A32 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("times with left half black prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsSmashProductPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A33")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%B3")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A33 later", "see \u2A32 later", "see \u2A38 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("smash product prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsSquaredTimesPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u22A0")
	encoded := strings.ReplaceAll(secret, "/", "%E2%8A%A0")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u22A0 later", "see \u229F later", "see \u22A1 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("squared times prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCircledTimesPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2297")
	encoded := strings.ReplaceAll(secret, "/", "%E2%8A%97")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2297 later", "see \u2296 later", "see \u2299 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circled times prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMultiplicationSignInTrianglePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A3B")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%BB")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A3B later", "see \u2A38 later", "see \u2A3C later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("multiplication sign in triangle prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMultiplicationSignInDoubleCirclePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A37")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%B7")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A37 later", "see \u2A38 later", "see \u2A33 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("multiplication sign in double circle prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCircledMultiplicationSignWithCircumflexPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A36")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%B6")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A36 later", "see \u2A37 later", "see \u2A33 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circled multiplication sign with circumflex prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMultiplicationSignInRightHalfCirclePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A35")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%B5")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A35 later", "see \u2A36 later", "see \u2A33 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("multiplication sign in right half circle prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMultiplicationSignInLeftHalfCirclePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A34")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%B4")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A34 later", "see \u2A35 later", "see \u2A33 later", "see \u2719 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("multiplication sign in left half circle prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMultiplicationSignWithUnderbarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A31")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%B1")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A31 later", "see \u2A33 later", "see \u2719 later", "see \u2A30 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("multiplication sign with underbar prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMultiplicationSignWithDotAbovePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A30")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%B0")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A30 later", "see \u2A31 later", "see \u2719 later", "see \u2A2F later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("multiplication sign with dot above prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsVectorOrCrossProductPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2A2F")
	encoded := strings.ReplaceAll(secret, "/", "%E2%A8%AF")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2A2F later", "see \u2A30 later", "see \u2719 later", "see \u00D7 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("vector or cross product prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMultiplicationSignPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u00D7")
	encoded := strings.ReplaceAll(secret, "/", "%C3%97")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u00D7 later", "see \u2A2F later", "see \u2719 later", "see \U0001F5D9 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("multiplication sign prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCancellationXPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F5D9")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%97%99")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F5D9 later", "see \u00D7 later", "see \u2719 later", "see \u274E later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("cancellation x prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsNegativeSquaredCrossMarkPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u274E")
	encoded := strings.ReplaceAll(secret, "/", "%E2%9D%8E")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u274E later", "see \U0001F5D9 later", "see \u2719 later", "see \u274C later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("negative squared cross mark prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCrossMarkPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u274C")
	encoded := strings.ReplaceAll(secret, "/", "%E2%9D%8C")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u274C later", "see \u274E later", "see \u2719 later", "see \u2718 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("cross mark prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavyBallotXPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2718")
	encoded := strings.ReplaceAll(secret, "/", "%E2%9C%98")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2718 later", "see \u2719 later", "see \u274C later", "see \u2717 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy ballot x prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsBallotXPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2717")
	encoded := strings.ReplaceAll(secret, "/", "%E2%9C%97")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2717 later", "see \u2718 later", "see \u2716 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("ballot x prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavyMultiplicationXPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2716")
	encoded := strings.ReplaceAll(secret, "/", "%E2%9C%96")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2716 later", "see \u2717 later", "see \u2715 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy multiplication x prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMultiplicationXPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2715")
	encoded := strings.ReplaceAll(secret, "/", "%E2%9C%95")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2715 later", "see \u2716 later", "see \u2714 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("multiplication x prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsNinePointedWhiteStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D9")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%99")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D9 later", "see \U0001F7E0 later", "see \U0001F7D8 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("nine pointed white star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsNegativeCircledSquarePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D8")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%98")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D8 later", "see \U0001F7D9 later", "see \U0001F7D7 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("negative circled square prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCircledSquarePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D7")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%97")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D7 later", "see \U0001F7D8 later", "see \U0001F7D6 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circled square prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsNegativeCircledTrianglePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D6")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%96")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D6 later", "see \U0001F7D7 later", "see \U0001F7D5 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("negative circled triangle prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCircledTrianglePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D5")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%95")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D5 later", "see \U0001F7D6 later", "see \U0001F7D4 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circled triangle prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavyTwelvePointedPinwheelStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D4")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%94")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D4 later", "see \U0001F7D5 later", "see \U0001F7D3 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy twelve pointed pinwheel star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavyTwelvePointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D3")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%93")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D3 later", "see \U0001F7D4 later", "see \U0001F7D2 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy twelve pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightTwelvePointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D2")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%92")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D2 later", "see \U0001F7D3 later", "see \U0001F7D1 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light twelve pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavyEightPointedPinwheelStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D1")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%91")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D1 later", "see \U0001F7D2 later", "see \U0001F7D0 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy eight pointed pinwheel star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsVeryHeavyEightPointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7D0")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%90")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7D0 later", "see \U0001F7D1 later", "see \U0001F7CF later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("very heavy eight pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavyEightPointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7CF")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%8F")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7CF later", "see \U0001F7D0 later", "see \U0001F7CE later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy eight pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMediumEightPointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7CE")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%8E")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7CE later", "see \U0001F7CF later", "see \U0001F7CD later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("medium eight pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsSixPointedPinwheelStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7CD")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%8D")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7CD later", "see \U0001F7CE later", "see \U0001F7CC later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("six pointed pinwheel star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavySixPointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7CC")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%8C")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7CC later", "see \U0001F7CD later", "see \U0001F7CB later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy six pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMediumSixPointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7CB")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%8B")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7CB later", "see \U0001F7CC later", "see \U0001F7CA later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("medium six pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavyFivePointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7CA")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%8A")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7CA later", "see \U0001F7CB later", "see \U0001F7C9 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy five pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightFivePointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C9")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%89")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C9 later", "see \U0001F7CA later", "see \U0001F7C8 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light five pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsReverseLightFourPointedPinwheelStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C8")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%88")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C8 later", "see \U0001F7C9 later", "see \U0001F7C7 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("reverse light four pointed pinwheel star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMediumFourPointedPinwheelStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C7")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%87")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C7 later", "see \U0001F7C8 later", "see \U0001F7C6 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("medium four pointed pinwheel star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsFourPointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C6")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%86")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C6 later", "see \U0001F7C7 later", "see \U0001F7C5 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("four pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMediumFourPointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C5")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%85")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C5 later", "see \U0001F7C6 later", "see \U0001F7C4 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("medium four pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightFourPointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C4")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%84")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C4 later", "see \U0001F7C5 later", "see \U0001F7C3 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light four pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMediumThreePointedPinwheelStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C3")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%83")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C3 later", "see \U0001F7C4 later", "see \U0001F7C2 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("medium three pointed pinwheel star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsThreePointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C2")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%82")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C2 later", "see \U0001F7C3 later", "see \U0001F7C1 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("three pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMediumThreePointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C1")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%81")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C1 later", "see \U0001F7C2 later", "see \U0001F7C0 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("medium three pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightThreePointedBlackStarPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7C0")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9F%80")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7C0 later", "see \U0001F7C1 later", "see \U0001F7BF later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light three pointed black star prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsEightSpokedAsteriskPaths(t *testing.T) {
	secret := "code/ver/1"
	marks := []struct {
		name string
		r    rune
		next rune
	}{
		{"light", '\U0001F7BB', '\U0001F7BC'},
		{"medium", '\U0001F7BC', '\U0001F7BD'},
		{"bold", '\U0001F7BD', '\U0001F7BE'},
		{"heavy", '\U0001F7BE', '\U0001F7BF'},
		{"very heavy", '\U0001F7BF', '\U0001F7C0'},
	}
	for _, mark := range marks {
		block := strings.ReplaceAll(secret, "/", string(mark.r))
		var bytes []string
		for _, b := range []byte(string(mark.r)) {
			bytes = append(bytes, fmt.Sprintf("%%%02X", b))
		}
		encoded := strings.ReplaceAll(secret, "/", strings.Join(bytes, ""))
		got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
		for _, item := range []string{secret, block, encoded, "code", "ver"} {
			if strings.Contains(got, item) {
				t.Fatalf("%s leaked %q in %q", mark.name, item, got)
			}
		}
		if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
			t.Fatalf("%s lost context: %q", mark.name, got)
		}
		for _, prose := range []string{
			"see " + string(mark.r) + " later",
			"see " + string(mark.next) + " later",
			"see \u2B59 later",
		} {
			if got := SanitizeFailure(prose); got != prose {
				t.Fatalf("%s eight spoked asterisk prose changed: %q -> %q", mark.name, prose, got)
			}
		}
	}
}

func TestSanitizeFailureStripsExtremelyHeavySixSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7BA")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%BA")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7BA later", "see \U0001F7BB later", "see \U0001F7B9 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("extremely heavy six spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsVeryHeavySixSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B9")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B9")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B9 later", "see \U0001F7BA later", "see \U0001F7B8 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("very heavy six spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavySixSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B8")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B8")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B8 later", "see \U0001F7B9 later", "see \U0001F7B7 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy six spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsBoldSixSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B7")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B7")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B7 later", "see \U0001F7B8 later", "see \U0001F7B6 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("bold six spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMediumSixSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B6")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B6")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B6 later", "see \U0001F7B7 later", "see \U0001F7B5 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("medium six spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightSixSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B5")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B5")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B5 later", "see \U0001F7B6 later", "see \U0001F7B4 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light six spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsExtremelyHeavyFiveSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B4")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B4")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B4 later", "see \U0001F7B5 later", "see \U0001F7B3 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("extremely heavy five spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsVeryHeavyFiveSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B3")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B3")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B3 later", "see \U0001F7B4 later", "see \U0001F7B2 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("very heavy five spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavyFiveSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B2")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B2")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B2 later", "see \U0001F7B3 later", "see \U0001F7B1 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy five spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsBoldFiveSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B1")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B1")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B1 later", "see \U0001F7B2 later", "see \U0001F7B0 later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("bold five spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMediumFiveSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7B0")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%B0")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7B0 later", "see \U0001F7B1 later", "see \U0001F7AF later", "see \u2B59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("medium five spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightFiveSpokedAsteriskPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7AF")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%AF")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7AF later", "see \U0001F7B0 later", "see \u2B59 later", "see \u26DD later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light five spoked asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavyCircledSaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2B59")
	encoded := strings.ReplaceAll(secret, "/", "%E2%AD%99")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2B59 later", "see \U0001F7AF later", "see \u26DD later", "see \u2613 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy circled saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsSquaredSaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u26DD")
	encoded := strings.ReplaceAll(secret, "/", "%E2%9B%9D")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u26DD later", "see \u2B59 later", "see \u2613 later", "see \U0001F7AF later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("squared saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsSaltireMarkPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\u2613")
	encoded := strings.ReplaceAll(secret, "/", "%E2%98%93")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u2613 later", "see \u26DD later", "see \U0001F7AF later", "see \U0001F7AE later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("saltire mark prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsExtremelyHeavySaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7AE")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%AE")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7AE later", "see \U0001F7AD later", "see \U0001F7AF later", "see \U0001F7AC later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("extremely heavy saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsVeryHeavySaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7AD")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%AD")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7AD later", "see \U0001F7AC later", "see \U0001F7AE later", "see \U0001F7AB later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("very heavy saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsHeavySaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7AC")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%AC")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7AC later", "see \U0001F7AB later", "see \U0001F7AD later", "see \U0001F7AA later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("heavy saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsBoldSaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7AB")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%AB")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7AB later", "see \U0001F7AA later", "see \U0001F7AC later", "see \U0001F7A9 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("bold saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMediumSaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7AA")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%AA")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7AA later", "see \U0001F7A9 later", "see \U0001F7AB later", "see \U0001F7A8 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("medium saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLightSaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7A9")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%A9")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7A9 later", "see \U0001F7A8 later", "see \U0001F7AA later", "see \U0001F7A7 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("light saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsThinSaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001F7A8")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%9E%A8")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001F7A8 later", "see \U0001F7A7 later", "see \U0001F7A9 later", "see \U0001FBCA later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("thin saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsWhiteUpPointingChevronPath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBCA")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AF%8A")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBCA later", "see \U0001FBC0 later", "see \U0001FBC1 later", "see \U0001FBF0 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("white up-pointing chevron prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsWhiteHeavySaltirePath(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FBC0")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AF%80")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FBC0 later", "see \U0001FBBD later", "see \U0001FBC1 later", "see \U0001FBCA later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("white heavy saltire prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsSquareUpperLeftToLowerRightFill(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\u25A7")
	encoded := strings.ReplaceAll(secret, "\\", "%E2%96%A7")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \u25A7 later", "see \u25A8 later", "see \u25A9 later", "see \U0001FB98 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("square upper left to lower right fill prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsUpperLeftToLowerRightFill(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB98")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AE%98")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB98 later", "see \U0001FB99 later", "see \U0001FB68 later", "see \U0001FB52 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("upper left to lower right fill prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortLowerBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB52")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%92")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB52 later", "see \U0001FB51 later", "see \U0001FB68 later", "see \U0001FB53 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short lower block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsLowerBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB53")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%93")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB53 later", "see \U0001FB52 later", "see \U0001FB68 later", "see \U0001FB54 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("lower block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortLowerCentreBlockDiagonal(t *testing.T) {
	secret := "code\\ver\\1"
	block := strings.ReplaceAll(secret, "\\", "\U0001FB54")
	encoded := strings.ReplaceAll(secret, "\\", "%F0%9F%AD%94")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB54 later", "see \U0001FB53 later", "see \U0001FB68 later", "see \U0001FB55 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short lower centre block diagonal prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsRisingBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB5B")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%9B")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB5B later", "see \U0001FB5A later", "see \U0001FB5C later", "see \U0001FBA0 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("rising block prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsWiderRisingBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB5A")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%9A")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB5A later", "see \U0001FB59 later", "see \U0001FB5C later", "see \U0001FB5B later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("wider rising block prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsMiddleRisingBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB5C")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%9C")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB5C later", "see \U0001FB5D later", "see \U0001FB59 later", "see \U0001FB5A later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("middle rising block prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsInnerRisingBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB59")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%99")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB59 later", "see \U0001FB58 later", "see \U0001FB5D later", "see \U0001FB5A later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("inner rising block prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsTopRisingBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB58")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%98")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB58 later", "see \U0001FB57 later", "see \U0001FB5D later", "see \U0001FB59 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("top rising block prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsShortTopRisingBlockDiagonal(t *testing.T) {
	secret := "code/ver/1"
	block := strings.ReplaceAll(secret, "/", "\U0001FB57")
	encoded := strings.ReplaceAll(secret, "/", "%F0%9F%AD%97")
	got := SanitizeFailure("rejected "+block+" "+encoded+" later", secret)
	for _, item := range []string{secret, block, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{"see \U0001FB57 later", "see \U0001FB56 later", "see \U0001FB5D later", "see \U0001FB58 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("short top rising block prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsParentheses(t *testing.T) {
	secret := "code(ver)1"
	marked := strings.NewReplacer("(", "\u207d", ")", "\u208e").Replace(secret)
	encoded := strings.NewReplacer("(", "%EF%BC%88", ")", "%EF%BC%89").Replace(secret)
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	vertical := strings.NewReplacer("(", "\ufe35", ")", "\ufe36").Replace(secret)
	got = SanitizeFailure("rejected "+vertical+" later", secret)
	for _, item := range []string{secret, vertical, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("vertical leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2474 later",
		"see \u27ee later",
		"see \u2768 later",
		"see \uff5f later",
		"path \uff08 file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("paren prose changed: %q -> %q", prose, got)
		}
	}
}

func TestParenASCIIFoldsOnlyParentheses(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x207D, '(', true},
		{0x208D, '(', true},
		{0xFE35, '(', true},
		{0xFE59, '(', true},
		{0xFF08, '(', true},
		{0x207E, ')', true},
		{0x208E, ')', true},
		{0xFE36, ')', true},
		{0xFE5A, ')', true},
		{0xFF09, ')', true},
		{'(', 0, false},
		{')', 0, false},
		{0x2474, 0, false},
		{0x27EE, 0, false},
		{0x27EF, 0, false},
		{0x2985, 0, false},
		{0xFF5F, 0, false},
		{0x2768, 0, false},
		{0x2E28, 0, false},
		{0x207A, 0, false},
	}
	for _, check := range checks {
		got, ok := parenASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := parenASCII(r); ok {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("paren fold count %d", n)
	}
}

func TestSanitizeFailureStripsCompatibilityPercent(t *testing.T) {
	secret := "code+verifier12"
	refresh := "rt_submitted_123456"
	opaque := "AbCdEf0123456789xyzTOKENVALUEEXTRA"
	withPercent := func(s, percent string) string {
		return strings.ReplaceAll(encodeEveryByte(s), "%", percent)
	}
	full := withPercent(secret, "\uFF05")
	small := withPercent(refresh, "\uFE6A")
	hexed := fullwidthHexEscapes(encodeEveryByte(opaque))
	nested := withPercent(encodeEveryByte(secret), "\uFF05")
	text := "rejected " + full + " " + small + " " + hexed + " " + nested + " later"
	got := SanitizeFailure(text, secret)
	for _, leaked := range []string{secret, refresh, opaque, full, small, hexed, nested, "verifier", "submitted", "TOKEN"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{
		"about \uFF05 later",
		"about \uFE6A later",
		"about \u066A later",
		"about \u2030 later",
		"score \uFF05ZZ later",
		"score \uFF0541 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("percent prose changed: %q -> %q", prose, got)
		}
	}
}

func TestPercentASCIIFoldsOnlyPercentSigns(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE6A, '%', true},
		{0xFF05, '%', true},
		{'%', 0, false},
		{0x066A, 0, false},
		{0x2030, 0, false},
		{0x2031, 0, false},
		{0x0609, 0, false},
		{0x2052, 0, false},
		{0xFF06, 0, false},
	}
	for _, check := range checks {
		got, ok := percentASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := percentASCII(r); ok {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("percent fold count %d", n)
	}
}

func fullwidthHexEscapes(encoded string) string {
	var b strings.Builder
	for _, r := range encoded {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(0xFF10 + (r - '0'))
		case r >= 'A' && r <= 'F':
			b.WriteRune(0xFF21 + (r - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestSanitizeFailureStripsExclamationMarks(t *testing.T) {
	secret := "code!ver1"
	marked := strings.ReplaceAll(secret, "!", "\uFE57")
	encoded := strings.ReplaceAll(secret, "!", "%EF%BC%81")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	vertical := strings.ReplaceAll(secret, "!", "\uFE15")
	full := strings.ReplaceAll(secret, "!", "\uFF01")
	got = SanitizeFailure("rejected "+vertical+" "+full+" later", secret)
	for _, item := range []string{secret, vertical, full, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("vertical leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u00a1 later",
		"see \u01c3 later",
		"see \u203c later",
		"see \u2049 later",
		"see \u2757 later",
		"see \u2762 later",
		"path \uff01 file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("exclamation prose changed: %q -> %q", prose, got)
		}
	}
}

func TestExclamationASCIIFoldsOnlyExclamationMarks(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE15, '!', true},
		{0xFE57, '!', true},
		{0xFF01, '!', true},
		{'!', 0, false},
		{0x00A1, 0, false},
		{0x01C3, 0, false},
		{0x203C, 0, false},
		{0x2049, 0, false},
		{0x2757, 0, false},
		{0x2762, 0, false},
		{0xFF1F, 0, false},
	}
	for _, check := range checks {
		got, ok := exclamationASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := exclamationASCII(r); ok {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("exclamation fold count %d", n)
	}
}

func TestSanitizeFailureStripsReverseSolidus(t *testing.T) {
	secret := "code\\ver1"
	marked := strings.ReplaceAll(secret, "\\", "\uFE68")
	encoded := strings.ReplaceAll(secret, "\\", "%EF%BC%BC")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	full := strings.ReplaceAll(secret, "\\", "\uFF3C")
	got = SanitizeFailure("rejected "+full+" later", secret)
	for _, item := range []string{secret, full, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("fullwidth leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2216 later",
		"see \u29f5 later",
		"see \u29f9 later",
		"see \u00a5 later",
		"see \u20a9 later",
		"see \u244a later",
		"path \uff3c file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("reverse solidus prose changed: %q -> %q", prose, got)
		}
	}
}

func TestReverseSolidusASCIIFoldsOnlyReverseSolidus(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE68, '\\', true},
		{0xFF3C, '\\', true},
		{0x00A5, '\\', true},
		{0x20A9, '\\', true},
		{0x2216, '\\', true},
		{0x244A, '\\', true},
		{0x29F5, '\\', true},
		{0x29F7, '\\', true},
		{0x29F9, '\\', true},
		{0x2572, '\\', true},
		{0x27CD, '\\', true},
		{0x29C5, '\\', true},
		{0x2F02, '\\', true},
		{0x31D4, '\\', true},
		{0x1D20F, '\\', true},
		{0x1D23A, '\\', true},
		{0x1D23B, '\\', true},
		{0x1F67D, '\\', true},
		{'\\', 0, false},
		{0x2215, 0, false},
		{0x2044, 0, false},
		{0x3035, '\\', true},
		{0x3031, 0, false},
		{0x4E36, '\\', true},
		{0x27C8, '\\', true},
		{0x27C9, 0, false},
		{0x1455, 0, false},
		{0x2340, '\\', true},
		{0x233F, 0, false},
		{0x2342, '\\', true},
		{0x2341, 0, false},
		{0x29B8, '\\', true},
		{0x2349, '\\', true},
		{0x2298, 0, false},
		{0x2A38, 0, false},
		{0x20E0, 0, false},
		{0x1FBA1, '\\', true},
		{0x1FBA2, '\\', true},
		{0x1FBA0, 0, false},
		{0x1FBA3, 0, false},
		{0x2573, 0, false},
		{0x1FBA4, 0, false},
		{0x1FBA5, 0, false},
		{0x1FBA6, 0, false},
		{0x1FBA7, 0, false},
		{0x1FBA8, 0, false},
		{0x1FBA9, '\\', true},
		{0x1FBAA, 0, false},
		{0x1FBAB, 0, false},
		{0x1FBAC, 0, false},
		{0x1FBAD, 0, false},
		{0x1FBAE, 0, false},
		{0x1FBAF, 0, false},
		{0x1FBBE, 0, false},
		{0x1FBBF, 0, false},
		{0x1FBBD, 0, false},
		{0x1FBC0, 0, false},
		{0x1FBCA, 0, false},
		{0x1F7A8, 0, false},
		{0x1F7A7, 0, false},
		{0x1F7A9, 0, false},
		{0x1F7AA, 0, false},
		{0x1F7AB, 0, false},
		{0x1F7AC, 0, false},
		{0x1F7AD, 0, false},
		{0x1F7AE, 0, false},
		{0x1F7AF, 0, false},
		{0x1F7B0, 0, false},
		{0x1F7B1, 0, false},
		{0x1F7B2, 0, false},
		{0x1F7B3, 0, false},
		{0x1F7B4, 0, false},
		{0x1F7B5, 0, false},
		{0x1F7B6, 0, false},
		{0x1F7B7, 0, false},
		{0x1F7B8, 0, false},
		{0x1F7B9, 0, false},
		{0x1F7BA, 0, false},
		{0x1F7BB, 0, false},
		{0x1F7BC, 0, false},
		{0x1F7BD, 0, false},
		{0x1F7BE, 0, false},
		{0x1F7BF, 0, false},
		{0x1F7C0, 0, false},
		{0x1F7C1, 0, false},
		{0x1F7C2, 0, false},
		{0x1F7C3, 0, false},
		{0x1F7C4, 0, false},
		{0x1F7C5, 0, false},
		{0x1F7C6, 0, false},
		{0x1F7C7, 0, false},
		{0x1F7C8, 0, false},
		{0x1F7C9, 0, false},
		{0x1F7CA, 0, false},
		{0x1F7CB, 0, false},
		{0x1F7CC, 0, false},
		{0x1F7CD, 0, false},
		{0x1F7CE, 0, false},
		{0x1F7CF, 0, false},
		{0x1F7D0, 0, false},
		{0x1F7D1, 0, false},
		{0x1F7D2, 0, false},
		{0x1F7D3, 0, false},
		{0x1F7D4, 0, false},
		{0x1F7D5, 0, false},
		{0x1F7D6, 0, false},
		{0x1F7D7, 0, false},
		{0x1F7D8, 0, false},
		{0x1F7D9, 0, false},
		{0x2715, 0, false},
		{0x2716, 0, false},
		{0x2717, 0, false},
		{0x2718, 0, false},
		{0x2719, 0, false},
		{0x274C, 0, false},
		{0x274E, 0, false},
		{0x1F5D9, 0, false},
		{0x00D7, 0, false},
		{0x2A2F, 0, false},
		{0x2A30, 0, false},
		{0x2A31, 0, false},
		{0x2A34, 0, false},
		{0x2A35, 0, false},
		{0x2A36, 0, false},
		{0x2A37, 0, false},
		{0x2A3B, 0, false},
		{0x2297, 0, false},
		{0x22A0, 0, false},
		{0x229F, 0, false},
		{0x22A1, 0, false},
		{0x2296, 0, false},
		{0x2299, 0, false},
		{0x2A38, 0, false},
		{0x2A3C, 0, false},
		{0x2A33, 0, false},
		{0x29D4, 0, false},
		{0x29D5, 0, false},
		{0x29D6, 0, false},
		{0x29D7, 0, false},
		{0x1F7E0, 0, false},
		{0x2613, 0, false},
		{0x26DD, 0, false},
		{0x2B59, 0, false},
		{0x1FBC1, 0, false},
		{0x1FBF0, 0, false},
		{0x1FB65, '\\', true},
		{0x1FB41, 0, false},
		{0x1FB44, 0, false},
		{0x1FB45, 0, false},
		{0x1FB42, 0, false},
		{0x1FB43, 0, false},
		{0x1FB46, 0, false},
		{0x1FB4B, 0, false},
		{0x1FB4A, 0, false},
		{0x1FB49, 0, false},
		{0x1FB48, 0, false},
		{0x1FB47, 0, false},
		{0x1FB61, 0, false},
		{0x1FB60, 0, false},
		{0x1FB5F, 0, false},
		{0x1FB5E, 0, false},
		{0x1FB5D, 0, false},
		{0x1FB3C, '\\', true},
		{0x1FB3D, '\\', true},
		{0x1FB3E, '\\', true},
		{0x1FB3F, '\\', true},
		{0x1FB40, '\\', true},
		{0x1FB4C, '\\', true},
		{0x1FB4D, '\\', true},
		{0x1FB4E, '\\', true},
		{0x1FB4F, '\\', true},
		{0x1FB50, '\\', true},
		{0x1FB51, '\\', true},
		{0x1FB52, '\\', true},
		{0x1FB53, '\\', true},
		{0x1FB54, '\\', true},
		{0x1FB55, '\\', true},
		{0x1FB56, '\\', true},
		{0x1FB62, '\\', true},
		{0x1FB63, '\\', true},
		{0x1FB64, '\\', true},
		{0x1FB66, '\\', true},
		{0x1FB67, '\\', true},
		{0x1FB98, '\\', true},
		{0x25A7, '\\', true},
		{0x25A8, 0, false},
		{0x25A9, 0, false},
		{0x1FB99, 0, false},
		{0x1FB68, 0, false},
		{0x30CE, 0, false},
		{0xFF0F, 0, false},
	}
	for _, check := range checks {
		got, ok := reverseSolidusASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := reverseSolidusASCII(r); ok {
			n++
		}
	}
	if n != 52 {
		t.Fatalf("reverse solidus fold count %d", n)
	}
}

func TestSanitizeFailureStripsNumberSigns(t *testing.T) {
	secret := "code#ver1"
	marked := strings.ReplaceAll(secret, "#", "\uFE5F")
	encoded := strings.ReplaceAll(secret, "#", "%EF%BC%83")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	full := strings.ReplaceAll(secret, "#", "\uFF03")
	got = SanitizeFailure("rejected "+full+" later", secret)
	for _, item := range []string{secret, full, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("fullwidth leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u266f later",
		"see \u2317 later",
		"see \u203b later",
		"path \uff03 file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("number sign prose changed: %q -> %q", prose, got)
		}
	}
}

func TestNumberSignASCIIFoldsOnlyNumberSigns(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE5F, '#', true},
		{0xFF03, '#', true},
		{'#', 0, false},
		{0x266F, 0, false},
		{0x2317, 0, false},
		{0x203B, 0, false},
		{0xFF04, 0, false},
	}
	for _, check := range checks {
		got, ok := numberSignASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := numberSignASCII(r); ok {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("number sign fold count %d", n)
	}
}

func TestSanitizeFailureStripsDollarSigns(t *testing.T) {
	secret := "code$ver1"
	marked := strings.ReplaceAll(secret, "$", "\uFE69")
	encoded := strings.ReplaceAll(secret, "$", "%EF%BC%84")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	full := strings.ReplaceAll(secret, "$", "\uFF04")
	got = SanitizeFailure("rejected "+full+" later", secret)
	for _, item := range []string{secret, full, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("fullwidth leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u1f4b2 later",
		"see \u00a2 later",
		"see \u00a3 later",
		"see \u20ac later",
		"path \uff04 file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("dollar prose changed: %q -> %q", prose, got)
		}
	}
}

func TestDollarASCIIFoldsOnlyDollarSigns(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE69, '$', true},
		{0xFF04, '$', true},
		{'$', 0, false},
		{0x1F4B2, 0, false},
		{0x00A2, 0, false},
		{0x00A3, 0, false},
		{0x00A4, 0, false},
		{0x20AC, 0, false},
		{0xFF03, 0, false},
	}
	for _, check := range checks {
		got, ok := dollarASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := dollarASCII(r); ok {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("dollar fold count %d", n)
	}
}

func TestSanitizeFailureStripsAmpersands(t *testing.T) {
	secret := "code&ver1"
	marked := strings.ReplaceAll(secret, "&", "\uFE60")
	encoded := strings.ReplaceAll(secret, "&", "%EF%BC%86")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	full := strings.ReplaceAll(secret, "&", "\uFF06")
	got = SanitizeFailure("rejected "+full+" later", secret)
	for _, item := range []string{secret, full, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("fullwidth leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u214b later",
		"see \U0001f674 later",
		"see \U0001f675 later",
		"path \uff06 file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("ampersand prose changed: %q -> %q", prose, got)
		}
	}
}

func TestAmpersandASCIIFoldsOnlyAmpersands(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE60, '&', true},
		{0xFF06, '&', true},
		{'&', 0, false},
		{0x214B, 0, false},
		{0x1F674, 0, false},
		{0x1F675, 0, false},
		{0xFF05, 0, false},
	}
	for _, check := range checks {
		got, ok := ampersandASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := ampersandASCII(r); ok {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("ampersand fold count %d", n)
	}
}

func TestSanitizeFailureStripsAsterisks(t *testing.T) {
	secret := "code*ver1"
	marked := strings.ReplaceAll(secret, "*", "\uFE61")
	encoded := strings.ReplaceAll(secret, "*", "%EF%BC%8A")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	full := strings.ReplaceAll(secret, "*", "\uFF0A")
	got = SanitizeFailure("rejected "+full+" later", secret)
	for _, item := range []string{secret, full, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("fullwidth leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2217 later",
		"see \u204e later",
		"see \u2731 later",
		"see \u066d later",
		"path \uff0a file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestAsteriskASCIIFoldsOnlyAsterisks(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE61, '*', true},
		{0xFF0A, '*', true},
		{'*', 0, false},
		{0x066D, 0, false},
		{0x204E, 0, false},
		{0x2217, 0, false},
		{0x2731, 0, false},
		{0xFF0B, 0, false},
	}
	for _, check := range checks {
		got, ok := asteriskASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := asteriskASCII(r); ok {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("asterisk fold count %d", n)
	}
}

func TestSanitizeFailureStripsQuestionMarks(t *testing.T) {
	secret := "code?ver1"
	marked := strings.ReplaceAll(secret, "?", "\uFE56")
	encoded := strings.ReplaceAll(secret, "?", "%EF%BC%9F")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	vertical := strings.ReplaceAll(secret, "?", "\uFE16")
	full := strings.ReplaceAll(secret, "?", "\uFF1F")
	got = SanitizeFailure("rejected "+vertical+" "+full+" later", secret)
	for _, item := range []string{secret, vertical, full, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("vertical leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u00bf later",
		"see \u061f later",
		"see \u037e later",
		"see \u2047 later",
		"see \u2048 later",
		"see \u2753 later",
		"path \uff1f file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("question prose changed: %q -> %q", prose, got)
		}
	}
}

func TestQuestionASCIIFoldsOnlyQuestionMarks(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE16, '?', true},
		{0xFE56, '?', true},
		{0xFF1F, '?', true},
		{'?', 0, false},
		{0x00BF, 0, false},
		{0x037E, 0, false},
		{0x061F, 0, false},
		{0x2047, 0, false},
		{0x2048, 0, false},
		{0x2753, 0, false},
		{0xFF01, 0, false},
	}
	for _, check := range checks {
		got, ok := questionASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := questionASCII(r); ok {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("question fold count %d", n)
	}
}

func TestSanitizeFailureStripsSemicolons(t *testing.T) {
	secret := "code;ver1"
	marked := strings.ReplaceAll(secret, ";", "\uFE54")
	encoded := strings.ReplaceAll(secret, ";", "%EF%BC%9B")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	greek := strings.ReplaceAll(secret, ";", "\u037E")
	vertical := strings.ReplaceAll(secret, ";", "\uFE14")
	full := strings.ReplaceAll(secret, ";", "\uFF1B")
	got = SanitizeFailure("rejected "+greek+" "+vertical+" "+full+" later", secret)
	for _, item := range []string{secret, greek, vertical, full, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("vertical leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u061b later",
		"see \u1364 later",
		"see \u204f later",
		"see \u2e35 later",
		"see \u037e later",
		"path \uff1b file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("semicolon prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSemicolonASCIIFoldsOnlySemicolons(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x037E, ';', true},
		{0xFE14, ';', true},
		{0xFE54, ';', true},
		{0xFF1B, ';', true},
		{';', 0, false},
		{0x061B, 0, false},
		{0x1364, 0, false},
		{0x204F, 0, false},
		{0x2E35, 0, false},
		{0x061F, 0, false},
		{0xFF1F, 0, false},
	}
	for _, check := range checks {
		got, ok := semicolonASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := semicolonASCII(r); ok {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("semicolon fold count %d", n)
	}
}

func TestSanitizeFailureStripsCommas(t *testing.T) {
	secret := "code,ver1"
	marked := strings.ReplaceAll(secret, ",", "\uFE50")
	encoded := strings.ReplaceAll(secret, ",", "%EF%BC%8C")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	vertical := strings.ReplaceAll(secret, ",", "\uFE10")
	full := strings.ReplaceAll(secret, ",", "\uFF0C")
	got = SanitizeFailure("rejected "+vertical+" "+full+" later", secret)
	for _, item := range []string{secret, vertical, full, "code", "ver1"} {
		if strings.Contains(got, item) {
			t.Fatalf("vertical leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u060c later",
		"see \u3001 later",
		"see \ufe51 later",
		"see \u2e41 later",
		"see \u2e4c later",
		"path \uff0c file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("comma prose changed: %q -> %q", prose, got)
		}
	}
}

func TestCommaASCIIFoldsOnlyCommas(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE10, ',', true},
		{0xFE50, ',', true},
		{0xFF0C, ',', true},
		{',', 0, false},
		{0x060C, 0, false},
		{0x3001, 0, false},
		{0xFE11, 0, false},
		{0xFE51, 0, false},
		{0x2E41, 0, false},
		{0x2E4C, 0, false},
		{0xFF1B, 0, false},
	}
	for _, check := range checks {
		got, ok := commaASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := commaASCII(r); ok {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("comma fold count %d", n)
	}
}

func TestSanitizeFailureStripsCurlyBrackets(t *testing.T) {
	secret := "code{ver}1"
	marked := strings.NewReplacer("{", "\uFE5B", "}", "\uFE5C").Replace(secret)
	encoded := strings.NewReplacer("{", "%EF%BD%9B", "}", "%EF%BD%9D").Replace(secret)
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	vertical := strings.NewReplacer("{", "\uFE37", "}", "\uFE38").Replace(secret)
	full := strings.NewReplacer("{", "\uFF5B", "}", "\uFF5D").Replace(secret)
	got = SanitizeFailure("rejected "+vertical+" "+full+" later", secret)
	for _, item := range []string{secret, vertical, full, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("vertical leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2774 later",
		"see \u2775 later",
		"see \u2983 later",
		"see \u2984 later",
		"see \ufe5d later",
		"see \ufe39 later",
		"path \uff5b file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("brace prose changed: %q -> %q", prose, got)
		}
	}
}

func TestBraceASCIIFoldsOnlyCurlyBrackets(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE37, '{', true},
		{0xFE5B, '{', true},
		{0xFF5B, '{', true},
		{0xFE38, '}', true},
		{0xFE5C, '}', true},
		{0xFF5D, '}', true},
		{'{', 0, false},
		{'}', 0, false},
		{0x2774, 0, false},
		{0x2775, 0, false},
		{0x2983, 0, false},
		{0x2984, 0, false},
		{0xFE5D, 0, false},
		{0xFE39, 0, false},
		{0x3014, 0, false},
		{0x23A7, 0, false},
		{0xFF08, 0, false},
	}
	for _, check := range checks {
		got, ok := braceASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := braceASCII(r); ok {
			n++
		}
	}
	if n != 6 {
		t.Fatalf("brace fold count %d", n)
	}
}

func TestSanitizeFailureStripsSquareBrackets(t *testing.T) {
	secret := "code[ver]1"
	marked := strings.NewReplacer("[", "\uFF3B", "]", "\uFF3D").Replace(secret)
	encoded := strings.NewReplacer("[", "%EF%BC%BB", "]", "%EF%BC%BD").Replace(secret)
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	vertical := strings.NewReplacer("[", "\uFE47", "]", "\uFE48").Replace(secret)
	got = SanitizeFailure("rejected "+vertical+" later", secret)
	for _, item := range []string{secret, vertical, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("vertical leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2045 later",
		"see \u2046 later",
		"see \u27e6 later",
		"see \u3010 later",
		"see \u301a later",
		"see \ufe17 later",
		"path \uff3b file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("bracket prose changed: %q -> %q", prose, got)
		}
	}
}

func TestBracketASCIIFoldsOnlySquareBrackets(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE47, '[', true},
		{0xFF3B, '[', true},
		{0xFE48, ']', true},
		{0xFF3D, ']', true},
		{'[', 0, false},
		{']', 0, false},
		{0x2045, 0, false},
		{0x2046, 0, false},
		{0x27E6, 0, false},
		{0x27E7, 0, false},
		{0x298B, 0, false},
		{0x3010, 0, false},
		{0x301A, 0, false},
		{0xFE17, 0, false},
		{0xFF5B, 0, false},
	}
	for _, check := range checks {
		got, ok := bracketASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := bracketASCII(r); ok {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("bracket fold count %d", n)
	}
}

func TestSanitizeFailureStripsLessGreaterSigns(t *testing.T) {
	secret := "code<ver>1"
	marked := strings.NewReplacer("<", "\uFE64", ">", "\uFE65").Replace(secret)
	encoded := strings.NewReplacer("<", "%EF%BC%9C", ">", "%EF%BC%9E").Replace(secret)
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	full := strings.NewReplacer("<", "\uFF1C", ">", "\uFF1E").Replace(secret)
	got = SanitizeFailure("rejected "+full+" later", secret)
	for _, item := range []string{secret, full, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("fullwidth leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2264 later",
		"see \u2265 later",
		"see \u2039 later",
		"see \u3008 later",
		"see \u2329 later",
		"see \u27e8 later",
		"see \ufe3f later",
		"path \uff1c file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("less-greater prose changed: %q -> %q", prose, got)
		}
	}
}

func TestLessGreaterASCIIFoldsOnlySigns(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE64, '<', true},
		{0xFF1C, '<', true},
		{0xFE65, '>', true},
		{0xFF1E, '>', true},
		{'<', 0, false},
		{'>', 0, false},
		{0x2264, 0, false},
		{0x2265, 0, false},
		{0x2039, 0, false},
		{0x203A, 0, false},
		{0x2329, 0, false},
		{0x3008, 0, false},
		{0x27E8, 0, false},
		{0xFE3F, 0, false},
		{0xFF1B, 0, false},
	}
	for _, check := range checks {
		got, ok := lessGreaterASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := lessGreaterASCII(r); ok {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("less-greater fold count %d", n)
	}
}

func TestSanitizeFailureStripsGraveAccents(t *testing.T) {
	secret := "code`ver`1"
	marked := strings.NewReplacer("`", "\uFF40").Replace(secret)
	varia := strings.NewReplacer("`", "\u1FEF").Replace(secret)
	encoded := strings.NewReplacer("`", "%EF%BD%80").Replace(secret)
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	got = SanitizeFailure("rejected "+varia+" later", secret)
	for _, item := range []string{secret, varia, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("varia leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u02CB later",
		"see \u0300 later",
		"see \u00B4 later",
		"see \u1FBF later",
		"see \u1FCD later",
		"path \uFF40 file",
		"path \u1FEF file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("grave prose changed: %q -> %q", prose, got)
		}
	}
}

func TestGraveASCIIFoldsOnlyGraveAccents(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x1FEF, '`', true},
		{0xFF40, '`', true},
		{'`', 0, false},
		{0x02CB, 0, false},
		{0x0300, 0, false},
		{0x00B4, 0, false},
		{0x1FBF, 0, false},
		{0x1FCD, 0, false},
		{0xFF07, 0, false},
		{0x2018, 0, false},
		{0x2019, 0, false},
	}
	for _, check := range checks {
		got, ok := graveASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := graveASCII(r); ok {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("grave fold count %d", n)
	}
}

func TestSanitizeFailureStripsCircumflexAccents(t *testing.T) {
	secret := "code^ver^1"
	marked := strings.NewReplacer("^", "\uFF3E").Replace(secret)
	encoded := strings.NewReplacer("^", "%EF%BC%BE").Replace(secret)
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{
		"see \u02C6 later",
		"see \u0302 later",
		"see \u2038 later",
		"see \u2303 later",
		"path \uFF3E file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circumflex prose changed: %q -> %q", prose, got)
		}
	}
}

func TestCircumflexASCIIFoldsOnlyCircumflex(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFF3E, '^', true},
		{'^', 0, false},
		{0x02C6, 0, false},
		{0x0302, 0, false},
		{0x2038, 0, false},
		{0x2303, 0, false},
		{0xFF40, 0, false},
		{0x2227, 0, false},
	}
	for _, check := range checks {
		got, ok := circumflexASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := circumflexASCII(r); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("circumflex fold count %d", n)
	}
}

func TestSanitizeFailureStripsVerticalLines(t *testing.T) {
	secret := "code|ver|1"
	marked := strings.NewReplacer("|", "\uFF5C").Replace(secret)
	encoded := strings.NewReplacer("|", "%EF%BD%9C").Replace(secret)
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{
		"see \u00A6 later",
		"see \u2223 later",
		"see \u01C0 later",
		"see \u2502 later",
		"see \uFFE8 later",
		"path \uFF5C file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("vertical line prose changed: %q -> %q", prose, got)
		}
	}
}

func TestVerticalLineASCIIFoldsOnlyVerticalLines(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFF5C, '|', true},
		{'|', 0, false},
		{0x00A6, 0, false},
		{0x2223, 0, false},
		{0x01C0, 0, false},
		{0x2502, 0, false},
		{0xFFE8, 0, false},
		{0x2225, 0, false},
		{0x2758, 0, false},
	}
	for _, check := range checks {
		got, ok := verticalLineASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := verticalLineASCII(r); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("vertical line fold count %d", n)
	}
}

func TestSanitizeFailureStripsApostrophes(t *testing.T) {
	secret := "code'ver'1"
	marked := strings.NewReplacer("'", "\uFF07").Replace(secret)
	encoded := strings.NewReplacer("'", "%EF%BC%87").Replace(secret)
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{
		"see \u2018 later",
		"see \u2019 later",
		"see \u02BC later",
		"see \u2032 later",
		"see \u055A later",
		"path \uFF07 file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("apostrophe prose changed: %q -> %q", prose, got)
		}
	}
}

func TestApostropheASCIIFoldsOnlyApostrophes(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFF07, '\'', true},
		{'\'', 0, false},
		{0x2018, 0, false},
		{0x2019, 0, false},
		{0x02BC, 0, false},
		{0x02B9, 0, false},
		{0x2032, 0, false},
		{0x055A, 0, false},
		{0xFF02, 0, false},
	}
	for _, check := range checks {
		got, ok := apostropheASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := apostropheASCII(r); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("apostrophe fold count %d", n)
	}
}

func TestSanitizeFailureStripsQuotationMarks(t *testing.T) {
	secret := "code\"ver\"1"
	marked := strings.NewReplacer("\"", "\uFF02").Replace(secret)
	encoded := strings.NewReplacer("\"", "%EF%BC%82").Replace(secret)
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	for _, prose := range []string{
		"see \u201C later",
		"see \u201D later",
		"see \u201E later",
		"see \u2033 later",
		"see \u301D later",
		"see \u275D later",
		"path \uFF02 file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("quotation prose changed: %q -> %q", prose, got)
		}
	}
}

func TestQuotationASCIIFoldsOnlyQuotationMarks(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFF02, '"', true},
		{'"', 0, false},
		{0x201C, 0, false},
		{0x201D, 0, false},
		{0x201E, 0, false},
		{0x2033, 0, false},
		{0x301D, 0, false},
		{0x275D, 0, false},
		{0xFF07, 0, false},
	}
	for _, check := range checks {
		got, ok := quotationASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := quotationASCII(r); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("quotation fold count %d", n)
	}
}

func TestSanitizeFailureStripsCompatibilityColons(t *testing.T) {
	secret := "code:ver:1"
	vertical := strings.NewReplacer(":", "\uFE13").Replace(secret)
	small := strings.NewReplacer(":", "\uFE55").Replace(secret)
	full := strings.NewReplacer(":", "\uFF1A").Replace(secret)
	encoded := strings.NewReplacer(":", "%EF%BC%9A").Replace(secret)
	got := SanitizeFailure("rejected "+full+" "+encoded+" later", secret)
	for _, item := range []string{secret, full, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	got = SanitizeFailure("rejected "+vertical+" "+small+" later", secret)
	for _, item := range []string{secret, vertical, small, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("small leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2236 later",
		"see \u02D0 later",
		"see \uA789 later",
		"see \uFE30 later",
		"see \u1804 later",
		"see \u0589 later",
		"path \uFF1A file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("colon prose changed: %q -> %q", prose, got)
		}
	}
}

func TestColonASCIIFoldsColonLookalikes(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE13, ':', true},
		{0xFE55, ':', true},
		{0xFF1A, ':', true},
		{0x2236, ':', true},
		{0x02D0, ':', true},
		{0x02D1, ':', true},
		{0xA789, ':', true},
		{0xFE30, ':', true},
		{0x1804, ':', true},
		{0x0589, ':', true},
		{0x205A, ':', true},
		{0x2237, ':', true},
		{':', 0, false},
		{0xFF1B, 0, false},
		{0x0903, 0, false},
		{0x1803, 0, false},
		{0xE003A, 0, false},
	}
	for _, check := range checks {
		got, ok := colonASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	if visargaColon(0x0903) != true || visargaColon(0x17C7) != true || visargaColon(0x2236) || visargaColon(':') {
		t.Fatal("visarga colon fold is wrong")
	}
	n := 0
	visarga := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := colonASCII(r); ok {
			n++
		}
		if visargaColon(r) {
			visarga++
		}
	}
	if n != 47 || visarga != 22 {
		t.Fatalf("colon fold count %d visarga %d", n, visarga)
	}
}

func TestSanitizeFailureStripsColonLookalikesInKnownSecrets(t *testing.T) {
	secret := "code:ver:1"
	ratio := strings.NewReplacer(":", "\u2236").Replace(secret)
	mod := strings.NewReplacer(":", "\u02D0").Replace(secret)
	arm := strings.NewReplacer(":", "\u0589").Replace(secret)
	encoded := strings.NewReplacer(":", "%E2%88%B6").Replace(secret)
	visarga := strings.NewReplacer(":", "\u0903").Replace(secret)
	got := SanitizeFailure("rejected "+ratio+" "+encoded+" later", secret)
	for _, item := range []string{secret, ratio, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	got = SanitizeFailure("rejected "+mod+" "+arm+" "+visarga+" later", secret)
	for _, item := range []string{secret, mod, arm, visarga, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("lookalike leaked %q in %q", item, got)
		}
	}
	refresh := "rt_submitted_123456"
	marked := "rt_sub\u0903mitted_123456"
	got = SanitizeFailure("rejected "+marked+" later", refresh)
	for _, item := range []string{refresh, marked, "submitted_123456"} {
		if strings.Contains(got, item) {
			t.Fatalf("inserted visarga leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("inserted visarga lost context: %q", got)
	}
	for _, prose := range []string{"see \u2236 later", "see \u0903 later", "see \u1803 later"} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("colon prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsCommercialAtSigns(t *testing.T) {
	secret := "code@ver@1"
	small := strings.NewReplacer("@", "\uFE6B").Replace(secret)
	full := strings.NewReplacer("@", "\uFF20").Replace(secret)
	encoded := strings.NewReplacer("@", "%EF%BC%A0").Replace(secret)
	got := SanitizeFailure("rejected "+full+" "+encoded+" later", secret)
	for _, item := range []string{secret, full, encoded, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	got = SanitizeFailure("rejected "+small+" later", secret)
	for _, item := range []string{secret, small, "code", "ver"} {
		if strings.Contains(got, item) {
			t.Fatalf("small leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \uFE69 later",
		"see \u24B6 later",
		"path \uFF20 file",
		"path \uFE6B file",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("commercial at prose changed: %q -> %q", prose, got)
		}
	}
}

func TestCommercialAtASCIIFoldsOnlyCommercialAt(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xFE6B, '@', true},
		{0xFF20, '@', true},
		{'@', 0, false},
		{0xFE69, 0, false},
		{0xFF03, 0, false},
		{0x24B6, 0, false},
		{0x0040, 0, false},
	}
	for _, check := range checks {
		got, ok := commercialAtASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := commercialAtASCII(r); ok {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("commercial at fold count %d", n)
	}
}

func TestSanitizeFailureStripsCompatibilitySpaces(t *testing.T) {
	secret := "rt_Zz9q Refresh 7f3a"
	spaces := []rune{
		0x00A0, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
		0x2007, 0x2008, 0x2009, 0x200A, 0x202F, 0x205F, 0x3000,
	}
	var parts []string
	var leaked []string
	for _, r := range spaces {
		marked := strings.ReplaceAll(secret, " ", string(r))
		parts = append(parts, marked)
		leaked = append(leaked, marked)
	}
	encoded := strings.ReplaceAll(secret, " ", "%C2%A0")
	ideoEncoded := strings.ReplaceAll(secret, " ", "%E3%80%80")
	parts = append(parts, encoded, ideoEncoded)
	leaked = append(leaked, secret, encoded, ideoEncoded, "Zz9q", "Refresh", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secret)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(secret, " ", "\u3000")
	shown := strings.ReplaceAll(secret, " ", "\u00A0")
	got = SanitizeFailure("rejected "+secret+" "+shown+" later", stored)
	for _, item := range []string{secret, stored, shown, "Zz9q", "Refresh", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored space leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"slow\u00a0down",
		"slow\u2003down",
		"slow\u3000down",
		"slow\u1680down",
	} {
		if got := SanitizeFailure(prose); got != "slow down" || strings.Contains(got, "[redacted]") {
			t.Fatalf("space prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSpaceASCIIFoldsOnlyCompatibilitySpaces(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0x00A0, ' ', true},
		{0x2000, ' ', true},
		{0x2003, ' ', true},
		{0x2009, ' ', true},
		{0x202F, ' ', true},
		{0x205F, ' ', true},
		{0x3000, ' ', true},
		{' ', 0, false},
		{'\t', 0, false},
		{'\n', 0, false},
		{0x1680, 0, false},
		{0x200B, 0, false},
		{0x2028, 0, false},
		{0xFEFF, 0, false},
	}
	for _, check := range checks {
		got, ok := spaceASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := spaceASCII(r); ok {
			n++
		}
	}
	if n != 15 {
		t.Fatalf("space fold count %d", n)
	}
}

func TestSanitizeFailureStripsLatinLigatures(t *testing.T) {
	secret := "rt_Zz9qstaff7f3a"
	st := strings.ReplaceAll(secret, "st", "\uFB06")
	longST := strings.ReplaceAll(secret, "st", "\uFB05")
	fiSecret := "officeToken12"
	fi := strings.ReplaceAll(fiSecret, "fi", "\uFB01")
	ffi := "o" + "\uFB03" + "ceToken12"
	ij := "\u0133" + "TokenValue12"
	encoded := strings.ReplaceAll(secret, "st", "%EF%AC%86")
	fiEncoded := strings.ReplaceAll(fiSecret, "fi", "%EF%AC%81")
	got := SanitizeFailure("rejected "+st+" "+longST+" "+fi+" "+ffi+" "+ij+" "+encoded+" "+fiEncoded+" later", secret, fiSecret, "officeToken12", "ijTokenValue12")
	for _, item := range []string{secret, st, longST, fiSecret, fi, ffi, ij, encoded, fiEncoded, "ijTokenValue12", "Zz9q", "staff", "7f3a", "office", "Token12"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.officemore12"
	markedJWT := strings.ReplaceAll(jwt, "fi", "\uFB01")
	got = SanitizeFailure("rejected " + markedJWT + " later")
	for _, item := range []string{jwt, markedJWT, "officemore12", "eyJ", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("jwt leaked %q in %q", item, got)
		}
	}
	opaque := "staffToken12staffToken12tokenAb1"
	markedOpaque := strings.ReplaceAll(opaque, "st", "\uFB06")
	got = SanitizeFailure("rejected " + markedOpaque + " later")
	for _, item := range []string{opaque, markedOpaque, "staffToken12", "tokenAb1"} {
		if strings.Contains(got, item) {
			t.Fatalf("opaque leaked %q in %q", item, got)
		}
	}
	stored := strings.ReplaceAll(secret, "st", "\uFB05")
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, item := range []string{secret, stored, "Zz9q", "staff", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored ligature leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \uFB05 later",
		"the \uFB01le stays",
		"see \u2161 later",
		"see \u2122 later",
		"see \u3373 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("ligature prose changed: %q -> %q", prose, got)
		}
	}
}

func TestLigatureASCIIFoldsOnlyLatinLigatures(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x0132, "IJ"},
		{0x0133, "ij"},
		{0x01C7, "LJ"},
		{0x01C8, "Lj"},
		{0x01C9, "lj"},
		{0x01CA, "NJ"},
		{0x01CB, "Nj"},
		{0x01CC, "nj"},
		{0x01F1, "DZ"},
		{0x01F2, "Dz"},
		{0x01F3, "dz"},
		{0xFB00, "ff"},
		{0xFB01, "fi"},
		{0xFB02, "fl"},
		{0xFB03, "ffi"},
		{0xFB04, "ffl"},
		{0xFB05, "st"},
		{0xFB06, "st"},
	}
	for _, check := range checks {
		got, ok := ligatureASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'f', 'i', 0x017F, 0x2161, 0x2171, 0x2122, 0x2116, 0x3373, 0xFB07} {
		if _, ok := ligatureASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := ligatureASCII(r); ok {
			n++
		}
	}
	if n != 18 {
		t.Fatalf("ligature fold count %d", n)
	}
}

func TestSanitizeFailureStripsAdditiveRomanNumerals(t *testing.T) {
	secret := "rt_Zz9qVII7f3a"
	seven := strings.ReplaceAll(secret, "VII", "\u2166")
	eightSecret := "rt_Zz9qVIII7f3a"
	eight := strings.ReplaceAll(eightSecret, "VIII", "\u2167")
	lowerSecret := "rt_Zz9qviii7f3a"
	lower := strings.ReplaceAll(lowerSecret, "viii", "\u2177")
	encoded := strings.ReplaceAll(secret, "VII", "%E2%85%A6")
	got := SanitizeFailure("rejected "+seven+" "+eight+" "+lower+" "+encoded+" later", secret, eightSecret, lowerSecret)
	for _, item := range []string{secret, seven, eightSecret, eight, lowerSecret, lower, encoded, "Zz9q", "VII", "VIII", "viii", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.VIIValue12"
	markedJWT := strings.ReplaceAll(jwt, "VII", "\u2166")
	got = SanitizeFailure("rejected " + markedJWT + " later")
	for _, item := range []string{jwt, markedJWT, "VIIValue12", "eyJ", "eyJzdWIiOiJ1c2VyIn0"} {
		if strings.Contains(got, item) {
			t.Fatalf("jwt leaked %q in %q", item, got)
		}
	}
	opaque := "VIIValue12VIIValue12VIIValue12ab"
	markedOpaque := strings.ReplaceAll(opaque, "VII", "\u2166")
	got = SanitizeFailure("rejected " + markedOpaque + " later")
	for _, item := range []string{opaque, markedOpaque, "VIIValue12"} {
		if strings.Contains(got, item) {
			t.Fatalf("opaque leaked %q in %q", item, got)
		}
	}
	stored := strings.ReplaceAll(secret, "VII", "\u2166")
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, item := range []string{secret, stored, "Zz9q", "VII", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored numeral leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2161 later",
		"see \u2166 later",
		"archaic \u2180 later",
		"late \u2185 later",
		"chapter \u2160 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("roman prose changed: %q -> %q", prose, got)
		}
	}
}

func TestAdditiveRomanASCIIFoldsOnlyAdditiveNumerals(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x2161, "II"},
		{0x2162, "III"},
		{0x2163, "IV"},
		{0x2165, "VI"},
		{0x2166, "VII"},
		{0x2167, "VIII"},
		{0x2168, "IX"},
		{0x216A, "XI"},
		{0x216B, "XII"},
		{0x2171, "ii"},
		{0x2172, "iii"},
		{0x2173, "iv"},
		{0x2175, "vi"},
		{0x2176, "vii"},
		{0x2177, "viii"},
		{0x2178, "ix"},
		{0x217A, "xi"},
		{0x217B, "xii"},
	}
	for _, check := range checks {
		got, ok := additiveRomanASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{0x2160, 0x2164, 0x2169, 0x216C, 0x2170, 0x2174, 0x2180, 0x2185, 0x2153} {
		if _, ok := additiveRomanASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := additiveRomanASCII(r); ok {
			n++
		}
	}
	if n != 18 {
		t.Fatalf("additive roman fold count %d", n)
	}
}

func TestSanitizeFailureStripsDoublePunctuation(t *testing.T) {
	pairs := []struct {
		secret string
		mark   string
	}{
		{"rt_Zz9q!!7f3a", "\u203C"},
		{"rt_Zz9q??7f3a", "\u2047"},
		{"rt_Zz9q?!7f3a", "\u2048"},
		{"rt_Zz9q!?7f3a", "\u2049"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		asciiPair := pair.secret[len("rt_Zz9q") : len("rt_Zz9q")+2]
		marked := strings.ReplaceAll(pair.secret, asciiPair, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, asciiPair)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "!!", "%E2%80%BC")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[0].secret, "!!", "\u203C")
	got = SanitizeFailure("rejected "+pairs[0].secret+" later", stored)
	for _, item := range []string{pairs[0].secret, stored, "Zz9q", "!!", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u203C later",
		"see \u2047 later",
		"see \u203D later",
		"see \u00A1 later",
		"see \u2026 later",
		"see \u2A74 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("punctuation prose changed: %q -> %q", prose, got)
		}
	}
}

func TestDoublePunctuationASCIIFoldsOnlyDoubledMarks(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x203C, "!!"},
		{0x2047, "??"},
		{0x2048, "?!"},
		{0x2049, "!?"},
	}
	for _, check := range checks {
		got, ok := doublePunctuationASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'!', '?', 0x203D, 0x00A1, 0x00BF, 0x2025, 0x2026, 0x2A74, 0x2A75, 0xFE15, 0xFF01} {
		if _, ok := doublePunctuationASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := doublePunctuationASCII(r); ok {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("double punctuation fold count %d", n)
	}
}

func TestSanitizeFailureStripsConsecutiveEquals(t *testing.T) {
	pairs := []struct {
		secret string
		mark   string
	}{
		{"rt_Zz9q==7f3a", "\u2A75"},
		{"rt_Zz9q===7f3a", "\u2A76"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		run := strings.TrimPrefix(pair.secret, "rt_Zz9q")
		run = run[:len(run)-len("7f3a")]
		marked := strings.ReplaceAll(pair.secret, run, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, run)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "==", "%E2%A9%B5")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	opaque := "tokenValue1tokenValue1tokenVal=="
	opaqueMarked := strings.ReplaceAll(opaque, "==", "\u2A75")
	parts = append(parts, opaqueMarked)
	leaked = append(leaked, opaque, opaqueMarked, "tokenValue")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[0].secret, "==", "\u2A75")
	got = SanitizeFailure("rejected "+pairs[0].secret+" later", stored)
	for _, item := range []string{pairs[0].secret, stored, "Zz9q", "==", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	triple := "tokenValue1tokenValue1tokenVal==="
	tripleMarked := strings.ReplaceAll(triple, "===", "\u2A76")
	got = SanitizeFailure("rejected " + tripleMarked + " later")
	for _, item := range []string{triple, tripleMarked, "tokenValue"} {
		if strings.Contains(got, item) {
			t.Fatalf("triple leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2A75 later",
		"see \u2A76 later",
		"see \u2A74 later",
		"see \u2260 later",
		"see \uFF1D later",
		"a = b",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("equals prose changed: %q -> %q", prose, got)
		}
	}
}

func TestEqualsRunASCIIFoldsOnlyConsecutiveEquals(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x2A75, "=="},
		{0x2A76, "==="},
	}
	for _, check := range checks {
		got, ok := equalsRunASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'=', 0x2A74, 0x207C, 0x208C, 0x2260, 0x2261, 0xFE66, 0xFF1D} {
		if _, ok := equalsRunASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := equalsRunASCII(r); ok {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("equals run fold count %d", n)
	}
}

func TestSanitizeFailureStripsCircledNumbers(t *testing.T) {
	pairs := []struct {
		secret string
		digits string
		mark   string
	}{
		{"rt_Zz9q10ab7f", "10", "\u2469"},
		{"rt_Zz9q20ab7f", "20", "\u2473"},
		{"rt_Zz9q21ab7f", "21", "\u3251"},
		{"rt_Zz9q35ab7f", "35", "\u325F"},
		{"rt_Zz9q36ab7f", "36", "\u32B1"},
		{"rt_Zz9q50ab7f", "50", "\u32BF"},
	}
	var parts []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.digits, pair.mark)
		parts = append(parts, marked)
		leaked = append(leaked, pair.secret, marked, pair.digits)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "10", "%E2%91%A9")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "ab7f")
	got := SanitizeFailure("rejected " + strings.Join(parts, " ") + " later")
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[0].secret, "10", "\u2469")
	got = SanitizeFailure("rejected "+pairs[0].secret+" later", stored)
	for _, item := range []string{pairs[0].secret, stored, "Zz9q", "10", "ab7f"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2469 later",
		"see \u2473 later",
		"see \u3251 later",
		"see \u32BF later",
		"see \u2460 later",
		"see \u24EB later",
		"see \u2474 later",
		"see \u2488 later",
		"see \u3248 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("circled prose changed: %q -> %q", prose, got)
		}
	}
}

func TestCircledNumberASCIIFoldsOnlyTensThroughFifty(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x2469, "10"},
		{0x246A, "11"},
		{0x2473, "20"},
		{0x3251, "21"},
		{0x325F, "35"},
		{0x32B1, "36"},
		{0x32BF, "50"},
	}
	for _, check := range checks {
		got, ok := circledNumberASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{0x2460, 0x2468, 0x2474, 0x2488, 0x249C, 0x24EA, 0x24EB, 0x24FE, 0x277F, 0x3248, 0x3250, 0x32B0, 0x32C0} {
		if _, ok := circledNumberASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := circledNumberASCII(r); ok {
			n++
		}
	}
	if n != 41 {
		t.Fatalf("circled number fold count %d", n)
	}
}

func TestSanitizeFailureStripsDotLeaders(t *testing.T) {
	pairs := []struct {
		secret string
		dots   string
		mark   string
	}{
		{"rt_Zz9q..7f3a", "..", "\u2025"},
		{"rt_Zz9q...7f3a", "...", "\u2026"},
		{"rt_Aa8k...7f3a", "...", "\uFE19"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.dots, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.dots)
	}
	bearer := "Bearer q7.Zz9q..token7"
	bearerMarked := strings.ReplaceAll(bearer, "..", "\u2025")
	parts = append(parts, bearerMarked)
	leaked = append(leaked, bearer, bearerMarked, "token7")
	encoded := strings.ReplaceAll(pairs[0].secret, "..", "%E2%80%A5")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[1].secret, "...", "\u2026")
	got = SanitizeFailure("rejected "+pairs[1].secret+" later", stored)
	for _, item := range []string{pairs[1].secret, stored, "Zz9q", "...", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2025 later",
		"see \u2026 later",
		"see \uFE19 later",
		"see \uFE30 later",
		"see \u2024 later",
		"see \u22EF later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("leader prose changed: %q -> %q", prose, got)
		}
	}
}

func TestDotLeaderASCIIFoldsOnlyLeaders(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x2025, ".."},
		{0x2026, "..."},
		{0xFE19, "..."},
	}
	for _, check := range checks {
		got, ok := dotLeaderASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'.', 0x2024, 0x2027, 0x22EF, 0xFE30, 0xFE52, 0xFF0E} {
		if _, ok := dotLeaderASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := dotLeaderASCII(r); ok {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("dot leader fold count %d", n)
	}
}

func TestSanitizeFailureStripsDigitStops(t *testing.T) {
	pairs := []struct {
		secret string
		digits string
		mark   string
	}{
		{"rt_Zz9q0.7f3a", "0.", "\U0001F100"},
		{"rt_Zz9q1.7f3a", "1.", "\u2488"},
		{"rt_Aa8k10.7f3a", "10.", "\u2491"},
		{"rt_Bb7m20.7f3a", "20.", "\u249B"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.digits, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.digits)
	}
	bearer := "Bearer q7.Zz9q1.token7"
	bearerMarked := strings.ReplaceAll(bearer, "1.", "\u2488")
	parts = append(parts, bearerMarked)
	leaked = append(leaked, bearer, bearerMarked, "token7")
	jwt := "eyJhbGciOi1.eyJzdWIiOiJ1.c2lnbmF0dXJl"
	jwtMarked := strings.ReplaceAll(jwt, "1.", "\u2488")
	parts = append(parts, jwtMarked)
	leaked = append(leaked, jwt, jwtMarked, "c2lnbmF0dXJl")
	encoded := strings.ReplaceAll(pairs[1].secret, "1.", "%E2%92%88")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[2].secret, "10.", "\u2491")
	got = SanitizeFailure("rejected "+pairs[2].secret+" later", stored)
	for _, item := range []string{pairs[2].secret, stored, "Zz9q", "10.", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \U0001F100 later",
		"see \u2488 later",
		"see \u2491 later",
		"see \u249B later",
		"see \U0001F101 later",
		"see \u2474 later",
		"see \u2469 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("digit stop prose changed: %q -> %q", prose, got)
		}
	}
}

func TestDigitStopASCIIFoldsOnlyFullStops(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x1F100, "0."},
		{0x2488, "1."},
		{0x2490, "9."},
		{0x2491, "10."},
		{0x249B, "20."},
	}
	for _, check := range checks {
		got, ok := digitStopASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'.', '0', '1', 0x2487, 0x249C, 0x2469, 0x2474, 0x1F101, 0x2024, 0xFF11} {
		if _, ok := digitStopASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := digitStopASCII(r); ok {
			n++
		}
	}
	if n != 21 {
		t.Fatalf("digit stop fold count %d", n)
	}
}

func TestSanitizeFailureStripsDigitCommas(t *testing.T) {
	pairs := []struct {
		secret string
		digits string
		mark   string
	}{
		{"rt_Zz9q0,7f3a", "0,", "\U0001F101"},
		{"rt_Aa8k5,7f3a", "5,", "\U0001F106"},
		{"rt_Bb7m9,7f3a", "9,", "\U0001F10A"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.digits, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.digits)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "0,", "%F0%9F%84%81")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[2].secret, "9,", "\U0001F10A")
	got = SanitizeFailure("rejected "+pairs[2].secret+" later", stored)
	for _, item := range []string{pairs[2].secret, stored, "Bb7m", "9,", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \U0001F101 later",
		"see \U0001F10A later",
		"see \u060C later",
		"see \u3001 later",
		"see \u2488 later",
		"see \uFE50 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("digit comma prose changed: %q -> %q", prose, got)
		}
	}
}

func TestDigitCommaASCIIFoldsOnlyDigitCommas(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x1F101, "0,"},
		{0x1F106, "5,"},
		{0x1F10A, "9,"},
	}
	for _, check := range checks {
		got, ok := digitCommaASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{',', '0', '9', 0x1F100, 0x1F10B, 0xFE10, 0xFE50, 0xFF0C, 0x060C, 0x3001, 0x2488} {
		if _, ok := digitCommaASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := digitCommaASCII(r); ok {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("digit comma fold count %d", n)
	}
}

func TestSanitizeFailureStripsParenNumbers(t *testing.T) {
	pairs := []struct {
		secret string
		digits string
		mark   string
	}{
		{"rt_Zz9q(1)7f3a", "(1)", "\u2474"},
		{"rt_Aa8k(9)7f3a", "(9)", "\u247C"},
		{"rt_Bb7m(10)7f", "(10)", "\u247D"},
		{"rt_Cc6n(20)7f", "(20)", "\u2487"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.digits, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.digits)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "(1)", "%E2%91%B4")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[3].secret, "(20)", "\u2487")
	got = SanitizeFailure("rejected "+pairs[3].secret+" later", stored)
	for _, item := range []string{pairs[3].secret, stored, "Cc6n", "(20)", "7f"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2474 later",
		"see \u247C later",
		"see \u247D later",
		"see \u2487 later",
		"see \u249C later",
		"see \u3200 later",
		"see \u2488 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("paren number prose changed: %q -> %q", prose, got)
		}
	}
}

func TestParenNumberASCIIFoldsOnlyNumbers(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x2474, "(1)"},
		{0x247C, "(9)"},
		{0x247D, "(10)"},
		{0x2487, "(20)"},
	}
	for _, check := range checks {
		got, ok := parenNumberASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'(', ')', '1', 0x2473, 0x2488, 0x249C, 0x3200, 0xFF08, 0x2460, 0x1F100} {
		if _, ok := parenNumberASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := parenNumberASCII(r); ok {
			n++
		}
	}
	if n != 20 {
		t.Fatalf("paren number fold count %d", n)
	}
}

func TestSanitizeFailureStripsParenLetters(t *testing.T) {
	pairs := []struct {
		secret  string
		letters string
		mark    string
	}{
		{"rt_Zz9q(a)7f3a", "(a)", "\u249C"},
		{"rt_Aa8k(z)7f3a", "(z)", "\u24B5"},
		{"rt_Bb7m(A)7f3a", "(A)", "\U0001F110"},
		{"rt_Cc6n(Z)7f", "(Z)", "\U0001F129"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.letters, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.letters)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "(a)", "%E2%92%9C")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[3].secret, "(Z)", "\U0001F129")
	got = SanitizeFailure("rejected "+pairs[3].secret+" later", stored)
	for _, item := range []string{pairs[3].secret, stored, "Cc6n", "(Z)", "7f"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u249C later",
		"see \u24B5 later",
		"see \U0001F110 later",
		"see \U0001F129 later",
		"see \u2474 later",
		"see \u3200 later",
		"see \u24B6 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("paren letter prose changed: %q -> %q", prose, got)
		}
	}
}

func TestParenLetterASCIIFoldsOnlyLetters(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x249C, "(a)"},
		{0x24B5, "(z)"},
		{0x1F110, "(A)"},
		{0x1F129, "(Z)"},
	}
	for _, check := range checks {
		got, ok := parenLetterASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'(', ')', 'a', 'A', 0x249B, 0x24B6, 0x2474, 0x1F10F, 0x1F12A, 0x3200, 0xFF08} {
		if _, ok := parenLetterASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := parenLetterASCII(r); ok {
			n++
		}
	}
	if n != 52 {
		t.Fatalf("paren letter fold count %d", n)
	}
}

func TestSanitizeFailureStripsEnclosedAbbrevs(t *testing.T) {
	pairs := []struct {
		secret string
		plain  string
		mark   string
	}{
		{"rt_Zz9qHV7f3a", "HV", "\U0001F14A"},
		{"rt_Aa8kPPV7f", "PPV", "\U0001F14E"},
		{"rt_Bb7mCD7f3a", "CD", "\U0001F12D"},
		{"rt_Cc6nMR7f", "MR", "\U0001F16C"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.plain, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.plain)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "HV", "%F0%9F%85%8A")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[3].secret, "MR", "\U0001F16C")
	got = SanitizeFailure("rejected "+pairs[3].secret+" later", stored)
	for _, item := range []string{pairs[3].secret, stored, "Cc6n", "MR", "7f"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \U0001F14A later",
		"see \U0001F14E later",
		"see \U0001F12D later",
		"see \U0001F16C later",
		"see \U0001F190 later",
		"see \u338F later",
		"see \u2105 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("enclosed abbrev prose changed: %q -> %q", prose, got)
		}
	}
}

func TestEnclosedAbbrevASCIIFoldsOnlyAbbreviations(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x1F12D, "CD"},
		{0x1F12E, "WZ"},
		{0x1F14A, "HV"},
		{0x1F14B, "MV"},
		{0x1F14C, "SD"},
		{0x1F14D, "SS"},
		{0x1F14E, "PPV"},
		{0x1F14F, "WC"},
		{0x1F16A, "MC"},
		{0x1F16B, "MD"},
		{0x1F16C, "MR"},
		{0x1F190, "DJ"},
	}
	for _, check := range checks {
		got, ok := enclosedAbbrevASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'H', 'V', 0x1F149, 0x1F150, 0x1F12C, 0x1F169, 0x1F18F, 0x338F, 0x2100, 0x3250, 0x32CF} {
		if _, ok := enclosedAbbrevASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := enclosedAbbrevASCII(r); ok {
			n++
		}
	}
	if n != 12 {
		t.Fatalf("enclosed abbrev fold count %d", n)
	}
}

func TestSanitizeFailureStripsLetterlikeSigns(t *testing.T) {
	pairs := []struct {
		secret string
		plain  string
		mark   string
	}{
		{"rt_Zz9qc/o7f3a", "c/o", "\u2105"},
		{"rt_Aa8kNo7f3a", "No", "\u2116"},
		{"rt_Bb7mTEL7f", "TEL", "\u2121"},
		{"rt_Cc6nFAX7f", "FAX", "\u213B"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.plain, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.plain)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "c/o", "%E2%84%85")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[3].secret, "FAX", "\u213B")
	got = SanitizeFailure("rejected "+pairs[3].secret+" later", stored)
	for _, item := range []string{pairs[3].secret, stored, "Cc6n", "FAX", "7f"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u2105 later",
		"see \u2116 later",
		"see \u2121 later",
		"see \u213B later",
		"see \u2100 later",
		"see \u20A8 later",
		"see \u338F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("letterlike prose changed: %q -> %q", prose, got)
		}
	}
}

func TestLetterlikeASCIIFoldsOnlySigns(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x2100, "a/c"},
		{0x2101, "a/s"},
		{0x2105, "c/o"},
		{0x2106, "c/u"},
		{0x2116, "No"},
		{0x2120, "SM"},
		{0x2121, "TEL"},
		{0x2122, "TM"},
		{0x213B, "FAX"},
	}
	for _, check := range checks {
		got, ok := letterlikeASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'c', '/', 'o', 0x2102, 0x2103, 0x20A8, 0x2126, 0x213A, 0x213C, 0x338F, 0x3250} {
		if _, ok := letterlikeASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := letterlikeASCII(r); ok {
			n++
		}
	}
	if n != 9 {
		t.Fatalf("letterlike fold count %d", n)
	}
}

func TestSanitizeFailureStripsSquareSymbols(t *testing.T) {
	pairs := []struct {
		secret string
		plain  string
		mark   string
	}{
		{"rt_Zz9qkg7f3a", "kg", "\u338F"},
		{"rt_Aa8ka.m.7f", "a.m.", "\u33C2"},
		{"rt_Bb7mPTE7f", "PTE", "\u3250"},
		{"rt_Cc6ngal7f", "gal", "\u33FF"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.plain, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.plain)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "kg", "%E3%8E%8F")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[3].secret, "gal", "\u33FF")
	got = SanitizeFailure("rejected "+pairs[3].secret+" later", stored)
	for _, item := range []string{pairs[3].secret, stored, "Cc6n", "gal", "7f"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u338F later",
		"see \u33C2 later",
		"see \u3250 later",
		"see \u33FF later",
		"see \u20A8 later",
		"see \u2A74 later",
		"see \uFE30 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("square prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSquareASCIIFoldsOnlySquareSymbols(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x3250, "PTE"},
		{0x32CC, "Hg"},
		{0x32CD, "erg"},
		{0x32CE, "eV"},
		{0x32CF, "LTD"},
		{0x3371, "hPa"},
		{0x3372, "da"},
		{0x3373, "AU"},
		{0x3374, "bar"},
		{0x3375, "oV"},
		{0x3376, "pc"},
		{0x3377, "dm"},
		{0x3378, "dm2"},
		{0x3379, "dm3"},
		{0x337A, "IU"},
		{0x3380, "pA"},
		{0x3381, "nA"},
		{0x3383, "mA"},
		{0x3384, "kA"},
		{0x3385, "KB"},
		{0x3386, "MB"},
		{0x3387, "GB"},
		{0x3388, "cal"},
		{0x3389, "kcal"},
		{0x338A, "pF"},
		{0x338B, "nF"},
		{0x338E, "mg"},
		{0x338F, "kg"},
		{0x3390, "Hz"},
		{0x3391, "kHz"},
		{0x3392, "MHz"},
		{0x3393, "GHz"},
		{0x3394, "THz"},
		{0x3396, "ml"},
		{0x3397, "dl"},
		{0x3398, "kl"},
		{0x3399, "fm"},
		{0x339A, "nm"},
		{0x339C, "mm"},
		{0x339D, "cm"},
		{0x339E, "km"},
		{0x339F, "mm2"},
		{0x33A0, "cm2"},
		{0x33A1, "m2"},
		{0x33A2, "km2"},
		{0x33A3, "mm3"},
		{0x33A4, "cm3"},
		{0x33A5, "m3"},
		{0x33A6, "km3"},
		{0x33A7, "m/s"},
		{0x33A8, "m/s2"},
		{0x33A9, "Pa"},
		{0x33AA, "kPa"},
		{0x33AB, "MPa"},
		{0x33AC, "GPa"},
		{0x33AD, "rad"},
		{0x33AE, "rad/s"},
		{0x33AF, "rad/s2"},
		{0x33B0, "ps"},
		{0x33B1, "ns"},
		{0x33B3, "ms"},
		{0x33B4, "pV"},
		{0x33B5, "nV"},
		{0x33B7, "mV"},
		{0x33B8, "kV"},
		{0x33B9, "MV"},
		{0x33BA, "pW"},
		{0x33BB, "nW"},
		{0x33BD, "mW"},
		{0x33BE, "kW"},
		{0x33BF, "MW"},
		{0x33C2, "a.m."},
		{0x33C3, "Bq"},
		{0x33C4, "cc"},
		{0x33C5, "cd"},
		{0x33C6, "C/kg"},
		{0x33C7, "Co."},
		{0x33C8, "dB"},
		{0x33C9, "Gy"},
		{0x33CA, "ha"},
		{0x33CB, "HP"},
		{0x33CC, "in"},
		{0x33CD, "KK"},
		{0x33CE, "KM"},
		{0x33CF, "kt"},
		{0x33D0, "lm"},
		{0x33D1, "ln"},
		{0x33D2, "log"},
		{0x33D3, "lx"},
		{0x33D4, "mb"},
		{0x33D5, "mil"},
		{0x33D6, "mol"},
		{0x33D7, "PH"},
		{0x33D8, "p.m."},
		{0x33D9, "PPM"},
		{0x33DA, "PR"},
		{0x33DB, "sr"},
		{0x33DC, "Sv"},
		{0x33DD, "Wb"},
		{0x33DE, "V/m"},
		{0x33DF, "A/m"},
		{0x33FF, "gal"},
	}
	if len(checks) != 102 {
		t.Fatalf("square table %d", len(checks))
	}
	for _, check := range checks {
		got, ok := squareASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'k', 'g', '/', '.', 0x2215, 0x20A8, 0x2A74, 0xFE30, 0x3328, 0x3382, 0x338C, 0x33C0, 0x1F190, 0x1F14A} {
		if _, ok := squareASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := squareASCII(r); ok {
			n++
		}
	}
	if n != 102 {
		t.Fatalf("square fold count %d", n)
	}
}

func TestSanitizeFailureStripsSquareDivisionSlashes(t *testing.T) {
	pairs := []struct {
		secret string
		plain  string
		mark   string
	}{
		{"rt_Zz9qm/s7f3a", "m/s", "\u33A7"},
		{"rt_Aa8krad/s2x", "rad/s2", "\u33AF"},
		{"rt_Bb7mC/kg7f3", "C/kg", "\u33C6"},
		{"rt_Cc6nV/m7f3a", "V/m", "\u33DE"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.plain, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.plain)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "m/s", "%E3%8E%A7")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[1].secret, "rad/s2", "\u33AF")
	got = SanitizeFailure("rejected "+pairs[1].secret+" later", stored)
	for _, item := range []string{pairs[1].secret, stored, "Aa8k", "rad/s2", "x"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u33A7 later",
		"see \u33A8 later",
		"see \u33AE later",
		"see \u33AF later",
		"see \u33C6 later",
		"see \u33DE later",
		"see \u33DF later",
		"see \u2215 later",
		"see m/s later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("square slash prose changed: %q -> %q", prose, got)
		}
	}
}

func TestSanitizeFailureStripsRupeeSign(t *testing.T) {
	secret := "rt_Zz9qRs7f3a"
	marked := strings.ReplaceAll(secret, "Rs", "\u20A8")
	encoded := strings.ReplaceAll(secret, "Rs", "%E2%82%A8")
	got := SanitizeFailure("rejected "+marked+" "+encoded+" later", secret)
	for _, item := range []string{secret, marked, encoded, "Rs", "Zz9q", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(secret, "Rs", "\u20A8")
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, item := range []string{secret, stored, "Zz9q", "Rs", "7f3a"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u20A8 later",
		"see \u20A9 later",
		"see \u338F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("rupee prose changed: %q -> %q", prose, got)
		}
	}
}

func TestRupeeASCIIFoldsOnlyTheRupeeSign(t *testing.T) {
	got, ok := rupeeASCII(0x20A8)
	if !ok || got != "Rs" {
		t.Fatalf("rupee folded to %q ok=%v", got, ok)
	}
	for _, r := range []rune{'R', 's', 0x20A9, 0x20B9, 0x338F, 0x2A74, 0xFE30} {
		if _, ok := rupeeASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := rupeeASCII(r); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("rupee fold count %d", n)
	}
}

func TestSanitizeFailureStripsVulgarFractions(t *testing.T) {
	pairs := []struct {
		secret string
		plain  string
		mark   string
	}{
		{"rt_Zz9q1/27f3a", "1/2", "\u00BD"},
		{"rt_Aa8k1/10ab", "1/10", "\u2152"},
		{"rt_Bb7m1/x7f3", "1/", "\u215F"},
		{"rt_Cc6n0/37f3a", "0/3", "\u2189"},
	}
	var parts []string
	var secrets []string
	var leaked []string
	for _, pair := range pairs {
		marked := strings.ReplaceAll(pair.secret, pair.plain, pair.mark)
		parts = append(parts, marked)
		secrets = append(secrets, pair.secret)
		leaked = append(leaked, pair.secret, marked, pair.plain)
	}
	encoded := strings.ReplaceAll(pairs[0].secret, "1/2", "%C2%BD")
	parts = append(parts, encoded)
	leaked = append(leaked, encoded, "Zz9q", "7f3a")
	got := SanitizeFailure("rejected "+strings.Join(parts, " ")+" later", secrets...)
	for _, item := range leaked {
		if strings.Contains(got, item) {
			t.Fatalf("leaked %q in %q", item, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := strings.ReplaceAll(pairs[1].secret, "1/10", "\u2152")
	got = SanitizeFailure("rejected "+pairs[1].secret+" later", stored)
	for _, item := range []string{pairs[1].secret, stored, "Aa8k", "1/10", "ab"} {
		if strings.Contains(got, item) {
			t.Fatalf("stored mark leaked %q in %q", item, got)
		}
	}
	for _, prose := range []string{
		"see \u00BD later",
		"see \u2152 later",
		"see \u215F later",
		"see \u2189 later",
		"see \u2044 later",
		"see 1/2 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("fraction prose changed: %q -> %q", prose, got)
		}
	}
}

func TestFractionASCIIFoldsOnlyVulgarFractions(t *testing.T) {
	checks := []struct {
		r    rune
		want string
	}{
		{0x00BC, "1/4"},
		{0x00BD, "1/2"},
		{0x00BE, "3/4"},
		{0x2150, "1/7"},
		{0x2151, "1/9"},
		{0x2152, "1/10"},
		{0x2153, "1/3"},
		{0x2154, "2/3"},
		{0x2155, "1/5"},
		{0x2156, "2/5"},
		{0x2157, "3/5"},
		{0x2158, "4/5"},
		{0x2159, "1/6"},
		{0x215A, "5/6"},
		{0x215B, "1/8"},
		{0x215C, "3/8"},
		{0x215D, "5/8"},
		{0x215E, "7/8"},
		{0x215F, "1/"},
		{0x2189, "0/3"},
	}
	for _, check := range checks {
		got, ok := fractionASCII(check.r)
		if !ok || got != check.want {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q", check.r, got, ok, check.want)
		}
	}
	for _, r := range []rune{'1', '/', '2', 0x2044, 0x2215, 0x2100, 0x00B0, 0x2160} {
		if _, ok := fractionASCII(r); ok {
			t.Fatalf("U+%04X should stay out", r)
		}
	}
	n := 0
	for r := rune(0); r <= 0x2FFFF; r++ {
		if _, ok := fractionASCII(r); ok {
			n++
		}
	}
	if n != 20 {
		t.Fatalf("fraction fold count %d", n)
	}
}

func TestSanitizeFailureStripsTagPunctuation(t *testing.T) {
	secret := "code/ver1"
	solidus := "code\U000E002Fver1"
	dotSecret := "code.ver1x"
	dot := "code\U000E002Ever1x"
	hyphenSecret := "code-verifier12"
	hyphen := "code\U000E002Dverifier12"
	colonSecret := "code:ver1x"
	colon := "code\U000E003Aver1x"
	slashSecret := "code\\ver1x"
	rev := "code\U000E005Cver1x"
	encoded := "code%F3%A0%80%AFver1"
	inserted := "tokenValue1\U000E002FtokenValue1"
	spaceSecret := "rt_Zz9q ab7f3a"
	spaceMark := strings.ReplaceAll(spaceSecret, " ", "\U000E0020")
	insertedSpace := "tokenValue1\U000E0020tokenValue1"
	text := "rejected " + solidus + " " + dot + " " + hyphen + " " + colon + " " + rev + " " + encoded + " " + inserted + " " + spaceMark + " " + insertedSpace + " later"
	got := SanitizeFailure(text, secret, dotSecret, hyphenSecret, colonSecret, slashSecret, "tokenValue1tokenValue1", spaceSecret)
	for _, leaked := range []string{
		secret, solidus, dotSecret, dot, hyphenSecret, hyphen, colonSecret, colon, slashSecret, rev,
		encoded, inserted, spaceSecret, spaceMark, insertedSpace, "ver1", "verifier12", "tokenValue1", "Zz9q", "ab7f3a",
	} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E002Fver1"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "ver1"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag leaked %q in %q", leaked, got)
		}
	}
	storedSpace := strings.ReplaceAll(spaceSecret, " ", "\U000E0020")
	got = SanitizeFailure("rejected "+spaceSecret+" later", storedSpace)
	for _, leaked := range []string{spaceSecret, storedSpace, "Zz9q", "ab7f3a"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag space leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E002F later",
		"see \U000E005C later",
		"see \U000E002E later",
		"see \U000E002D later",
		"see \U000E003A later",
		"see \U000E0001 later",
		"see \U000E007F later",
		"see \U000E0020 later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagPunctuationASCIIFoldsOnlyThose(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xE0020, ' ', true},
		{0xE002D, '-', true},
		{0xE002E, '.', true},
		{0xE002F, '/', true},
		{0xE003A, ':', true},
		{0xE005C, '\\', true},
		{'-', 0, false},
		{'.', 0, false},
		{'/', 0, false},
		{':', 0, false},
		{'\\', 0, false},
		{0xE0001, 0, false},
		{0xE0061, 0, false},
		{0xE007F, 0, false},
		{0x00AD, 0, false},
	}
	for _, check := range checks {
		got, ok := tagPunctuationASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0xE007F; r++ {
		if _, ok := tagPunctuationASCII(r); ok {
			n++
		}
	}
	if n != 6 {
		t.Fatalf("tag punctuation fold count %d", n)
	}
}

func TestSanitizeFailureStripsTagLetters(t *testing.T) {
	secret := "tokenValue1"
	lower := "t\U000E006FkenValue1"
	upper := "token\U000E0056alue1"
	encoded := "t%F3%A0%81%AFkenValue1"
	inserted := "token\U000E0061Value1"
	mixedSecret := "code/ver1"
	mixed := "code\U000E002Fv\U000E0065r1"
	text := "rejected " + lower + " " + upper + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "tokenValue1tokenValue1")
	for _, leaked := range []string{secret, lower, upper, encoded, inserted, mixedSecret, mixed, "kenValue1", "alue1", "ver1"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "t\U000E006FkenValue1"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "kenValue1"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag letter leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0061 later",
		"see \U000E0041 later",
		"see \U000E007A later",
		"see \U000E0031 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag letter prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagLetterASCIIFoldsOnlyLetters(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xE0041, 'A', true},
		{0xE005A, 'Z', true},
		{0xE0061, 'a', true},
		{0xE007A, 'z', true},
		{0xE0040, 0, false},
		{0xE005B, 0, false},
		{0xE0060, 0, false},
		{0xE007B, 0, false},
		{0xE0030, 0, false},
		{0xE0020, 0, false},
		{0xE002F, 0, false},
		{'a', 0, false},
		{'A', 0, false},
		{0xE0001, 0, false},
		{0xE007F, 0, false},
	}
	for _, check := range checks {
		got, ok := tagLetterASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0xE007F; r++ {
		if _, ok := tagLetterASCII(r); ok {
			n++
		}
	}
	if n != 52 {
		t.Fatalf("tag letter fold count %d", n)
	}
}

func TestSanitizeFailureStripsTagDigits(t *testing.T) {
	secret := "tokenValue19"
	digit := "tokenValue1\U000E0039"
	encoded := "tokenValue1%F3%A0%80%B9"
	inserted := "tokenValue\U000E003019"
	mixedSecret := "code9/ver1"
	mixed := "cod\U000E00659\U000E002Fv\U000E0065r\U000E0031"
	text := "rejected " + digit + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "tokenValue19tokenValue19")
	for _, leaked := range []string{secret, digit, encoded, inserted, mixedSecret, mixed, "Value19", "ver1"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "tokenValue1\U000E0039"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "Value19"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag digit leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0030 later",
		"see \U000E0039 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag digit prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagDigitASCIIFoldsOnlyDigits(t *testing.T) {
	checks := []struct {
		r    rune
		want byte
		ok   bool
	}{
		{0xE0030, '0', true},
		{0xE0039, '9', true},
		{0xE002F, 0, false},
		{0xE003A, 0, false},
		{0xE0061, 0, false},
		{0xE0041, 0, false},
		{'0', 0, false},
		{'9', 0, false},
		{0xE0001, 0, false},
		{0xE007F, 0, false},
	}
	for _, check := range checks {
		got, ok := tagDigitASCII(check.r)
		if ok != check.ok || (check.ok && got != check.want) {
			t.Fatalf("U+%04X folded to %q ok=%v, want %q ok=%v", check.r, string(got), ok, string(check.want), check.ok)
		}
	}
	n := 0
	for r := rune(0); r <= 0xE007F; r++ {
		if _, ok := tagDigitASCII(r); ok {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("tag digit fold count %d", n)
	}
}

func TestSanitizeFailureStripsTagLowLine(t *testing.T) {
	secret := "rt_Zz9qab7f"
	mark := "rt\U000E005FZz9qab7f"
	encoded := "rt%F3%A0%81%9FZz9qab7f"
	inserted := "rt_\U000E005FZz9qab7f"
	mixedSecret := "id_ed25519"
	mixed := "i\U000E0064\U000E005Fed\U000E00325519"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "rt_Zz9qab7frt_Zz9qab7f")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "Zz9q", "ed25519"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "rt\U000E005FZz9qab7f"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "Zz9q"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag low line leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E005F later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag low line prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagLowLineFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagLowLinePieces(rawPieces("id\U000E005Frsa"))
	if !ok || renderPieces(folded) != "id_rsa" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagLowLinePieces(rawPieces("id_rsa")); ok {
		t.Fatalf("ascii underscore was folded")
	}
	if foldTagLowLineString("id\U000E0064_rsa") != "id\U000E0064_rsa" {
		t.Fatalf("tag letter was treated as a low line")
	}
}

func TestSanitizeFailureStripsTagPlus(t *testing.T) {
	secret := "code+verifier12"
	mark := "code\U000E002Bverifier12"
	encoded := "code%F3%A0%80%ABverifier12"
	inserted := "code+\U000E002Bverifier12"
	mixedSecret := "rt_Zz9q+ab7f"
	mixed := "rt\U000E005FZz9q\U000E002Bab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code+verifier12code+verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E002Bverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag plus leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E002B later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag plus prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagPlusFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagPlusPieces(rawPieces("code\U000E002Bverifier12"))
	if !ok || renderPieces(folded) != "code+verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagPlusPieces(rawPieces("code+verifier12")); ok {
		t.Fatalf("ascii plus was folded")
	}
	if foldTagPlusString("id\U000E005Frsa") != "id\U000E005Frsa" {
		t.Fatalf("tag low line was treated as a plus")
	}
}

func TestSanitizeFailureStripsTagEquals(t *testing.T) {
	secret := "code=verifier12"
	mark := "code\U000E003Dverifier12"
	encoded := "code%F3%A0%80%BDverifier12"
	inserted := "code=\U000E003Dverifier12"
	mixedSecret := "rt+Zz9q=ab7f"
	mixed := "rt\U000E002BZz9q\U000E003Dab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code=verifier12code=verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E003Dverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag equals leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E003D later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag equals prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagEqualsFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagEqualsPieces(rawPieces("code\U000E003Dverifier12"))
	if !ok || renderPieces(folded) != "code=verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagEqualsPieces(rawPieces("code=verifier12")); ok {
		t.Fatalf("ascii equals was folded")
	}
	if foldTagEqualsString("code\U000E002Bverifier12") != "code\U000E002Bverifier12" {
		t.Fatalf("tag plus was treated as an equals")
	}
}

func TestSanitizeFailureStripsTagPercent(t *testing.T) {
	secret := "100%done"
	mark := "100\U000E0025done"
	encodedSecret := "code+verifier12"
	encoded := strings.ReplaceAll(encodeEveryByte(encodedSecret), "%", "\U000E0025")
	inserted := "100%\U000E0025done"
	text := "rejected " + mark + " " + encoded + " " + inserted + " later"
	got := SanitizeFailure(text, secret, encodedSecret)
	for _, leaked := range []string{secret, mark, encodedSecret, encoded, inserted, "verifier12", "done"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "100\U000E0025done"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "done"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag percent leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0025 later",
		"score \U000E0025ZZ later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag percent prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagPercentFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagPercentPieces(rawPieces("100\U000E0025done"))
	if !ok || renderPieces(folded) != "100%done" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagPercentPieces(rawPieces("100%done")); ok {
		t.Fatalf("ascii percent was folded")
	}
	if foldTagPercentString("code\U000E003Dverifier12") != "code\U000E003Dverifier12" {
		t.Fatalf("tag equals was treated as a percent")
	}
	if _, ok := percentASCII(0xE0025); ok {
		t.Fatalf("tag percent joined the credential fold")
	}
}

func TestSanitizeFailureStripsTagCommercialAt(t *testing.T) {
	secret := "code@verifier12"
	mark := "code\U000E0040verifier12"
	encoded := "code%F3%A0%81%80verifier12"
	inserted := "code@\U000E0040verifier12"
	mixedSecret := "rt%Zz9q@ab7f"
	mixed := "rt\U000E0025Zz9q\U000E0040ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code@verifier12code@verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0040verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag commercial at leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0040 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag commercial at prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagCommercialAtFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagCommercialAtPieces(rawPieces("code\U000E0040verifier12"))
	if !ok || renderPieces(folded) != "code@verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagCommercialAtPieces(rawPieces("code@verifier12")); ok {
		t.Fatalf("ascii commercial at was folded")
	}
	if foldTagCommercialAtString("100\U000E0025done") != "100\U000E0025done" {
		t.Fatalf("tag percent was treated as a commercial at")
	}
}

func TestSanitizeFailureStripsTagQuotation(t *testing.T) {
	secret := "code\"verifier12"
	mark := "code\U000E0022verifier12"
	encoded := "code%F3%A0%80%A2verifier12"
	inserted := "code\"\U000E0022verifier12"
	mixedSecret := "rt@Zz9q\"ab7f"
	mixed := "rt\U000E0040Zz9q\U000E0022ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code\"verifier12code\"verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0022verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag quotation leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0022 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag quotation prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagQuotationFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagQuotationPieces(rawPieces("code\U000E0022verifier12"))
	if !ok || renderPieces(folded) != "code\"verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagQuotationPieces(rawPieces("code\"verifier12")); ok {
		t.Fatalf("ascii quotation mark was folded")
	}
	if foldTagQuotationString("code\U000E0040verifier12") != "code\U000E0040verifier12" {
		t.Fatalf("tag commercial at was treated as a quotation mark")
	}
}

func TestSanitizeFailureStripsTagApostrophe(t *testing.T) {
	secret := "code'verifier12"
	mark := "code\U000E0027verifier12"
	encoded := "code%F3%A0%80%A7verifier12"
	inserted := "code'\U000E0027verifier12"
	mixedSecret := "rt\"Zz9q'ab7f"
	mixed := "rt\U000E0022Zz9q\U000E0027ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code'verifier12code'verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0027verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag apostrophe leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0027 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag apostrophe prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagApostropheFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagApostrophePieces(rawPieces("code\U000E0027verifier12"))
	if !ok || renderPieces(folded) != "code'verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagApostrophePieces(rawPieces("code'verifier12")); ok {
		t.Fatalf("ascii apostrophe was folded")
	}
	if foldTagApostropheString("code\U000E0022verifier12") != "code\U000E0022verifier12" {
		t.Fatalf("tag quotation mark was treated as an apostrophe")
	}
}

func TestSanitizeFailureStripsTagVerticalLine(t *testing.T) {
	secret := "code|verifier12"
	mark := "code\U000E007Cverifier12"
	encoded := "code%F3%A0%81%BCverifier12"
	inserted := "code|\U000E007Cverifier12"
	mixedSecret := "rt'Zz9q|ab7f"
	mixed := "rt\U000E0027Zz9q\U000E007Cab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code|verifier12code|verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E007Cverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag vertical line leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E007C later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag vertical line prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagVerticalLineFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagVerticalLinePieces(rawPieces("code\U000E007Cverifier12"))
	if !ok || renderPieces(folded) != "code|verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagVerticalLinePieces(rawPieces("code|verifier12")); ok {
		t.Fatalf("ascii vertical line was folded")
	}
	if foldTagVerticalLineString("code\U000E0027verifier12") != "code\U000E0027verifier12" {
		t.Fatalf("tag apostrophe was treated as a vertical line")
	}
}

func TestSanitizeFailureStripsTagCircumflex(t *testing.T) {
	secret := "code^verifier12"
	mark := "code\U000E005Everifier12"
	encoded := "code%F3%A0%81%9Everifier12"
	inserted := "code^\U000E005Everifier12"
	mixedSecret := "rt|Zz9q^ab7f"
	mixed := "rt\U000E007CZz9q\U000E005Eab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code^verifier12code^verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E005Everifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag circumflex leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E005E later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag circumflex prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagCircumflexFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagCircumflexPieces(rawPieces("code\U000E005Everifier12"))
	if !ok || renderPieces(folded) != "code^verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagCircumflexPieces(rawPieces("code^verifier12")); ok {
		t.Fatalf("ascii circumflex was folded")
	}
	if foldTagCircumflexString("code\U000E007Cverifier12") != "code\U000E007Cverifier12" {
		t.Fatalf("tag vertical line was treated as a circumflex")
	}
}

func TestSanitizeFailureStripsTagGrave(t *testing.T) {
	secret := "code`verifier12"
	mark := "code\U000E0060verifier12"
	encoded := "code%F3%A0%81%A0verifier12"
	inserted := "code`\U000E0060verifier12"
	mixedSecret := "rt^Zz9q`ab7f"
	mixed := "rt\U000E005EZz9q\U000E0060ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code`verifier12code`verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0060verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag grave accent leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0060 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag grave accent prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagGraveFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagGravePieces(rawPieces("code\U000E0060verifier12"))
	if !ok || renderPieces(folded) != "code`verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagGravePieces(rawPieces("code`verifier12")); ok {
		t.Fatalf("ascii grave accent was folded")
	}
	if foldTagGraveString("code\U000E005Everifier12") != "code\U000E005Everifier12" {
		t.Fatalf("tag circumflex was treated as a grave accent")
	}
}

func TestSanitizeFailureStripsTagLessThan(t *testing.T) {
	secret := "code<verifier12"
	mark := "code\U000E003Cverifier12"
	encoded := "code%F3%A0%80%BCverifier12"
	inserted := "code<\U000E003Cverifier12"
	mixedSecret := "rt`Zz9q<ab7f"
	mixed := "rt\U000E0060Zz9q\U000E003Cab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code<verifier12code<verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E003Cverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag less-than sign leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E003C later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag less-than sign prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagLessThanFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagLessThanPieces(rawPieces("code\U000E003Cverifier12"))
	if !ok || renderPieces(folded) != "code<verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagLessThanPieces(rawPieces("code<verifier12")); ok {
		t.Fatalf("ascii less-than sign was folded")
	}
	if foldTagLessThanString("code\U000E0060verifier12") != "code\U000E0060verifier12" {
		t.Fatalf("tag grave accent was treated as a less-than sign")
	}
}

func TestSanitizeFailureStripsTagGreaterThan(t *testing.T) {
	secret := "code>verifier12"
	mark := "code\U000E003Everifier12"
	encoded := "code%F3%A0%80%BEverifier12"
	inserted := "code>\U000E003Everifier12"
	mixedSecret := "rt<Zz9q>ab7f"
	mixed := "rt\U000E003CZz9q\U000E003Eab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code>verifier12code>verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E003Everifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag greater-than sign leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E003E later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag greater-than sign prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagGreaterThanFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagGreaterThanPieces(rawPieces("code\U000E003Everifier12"))
	if !ok || renderPieces(folded) != "code>verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagGreaterThanPieces(rawPieces("code>verifier12")); ok {
		t.Fatalf("ascii greater-than sign was folded")
	}
	if foldTagGreaterThanString("code\U000E003Cverifier12") != "code\U000E003Cverifier12" {
		t.Fatalf("tag less-than sign was treated as a greater-than sign")
	}
}

func TestSanitizeFailureStripsTagLeftSquareBracket(t *testing.T) {
	secret := "code[verifier12"
	mark := "code\U000E005Bverifier12"
	encoded := "code%F3%A0%81%9Bverifier12"
	inserted := "code[\U000E005Bverifier12"
	mixedSecret := "rt>Zz9q[ab7f"
	mixed := "rt\U000E003EZz9q\U000E005Bab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code[verifier12code[verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E005Bverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag left square bracket leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E005B later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag left square bracket prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagLeftSquareBracketFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagLeftSquareBracketPieces(rawPieces("code\U000E005Bverifier12"))
	if !ok || renderPieces(folded) != "code[verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagLeftSquareBracketPieces(rawPieces("code[verifier12")); ok {
		t.Fatalf("ascii left square bracket was folded")
	}
	if foldTagLeftSquareBracketString("code\U000E003Everifier12") != "code\U000E003Everifier12" {
		t.Fatalf("tag greater-than sign was treated as a left square bracket")
	}
}

func TestSanitizeFailureStripsTagRightSquareBracket(t *testing.T) {
	secret := "code]verifier12"
	mark := "code\U000E005Dverifier12"
	encoded := "code%F3%A0%81%9Dverifier12"
	inserted := "code]\U000E005Dverifier12"
	mixedSecret := "rt[Zz9q]ab7f"
	mixed := "rt\U000E005BZz9q\U000E005Dab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code]verifier12code]verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E005Dverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag right square bracket leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E005D later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag right square bracket prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagRightSquareBracketFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagRightSquareBracketPieces(rawPieces("code\U000E005Dverifier12"))
	if !ok || renderPieces(folded) != "code]verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagRightSquareBracketPieces(rawPieces("code]verifier12")); ok {
		t.Fatalf("ascii right square bracket was folded")
	}
	if foldTagRightSquareBracketString("code\U000E005Bverifier12") != "code\U000E005Bverifier12" {
		t.Fatalf("tag left square bracket was treated as a right square bracket")
	}
}

func TestSanitizeFailureStripsTagLeftCurlyBracket(t *testing.T) {
	secret := "code{verifier12"
	mark := "code\U000E007Bverifier12"
	encoded := "code%F3%A0%81%BBverifier12"
	inserted := "code{\U000E007Bverifier12"
	mixedSecret := "rt]Zz9q{ab7f"
	mixed := "rt\U000E005DZz9q\U000E007Bab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code{verifier12code{verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E007Bverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag left curly bracket leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E007B later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag left curly bracket prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagLeftCurlyBracketFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagLeftCurlyBracketPieces(rawPieces("code\U000E007Bverifier12"))
	if !ok || renderPieces(folded) != "code{verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagLeftCurlyBracketPieces(rawPieces("code{verifier12")); ok {
		t.Fatalf("ascii left curly bracket was folded")
	}
	if foldTagLeftCurlyBracketString("code\U000E005Dverifier12") != "code\U000E005Dverifier12" {
		t.Fatalf("tag right square bracket was treated as a left curly bracket")
	}
}

func TestSanitizeFailureStripsTagRightCurlyBracket(t *testing.T) {
	secret := "code}verifier12"
	mark := "code\U000E007Dverifier12"
	encoded := "code%F3%A0%81%BDverifier12"
	inserted := "code}\U000E007Dverifier12"
	mixedSecret := "rt{Zz9q}ab7f"
	mixed := "rt\U000E007BZz9q\U000E007Dab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code}verifier12code}verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E007Dverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag right curly bracket leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E007D later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag right curly bracket prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagRightCurlyBracketFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagRightCurlyBracketPieces(rawPieces("code\U000E007Dverifier12"))
	if !ok || renderPieces(folded) != "code}verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagRightCurlyBracketPieces(rawPieces("code}verifier12")); ok {
		t.Fatalf("ascii right curly bracket was folded")
	}
	if foldTagRightCurlyBracketString("code\U000E007Bverifier12") != "code\U000E007Bverifier12" {
		t.Fatalf("tag left curly bracket was treated as a right curly bracket")
	}
}

func TestSanitizeFailureStripsTagComma(t *testing.T) {
	secret := "code,verifier12"
	mark := "code\U000E002Cverifier12"
	encoded := "code%F3%A0%80%ACverifier12"
	inserted := "code,\U000E002Cverifier12"
	mixedSecret := "rt}Zz9q,ab7f"
	mixed := "rt\U000E007DZz9q\U000E002Cab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code,verifier12code,verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E002Cverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag comma leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E002C later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag comma prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagCommaFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagCommaPieces(rawPieces("code\U000E002Cverifier12"))
	if !ok || renderPieces(folded) != "code,verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagCommaPieces(rawPieces("code,verifier12")); ok {
		t.Fatalf("ascii comma was folded")
	}
	if foldTagCommaString("code\U000E007Dverifier12") != "code\U000E007Dverifier12" {
		t.Fatalf("tag right curly bracket was treated as a comma")
	}
}

func TestSanitizeFailureStripsTagSemicolon(t *testing.T) {
	secret := "code;verifier12"
	mark := "code\U000E003Bverifier12"
	encoded := "code%F3%A0%80%BBverifier12"
	inserted := "code;\U000E003Bverifier12"
	mixedSecret := "rt,Zz9q;ab7f"
	mixed := "rt\U000E002CZz9q\U000E003Bab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code;verifier12code;verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E003Bverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag semicolon leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E003B later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag semicolon prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagSemicolonFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagSemicolonPieces(rawPieces("code\U000E003Bverifier12"))
	if !ok || renderPieces(folded) != "code;verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagSemicolonPieces(rawPieces("code;verifier12")); ok {
		t.Fatalf("ascii semicolon was folded")
	}
	if foldTagSemicolonString("code\U000E002Cverifier12") != "code\U000E002Cverifier12" {
		t.Fatalf("tag comma was treated as a semicolon")
	}
}

func TestSanitizeFailureStripsTagQuestionMark(t *testing.T) {
	secret := "code?verifier12"
	mark := "code\U000E003Fverifier12"
	encoded := "code%F3%A0%80%BFverifier12"
	inserted := "code?\U000E003Fverifier12"
	mixedSecret := "rt;Zz9q?ab7f"
	mixed := "rt\U000E003BZz9q\U000E003Fab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code?verifier12code?verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E003Fverifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag question mark leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E003F later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag question mark prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagQuestionMarkFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagQuestionMarkPieces(rawPieces("code\U000E003Fverifier12"))
	if !ok || renderPieces(folded) != "code?verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagQuestionMarkPieces(rawPieces("code?verifier12")); ok {
		t.Fatalf("ascii question mark was folded")
	}
	if foldTagQuestionMarkString("code\U000E003Bverifier12") != "code\U000E003Bverifier12" {
		t.Fatalf("tag semicolon was treated as a question mark")
	}
}

func TestSanitizeFailureStripsTagAsterisk(t *testing.T) {
	secret := "code*verifier12"
	mark := "code\U000E002Averifier12"
	encoded := "code%F3%A0%80%AAverifier12"
	inserted := "code*\U000E002Averifier12"
	mixedSecret := "rt?Zz9q*ab7f"
	mixed := "rt\U000E003FZz9q\U000E002Aab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code*verifier12code*verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E002Averifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag asterisk leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E002A later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag asterisk prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagAsteriskFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagAsteriskPieces(rawPieces("code\U000E002Averifier12"))
	if !ok || renderPieces(folded) != "code*verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagAsteriskPieces(rawPieces("code*verifier12")); ok {
		t.Fatalf("ascii asterisk was folded")
	}
	if foldTagAsteriskString("code\U000E003Fverifier12") != "code\U000E003Fverifier12" {
		t.Fatalf("tag question mark was treated as an asterisk")
	}
}

func TestSanitizeFailureStripsTagAmpersand(t *testing.T) {
	secret := "code&verifier12"
	mark := "code\U000E0026verifier12"
	encoded := "code%F3%A0%80%A6verifier12"
	inserted := "code&\U000E0026verifier12"
	mixedSecret := "rt*Zz9q&ab7f"
	mixed := "rt\U000E002AZz9q\U000E0026ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code&verifier12code&verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0026verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag ampersand leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0026 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag ampersand prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagAmpersandFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagAmpersandPieces(rawPieces("code\U000E0026verifier12"))
	if !ok || renderPieces(folded) != "code&verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagAmpersandPieces(rawPieces("code&verifier12")); ok {
		t.Fatalf("ascii ampersand was folded")
	}
	if foldTagAmpersandString("code\U000E002Averifier12") != "code\U000E002Averifier12" {
		t.Fatalf("tag asterisk was treated as an ampersand")
	}
}

func TestSanitizeFailureStripsTagDollar(t *testing.T) {
	secret := "code$verifier12"
	mark := "code\U000E0024verifier12"
	encoded := "code%F3%A0%80%A4verifier12"
	inserted := "code$\U000E0024verifier12"
	mixedSecret := "rt&Zz9q$ab7f"
	mixed := "rt\U000E0026Zz9q\U000E0024ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code$verifier12code$verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0024verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag dollar sign leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0024 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag dollar sign prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagDollarFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagDollarPieces(rawPieces("code\U000E0024verifier12"))
	if !ok || renderPieces(folded) != "code$verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagDollarPieces(rawPieces("code$verifier12")); ok {
		t.Fatalf("ascii dollar sign was folded")
	}
	if foldTagDollarString("code\U000E0026verifier12") != "code\U000E0026verifier12" {
		t.Fatalf("tag ampersand was treated as a dollar sign")
	}
}

func TestSanitizeFailureStripsTagNumberSign(t *testing.T) {
	secret := "code#verifier12"
	mark := "code\U000E0023verifier12"
	encoded := "code%F3%A0%80%A3verifier12"
	inserted := "code#\U000E0023verifier12"
	mixedSecret := "rt$Zz9q#ab7f"
	mixed := "rt\U000E0024Zz9q\U000E0023ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code#verifier12code#verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0023verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag number sign leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0023 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag number sign prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagNumberSignFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagNumberSignPieces(rawPieces("code\U000E0023verifier12"))
	if !ok || renderPieces(folded) != "code#verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagNumberSignPieces(rawPieces("code#verifier12")); ok {
		t.Fatalf("ascii number sign was folded")
	}
	if foldTagNumberSignString("code\U000E0024verifier12") != "code\U000E0024verifier12" {
		t.Fatalf("tag dollar sign was treated as a number sign")
	}
}

func TestSanitizeFailureStripsTagExclamation(t *testing.T) {
	secret := "code!verifier12"
	mark := "code\U000E0021verifier12"
	encoded := "code%F3%A0%80%A1verifier12"
	inserted := "code!\U000E0021verifier12"
	mixedSecret := "rt#Zz9q!ab7f"
	mixed := "rt\U000E0023Zz9q\U000E0021ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code!verifier12code!verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0021verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag exclamation mark leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0021 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag exclamation mark prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagExclamationFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagExclamationPieces(rawPieces("code\U000E0021verifier12"))
	if !ok || renderPieces(folded) != "code!verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagExclamationPieces(rawPieces("code!verifier12")); ok {
		t.Fatalf("ascii exclamation mark was folded")
	}
	if foldTagExclamationString("code\U000E0023verifier12") != "code\U000E0023verifier12" {
		t.Fatalf("tag number sign was treated as an exclamation mark")
	}
}

func TestSanitizeFailureStripsTagLeftParenthesis(t *testing.T) {
	secret := "code(verifier12"
	mark := "code\U000E0028verifier12"
	encoded := "code%F3%A0%80%A8verifier12"
	inserted := "code(\U000E0028verifier12"
	mixedSecret := "rt!Zz9q(ab7f"
	mixed := "rt\U000E0021Zz9q\U000E0028ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code(verifier12code(verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0028verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag left parenthesis leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0028 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag left parenthesis prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagLeftParenthesisFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagLeftParenthesisPieces(rawPieces("code\U000E0028verifier12"))
	if !ok || renderPieces(folded) != "code(verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagLeftParenthesisPieces(rawPieces("code(verifier12")); ok {
		t.Fatalf("ascii left parenthesis was folded")
	}
	if foldTagLeftParenthesisString("code\U000E0021verifier12") != "code\U000E0021verifier12" {
		t.Fatalf("tag exclamation mark was treated as a left parenthesis")
	}
}

func TestSanitizeFailureStripsTagRightParenthesis(t *testing.T) {
	secret := "code)verifier12"
	mark := "code\U000E0029verifier12"
	encoded := "code%F3%A0%80%A9verifier12"
	inserted := "code)\U000E0029verifier12"
	mixedSecret := "rt(Zz9q)ab7f"
	mixed := "rt\U000E0028Zz9q\U000E0029ab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code)verifier12code)verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E0029verifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag right parenthesis leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E0029 later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag right parenthesis prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagRightParenthesisFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagRightParenthesisPieces(rawPieces("code\U000E0029verifier12"))
	if !ok || renderPieces(folded) != "code)verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagRightParenthesisPieces(rawPieces("code)verifier12")); ok {
		t.Fatalf("ascii right parenthesis was folded")
	}
	if foldTagRightParenthesisString("code\U000E0028verifier12") != "code\U000E0028verifier12" {
		t.Fatalf("tag left parenthesis was treated as a right parenthesis")
	}
}

func TestSanitizeFailureStripsTagTilde(t *testing.T) {
	secret := "code~verifier12"
	mark := "code\U000E007Everifier12"
	encoded := "code%F3%A0%81%BEverifier12"
	inserted := "code~\U000E007Everifier12"
	mixedSecret := "rt)Zz9q~ab7f"
	mixed := "rt\U000E0029Zz9q\U000E007Eab7f"
	text := "rejected " + mark + " " + encoded + " " + inserted + " " + mixed + " later"
	got := SanitizeFailure(text, secret, mixedSecret, "code~verifier12code~verifier12")
	for _, leaked := range []string{secret, mark, encoded, inserted, mixedSecret, mixed, "verifier12", "Zz9q", "ab7f"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "rejected") || !strings.Contains(got, "later") {
		t.Fatalf("lost context: %q", got)
	}
	stored := "code\U000E007Everifier12"
	got = SanitizeFailure("rejected "+secret+" later", stored)
	for _, leaked := range []string{secret, stored, "verifier12"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("stored tag tilde leaked %q in %q", leaked, got)
		}
	}
	for _, prose := range []string{
		"see \U000E007E later",
		"see \U000E0001 later",
		"see \U000E007F later",
	} {
		if got := SanitizeFailure(prose); got != prose {
			t.Fatalf("tag tilde prose changed: %q -> %q", prose, got)
		}
	}
}

func TestTagTildeFoldIsOnlyThatCharacter(t *testing.T) {
	folded, ok := foldTagTildePieces(rawPieces("code\U000E007Everifier12"))
	if !ok || renderPieces(folded) != "code~verifier12" {
		t.Fatalf("folded %q ok=%v", renderPieces(folded), ok)
	}
	if _, ok := foldTagTildePieces(rawPieces("code~verifier12")); ok {
		t.Fatalf("ascii tilde was folded")
	}
	if foldTagTildeString("code\U000E0029verifier12") != "code\U000E0029verifier12" {
		t.Fatalf("tag right parenthesis was treated as a tilde")
	}
}
