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
