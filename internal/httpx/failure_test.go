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
