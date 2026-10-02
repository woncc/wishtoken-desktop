package account

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/testutil"
)

func sampleJWT(email, id string) string {
	return testutil.MakeJWT(testutil.ChatGPTClaims(email, id, "plus", time.Now().Add(time.Hour)))
}

func TestParseCodexAuthJSON(t *testing.T) {
	raw := `{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"id_token":"` + sampleJWT("codex@example.com", "acct_codex") + `","access_token":"` + sampleJWT("codex@example.com", "acct_codex") + `","refresh_token":"rt_codex_1234567890","account_id":"acct_codex"},"last_refresh":"2026-09-01T10:00:00Z"}`
	res, err := Parse([]byte(raw), "auth.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 1 {
		t.Fatalf("expected 1 account, got %d (%v)", len(res.Accounts), res.Warnings)
	}
	acc := res.Accounts[0]
	if acc.Email != "codex@example.com" || acc.AccountID != "acct_codex" || acc.RefreshToken != "rt_codex_1234567890" || acc.PlanType != "plus" {
		t.Fatalf("unexpected account: %+v", acc)
	}
	if acc.LastRefresh.IsZero() || acc.ExpiresAt.IsZero() {
		t.Fatalf("timestamps not filled: %+v", acc)
	}
}

func TestParseCPAAndSub2APIAndText(t *testing.T) {
	cpa := `[{"type":"codex","email":"cpa@example.com","id_token":"` + sampleJWT("cpa@example.com", "acct_cpa") + `","access_token":"` + sampleJWT("cpa@example.com", "acct_cpa") + `","refresh_token":"rt_cpa_1234567890","account_id":"acct_cpa","last_refresh":"2026-09-02T00:00:00Z","expired":"2026-09-02T01:00:00Z"},{"type":"gemini","access_token":"x"}]`
	res, err := Parse([]byte(cpa), "cpa")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 1 || res.Skipped != 1 {
		t.Fatalf("cpa: accounts=%d skipped=%d warnings=%v", len(res.Accounts), res.Skipped, res.Warnings)
	}
	if res.Accounts[0].ExpiresAt.Year() != 2026 {
		t.Fatalf("expired not parsed: %v", res.Accounts[0].ExpiresAt)
	}

	sub := `{"accounts":[{"name":"team-a","credentials":{"accessToken":"` + sampleJWT("sub@example.com", "acct_sub") + `","refreshToken":"rt_sub_1234567890","chatgpt_account_id":"acct_sub","expires_at":1790000000}}]}`
	res, err = Parse([]byte(sub), "sub2api")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 1 || res.Accounts[0].Name != "team-a" || res.Accounts[0].AccountID != "acct_sub" || res.Accounts[0].RefreshToken != "rt_sub_1234567890" {
		t.Fatalf("sub2api: %+v", res.Accounts)
	}

	text := "# comment\nrt_line_abcdefghijklmnop\nuser@example.com----pass----rt_line_qrstuvwxyz1234\n" + sampleJWT("jwt@example.com", "acct_jwt") + "\n"
	res, err = Parse([]byte(text), "text")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 3 {
		t.Fatalf("text: expected 3 accounts, got %d (%v)", len(res.Accounts), res.Warnings)
	}
	if res.Accounts[1].Email != "user@example.com" || res.Accounts[1].RefreshToken != "rt_line_qrstuvwxyz1234" {
		t.Fatalf("text line 2: %+v", res.Accounts[1])
	}
	if res.Accounts[2].AccessToken == "" || res.Accounts[2].AccountID != "acct_jwt" {
		t.Fatalf("text jwt: %+v", res.Accounts[2])
	}
}

func TestParseDeduplicates(t *testing.T) {
	entry := map[string]any{"access_token": sampleJWT("dup@example.com", "acct_dup"), "refresh_token": "rt_dup_1234567890", "account_id": "acct_dup"}
	raw, _ := json.Marshal([]any{entry, entry})
	res, err := Parse(raw, "dup")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 1 || res.Skipped != 1 {
		t.Fatalf("expected dedupe, got %d accounts skipped=%d", len(res.Accounts), res.Skipped)
	}
}

func TestStoreUpsertMergesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first := Account{Email: "m@example.com", AccountID: "acct_m", RefreshToken: "rt_old_1234567890", AccessToken: sampleJWT("m@example.com", "acct_m")}
	first.FillFromTokens()
	up, err := store.Upsert(first)
	if err != nil || !up.Created {
		t.Fatalf("first upsert: %v %+v", err, up)
	}
	second := Account{AccountID: "acct_m", UserID: first.UserID, Email: first.Email, RefreshToken: "rt_new_1234567890", LastRefresh: time.Now(), Name: "named"}
	up2, err := store.Upsert(second)
	if err != nil || up2.Created || up2.ID != up.ID {
		t.Fatalf("second upsert should merge: %v %+v", err, up2)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Count() != 1 {
		t.Fatalf("expected 1 stored account, got %d", reopened.Count())
	}
	acc, _ := reopened.Get(up.ID)
	if acc.RefreshToken != "rt_new_1234567890" || acc.Name != "named" || acc.Email != "m@example.com" {
		t.Fatalf("merge lost data: %+v", acc)
	}
	view := acc.View()
	if strings.Contains(view.AccountID, "acct_m") && len(view.AccountID) > 9 {
		t.Fatalf("view must mask account id: %q", view.AccountID)
	}
	if view.Status != "ready" {
		t.Fatalf("status: %q", view.Status)
	}
	if err := reopened.Delete(up.ID); err != nil {
		t.Fatal(err)
	}
	if reopened.Count() != 0 {
		t.Fatal("delete failed")
	}
}

func TestExportRoundTrip(t *testing.T) {
	acc := Account{Email: "e@example.com", AccountID: "acct_e", RefreshToken: "rt_e_1234567890", AccessToken: sampleJWT("e@example.com", "acct_e"), IDToken: sampleJWT("e@example.com", "acct_e")}
	raw, err := ExportJSON([]Account{acc}, "codex")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(raw, "roundtrip")
	if err != nil || len(res.Accounts) != 1 || res.Accounts[0].AccountID != "acct_e" {
		t.Fatalf("codex round trip failed: %v %+v", err, res)
	}
	raw, _ = ExportJSON([]Account{acc}, "cpa")
	res, err = Parse(raw, "roundtrip")
	if err != nil || len(res.Accounts) != 1 || res.Accounts[0].RefreshToken != "rt_e_1234567890" {
		t.Fatalf("cpa round trip failed: %v %+v", err, res)
	}
}

func TestParseConcatenatedJSON(t *testing.T) {
	one := `{"refresh_token":"rt_line_one_1234567890","email":"one@example.test"}`
	two := `{"refresh_token":"rt_line_two_1234567890","email":"two@example.test"}`
	res, err := Parse([]byte(one+"\n"+two+"\n"), "lines")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 2 || res.Accounts[0].Email != "one@example.test" || res.Accounts[1].RefreshToken != "rt_line_two_1234567890" {
		t.Fatalf("json lines: %+v warnings=%v", res.Accounts, res.Warnings)
	}
	res, err = Parse([]byte(one+" "+two), "concat")
	if err != nil || len(res.Accounts) != 2 {
		t.Fatalf("concatenated values: %v accounts=%d warnings=%v", err, len(res.Accounts), res.Warnings)
	}
	res, err = Parse([]byte(one+"\nnot-json\n"), "partial")
	if err != nil || len(res.Accounts) != 1 || len(res.Warnings) == 0 {
		t.Fatalf("partial: err=%v accounts=%d warnings=%v", err, len(res.Accounts), res.Warnings)
	}
	if _, err = Parse([]byte("{"), "bad"); err == nil {
		t.Fatal("truncated JSON accepted")
	}
}

func TestSaveReplacesPermissiveFileAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"accounts":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	token := "rt_store_abcdefghij123456"
	if _, err := store.Upsert(Account{Email: "store@example.test", AccountID: "acct_store", RefreshToken: token}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("account file mode %o", info.Mode().Perm())
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), token) {
		t.Fatalf("stored credential missing: %q %v", raw, err)
	}

	elsewhere := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(elsewhere, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(elsewhere, path+".tmp"); err != nil {
		t.Skip(err)
	}
	rotated := "rt_store_rotated_abcdef1234"
	if _, err := store.Upsert(Account{Email: "store@example.test", AccountID: "acct_store", RefreshToken: rotated, LastRefresh: time.Now()}); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(elsewhere)
	if err != nil || string(kept) != "keep" {
		t.Fatalf("credential write followed a symlink: %q %v", kept, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("account file remained a symlink")
	}
	raw, err = os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), rotated) || strings.Contains(string(raw), "keep") {
		t.Fatalf("replacement account file: %q %v", raw, err)
	}
}

func TestImportWarningsOmitUnstoredCredentials(t *testing.T) {
	refresh := "rt_" + strings.Repeat("c", 28)
	access := sampleJWT("hidden@example.com", "acct_hidden")
	raw := `{"type":"` + refresh + `","access_token":"` + access + `","refresh_token":"` + refresh + `","name":"` + access + `"}`
	res, err := Parse([]byte(raw), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 0 || res.Skipped != 1 {
		t.Fatalf("expected skip, accounts=%d skipped=%d warnings=%v", len(res.Accounts), res.Skipped, res.Warnings)
	}
	joined := strings.Join(res.Warnings, "\n")
	if strings.Contains(joined, refresh) || strings.Contains(joined, access) || strings.Contains(joined, "eyJ") {
		t.Fatalf("warning leaked: %s", joined)
	}
	if !strings.Contains(joined, "non-Codex") {
		t.Fatalf("warning lost context: %s", joined)
	}

	named := testutil.MakeJWT(map[string]any{"email": "solo@example.com", "exp": time.Now().Add(time.Hour).Unix()})
	res, err = Parse([]byte(`{"name":"`+named+`","access_token":"`+named+`","tags":["team","`+refresh+`"]}`), "fixture")
	if err != nil || len(res.Accounts) != 1 {
		t.Fatalf("named import: %v %+v", err, res)
	}
	acc := res.Accounts[0]
	if acc.Name != "" || acc.Email != "solo@example.com" || len(acc.Tags) != 1 || acc.Tags[0] != "team" {
		t.Fatalf("display kept credential material: %+v", acc)
	}
	joined = strings.Join(res.Warnings, "\n")
	if strings.Contains(joined, named) || strings.Contains(joined, refresh) || strings.Contains(joined, "eyJ") {
		t.Fatalf("renewal warning leaked: %s", joined)
	}
}

func TestImportHidesProxyPasswordsInDisplayFields(t *testing.T) {
	const password = "s3cret-proxy"
	proxy := "http://user:" + password + "@127.0.0.1:7890"
	malformed := "http://user:" + password + "%zz@127.0.0.1:7890"
	token := sampleJWT("kept@example.com", "acct_keep")
	raw := `{"access_token":"` + token + `","refresh_token":"rt_keep_1234567890","email":"` + proxy + `","name":"` + malformed + `","plan_type":"` + proxy + `","source":"` + malformed + `","tags":["team","` + proxy + `"],"proxy_url":"` + proxy + `"}`
	res, err := Parse([]byte(raw), "fixture")
	if err != nil || len(res.Accounts) != 1 {
		t.Fatalf("import: %v %+v", err, res)
	}
	acc := res.Accounts[0]
	stored := acc.Name + "\n" + acc.Email + "\n" + strings.Join(acc.Tags, "\n")
	if strings.Contains(stored, password) || acc.Email != "kept@example.com" || acc.PlanType != "plus" || acc.ProxyURL != proxy {
		t.Fatalf("display stored a proxy password or dropped the real fields: %+v", acc)
	}
	if strings.Contains(acc.Label(), password) {
		t.Fatalf("label leaked: %s", acc.Label())
	}
	if !strings.Contains(acc.Name, "xxxxx") || len(acc.Tags) != 2 || !strings.Contains(acc.Tags[1], "xxxxx") {
		t.Fatalf("redacted display missing: %+v", acc)
	}
	acc.LastError = "dial " + malformed
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.ProxyURL + "\n" + view.LastError
	if strings.Contains(shown, password) || view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.ProxyURL, "xxxxx") || !strings.Contains(view.LastError, "xxxxx") {
		t.Fatalf("view leaked: %+v", view)
	}
}

func TestViewHidesEmbeddedCredentials(t *testing.T) {
	refresh := "rt_display_123456789"
	var encoded strings.Builder
	for i := 0; i < len(refresh); i++ {
		fmt.Fprintf(&encoded, "%%%02X", refresh[i])
	}
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	acc := Account{
		Name: "note " + refresh + " " + encoded.String(), Email: "kept@example.com", PlanType: "plus",
		Source: "from " + jwt, Tags: []string{"team", "see " + refresh}, LastError: "rejected " + encoded.String(),
		AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, encoded.String(), jwt, "eyJ"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") {
		t.Fatalf("display context lost: %+v", view)
	}
}

func TestViewHidesCredentialsSplitByMarks(t *testing.T) {
	refresh := "rt_display_123456789"
	marked := "rt_\uFE0Edisplay_123456789"
	acute := "rt_displ\u0301ay_123456789"
	enclosed := "rt_display_\u20dd123456789"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\uFE0FdXJl"
	acc := Account{
		Name: "note " + marked + " " + acute, Email: "kept@example.com", PlanType: "plus",
		Source: "from " + markedJWT, Tags: []string{"team", enclosed}, LastError: "rejected " + marked,
		AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, marked, acute, enclosed, jwt, markedJWT, "eyJ", "display_123456789"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") || len(view.Tags) != 1 || view.Tags[0] != "team" {
		t.Fatalf("display context lost: %+v", view)
	}
}

func TestViewHidesCredentialsSplitByUnicodeSpaces(t *testing.T) {
	refresh := "rt_display_123456789"
	nbsp := "rt_\u00a0display_123456789"
	ogham := "rt_display_\u1680123456789"
	encoded := "rt_%E3%80%80display_123456789"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u2009dXJl"
	acc := Account{
		Name: "note " + nbsp + " " + encoded, Email: "kept@example.com", PlanType: "plus",
		Source: "from " + markedJWT, Tags: []string{"team", ogham}, LastError: "rejected " + nbsp,
		AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, nbsp, ogham, encoded, jwt, markedJWT, "eyJ", "display_123456789"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") || len(view.Tags) != 1 || view.Tags[0] != "team" {
		t.Fatalf("display context lost: %+v", view)
	}
}

func TestViewHidesCredentialsSplitByFormatCharacters(t *testing.T) {
	refresh := "rt_display_123456789"
	zwsp := "rt_\u200Bdisplay_123456789"
	bom := "rt_display_\uFEFF123456789"
	encoded := "rt_%E2%80%8Bdisplay_123456789"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u200DdXJl"
	acc := Account{
		Name: "note " + zwsp + " " + encoded, Email: "kept@example.com", PlanType: "plus",
		Source: "from " + markedJWT, Tags: []string{"team", bom}, LastError: "rejected " + zwsp,
		AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, zwsp, bom, encoded, jwt, markedJWT, "eyJ", "display_123456789"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") || len(view.Tags) != 1 || view.Tags[0] != "team" {
		t.Fatalf("display context lost: %+v", view)
	}
}

func TestViewHidesCredentialsSplitByControls(t *testing.T) {
	refresh := "rt_display_123456789"
	nul := "rt_\x00display_123456789"
	line := "rt_display_\u2028123456789"
	encoded := "rt_%00display_123456789"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u2029dXJl"
	acc := Account{
		Name: "note " + nul + " " + encoded, Email: "kept@example.com", PlanType: "plus",
		Source: "from " + markedJWT, Tags: []string{"team", line}, LastError: "rejected " + nul,
		AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, nul, line, encoded, jwt, markedJWT, "eyJ", "display_123456789"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") || len(view.Tags) != 1 || view.Tags[0] != "team" {
		t.Fatalf("display context lost: %+v", view)
	}
}

func TestViewHidesCredentialsSplitByBlankFillers(t *testing.T) {
	refresh := "rt_display_123456789"
	filler := "rt_\u3164display_123456789"
	braille := "rt_display_\u2800123456789"
	encoded := "rt_%EF%BE%A0display_123456789"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u1160dXJl"
	acc := Account{
		Name: "note " + filler + " " + encoded, Email: "kept@example.com", PlanType: "plus",
		Source: "from " + markedJWT, Tags: []string{"team", braille}, LastError: "rejected " + filler,
		AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, filler, braille, encoded, jwt, markedJWT, "eyJ", "display_123456789"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") || len(view.Tags) != 1 || view.Tags[0] != "team" {
		t.Fatalf("display context lost: %+v", view)
	}
}

func TestViewHidesCredentialsSplitBySpacingMarks(t *testing.T) {
	refresh := "rt_display_123456789"
	vowel := "rt_\u093edisplay_123456789"
	tone := "rt_display_\u302e123456789"
	encoded := "rt_%E0%AE%BEdisplay_123456789"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0\u302fdXJl"
	acc := Account{
		Name: "note " + vowel + " " + encoded, Email: "kept@example.com", PlanType: "plus",
		Source: "from " + markedJWT, Tags: []string{"team", tone}, LastError: "rejected " + vowel,
		AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, vowel, tone, encoded, jwt, markedJWT, "eyJ", "display_123456789"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") || len(view.Tags) != 1 || view.Tags[0] != "team" {
		t.Fatalf("display context lost: %+v", view)
	}
}

func TestViewHidesCredentialsThatNeedJSONEscapes(t *testing.T) {
	refresh := "rt_quote\"x<secret\\value\nzzTAIL99"
	marked := refresh[:8] + "\u093e" + refresh[8:]
	encoded := "rt_quote%22x%3Csecret%5Cvalue%0AzzTAIL99"
	acc := Account{
		Name: "note " + refresh + " " + encoded, Email: "kept@example.com", PlanType: "plus",
		RefreshToken: refresh, Source: "from " + marked, Tags: []string{"team", "see " + marked},
		LastError: "rejected " + marked, AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, marked, encoded, "zzTAIL99", "x<secret", "secret\\value"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") || len(view.Tags) != 2 || view.Tags[0] != "team" || !strings.Contains(view.Tags[1], "see") {
		t.Fatalf("display context lost: %+v", view)
	}
}

func TestImportHidesCredentialsThatNeedJSONEscapes(t *testing.T) {
	refresh := "rt_quote\"x<secret\\value\nzzTAIL99"
	marked := "see " + refresh[:8] + "\u093e" + refresh[8:]
	token := sampleJWT("kept@example.com", "acct_keep")
	raw, err := json.Marshal(map[string]any{
		"access_token": token, "refresh_token": refresh, "email": "kept@example.com",
		"name": "note " + refresh, "tags": []string{"team", marked},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(raw, "fixture")
	if err != nil || len(res.Accounts) != 1 {
		t.Fatalf("import: %v %+v", err, res)
	}
	acc := res.Accounts[0]
	shown := acc.Name + "\n" + acc.Email + "\n" + strings.Join(acc.Tags, "\n") + "\n" + acc.Label()
	for _, leaked := range []string{refresh, "zzTAIL99", "x<secret", "secret\\value"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if acc.Email != "kept@example.com" || !strings.Contains(acc.Name, "note") || len(acc.Tags) != 2 || acc.Tags[0] != "team" || !strings.Contains(acc.Tags[1], "see") || acc.RefreshToken != refresh {
		t.Fatalf("import changed the stored credential or context: %+v", acc)
	}
}

func TestViewHidesCredentialsSplitByHyphens(t *testing.T) {
	refresh := "rt_display-123456789"
	hyphen := "rt_display\u2010" + "123456789"
	minus := "rt_\u2212display-123456789"
	tone := "rt_display\u1bf3123456789"
	encoded := "rt_display%E2%80%91123456789"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEi.c2ln-bmF0dXJl"
	markedJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEi.c2ln\u2013bmF0dXJl"
	acc := Account{
		Name: "note " + hyphen + " " + encoded, Email: "kept@example.com", PlanType: "plus",
		RefreshToken: refresh, Source: "from " + markedJWT, Tags: []string{"team", minus},
		LastError: "rejected " + tone, AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, hyphen, minus, tone, encoded, jwt, markedJWT, "eyJ", "display-123456789", "123456789"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") || len(view.Tags) != 1 || view.Tags[0] != "team" {
		t.Fatalf("display context lost: %+v", view)
	}
}

func TestViewHidesCredentialsSplitByEmDashes(t *testing.T) {
	refresh := "rt_display-123456789"
	em := "rt_display\u2014" + "123456789"
	bar := "rt_\u2015display-123456789"
	vertical := "rt_display\ufe31" + "123456789"
	acc := Account{
		Name: "note " + em, Email: "kept@example.com", PlanType: "plus",
		RefreshToken: refresh, Source: "from " + bar, Tags: []string{"team", vertical},
		LastError: "rejected " + em, AccountID: "acct_keep",
	}
	view := acc.View()
	shown := view.Name + "\n" + view.Email + "\n" + view.PlanType + "\n" + view.Source + "\n" + strings.Join(view.Tags, "\n") + "\n" + view.LastError + "\n" + acc.Label()
	for _, leaked := range []string{refresh, em, bar, vertical, "display-123456789", "123456789"} {
		if strings.Contains(shown, leaked) {
			t.Fatalf("leaked %q in %s", leaked, shown)
		}
	}
	if view.Email != "kept@example.com" || view.PlanType != "plus" || !strings.Contains(view.Name, "note") || !strings.Contains(view.LastError, "rejected") || !strings.Contains(view.Source, "from") || len(view.Tags) != 1 || view.Tags[0] != "team" {
		t.Fatalf("display context lost: %+v", view)
	}
}
