package account

import (
	"encoding/json"
	"path/filepath"
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
