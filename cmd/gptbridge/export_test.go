package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xxx-holic/wishtoken-desktop/internal/account"
)

func TestExportAccountsRefusesStdout(t *testing.T) {
	acc := account.Account{Email: "export@example.test", AccountID: "acct_export", RefreshToken: "rt_export_abcdefghij1234"}
	for _, out := range []string{"", "  ", "-"} {
		err := exportAccounts([]account.Account{acc}, "cpa", out)
		if err == nil {
			t.Fatalf("export to %q was accepted", out)
		}
		if strings.Contains(err.Error(), acc.RefreshToken) || strings.Contains(err.Error(), acc.AccountID) {
			t.Fatalf("refusal leaked credential material: %v", err)
		}
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "nested", "accounts.json")
	if err := exportAccounts([]account.Account{acc}, "codex", out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(raw), acc.RefreshToken) {
		t.Fatalf("export file: %q %v", raw, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(out)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("export mode %o", info.Mode().Perm())
		}
	}
	if err := exportAccounts([]account.Account{acc}, "cpa", dir); err == nil {
		t.Fatal("directory export accepted")
	}
}
