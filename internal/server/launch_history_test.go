package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxx-holic/wishtoken-desktop/internal/config"
)

func TestSaveLaunchReplacesSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GPTBRIDGE_HOME", home)
	if config.Home() != home {
		t.Fatalf("home %q", config.Home())
	}
	stolen := filepath.Join(home, "stolen.json")
	if err := os.WriteFile(stolen, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "launch-history.json")
	if err := os.Symlink(stolen, path); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(stolen, path+".tmp"); err != nil {
		t.Skip(err)
	}
	if err := saveLaunch(launchRecord{ID: "inst", AccountID: "acct_test", Directory: home}); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(stolen)
	if err != nil || string(kept) != "keep" || strings.Contains(string(kept), "acct_test") {
		t.Fatalf("launch history followed a symlink: %q %v", kept, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("launch history remained a symlink")
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), "acct_test") || strings.Contains(string(raw), "keep") {
		t.Fatalf("launch history: %q %v", raw, err)
	}
	tmp, err := os.Lstat(path + ".tmp")
	if err != nil || tmp.Mode()&os.ModeSymlink == 0 {
		t.Fatal("temporary symlink should not be reused")
	}
}
