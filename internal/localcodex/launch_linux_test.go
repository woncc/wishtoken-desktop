package localcodex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxTerminalLaunchPreservesArgumentsAndResume(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "codex fixture")
	receipt := filepath.Join(root, "receipt")
	program := "#!/bin/sh\nif [ \"$1\" = '--help' ]; then printf '%s\\n' '--no-daemon'; exit; fi\nprintf '%s\\n' \"$CODEX_HOME\" \"$GPTBRIDGE_CODEX_KEY\" \"$@\" > " + shellQuote(receipt) + "\n"
	if err := os.WriteFile(bin, []byte(program), 0700); err != nil {
		t.Fatal(err)
	}
	terminal := filepath.Join(root, "x-terminal-emulator")
	if err := os.WriteFile(terminal, []byte("#!/bin/sh\n[ \"$1\" = '-e' ] || exit 1\nshift\nexec \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	t.Setenv("GPTBRIDGE_CODEX_BIN", bin)
	o := Options{Home: filepath.Join(root, "profile space"), Directory: root, BaseURL: "http://127.0.0.1:8792", APIKey: "fixture-local", AccountID: "acc-fixture", Model: "gpt-6-astra", Effort: "high", Resume: true}
	pid, err := Launch(o)
	if err != nil || pid <= 0 {
		t.Fatalf("launch failed: %d %v", pid, err)
	}
	var raw []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ = os.ReadFile(receipt)
		if strings.Contains(string(raw), "--last\n") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	expected := o.Home + "\nfixture-local\n--no-daemon\nresume\n--last\n"
	if string(raw) != expected {
		t.Fatalf("argument/environment mismatch: %q", raw)
	}
	scripts, _ := filepath.Glob(filepath.Join(o.Home, "launch-*.sh"))
	if len(scripts) != 0 {
		t.Fatal("one-use launcher was not removed")
	}
}
