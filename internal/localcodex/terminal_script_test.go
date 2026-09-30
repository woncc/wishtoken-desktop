package localcodex

import (
	"strings"
	"testing"
)

func TestMacTerminalQuoting(t *testing.T) {
	o := Options{Home: "/Users/test/a'b", Directory: "/tmp/项目 $(touch forbidden)", APIKey: "local-key", Resume: true}
	script := macTerminalScript(o, "/tmp/codex space/bin/codex", "/opt/homebrew/bin:/usr/bin")
	for _, want := range []string{"CODEX_HOME='/Users/test/a'\\''b'", "cd -- '/tmp/项目 $(touch forbidden)'", "'/tmp/codex space/bin/codex' \"${codex_args[@]}\" resume --last", "codex_args+=(--no-daemon)", "/bin/rm -f -- \"$0\"", "unset GPTBRIDGE_CODEX_KEY"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing safely quoted fragment %q", want)
		}
	}
}
