package localcodex

import "strings"

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

// The private, one-use launcher carries only the local bridge key. Credentials
// never appear in open(1)'s arguments or Terminal's AppleScript history.
func macTerminalScript(o Options, bin, path string) string {
	key := o.APIKey
	if key == "" {
		key = "gptbridge-local"
	}
	command := shellQuote(bin) + " \"${codex_args[@]}\""
	if o.Resume {
		command += " resume --last"
	}
	return "#!/bin/zsh\n" +
		"/bin/rm -f -- \"$0\"\n" +
		"export CODEX_HOME=" + shellQuote(o.Home) + "\n" +
		"export GPTBRIDGE_CODEX_KEY=" + shellQuote(key) + "\n" +
		"export PATH=" + shellQuote(path) + "\n" +
		"cd -- " + shellQuote(o.Directory) + " || exit 1\n" +
		"codex_args=()\ncase \"$(" + shellQuote(bin) + " --help 2>/dev/null)\" in *--no-daemon*) codex_args+=(--no-daemon);; esac\n" +
		command + "\n" +
		"result=$?\nunset GPTBRIDGE_CODEX_KEY\nprintf '\\nCodex exited (%s). Press Enter to close.\\n' \"$result\"\nread -r reply\nexit \"$result\"\n"
}
