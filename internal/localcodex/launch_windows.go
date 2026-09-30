package localcodex

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
)

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func encodedCommand(script string) string {
	units := utf16.Encode([]rune(script))
	buf := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[2*i:], u)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// Launch opens an interactive terminal only after the user's launch action.
func Launch(o Options) (int, error) {
	bin, err := Binary()
	if err != nil {
		return 0, err
	}
	o, err = Prepare(o)
	if err != nil {
		return 0, err
	}
	script := windowsTerminalScript(o, bin)
	// Start-Process assigns fresh console handles. Direct Go CreateProcess with
	// nil standard streams inherits NUL handles even with CREATE_NEW_CONSOLE,
	// making interactive Codex exit with "stdin is not a terminal".
	outer := "$p = Start-Process -FilePath powershell.exe -ArgumentList @('-NoLogo','-NoProfile','-NoExit','-EncodedCommand'," + psQuote(encodedCommand(script)) + ") -WindowStyle Normal -PassThru; $p.Id"
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedCommand(outer))
	cmd.Env, cmd.Dir = Environment(o), o.Directory
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("启动 Codex 终端失败: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("未获取到 Codex 终端进程")
	}
	return pid, nil
}

func windowsTerminalScript(o Options, bin string) string {
	// New CLI versions default to a daemon that requires a complete local
	// package. Embedded mode also works for standalone/single-file installs.
	script := "Set-Location -LiteralPath " + psQuote(o.Directory) + "; $codexArgs = @(); $codexHelp = & " + psQuote(bin) + " --help 2>$null; if ($codexHelp -match '--no-daemon') { $codexArgs += '--no-daemon' }; "
	if o.Resume {
		script += "$codexArgs += @('resume','--last'); "
	}
	return script + "& " + psQuote(bin) + " @codexArgs"
}
