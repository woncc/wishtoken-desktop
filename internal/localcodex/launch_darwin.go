package localcodex

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func Launch(o Options) (int, error) {
	bin, err := Binary()
	if err != nil {
		return 0, err
	}
	o, err = Prepare(o)
	if err != nil {
		return 0, err
	}
	f, err := os.CreateTemp(o.Home, "launch-*.command")
	if err != nil {
		return 0, err
	}
	name := f.Name()
	path := filepath.Dir(bin) + ":/opt/homebrew/bin:/usr/local/bin:" + os.Getenv("PATH")
	_, err = f.WriteString(macTerminalScript(o, bin, path))
	if err == nil {
		err = f.Chmod(0700)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
		return 0, err
	}
	// open asks Terminal to execute the private .command without needing
	// Apple Events permission. The script removes itself as its first action.
	if err := exec.Command("/usr/bin/open", "-a", "Terminal", name).Run(); err != nil {
		_ = os.Remove(name)
		return 0, fmt.Errorf("启动 macOS Terminal 失败: %w", err)
	}
	return 0, nil // open's short-lived process is not the Terminal PID.
}
