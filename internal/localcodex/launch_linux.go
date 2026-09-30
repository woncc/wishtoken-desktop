package localcodex

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	terminals := []struct {
		name string
		args []string
	}{
		{"x-terminal-emulator", []string{"-e"}},
		{"gnome-terminal", []string{"--"}},
		{"konsole", []string{"-e"}},
		{"xfce4-terminal", []string{"-x"}},
		{"mate-terminal", []string{"-x"}},
		{"kitty", nil},
		{"alacritty", []string{"-e"}},
		{"xterm", []string{"-e"}},
	}
	terminal := ""
	var args []string
	for _, candidate := range terminals {
		if p, e := exec.LookPath(candidate.name); e == nil {
			terminal = p
			args = candidate.args
			break
		}
	}
	if terminal == "" {
		return 0, fmt.Errorf("未找到 Linux 图形终端，请安装 gnome-terminal、konsole 或 xterm 后重试")
	}
	file, err := os.CreateTemp(o.Home, "launch-*.sh")
	if err != nil {
		return 0, err
	}
	name := file.Name()
	// Bash supports the same quoted argument array as our macOS launcher.
	script := strings.Replace(macTerminalScript(o, bin, filepath.Dir(bin)+":"+os.Getenv("PATH")), "#!/bin/zsh", "#!/bin/bash", 1)
	_, err = file.WriteString(script)
	if err == nil {
		err = file.Chmod(0700)
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
		return 0, err
	}
	cmd := exec.Command(terminal, append(args, "/bin/bash", name)...)
	cmd.Env, cmd.Dir = Environment(o), o.Directory
	if err = cmd.Start(); err != nil {
		_ = os.Remove(name)
		return 0, fmt.Errorf("启动 Linux 终端失败: %w", err)
	}
	pid := cmd.Process.Pid
	go func() { _ = cmd.Wait() }()
	return pid, nil
}
