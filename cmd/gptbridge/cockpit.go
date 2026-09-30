package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xxx-holic/wishtoken-desktop/internal/cockpit"
	"github.com/xxx-holic/wishtoken-desktop/internal/config"
)

func runCockpit(args []string) error {
	fs := flag.NewFlagSet("cockpit", flag.ContinueOnError)
	exe := fs.String("exe", "", "Cockpit executable")
	data := fs.String("data-dir", "", "Cockpit data directory")
	installOnly := fs.Bool("install-only", false, "configure the independent OAuth instance without starting apps")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *exe == "" {
		for _, p := range []string{`D:\Cockpit Tools\cockpit-tools.exe`, filepath.Join(os.Getenv("LOCALAPPDATA"), "Cockpit Tools", "cockpit-tools.exe"), filepath.Join(os.Getenv("ProgramFiles"), "Cockpit Tools", "cockpit-tools.exe")} {
			if _, e := os.Stat(p); e == nil {
				*exe = p
				break
			}
		}
	}
	cfg, e := config.Load(config.Path())
	if e != nil {
		return e
	}
	base := "http://" + displayAddr(cfg.Listen)
	ins, e := cockpit.Install(config.Home(), *data, *exe, base, cfg)
	if e != nil {
		return e
	}
	fmt.Printf("Cockpit OAuth instance ready: %s\n", ins.Profile)
	if *installOnly {
		return nil
	}
	if e = ensureDesktopService(base, true); e != nil {
		return e
	}
	if e = checkCockpitProcess(ins.CockpitExe, cfg.CockpitKey); e != nil {
		return e
	}
	cmd := exec.Command(ins.CockpitExe)
	cmd.Env = os.Environ()
	for i := len(cmd.Env) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.ToUpper(cmd.Env[i]), "CODEX_AUTHAPI_BASE_URL=") {
			cmd.Env = append(cmd.Env[:i], cmd.Env[i+1:]...)
		}
	}
	cmd.Env = append(cmd.Env, "CODEX_AUTHAPI_BASE_URL="+base+"/cockpit-auth/"+cfg.CockpitKey)
	if e = cmd.Start(); e != nil {
		return e
	}
	rememberCockpitProcess(cmd.Process.Pid, cfg.CockpitKey)
	return cmd.Process.Release()
}
