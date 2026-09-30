package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/config"
	"github.com/xxx-holic/wishtoken-desktop/internal/version"
)

type serviceStatus struct {
	App          string `json:"app"`
	Version      string `json:"version"`
	CockpitOAuth bool   `json:"cockpit_oauth"`
}

func desktopStatus(base string) serviceStatus {
	c := &http.Client{Timeout: time.Second}
	r, e := c.Get(base + "/healthz")
	if e != nil {
		return serviceStatus{}
	}
	defer r.Body.Close()
	var status serviceStatus
	_ = json.NewDecoder(r.Body).Decode(&status)
	return status
}

func desktopURL() (string, error) {
	cfg, err := config.Load(config.Path())
	if err != nil {
		return "", err
	}
	return "http://" + displayAddr(cfg.Listen), nil
}

func desktopReady(base string) bool {
	return desktopStatus(base).App == "gptbridge-team"
}

func runDesktop() error {
	base, err := desktopURL()
	if err != nil {
		return err
	}
	if err := ensureDesktopService(base, false); err != nil {
		return err
	}
	return browse(base)
}

func ensureDesktopService(base string, requireCockpit bool) error {
	if desktopReady(base) {
		status := desktopStatus(base)
		if status.Version == version.Version && (!requireCockpit || status.CockpitOAuth) {
			return nil
		}
		return fmt.Errorf("本地服务版本与接入器不匹配，请先运行 stop，再打开 GPTBridge Cockpit")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.Home(), 0700); err != nil {
		return err
	}
	logfile, err := os.OpenFile(filepath.Join(config.Home(), "service.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logfile.Close()
	cmd := exec.Command(exe, "serve")
	cmd.Stdout, cmd.Stderr = logfile, logfile
	backgroundProcess(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	for i := 0; i < 40; i++ {
		if desktopReady(base) {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("service did not start; check %s (port may be occupied)", filepath.Join(config.Home(), "service.log"))
}

func runStop() error {
	base, err := desktopURL()
	if err != nil {
		return err
	}
	if !desktopReady(base) {
		return fmt.Errorf("GPTBridge Team service is not running at %s", base)
	}
	c := &http.Client{Timeout: 5 * time.Second}
	r, err := c.Post(base+"/api/shutdown", "application/json", nil)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("shutdown returned HTTP %d", r.StatusCode)
	}
	fmt.Println("GPTBridge Team stopped")
	return nil
}
