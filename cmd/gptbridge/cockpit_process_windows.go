package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xxx-holic/wishtoken-desktop/internal/config"
)

type cockpitProcess struct {
	PID     int    `json:"pid"`
	KeyHash string `json:"key_hash"`
}

func cockpitKeyHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
func checkCockpitProcess(exe, key string) error {
	cmd := exec.Command("tasklist.exe", "/FI", "IMAGENAME eq "+filepath.Base(exe), "/FO", "CSV", "/NH")
	backgroundProcess(cmd)
	raw, e := cmd.Output()
	if e != nil {
		return fmt.Errorf("无法检查 Cockpit 运行状态：%w", e)
	}
	var previous cockpitProcess
	if b, e := os.ReadFile(filepath.Join(config.Home(), "cockpit-process.json")); e == nil {
		_ = json.Unmarshal(b, &previous)
	}
	reader := csv.NewReader(strings.NewReader(string(raw)))
	reader.FieldsPerRecord = -1
	rows, _ := reader.ReadAll()
	for _, row := range rows {
		if len(row) < 2 || !strings.EqualFold(row[0], filepath.Base(exe)) {
			continue
		}
		pid, _ := strconv.Atoi(row[1])
		if pid != previous.PID || previous.KeyHash != cockpitKeyHash(key) {
			return fmt.Errorf("Cockpit 已在运行。首次接入请从托盘完全退出 Cockpit，再双击此启动器，以加载仅 access token 子号的兼容环境。现有 Codex 会话无需关闭。")
		}
	}
	return nil
}
func rememberCockpitProcess(pid int, key string) {
	// A second launch can exit immediately due to Cockpit's single-instance
	// guard. Keep the existing marker when its process is still present.
	path := filepath.Join(config.Home(), "cockpit-process.json")
	var previous cockpitProcess
	if b, e := os.ReadFile(path); e == nil {
		_ = json.Unmarshal(b, &previous)
		if previous.KeyHash == cockpitKeyHash(key) {
			cmd := exec.Command("tasklist.exe", "/FI", fmt.Sprintf("PID eq %d", previous.PID), "/FO", "CSV", "/NH")
			backgroundProcess(cmd)
			if b, e := cmd.Output(); e == nil && strings.Contains(string(b), fmt.Sprintf("\"%d\"", previous.PID)) {
				return
			}
		}
	}
	b, _ := json.Marshal(cockpitProcess{PID: pid, KeyHash: cockpitKeyHash(key)})
	_ = os.WriteFile(path, b, 0600)
}
