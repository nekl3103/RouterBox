package routerbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Structured settings are kept as a single UCI option to avoid hundreds of
// subprocesses on MT7621. Node credentials and runtime data remain separate.
func uciQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func (m *Manager) loadUCI() {
	if m.Root != "/etc/routerbox" || m.CoreOverride != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "uci", "-q", "get", "routerbox.main.settings_json").Output()
	if e != nil {
		return
	}
	var s Settings
	if json.Unmarshal(b, &s) == nil && validate(s) == nil {
		m.Settings = s
		_ = writeJSON(filepath.Join(m.Root, "settings.json"), s)
	}
}
func (m *Manager) persistSettings(s Settings) error {
	path := filepath.Join(m.Root, "settings.json")
	old, _ := os.ReadFile(path)
	if e := writeJSON(path, s); e != nil {
		return e
	}
	if m.Root != "/etc/routerbox" || m.CoreOverride != "" {
		return nil
	}
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	current, _ := exec.Command("uci", "-q", "get", "routerbox.main.settings_json").Output()
	if strings.TrimSpace(string(current)) == string(b) {
		return nil
	}
	ctx, cancel := context.WithTimeout(m.commandContext(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "uci", "batch")
	cmd.Stdin = strings.NewReader("set routerbox.main=routerbox\nset routerbox.main.settings_json=" + uciQuote(string(b)) + "\ncommit routerbox\n")
	if e = cmd.Run(); e != nil {
		_ = exec.Command("uci", "revert", "routerbox").Run()
		if len(old) > 0 {
			_ = atomicWrite(path, old, 0600)
		}
		return errors.New("не удалось сохранить настройки UCI")
	}
	return os.Chmod("/etc/config/routerbox", 0600)
}
