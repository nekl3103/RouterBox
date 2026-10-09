package routerbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func prebuiltCategory(category string) bool { return category == "openai" || category == "instagram" }
func (m *Manager) cachedRule(category string) string {
	var cfg Object
	if loadJSON(filepath.Join(m.Root, "last-good.json"), &cfg) != nil {
		return ""
	}
	route, _ := cfg["route"].(map[string]any)
	sets, _ := route["rule_set"].([]any)
	for _, value := range sets {
		set, _ := value.(map[string]any)
		if str(set, "tag") != categoryTag(category) {
			continue
		}
		path := str(set, "path")
		if strings.HasPrefix(filepath.Clean(path), filepath.Join(m.Root, "rules")+string(os.PathSeparator)) {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}
	return ""
}
func (m *Manager) prebuiltRule(category string) (string, error) {
	data, err := m.fetch("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/"+category+".srs", 2<<20)
	if err != nil {
		if cached := m.cachedRule(category); cached != "" {
			m.event("Список «" + category + "» недоступен; используется последняя рабочая копия")
			return cached, nil
		}
		return "", err
	}
	dir := filepath.Join(m.Root, "rules", hashID(data))
	path := filepath.Join(dir, categoryTag(category)+".srs")
	if _, err = os.Stat(path); err == nil {
		return path, nil
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	if err = atomicWrite(path, data, 0600); err != nil {
		return "", err
	}
	decoded := filepath.Join(m.Run, "verify-rule.json")
	defer os.Remove(decoded)
	if err = m.command(30, m.corePath(), "rule-set", "decompile", path, "-o", decoded); err != nil {
		os.Remove(path)
		return "", errors.New("ядро отклонило готовый список «" + category + "»")
	}
	return path, nil
}
