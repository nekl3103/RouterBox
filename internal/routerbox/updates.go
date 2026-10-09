package routerbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var releaseVersionPattern = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)

func versionNumbers(v string) ([3]int, error) {
	var out [3]int
	parts := releaseVersionPattern.FindStringSubmatch(v)
	if parts == nil {
		return out, errors.New("неизвестный формат версии выпуска")
	}
	for i := range out {
		n, e := strconv.Atoi(parts[i+1])
		if e != nil {
			return out, errors.New("некорректная версия выпуска")
		}
		out[i] = n
	}
	return out, nil
}
func newerVersion(latest, current string) (bool, error) {
	a, e := versionNumbers(latest)
	if e != nil {
		return false, e
	}
	b, e := versionNumbers(current)
	if e != nil {
		return false, e
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i], nil
		}
	}
	return false, nil
}
func releaseInfo(data []byte, current string) (Object, error) {
	var r struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if json.Unmarshal(data, &r) != nil {
		return nil, errors.New("не удалось прочитать информацию о выпуске")
	}
	if r.Draft || r.Prerelease {
		return nil, errors.New("стабильный выпуск не найден")
	}
	available, e := newerVersion(r.Tag, current)
	if e != nil {
		return nil, e
	}
	version := strings.TrimPrefix(r.Tag, "v")
	archive := fmt.Sprintf("routerbox-mt7621-%s.tar.gz", version)
	ready := false
	for _, a := range r.Assets {
		if a.Name == archive {
			ready = true
		}
	}
	if !ready {
		return nil, errors.New("в выпуске отсутствует сборка для MT7621")
	}
	return Object{"latest": version, "available": available, "url": "https://github.com/nekl3103/RouterBox/releases/tag/" + r.Tag, "download": "https://github.com/nekl3103/RouterBox/releases/download/" + r.Tag + "/" + archive}, nil
}
func (m *Manager) checkUpdate() error {
	if m.updateInfo == nil {
		m.updateInfo = Object{}
	}
	m.updateInfo["checked"] = time.Now().Unix()
	data, err := m.fetch("https://api.github.com/repos/nekl3103/RouterBox/releases/latest", 1<<20)
	if err == nil {
		var info Object
		info, err = releaseInfo(data, Version)
		if err == nil {
			info["checked"] = time.Now().Unix()
			m.updateInfo = info
			m.event("Проверка обновлений: последняя версия " + str(info, "latest"))
			return nil
		}
	}
	m.updateInfo["error"] = "не удалось проверить обновление: " + err.Error()
	return errors.New(str(m.updateInfo, "error"))
}
