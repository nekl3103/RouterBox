package routerbox

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var dnsmasqUpstreams = []string{"127.0.0.1#5354", "/lan/", "/local/", "/home.arpa/", "//"}

type DNSBackup struct {
	Sections map[string]Object `json:"sections"`
}

func (m *Manager) configureDNS(enable bool) error {
	if m.CoreOverride != "" {
		return nil
	}
	backupPath := filepath.Join(m.Root, "dns-backup.json")
	backup := DNSBackup{Sections: map[string]Object{}}
	err := loadJSON(backupPath, &backup)
	if enable && err == nil {
		configured := true
		for section := range backup.Sections {
			server, e := exec.Command("uci", "-q", "get", "dhcp."+section+".server").Output()
			if e != nil || strings.Join(strings.Fields(string(server)), " ") != strings.Join(dnsmasqUpstreams, " ") {
				configured = false
			}
			noresolv, e := exec.Command("uci", "-q", "get", "dhcp."+section+".noresolv").Output()
			if e != nil || strings.TrimSpace(string(noresolv)) != "1" {
				configured = false
			}
		}
		if configured {
			return nil
		}
	}
	if enable && os.IsNotExist(err) {
		b, e := exec.Command("ubus", "call", "uci", "get", `{"config":"dhcp"}`).Output()
		if e != nil {
			return errors.New("не удалось прочитать dnsmasq")
		}
		var doc struct {
			Values map[string]Object `json:"values"`
		}
		if e = json.Unmarshal(b, &doc); e != nil {
			return e
		}
		for name, v := range doc.Values {
			if str(v, ".type") == "dnsmasq" {
				saved := Object{}
				for _, k := range []string{"server", "noresolv"} {
					if value, ok := v[k]; ok {
						saved[k] = value
					}
				}
				backup.Sections[name] = saved
			}
		}
		if len(backup.Sections) == 0 {
			return errors.New("dnsmasq не найден")
		}
		if e = writeJSON(backupPath, backup); e != nil {
			return e
		}
	} else if err != nil {
		if !enable && os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for section, options := range backup.Sections {
		if !validID.MatchString(section) {
			return errors.New("некорректная секция dnsmasq")
		}
		prefix := "dhcp." + section + "."
		for _, k := range []string{"server", "noresolv"} {
			_ = m.command(5, "uci", "-q", "delete", prefix+k)
		}
		if enable {
			if e := m.command(5, "uci", "set", prefix+"noresolv=1"); e != nil {
				return e
			}
			for _, address := range dnsmasqUpstreams {
				if e := m.command(5, "uci", "add_list", prefix+"server="+address); e != nil {
					return e
				}
			}
		} else {
			for key, value := range options {
				switch v := value.(type) {
				case string:
					if e := m.command(5, "uci", "set", prefix+key+"="+v); e != nil {
						return e
					}
				case []any:
					for _, x := range v {
						s, ok := x.(string)
						if !ok || strings.ContainsAny(s, "\r\n") {
							return errors.New("некорректный DNS backup")
						}
						if e := m.command(5, "uci", "add_list", prefix+key+"="+s); e != nil {
							return e
						}
					}
				}
			}
		}
	}
	if e := m.command(5, "uci", "commit", "dhcp"); e != nil {
		return e
	}
	if e := m.command(20, "/etc/init.d/dnsmasq", "restart"); e != nil {
		return e
	}
	if !enable {
		os.Remove(backupPath)
	}
	return nil
}
