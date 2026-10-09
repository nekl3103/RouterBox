package routerbox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"unicode"
)

func nonNilObject(o Object) Object {
	if o == nil {
		return Object{}
	}
	return o
}
func subscriptionTitle(headers http.Header, data []byte, address string) string {
	title := strings.TrimSpace(headers.Get("Profile-Title"))
	if strings.HasPrefix(title, "base64:") {
		value := strings.TrimPrefix(title, "base64:")
		if b, err := base64.StdEncoding.DecodeString(value); err == nil {
			title = string(b)
		} else if b, err := base64.RawStdEncoding.DecodeString(value); err == nil {
			title = string(b)
		} else {
			title = ""
		}
	}
	if title == "" {
		_, params, _ := mime.ParseMediaType(headers.Get("Content-Disposition"))
		title = strings.TrimSuffix(params["filename"], filepath.Ext(params["filename"]))
	}
	if title == "" {
		var o Object
		if json.Unmarshal(data, &o) == nil {
			title = str(o, "name")
			if title == "" {
				title = str(o, "remarks")
			}
		}
	}
	title = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, title))
	if title == "" {
		if u, err := url.Parse(address); err == nil {
			title = u.Hostname()
		}
	}
	if title == "" {
		title = "Подписка"
	}
	r := []rune(title)
	if len(r) > 100 {
		title = string(r[:100])
	}
	return title
}

func (m *Manager) addSubscription(data json.RawMessage) error {
	var p Subscription
	if json.Unmarshal(data, &p) != nil {
		return fmt.Errorf("некорректная подписка")
	}
	if p.ID == "" {
		return fmt.Errorf("нужен ID подписки")
	}
	if p.Name == "" {
		p.Name = "Подписка"
	}
	s := m.Settings
	s.Subscriptions = append([]Subscription{}, s.Subscriptions...)
	for _, old := range s.Subscriptions {
		if old.ID == p.ID {
			return fmt.Errorf("подписка уже существует")
		}
	}
	s.Subscriptions = append(s.Subscriptions, p)
	if err := validate(s); err != nil {
		return err
	}
	if err := m.persistSettings(s); err != nil {
		return err
	}
	m.Settings = s
	if err := m.refresh(p.ID); err != nil {
		return err
	}
	for _, live := range m.Settings.Subscriptions {
		if live.ID == p.ID && live.Error != "" {
			return fmt.Errorf("%s", live.Error)
		}
	}
	return nil
}
