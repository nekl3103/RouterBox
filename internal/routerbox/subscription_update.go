package routerbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func validateSubscriptionOptions(p Subscription) error {
	if !validAgent(p.HWID) {
		return errors.New("HWID: не более 256 символов, без переводов строк")
	}
	if p.HWID != "" && !strings.HasPrefix(p.URL, "https://") {
		return errors.New("для передачи HWID нужен HTTPS URL подписки")
	}
	if !validAgent(p.UserAgent) {
		return errors.New("User-Agent: не более 256 символов, без переводов строк")
	}
	if p.DownloadVia != "" && p.DownloadVia != "direct" && p.DownloadVia != "vpn" {
		return errors.New("направление подписки: напрямую или VPN")
	}
	if p.FilterMode != "" && p.FilterMode != "disabled" && p.FilterMode != "whitelist" && p.FilterMode != "blacklist" {
		return errors.New("неизвестный фильтр подписки")
	}
	if len(p.FilterPatterns) > 32 {
		return errors.New("не более 32 фильтров подписки")
	}
	for _, pattern := range p.FilterPatterns {
		if len(pattern) > 256 {
			return errors.New("слишком длинный фильтр подписки")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.New("некорректное регулярное выражение фильтра подписки")
		}
	}
	return nil
}
func filterSubscription(nodes []Node, p Subscription) ([]Node, int) {
	patterns := []*regexp.Regexp{}
	for _, text := range p.FilterPatterns {
		r, err := regexp.Compile(text)
		if err == nil {
			patterns = append(patterns, r)
		}
	}
	seen := map[string]bool{}
	out := []Node{}
	duplicates := 0
	for _, n := range nodes {
		match := false
		for _, r := range patterns {
			if r.MatchString(n.Name) {
				match = true
				break
			}
		}
		if len(patterns) > 0 && ((p.FilterMode == "whitelist" && !match) || (p.FilterMode == "blacklist" && match)) {
			continue
		}
		if seen[n.ID] {
			duplicates++
			continue
		}
		seen[n.ID] = true
		out = append(out, n)
	}
	return out, duplicates
}
func selectedNodeIDs(s Settings) map[string]bool {
	out := map[string]bool{}
	add := func(ids []string, selected string) {
		for _, id := range ids {
			out[id] = true
		}
		if selected != "" {
			out[selected] = true
		}
	}
	add(s.FinalNodes, s.FinalSelected)
	for _, r := range s.Rules {
		add(r.Nodes, r.Selected)
		add(r.UDPNodes, r.UDPSelected)
	}
	for _, g := range s.Groups {
		add(g.Nodes, g.Selected)
	}
	return out
}
func subscriptionCandidate(old, valid []Node, s *Settings, p *Subscription) []Node {
	remapSubscriptionSelections(old, valid, s)
	referenced := selectedNodeIDs(*s)
	previous := map[string]Node{}
	incoming := map[string]bool{}
	others := []Node{}
	for _, n := range old {
		if n.Subscription == p.ID {
			previous[n.ID] = n
		} else {
			others = append(others, n)
		}
	}
	p.Added = 0
	p.Removed = 0
	p.Warning = ""
	for _, n := range valid {
		incoming[n.ID] = true
		if _, exists := previous[n.ID]; !exists {
			p.Added++
		}
	}
	retained := 0
	for _, n := range old {
		if n.Subscription != p.ID || incoming[n.ID] {
			continue
		}
		if referenced[n.ID] {
			valid = append(valid, n)
			retained++
		} else {
			p.Removed++
		}
	}
	if retained > 0 {
		p.Warning = fmt.Sprintf("В подписке отсутствуют %d выбранных серверов: прежние записи сохранены. Замените их в правилах.", retained)
	}
	return append(others, valid...)
}
func cloneSettings(s Settings) Settings {
	b, _ := json.Marshal(s)
	var out Settings
	_ = json.Unmarshal(b, &out)
	return out
}

func (m *Manager) refresh(id string) error {
	if err := m.ensureCore(); err != nil {
		return err
	}
	old := cloneSettings(m.Settings)
	oldNodes := append([]Node{}, m.Nodes...)
	candidate := cloneSettings(old)
	next := append([]Node{}, oldNodes...)
	changed := false
	failed := false
	for i := range candidate.Subscriptions {
		p := &candidate.Subscriptions[i]
		if (!p.Enabled && id != p.ID) || (id != "" && id != "__due__" && id != p.ID) {
			continue
		}
		if id == "__due__" && time.Now().Unix()-p.Updated < int64(p.Interval)*3600 {
			continue
		}
		p.Attempted = time.Now().Unix()
		b, headers, err := m.subscriptionDownload(*p)
		if err != nil {
			p.Error = err.Error()
			failed = true
			continue
		}
		nodes, bad, err := ParseSubscription(b, p.ID)
		if err != nil {
			p.Error = err.Error()
			failed = true
			continue
		}
		nodes, p.Duplicates = filterSubscription(nodes, *p)
		valid := []Node{}
		for _, n := range nodes {
			if err = m.checkNode(n); err != nil {
				bad = append(bad, Rejection{Name: n.Name, Reason: err.Error()})
			} else {
				valid = append(valid, n)
			}
		}
		p.Rejected = bad
		if len(valid) == 0 {
			p.Error = "нет серверов после проверки и фильтрации; предыдущий список сохранён"
			failed = true
			continue
		}
		beforeSelection := cloneSettings(candidate)
		proposed := subscriptionCandidate(next, valid, &candidate, p)
		if len(proposed) > 1024 {
			candidate.Rules = beforeSelection.Rules
			candidate.Groups = beforeSelection.Groups
			candidate.FinalNodes = beforeSelection.FinalNodes
			candidate.FinalSelected = beforeSelection.FinalSelected
			p.Error = "лимит: всего не более 1024 серверов"
			failed = true
			continue
		}
		next = proposed
		if p.Name == "" || p.Name == "Подписка" {
			p.Name = subscriptionTitle(headers, b, p.URL)
		}
		p.Updated = time.Now().Unix()
		p.Error = ""
		changed = true
	}
	if changed {
		stagedPath := filepath.Join(m.Root, "nodes.pending.json")
		defer os.Remove(stagedPath)
		if err := writeJSON(stagedPath, next); err != nil {
			return errors.New("не удалось подготовить список серверов; предыдущий список сохранён")
		}
		// Apply against a staged in-memory node set. Never replace the disk list before the core accepts it.
		m.Nodes = next
		err := m.apply(candidate)
		if err != nil {
			m.Nodes = oldNodes
			m.Settings = old
			for i := range old.Subscriptions {
				for _, p := range candidate.Subscriptions {
					if old.Subscriptions[i].ID == p.ID && p.Attempted > 0 {
						old.Subscriptions[i].Attempted = p.Attempted
						old.Subscriptions[i].Error = "новый список не применён; предыдущие серверы сохранены: " + err.Error()
					}
				}
			}
			m.Settings = old
			_ = m.persistSettings(old)
			return err
		}
		if err = os.Rename(stagedPath, filepath.Join(m.Root, "nodes.json")); err != nil {
			m.Nodes = oldNodes
			if rollback := m.apply(old); rollback != nil {
				return errors.New("не удалось сохранить серверы и восстановить ядро; прежний список на диске сохранён")
			}
			return errors.New("не удалось сохранить серверы; восстановлен предыдущий список")
		}
	} else {
		m.Settings = candidate
		if err := m.persistSettings(candidate); err != nil {
			m.Settings = old
			return err
		}
	}
	m.event("Обновление подписок завершено")
	if failed {
		return errors.New("часть подписок не обновилась; подробности во вкладке «Подписки»")
	}
	return nil
}

func nodeIdentity(n Node) string {
	// Never guess by label alone; endpoint and protocol must match uniquely.
	address := str(n.Config, "server")
	port := n.Config["server_port"]
	if n.Endpoint {
		data, _ := json.Marshal(n.Config["peers"])
		address = string(data)
	}
	if address == "" {
		return ""
	}
	return fmt.Sprint(n.Subscription, "/", str(n.Config, "type"), "/", address, "/", port, "/", n.Name)
}
func remapSubscriptionSelections(old, next []Node, s *Settings) {
	byIdentity := map[string]string{}
	present := map[string]bool{}
	for _, n := range next {
		present[n.ID] = true
		key := nodeIdentity(n)
		if key == "" {
			continue
		}
		if _, seen := byIdentity[key]; seen {
			byIdentity[key] = ""
		} else {
			byIdentity[key] = n.ID
		}
	}
	mapping := map[string]string{}
	for _, n := range old {
		if !present[n.ID] {
			if id := byIdentity[nodeIdentity(n)]; id != "" {
				mapping[n.ID] = id
			}
		}
	}
	mapIDs := func(ids *[]string) {
		out := []string{}
		seen := map[string]bool{}
		for _, id := range *ids {
			if next := mapping[id]; next != "" {
				id = next
			}
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
		*ids = out
	}
	mapSelected := func(id *string) {
		if next := mapping[*id]; next != "" {
			*id = next
		}
	}
	mapIDs(&s.FinalNodes)
	mapSelected(&s.FinalSelected)
	for i := range s.Rules {
		r := &s.Rules[i]
		mapIDs(&r.Nodes)
		mapSelected(&r.Selected)
		mapIDs(&r.UDPNodes)
		mapSelected(&r.UDPSelected)
	}
	for i := range s.Groups {
		g := &s.Groups[i]
		mapIDs(&g.Nodes)
		mapSelected(&g.Selected)
	}
}
