package routerbox

import (
	"fmt"
	"sort"
)

// Public rules own their server selection; core selectors remain an implementation detail.
func resolveRouting(s Settings, nodes []Node) (Settings, error) {
	s.Rules = append([]Rule{}, s.Rules...)
	s.Groups = append([]Group{}, s.Groups...)
	enabled := map[string]bool{}
	for _, p := range s.Subscriptions {
		enabled[p.ID] = p.Enabled
	}
	available := map[string]bool{}
	all := []string{}
	for _, n := range nodes {
		if enabled[n.Subscription] {
			available[n.ID] = true
			all = append(all, n.ID)
		}
	}
	sort.Strings(all)
	add := func(id, name string, chosen []string, mode, selected string) (string, error) {
		if mode == "" {
			mode = "stable"
		}
		if len(chosen) == 0 {
			chosen = all
		}
		if len(chosen) == 0 {
			return "", fmt.Errorf("%s: нет серверов во включённых подписках", name)
		}
		for _, nid := range chosen {
			if !available[nid] {
				return "", fmt.Errorf("%s: выбранный сервер отсутствует или его подписка отключена", name)
			}
		}
		if len(chosen) > 64 {
			return "", fmt.Errorf("%s: найдено %d серверов; для MT7621 выберите до 64", name, len(chosen))
		}
		s.Groups = append(s.Groups, Group{ID: id, Name: name, Nodes: append([]string{}, chosen...), Mode: mode, Selected: selected, Interval: 300, Timeout: 5, Tolerance: 50, Hold: 300, Failures: 3, Recovery: 2, Window: 30, TestURL: "https://www.gstatic.com/generate_204", Failure: "block"})
		return id, nil
	}
	var err error
	if s.Final == "vpn" {
		s.Final, err = add("vpn-default", "Остальной трафик", s.FinalNodes, s.FinalMode, s.FinalSelected)
		if err != nil {
			return s, err
		}
	}
	for i := range s.Rules {
		r := &s.Rules[i]
		if r.Target == "vpn" {
			if !r.Enabled {
				r.Target = "direct"
				continue
			}
			rid := r.ID
			if rid == "" {
				rid = fmt.Sprintf("legacy-%d", i)
			}
			if !validID.MatchString(rid) || len(rid) > 56 {
				return s, fmt.Errorf("некорректный ID правила")
			}
			r.Target, err = add("route-"+rid, r.Name, r.Nodes, r.Mode, r.Selected)
			if err != nil {
				return s, err
			}
		}
	}
	needDNSVPN := false
	for _, d := range s.DNS {
		if d.Detour == "vpn" {
			needDNSVPN = true
		}
	}
	if needDNSVPN {
		exists := false
		for _, g := range s.Groups {
			if g.ID == "vpn-default" {
				exists = true
			}
		}
		if !exists {
			if _, err = add("vpn-default", "DNS через VPN", s.FinalNodes, s.FinalMode, s.FinalSelected); err != nil {
				return s, err
			}
		}
		s.DNS = append([]Resolver{}, s.DNS...)
		for i := range s.DNS {
			if s.DNS[i].Detour == "vpn" {
				s.DNS[i].Detour = "vpn-default"
			}
		}
	}
	return s, nil
}

func migrateRouting(s *Settings) {
	groups := map[string]Group{}
	for _, g := range s.Groups {
		groups[g.ID] = g
	}
	if g, ok := groups[s.Final]; ok {
		s.Final = "vpn"
		s.FinalNodes = g.Nodes
		s.FinalMode = g.Mode
		s.FinalSelected = g.Selected
	}
	for i := range s.Rules {
		r := &s.Rules[i]
		if r.ID == "" {
			r.ID = hashID([]byte(fmt.Sprintf("%d/%s", i, r.Name)))
		}
		if g, ok := groups[r.Target]; ok {
			r.Target = "vpn"
			r.Nodes = g.Nodes
			r.Mode = g.Mode
			r.Selected = g.Selected
		}
	}
	// Keep old DNS detours until the user changes them; all route selection moves into rules.
	keep := []Group{}
	for _, g := range s.Groups {
		for _, d := range s.DNS {
			if d.Detour == g.ID {
				keep = append(keep, g)
				break
			}
		}
	}
	s.Groups = keep
}

func (m *Manager) runtimeGroups() []Group {
	s, err := resolveRouting(m.Settings, m.Nodes)
	if err != nil {
		return nil
	}
	return s.Groups
}
