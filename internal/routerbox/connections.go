package routerbox

import "strings"

func (m *Manager) connectionRows(state Object) []Object {
	rows := []Object{}
	connections, _ := state["connections"].([]any)
	labels := map[string]string{"direct": "Напрямую", "unavailable": "Нет сервера"}
	for _, n := range m.Nodes {
		labels["n-"+n.ID] = n.Name
	}
	rules := map[string]string{}
	for _, g := range m.runtimeGroups() {
		rules[groupTag(g.ID)] = g.Name
	}
	for _, value := range connections {
		c, ok := value.(map[string]any)
		if !ok {
			continue
		}
		meta, _ := c["metadata"].(map[string]any)
		if str(meta, "inboundName") == "subscription-in" || strings.HasSuffix(str(meta, "type"), "/subscription-in") {
			continue
		}
		host := str(meta, "host")
		if host == "" {
			host = str(meta, "destinationIP")
		}
		if host == "" {
			continue
		}
		rule, server := "", ""
		chains, _ := c["chains"].([]any)
		for _, chain := range chains {
			tag, _ := chain.(string)
			if name := rules[tag]; name != "" {
				rule = name
			}
			if name := labels[tag]; name != "" {
				server = name
			}
		}
		if rule == "" {
			rule = "Остальной трафик"
		}
		rows = append(rows, Object{"host": host, "source": str(meta, "sourceIP"), "network": str(meta, "network"), "rule": rule, "server": server, "download": c["download"], "upload": c["upload"]})
		if len(rows) >= 32 {
			break
		}
	}
	return rows
}
