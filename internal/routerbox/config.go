package routerbox

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

func Generate(s Settings, nodes []Node, paths map[string]string, run, secret string, probe bool) (Object, error) {
	var err error
	s, err = resolveRouting(s, nodes)
	if err != nil {
		return nil, err
	}
	if e := validate(s); e != nil {
		return nil, e
	}
	available := map[string]Node{}
	enabled := map[string]bool{}
	for _, p := range s.Subscriptions {
		enabled[p.ID] = p.Enabled
	}
	for _, n := range nodes {
		if enabled[n.Subscription] {
			available[n.ID] = n
		}
	}
	used := map[string]bool{}
	for _, g := range s.Groups {
		for _, id := range g.Nodes {
			if _, ok := available[id]; !ok {
				return nil, fmt.Errorf("выбранный сервер %s исчез или подписка отключена", id)
			}
			used[id] = true
		}
	}
	ipTunnels := 0
	for id := range used {
		typ := str(available[id].Config, "type")
		if typ == "wireguard" || typ == "masque" {
			ipTunnels++
		}
	}
	if ipTunnels > 2 {
		return nil, errors.New("профиль MT7621 допускает не более двух активных WireGuard/AmneziaWG/MASQUE туннелей")
	}
	outbounds := []Object{{"type": "direct", "tag": "direct"}, {"type": "socks", "tag": "unavailable", "server": "127.0.0.1", "server_port": 1, "version": "5"}}
	endpoints := []Object{}
	sortedNodes := append([]Node{}, nodes...)
	sort.Slice(sortedNodes, func(i, j int) bool { return sortedNodes[i].ID < sortedNodes[j].ID })
	for _, n := range sortedNodes {
		if !used[n.ID] {
			continue
		}
		o := copyObject(n.Config)
		o["tag"] = "n-" + n.ID
		if n.Endpoint {
			endpoints = append(endpoints, o)
		} else {
			o["domain_resolver"] = "bootstrap"
			outbounds = append(outbounds, o)
		}
	}
	for _, g := range s.Groups {
		tags := []string{"unavailable"}
		for _, id := range g.Nodes {
			tags = append(tags, "n-"+id)
		}
		if g.Failure == "direct" {
			tags = append(tags, "direct")
		}
		o := Object{"tag": groupTag(g.ID), "outbounds": tags, "type": "selector", "default": tags[0], "interrupt_exist_connections": false}
		if g.Mode == "manual" {
			o["default"] = "n-" + g.Selected
		}
		if g.Mode == "round_robin" {
			tags = tags[1:]
			if g.Failure == "direct" {
				tags = tags[:len(tags)-1]
			}
			pool := Object{"tag": "pool-" + g.ID, "outbounds": tags, "type": "urltest", "url": g.TestURL, "interval": fmt.Sprintf("%ds", g.Interval), "mode": "round_robin", "balancer": Object{"pool": len(tags), "sticky_hash": []string{"source_ip", "domain"}}}
			outbounds = append(outbounds, pool)
			choices := []string{"unavailable", "pool-" + g.ID}
			if g.Failure == "direct" {
				choices = append(choices, "direct")
			}
			o = Object{"type": "selector", "tag": groupTag(g.ID), "outbounds": choices, "default": "unavailable"}
		}
		outbounds = append(outbounds, o)
	}
	dnsServers := []Object{{"type": "udp", "tag": "bootstrap", "server": s.Bootstrap}, {"type": "udp", "tag": "lan-dns", "server": "127.0.0.1", "server_port": 53}}
	dnsTags := []string{}
	for _, d := range s.DNS {
		o, e := dnsObject(d)
		if e != nil {
			return nil, e
		}
		dnsServers = append(dnsServers, o)
		dnsTags = append(dnsTags, d.ID)
	}
	dnsServers = append(dnsServers, Object{"type": "group", "tag": "dns-default", "servers": dnsTags, "mode": s.DNSMode, "error_ttl": fmt.Sprintf("%ds", defaultSeconds(s.DNSErrorTTL, 120)), "win_ttl": fmt.Sprintf("%ds", defaultSeconds(s.DNSWinTTL, 300))})
	dnsRules := []Object{{"domain_suffix": []string{"lan", "local", "home.arpa"}, "domain_regex": []string{"^[^.]+$"}, "action": "route", "server": "lan-dns"}, {"domain": []string{"localhost"}, "action": "route", "server": "lan-dns"}}
	routeRules := []Object{{"inbound": []string{"dns-in"}, "action": "hijack-dns"}, {"action": "sniff", "timeout": "300ms"}, {"protocol": "dns", "action": "hijack-dns"}, {"ip_is_private": true, "action": "route", "outbound": "direct"}}
	sets := []Object{}
	for _, c := range selectedCategories(s) {
		path, ok := paths[c]
		if !ok {
			return nil, errors.New("список доменов ещё не загружен")
		}
		sets = append(sets, Object{"type": "local", "tag": categoryTag(c), "format": "binary", "path": path})
	}
	for _, r := range s.Rules {
		if !r.Enabled {
			continue
		}
		match := Object{}
		if r.Network != "" {
			match["network"] = r.Network
		}
		if len(r.Categories) > 0 {
			tags := []string{}
			for _, c := range r.Categories {
				tags = append(tags, categoryTag(c))
			}
			match["rule_set"] = tags
		}
		if len(r.Domains) > 0 {
			exact, suffix := []string{}, []string{}
			for _, d := range r.Domains {
				if strings.HasPrefix(d, "*.") {
					suffix = append(suffix, d[2:])
				} else {
					exact = append(exact, d)
				}
			}
			if len(exact) > 0 {
				match["domain"] = exact
			}
			if len(suffix) > 0 {
				match["domain_suffix"] = suffix
			}
		}
		if len(r.IPs) > 0 {
			match["ip_cidr"] = r.IPs
		}
		if len(r.Sources) > 0 {
			match["source_ip_cidr"] = r.Sources
		}
		if len(r.MACs) > 0 {
			match["source_mac_address"] = r.MACs
		}
		// Keep domain/IP alternatives separate from source restrictions. Rule-set is otherwise ANDed.
		alternatives := []Object{}
		for _, k := range []string{"rule_set", "domain", "domain_suffix", "ip_cidr"} {
			if v, ok := match[k]; ok {
				alternatives = append(alternatives, Object{k: v})
				delete(match, k)
			}
		}
		if len(alternatives) > 0 {
			dst := Object{"type": "logical", "mode": "or", "rules": alternatives}
			if len(match) > 0 {
				match = Object{"type": "logical", "mode": "and", "rules": []Object{match, dst}}
			} else {
				match = dst
			}
		}
		rule := copyObject(match)
		if r.Target == "block" {
			rule["action"] = "reject"
		} else {
			rule["action"] = "route"
			rule["outbound"] = groupTag(r.Target)
		}
		routeRules = append(routeRules, rule)
		if r.DNS != "" || r.Target == "block" {
			dm := Object{}
			if len(r.Categories) > 0 {
				tags := []string{}
				for _, c := range r.Categories {
					tags = append(tags, categoryTag(c))
				}
				dm["rule_set"] = tags
			}
			if len(r.Domains) > 0 {
				exact, suffix := []string{}, []string{}
				for _, d := range r.Domains {
					if strings.HasPrefix(d, "*.") {
						suffix = append(suffix, d[2:])
					} else {
						exact = append(exact, d)
					}
				}
				if len(exact) > 0 {
					dm["domain"] = exact
				}
				if len(suffix) > 0 {
					dm["domain_suffix"] = suffix
				}
			}
			if len(dm) > 1 {
				alternatives := []Object{}
				for _, key := range []string{"rule_set", "domain", "domain_suffix"} {
					if value, ok := dm[key]; ok {
						alternatives = append(alternatives, Object{key: value})
					}
				}
				dm = Object{"type": "logical", "mode": "or", "rules": alternatives}
			}
			if len(dm) > 0 && len(r.Sources) == 0 && len(r.MACs) == 0 {
				if r.Target == "block" {
					dm["action"] = "reject"
				} else {
					dm["action"] = "route"
					dm["server"] = r.DNS
				}
				dnsRules = append(dnsRules, dm)
			}
		}
	}
	final := groupTag(s.Final)
	if s.Final == "block" {
		routeRules = append(routeRules, Object{"action": "reject"})
		final = "direct"
	}
	tun := Object{"type": "tun", "tag": "tun-in", "interface_name": "rb-tun", "address": []string{"172.31.255.1/30"}, "mtu": s.MTU, "stack": "system", "auto_route": true, "auto_redirect": true, "strict_route": true, "include_interface": s.Interfaces, "route_exclude_address": []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"}, "iproute2_table_index": 2026, "iproute2_rule_index": 12000, "auto_redirect_input_mark": "0x2026", "auto_redirect_output_mark": "0x2027", "auto_redirect_reset_mark": "0x2028", "auto_redirect_nfqueue": 106}
	if s.IPv6 {
		tun["address"] = []string{"172.31.255.1/30", "fdfe:2026::1/126"}
		tun["route_exclude_address"] = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "fc00::/7", "fe80::/10", "ff00::/8"}
	}
	inbounds := []Object{{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 5354}}
	if len(s.Groups) > 0 {
		downloadGroups := []string{}
		for _, g := range s.Groups {
			if !strings.HasSuffix(g.ID, "-udp") {
				downloadGroups = append(downloadGroups, groupTag(g.ID))
			}
		}
		if len(downloadGroups) == 0 {
			downloadGroups = append(downloadGroups, groupTag(s.Groups[0].ID))
		}
		outbounds = append(outbounds, Object{"type": "selector", "tag": "subscription-out", "outbounds": downloadGroups, "default": downloadGroups[0]})
		inbounds = append(inbounds, Object{"type": "mixed", "tag": "subscription-in", "listen": "127.0.0.1", "listen_port": 9098, "users": []Object{{"username": "routerbox", "password": secret}}})
		routeRules = append([]Object{{"inbound": []string{"subscription-in"}, "action": "route", "outbound": "subscription-out"}}, routeRules...)
	}
	if !probe {
		inbounds = append(inbounds, tun)
	}
	config := Object{"log": Object{"disabled": true}, "dns": Object{"servers": dnsServers, "rules": dnsRules, "final": "dns-default", "strategy": s.DNSStrategy, "disable_cache": !s.DNSCache, "cache_capacity": 1024, "timeout": fmt.Sprintf("%ds", dnsTimeout(s)), "reverse_mapping": true}, "inbounds": inbounds, "outbounds": outbounds, "route": Object{"auto_detect_interface": true, "default_domain_resolver": "bootstrap", "rules": routeRules, "rule_set": sets, "final": final}, "experimental": Object{"clash_api": Object{"external_controller": "127.0.0.1:9097", "secret": secret}}}
	if probe {
		config["route"].(Object)["auto_detect_interface"] = false
	}
	if len(endpoints) > 0 {
		config["endpoints"] = endpoints
	}
	return config, nil
}
