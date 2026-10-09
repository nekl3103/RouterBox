package routerbox

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

var serviceFiles = map[string]string{"allow-youtube": "youtube", "allow-telegram": "telegram", "allow-meta": "meta", "allow-discord": "discord", "allow-tiktok": "tiktok", "allow-twitter": "twitter", "allow-google-ai": "google_ai", "allow-google-meet": "google_meet", "allow-hdrezka": "hdrezka", "allow-roblox": "roblox"}
var domainName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$`)

func parseServiceList(data []byte, ips bool) ([]string, error) {
	values := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if ips {
			if _, err := netip.ParsePrefix(line); err != nil {
				return nil, fmt.Errorf("некорректная подсеть в списке сервиса")
			}
		} else {
			if !domainName.MatchString(line) {
				return nil, fmt.Errorf("некорректный домен в списке сервиса")
			}
		}
		if !seen[line] {
			seen[line] = true
			values = append(values, line)
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("список сервиса пуст")
	}
	return values, nil
}

func (m *Manager) resolveService(category string) (Object, error) {
	file, ok := serviceFiles[category]
	if !ok {
		return nil, fmt.Errorf("неизвестный сервис")
	}
	b, err := m.fetch("https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/"+file+".lst", 2<<20)
	if err != nil {
		return nil, err
	}
	domains, err := parseServiceList(b, false)
	if err != nil {
		return nil, err
	}
	o := Object{"domain_suffix": domains}
	if file == "telegram" {
		b, err = m.fetch("https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/telegram", 1<<20)
		if err != nil {
			return nil, err
		}
		extra, err := parseServiceList(b, false)
		if err != nil {
			return nil, err
		}
		domains = mergeDomains(domains, extra)
		b, err = m.fetch("https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/telegram.lst", 1<<20)
		if err != nil {
			return nil, err
		}
		ips, err := parseServiceList(b, true)
		if err != nil {
			return nil, err
		}
		b, err = m.fetch("https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv6/telegram.lst", 1<<20)
		if err != nil {
			return nil, err
		}
		ipv6, err := parseServiceList(b, true)
		if err != nil {
			return nil, err
		}
		o = Object{"type": "logical", "mode": "or", "rules": []Object{{"domain_suffix": domains}, {"ip_cidr": append(ips, ipv6...)}}}
	}
	return o, nil
}

func mergeDomains(lists ...[]string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, list := range lists {
		for _, domain := range list {
			if !seen[domain] {
				seen[domain] = true
				result = append(result, domain)
			}
		}
	}
	return result
}
