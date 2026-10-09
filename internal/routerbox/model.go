package routerbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Object = map[string]any

const Version = "0.3.2"
const CoreVersion = "1.14.2-lx.12-router.1"
const MaxDownload = 8 << 20

var validID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var validCategory = regexp.MustCompile(`^[a-z0-9][a-z0-9_!.-]*(?:@[a-z0-9_!.-]+)?$`)
var validInterface = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

type Subscription struct {
	HWID           string      `json:"hwid,omitempty"`
	HasHWID        bool        `json:"has_hwid,omitempty"`
	ClearHWID      bool        `json:"clear_hwid,omitempty"`
	UserAgent      string      `json:"user_agent,omitempty"`
	DownloadVia    string      `json:"download_via,omitempty"`
	FilterMode     string      `json:"filter_mode,omitempty"`
	FilterPatterns []string    `json:"filter_patterns,omitempty"`
	Attempted      int64       `json:"attempted,omitempty"`
	Added          int         `json:"added,omitempty"`
	Removed        int         `json:"removed,omitempty"`
	Duplicates     int         `json:"duplicates,omitempty"`
	Warning        string      `json:"warning,omitempty"`
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	URL            string      `json:"url,omitempty"`
	Enabled        bool        `json:"enabled"`
	Interval       int         `json:"interval"`
	Updated        int64       `json:"updated,omitempty"`
	Error          string      `json:"error,omitempty"`
	Rejected       []Rejection `json:"rejected,omitempty"`
	HasURL         bool        `json:"has_url,omitempty"`
}
type Rejection struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}
type Node struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Subscription string `json:"subscription"`
	Endpoint     bool   `json:"endpoint,omitempty"`
	Config       Object `json:"config"`
}
type Group struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Nodes     []string `json:"nodes"`
	Mode      string   `json:"mode"`
	Selected  string   `json:"selected,omitempty"`
	Interval  int      `json:"interval"`
	Timeout   int      `json:"timeout"`
	Tolerance int      `json:"tolerance"`
	Hold      int      `json:"hold"`
	Failures  int      `json:"failures"`
	Recovery  int      `json:"recovery"`
	Window    int      `json:"window"`
	TestURL   string   `json:"test_url"`
	Failure   string   `json:"failure"`
}
type Rule struct {
	Network     string   `json:"network,omitempty"`
	SeparateUDP bool     `json:"separate_udp,omitempty"`
	UDPNodes    []string `json:"udp_nodes,omitempty"`
	UDPMode     string   `json:"udp_mode,omitempty"`
	UDPSelected string   `json:"udp_selected,omitempty"`
	ID          string   `json:"id,omitempty"`
	Nodes       []string `json:"nodes"`
	Mode        string   `json:"mode,omitempty"`
	Selected    string   `json:"selected,omitempty"`
	Name        string   `json:"name"`
	Enabled     bool     `json:"enabled"`
	Categories  []string `json:"categories"`
	Domains     []string `json:"domains"`
	IPs         []string `json:"ips"`
	Sources     []string `json:"sources"`
	MACs        []string `json:"macs"`
	Target      string   `json:"target"`
	DNS         string   `json:"dns,omitempty"`
}
type Resolver struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Detour  string `json:"detour"`
}
type Settings struct {
	Enabled       bool           `json:"enabled"`
	Interfaces    []string       `json:"interfaces"`
	IPv6          bool           `json:"ipv6"`
	MTU           int            `json:"mtu"`
	Failure       string         `json:"failure"`
	Final         string         `json:"final"`
	FinalNodes    []string       `json:"final_nodes"`
	FinalMode     string         `json:"final_mode,omitempty"`
	FinalSelected string         `json:"final_selected,omitempty"`
	Storage       string         `json:"storage"`
	CoreURL       string         `json:"core_url,omitempty"`
	CoreSHA       string         `json:"core_sha,omitempty"`
	CoreSize      int64          `json:"core_size,omitempty"`
	RulesInterval int            `json:"rules_interval"`
	DNSMode       string         `json:"dns_mode"`
	DNSStrategy   string         `json:"dns_strategy"`
	DNSErrorTTL   int            `json:"dns_error_ttl,omitempty"`
	DNSWinTTL     int            `json:"dns_win_ttl,omitempty"`
	DNSTimeout    int            `json:"dns_timeout,omitempty"`
	DNSCache      bool           `json:"dns_cache"`
	Bootstrap     string         `json:"bootstrap"`
	Subscriptions []Subscription `json:"subscriptions"`
	Groups        []Group        `json:"groups"`
	Rules         []Rule         `json:"rules"`
	DNS           []Resolver     `json:"dns"`
}

func Defaults() Settings {
	return Settings{Interfaces: []string{"br-lan"}, MTU: 1400, Failure: "block", Final: "direct", Storage: "flash", RulesInterval: 24, DNSMode: "stable", DNSStrategy: "prefer_ipv4", DNSCache: true, DNSTimeout: 10, Bootstrap: "1.1.1.1", DNS: []Resolver{{ID: "cloudflare", Name: "Cloudflare", Address: "https://1.1.1.1/dns-query", Detour: "direct"}, {ID: "quad9", Name: "Quad9", Address: "tls://9.9.9.9", Detour: "direct"}}, Subscriptions: []Subscription{}, Groups: []Group{}, Rules: []Rule{}}
}
func hashID(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:12]) }
func copyObject(o Object) Object {
	b, _ := json.Marshal(o)
	var n Object
	_ = json.Unmarshal(b, &n)
	return n
}
func str(o Object, k string) string { s, _ := o[k].(string); return s }
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	if old, e := os.ReadFile(path); e == nil && string(old) == string(b) {
		return nil
	}
	return atomicWrite(path, b, 0600)
}
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".new-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(name, path)
}
func loadJSON(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func validateURL(s string) error {
	u, e := url.Parse(s)
	if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return errors.New("нужен URL HTTP/HTTPS без логина и пароля")
	}
	return nil
}
func validate(s Settings) error {
	if len(s.Interfaces) == 0 {
		return errors.New("выберите LAN-интерфейс")
	}
	for _, i := range s.Interfaces {
		if !validInterface.MatchString(i) || i == "lo" || strings.HasPrefix(i, "rb-tun") {
			return errors.New("некорректный LAN-интерфейс")
		}
	}
	if s.MTU < 1280 || s.MTU > 9000 {
		return errors.New("MTU должен быть 1280–9000")
	}
	if s.Storage != "flash" && s.Storage != "ram" {
		return errors.New("неизвестный способ хранения ядра")
	}
	if s.Failure != "block" && s.Failure != "direct" {
		return errors.New("неизвестное поведение при отказе")
	}
	if (s.DNSErrorTTL != 0 && (s.DNSErrorTTL < 1 || s.DNSErrorTTL > 3600)) || (s.DNSWinTTL != 0 && (s.DNSWinTTL < 1 || s.DNSWinTTL > 86400)) {
		return errors.New("некорректное время резервирования DNS")
	}
	if s.DNSTimeout != 0 && (s.DNSTimeout < 2 || s.DNSTimeout > 30) {
		return errors.New("Таймаут DNS: 2–30 секунд")
	}
	if s.RulesInterval < 1 || s.RulesInterval > 720 {
		return errors.New("интервал списков: 1–720 часов")
	}
	if len(s.Subscriptions) > 16 || len(s.Groups) > 32 || len(s.Rules) > 256 || len(s.DNS) > 16 {
		return errors.New("превышен лимит конфигурации")
	}
	ids := map[string]bool{"direct": true, "block": true}
	for _, g := range s.Groups {
		if !validID.MatchString(g.ID) || ids[g.ID] {
			return errors.New("повторяющееся/некорректное имя группы")
		}
		ids[g.ID] = true
	}
	subIDs := map[string]bool{}
	for _, p := range s.Subscriptions {
		if !validID.MatchString(p.ID) || subIDs[p.ID] {
			return errors.New("повторяющийся ID подписки")
		}
		subIDs[p.ID] = true
		if e := validateSubscriptionOptions(p); e != nil {
			return e
		}
		if e := validateURL(p.URL); e != nil {
			return e
		}
		if p.Interval < 1 || p.Interval > 720 {
			return errors.New("интервал подписки: 1–720 часов")
		}
	}
	active := map[string]bool{}
	for _, g := range s.Groups {
		seenNodes := map[string]bool{}
		for _, id := range g.Nodes {
			if seenNodes[id] {
				return errors.New("повторяющийся сервер в группе")
			}
			seenNodes[id] = true
			active[id] = true
		}
		if len(active) > 64 {
			return errors.New("для MT7621 допускается не более 64 активных серверов")
		}
		if len(g.Nodes) == 0 || len(g.Nodes) > 64 {
			return errors.New("группа должна содержать 1–64 сервера")
		}
		switch g.Mode {
		case "manual", "fastest", "stable", "failover", "round_robin":
		default:
			return errors.New("неизвестный режим группы")
		}
		if g.Interval < 30 || g.Interval > 86400 || g.Timeout < 1 || g.Timeout > 30 || g.Hold < 0 || g.Hold > 86400 || g.Tolerance < 0 || g.Tolerance > 60000 || g.Window < 5 || g.Window > 120 || g.Failures < 1 || g.Failures > 10 || g.Recovery < 1 || g.Recovery > 10 {
			return errors.New("некорректные параметры проверки")
		}
		if g.Failure != "block" && g.Failure != "direct" {
			return errors.New("неизвестное поведение группы при отказе")
		}
		if !strings.HasPrefix(g.TestURL, "https://") {
			return errors.New("URL проверки должен использовать HTTPS")
		}
		if e := validateURL(g.TestURL); e != nil {
			return e
		}
		if g.Mode == "manual" && !contains(g.Nodes, g.Selected) {
			return errors.New("ручной сервер должен входить в группу")
		}
	}
	if !ids[s.Final] && s.Final != "vpn" {
		return errors.New("неизвестное направление остального трафика")
	}
	if len(s.DNS) == 0 {
		return errors.New("добавьте DNS")
	}
	if _, e := netip.ParseAddr(s.Bootstrap); e != nil {
		return errors.New("bootstrap DNS должен быть IP-адресом")
	}
	switch s.DNSMode {
	case "stable", "fastest", "parallel":
	default:
		return errors.New("неизвестный режим DNS")
	}
	switch s.DNSStrategy {
	case "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only":
	default:
		return errors.New("неизвестная стратегия DNS")
	}
	dnsIDs := map[string]bool{}
	for _, d := range s.DNS {
		if !validID.MatchString(d.ID) || dnsIDs[d.ID] || d.ID == "bootstrap" || d.ID == "dns-default" || d.ID == "lan-dns" {
			return errors.New("некорректный ID DNS")
		}
		dnsIDs[d.ID] = true
		if _, e := dnsObject(d); e != nil {
			return e
		}
		if d.Detour != "" && ((!ids[d.Detour] && d.Detour != "vpn") || d.Detour == "block") {
			return errors.New("неизвестное направление DNS")
		}
	}
	for _, r := range s.Rules {
		if r.Network != "" && r.Network != "tcp" && r.Network != "udp" {
			return errors.New("Протокол правила: TCP или UDP")
		}
		if r.SeparateUDP && (r.Target != "vpn" || r.Network != "" || len(r.ID) > 52) {
			return errors.New("Отдельный UDP доступен для общего VPN-правила с коротким ID")
		}
		if !ids[r.Target] && r.Target != "vpn" {
			return errors.New("неизвестное направление правила")
		}
		if r.DNS != "" && (len(r.Sources) > 0 || len(r.MACs) > 0) {
			return errors.New("DNS по устройствам недоступен через dnsmasq; создайте отдельное доменное правило")
		}
		if r.DNS != "" && !dnsIDs[r.DNS] {
			return errors.New("неизвестный DNS правила")
		}
		for _, c := range r.Categories {
			if !validCategory.MatchString(c) {
				return errors.New("некорректная категория")
			}
		}
		for _, ip := range append(append([]string{}, r.IPs...), r.Sources...) {
			if _, e := netip.ParsePrefix(ip); e != nil {
				if _, e = netip.ParseAddr(ip); e != nil {
					return errors.New("некорректный IP/CIDR")
				}
			}
		}
		for _, m := range r.MACs {
			if _, e := net.ParseMAC(m); e != nil {
				return errors.New("некорректный MAC")
			}
		}
		for _, d := range r.Domains {
			if len(d) > 253 || strings.ContainsAny(d, " /\\\n\r\t") || d == "" {
				return errors.New("некорректный домен")
			}
		}
		if r.Enabled && len(r.Categories)+len(r.Domains)+len(r.IPs)+len(r.Sources)+len(r.MACs) == 0 {
			return errors.New("пустое правило запрещено")
		}
	}
	choices := append([]Rule{{Target: s.Final, Nodes: s.FinalNodes, Mode: s.FinalMode, Selected: s.FinalSelected}}, s.Rules...)
	for _, r := range s.Rules {
		if r.SeparateUDP {
			choices = append(choices, Rule{Target: "vpn", Nodes: r.UDPNodes, Mode: r.UDPMode, Selected: r.UDPSelected})
		}
	}
	for _, choice := range choices {
		if len(choice.Nodes) > 64 {
			return errors.New("выберите не более 64 серверов")
		}
		if choice.Mode != "" && !contains([]string{"manual", "fastest", "stable", "failover", "round_robin"}, choice.Mode) {
			return errors.New("неизвестный режим выбора сервера")
		}
		if choice.Target == "vpn" && choice.Mode == "manual" && choice.Selected == "" {
			return errors.New("выберите сервер для ручного режима")
		}
	}
	if s.CoreURL != "" {
		if e := validateURL(s.CoreURL); e != nil {
			return e
		}
		if len(s.CoreSHA) != 64 {
			return errors.New("нужна SHA256 ядра")
		}
		if _, e := hex.DecodeString(s.CoreSHA); e != nil {
			return e
		}
		if s.CoreSize < 1 || s.CoreSize > 100<<20 {
			return errors.New("некорректный размер ядра")
		}
	}
	return nil
}
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
func dnsObject(d Resolver) (Object, error) {
	a := d.Address
	if !strings.Contains(a, "://") {
		a = "udp://" + a
	}
	u, e := url.Parse(a)
	if e != nil || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("некорректный DNS")
	}
	switch u.Scheme {
	case "udp", "tcp", "tls", "https", "quic", "h3":
	default:
		return nil, errors.New("неподдерживаемый тип DNS")
	}
	typ := u.Scheme
	if typ == "h3" {
		typ = "http3"
	}
	o := Object{"type": typ, "tag": d.ID, "server": u.Hostname(), "domain_resolver": "bootstrap"}
	if u.Port() != "" {
		var port int
		if _, e = fmt.Sscanf(u.Port(), "%d", &port); e != nil || port < 1 || port > 65535 {
			return nil, errors.New("некорректный порт DNS")
		}
		o["server_port"] = port
	}
	if u.Path != "" && typ == "https" {
		o["path"] = u.EscapedPath()
	}
	if d.Detour != "" && d.Detour != "direct" {
		o["detour"] = groupTag(d.Detour)
	}
	return o, nil
}
func groupTag(id string) string {
	if id == "direct" {
		return id
	}
	return "g-" + id
}
