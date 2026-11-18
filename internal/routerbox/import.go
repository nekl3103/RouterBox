package routerbox

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func unbase(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := enc.DecodeString(s); e == nil {
			return b, nil
		}
	}
	return nil, errors.New("некорректный Base64")
}
func number(s string) (int, error) {
	n, e := strconv.Atoi(s)
	if e != nil || n < 1 || n > 65535 {
		return 0, errors.New("некорректный порт")
	}
	return n, nil
}
func makeNode(o Object, name, sub string, endpoint bool) (Node, error) {
	typ := str(o, "type")
	switch typ {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria", "tuic", "anytls", "socks", "http", "ssh", "shadowtls", "naive", "snell", "masque", "wireguard", "openvpn", "openconnect":
	default:
		return Node{}, errors.New("протокол не поддерживается импортом")
	}
	o = copyObject(o)
	delete(o, "tag")
	if str(o, "detour") != "" {
		return Node{}, errors.New("сервер зависит от detour; вложенную цепочку нельзя импортировать отдельно")
	}
	delete(o, "detour")
	stripHostOptions(o, endpoint)
	if e := nodeSafety(o, endpoint); e != nil {
		return Node{}, e
	}
	if !endpoint {
		if str(o, "server") == "" {
			return Node{}, errors.New("не задан адрес сервера")
		}
	}
	b, _ := json.Marshal(o)
	id := hashID(append([]byte(sub+":"), b...))
	o["tag"] = "n-" + id
	if name == "" {
		name = typ + " · " + str(o, "server")
	}
	return Node{ID: id, Name: name, Subscription: sub, Endpoint: endpoint, Config: o}, nil
}
func ParseSubscription(b []byte, sub string) ([]Node, []Rejection, error) {
	if len(b) > MaxDownload {
		return nil, nil, errors.New("подписка больше 8 МБ")
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, nil, errors.New("пустая подписка")
	}
	var nodes []Node
	var bad []Rejection
	add := func(o Object, name string, ep bool) {
		n, e := makeNode(o, name, sub, ep)
		if e != nil {
			bad = append(bad, Rejection{Name: name, Reason: e.Error()})
		} else {
			nodes = append(nodes, n)
		}
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		var raw any
		if e := json.Unmarshal(b, &raw); e != nil {
			return nil, nil, errors.New("некорректный JSON")
		}
		var outs, eps []any
		switch v := raw.(type) {
		case map[string]any:
			if isXrayProfile(v) {
				return parseXrayProfiles([]any{v}, sub)
			}
			outs, _ = v["outbounds"].([]any)
			eps, _ = v["endpoints"].([]any)
			if str(v, "type") != "" {
				outs = []any{v}
			}
		case []any:
			if len(v) > 0 {
				if first, ok := v[0].(map[string]any); ok && isXrayProfile(first) {
					return parseXrayProfiles(v, sub)
				}
			}
			outs = v
		}
		for _, v := range outs {
			if o, ok := v.(map[string]any); ok {
				typ := str(o, "type")
				if typ == "selector" || typ == "urltest" || typ == "direct" || typ == "block" || typ == "dns" {
					continue
				}
				if typ == "wireguard" {
					bad = append(bad, Rejection{Name: str(o, "tag"), Reason: "старый WireGuard outbound: нужен endpoint формата sing-box 1.14"})
					continue
				}
				add(o, str(o, "tag"), false)
			}
		}
		for _, v := range eps {
			if o, ok := v.(map[string]any); ok {
				add(o, str(o, "tag"), true)
			}
		}
	} else if strings.Contains(s, "proxies:") {
		var doc struct {
			Proxies []Object `yaml:"proxies"`
		}
		if e := yaml.Unmarshal(b, &doc); e != nil {
			return nil, nil, errors.New("некорректный YAML")
		}
		for _, o := range doc.Proxies {
			out, e := clashNode(o)
			if e != nil {
				bad = append(bad, Rejection{Name: str(o, "name"), Reason: e.Error()})
			} else {
				add(out, str(o, "name"), false)
			}
		}
	} else {
		if !strings.Contains(s, "://") {
			decoded, e := unbase(strings.Join(strings.Fields(s), ""))
			if e != nil {
				return nil, nil, errors.New("неизвестный формат подписки")
			}
			s = strings.TrimSpace(string(decoded))
			if !strings.Contains(s, "://") {
				return nil, nil, errors.New("неизвестный формат подписки")
			}
		}
		for i, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			o, name, e := parseLink(line)
			if e != nil {
				if name == "" {
					name = fmt.Sprintf("Запись %d", i+1)
				}
				bad = append(bad, Rejection{Name: name, Reason: e.Error()})
			} else {
				add(o, name, false)
			}
		}
	}
	unique := map[string]bool{}
	out := []Node{}
	for _, n := range nodes {
		if !unique[n.ID] {
			unique[n.ID] = true
			out = append(out, n)
		}
	}
	if len(out) > 512 {
		return nil, nil, errors.New("в подписке больше 512 серверов")
	}
	if len(out) == 0 && len(bad) == 0 {
		return nil, nil, errors.New("серверы не найдены")
	}
	return out, bad, nil
}
func parseLink(raw string) (Object, string, error) {
	if strings.HasPrefix(raw, "vmess://") {
		b, e := unbase(strings.TrimPrefix(raw, "vmess://"))
		if e != nil {
			return nil, "", e
		}
		var v Object
		if e = json.Unmarshal(b, &v); e != nil {
			return nil, "", errors.New("некорректный VMess")
		}
		text := func(k string) string { return fmt.Sprint(v[k]) }
		port, e := number(text("port"))
		if e != nil {
			return nil, str(v, "ps"), e
		}
		o := Object{"type": "vmess", "server": str(v, "add"), "server_port": port, "uuid": str(v, "id"), "security": "auto"}
		if aid, e := strconv.Atoi(text("aid")); e == nil {
			o["alter_id"] = aid
		}
		if scy := str(v, "scy"); scy != "" {
			o["security"] = scy
		}
		q := url.Values{"type": {str(v, "net")}, "host": {str(v, "host")}, "path": {str(v, "path")}, "sni": {str(v, "sni")}}
		if str(v, "net") == "grpc" {
			q.Set("serviceName", str(v, "path"))
		}
		if str(v, "tls") == "tls" {
			q.Set("security", "tls")
		}
		if e = linkTransport(o, q); e != nil {
			return nil, str(v, "ps"), e
		}
		return o, str(v, "ps"), nil
	}
	if strings.HasPrefix(raw, "ss://") {
		return parseSS(raw)
	}
	u, e := url.Parse(raw)
	if e != nil {
		return nil, "", errors.New("некорректная ссылка")
	}
	name, _ := url.PathUnescape(u.Fragment)
	q := u.Query()
	port, e := number(u.Port())
	if e != nil {
		return nil, name, e
	}
	if u.Hostname() == "" || (u.User == nil && u.Scheme != "hysteria" && u.Scheme != "socks" && u.Scheme != "socks5" && u.Scheme != "http") {
		return nil, name, errors.New("неполная ссылка")
	}
	typ := u.Scheme
	if typ == "socks5" {
		typ = "socks"
	}
	if typ == "hy2" {
		typ = "hysteria2"
	}
	switch typ {
	case "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "socks", "http":
	default:
		return nil, name, errors.New("схема ссылки не поддерживается")
	}
	o := Object{"type": typ, "server": u.Hostname(), "server_port": port}
	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	switch typ {
	case "hysteria":
		if protocol := q.Get("protocol"); protocol != "" && protocol != "udp" {
			return nil, name, errors.New("неподдерживаемый транспорт Hysteria")
		}
		o["auth_str"] = q.Get("auth")
		for key, field := range map[string]string{"upmbps": "up_mbps", "downmbps": "down_mbps"} {
			n, e := strconv.Atoi(q.Get(key))
			if e != nil || n < 1 {
				return nil, name, errors.New("Hysteria требует upmbps и downmbps")
			}
			o[field] = n
		}
		if q.Get("obfsParam") != "" {
			o["obfs"] = q.Get("obfsParam")
		}
	case "vless":
		o["uuid"] = user
		if q.Get("flow") != "" {
			o["flow"] = q.Get("flow")
		}
		if q.Get("encryption") != "" && q.Get("encryption") != "none" {
			o["encryption"] = q.Get("encryption")
		}
	case "tuic":
		o["uuid"] = user
		o["password"] = pass
		if q.Get("congestion_control") != "" {
			o["congestion_control"] = q.Get("congestion_control")
		}
	case "socks", "http":
		o["username"] = user
		o["password"] = pass
	default:
		o["password"] = user
		if pass != "" {
			o["password"] = user + ":" + pass
		}
	}
	if typ == "hysteria" || typ == "trojan" || typ == "hysteria2" || typ == "tuic" || typ == "anytls" {
		if q.Get("security") == "" {
			q.Set("security", "tls")
		}
	}
	for _, key := range []string{"pqv", "spx", "spiderX", "ech"} {
		if q.Get(key) != "" {
			return nil, name, fmt.Errorf("параметр %s не поддерживается этим импортом", key)
		}
	}
	if e = linkTransport(o, q); e != nil {
		return nil, name, e
	}
	if typ == "hysteria2" {
		if q.Get("obfs") != "" {
			if q.Get("obfs") != "salamander" {
				return nil, name, errors.New("неподдерживаемая обфускация Hysteria2")
			}
			o["obfs"] = Object{"type": "salamander", "password": q.Get("obfs-password")}
		}
	}
	return o, name, nil
}
func linkTransport(o Object, q url.Values) error {
	sec := q.Get("security")
	if sec != "" && sec != "none" && sec != "tls" && sec != "reality" {
		return errors.New("неподдерживаемый тип защиты")
	}
	if sec == "tls" || sec == "reality" {
		tls := Object{"enabled": true}
		sni := q.Get("sni")
		if sni == "" {
			sni = q.Get("peer")
		}
		if sni != "" {
			tls["server_name"] = sni
		}
		if q.Get("insecure") == "1" || q.Get("insecure") == "true" || q.Get("allowInsecure") == "1" || q.Get("allowInsecure") == "true" {
			tls["insecure"] = true
		}
		if q.Get("alpn") != "" {
			tls["alpn"] = strings.Split(q.Get("alpn"), ",")
		}
		if q.Get("fp") != "" {
			tls["utls"] = Object{"enabled": true, "fingerprint": q.Get("fp")}
		}
		if sec == "reality" {
			r := Object{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
			if q.Get("key_share") != "" {
				r["key_share"] = q.Get("key_share")
			}
			tls["reality"] = r
			if tls["utls"] == nil {
				tls["utls"] = Object{"enabled": true, "fingerprint": "chrome"}
			}
		}
		o["tls"] = tls
	}
	typ := q.Get("type")
	if typ == "splithttp" {
		typ = "xhttp"
	}
	switch typ {
	case "", "tcp":
		if q.Get("headerType") != "" && q.Get("headerType") != "none" {
			return errors.New("TCP header camouflage не поддерживается")
		}
	case "ws":
		t := Object{"type": "ws", "path": q.Get("path")}
		if q.Get("host") != "" {
			t["headers"] = Object{"Host": q.Get("host")}
		}
		o["transport"] = t
	case "grpc":
		o["transport"] = Object{"type": "grpc", "service_name": q.Get("serviceName")}
	case "xhttp", "httpupgrade":
		t := Object{"type": typ, "path": q.Get("path"), "host": q.Get("host")}
		if typ == "xhttp" {
			if q.Get("mode") != "" {
				t["mode"] = q.Get("mode")
			}
			if q.Get("extra") != "" {
				var extra Object
				if e := json.Unmarshal([]byte(q.Get("extra")), &extra); e != nil {
					return errors.New("некорректный XHTTP extra")
				}
				if len(extra) > 0 {
					return errors.New("XHTTP extra требует JSON sing-box: автоматическое преобразование не поддерживается")
				}
			}
		}
		o["transport"] = t
	case "http", "h2":
		o["transport"] = Object{"type": "http", "path": q.Get("path"), "host": strings.Split(q.Get("host"), ",")}
	default:
		return errors.New("транспорт ссылки не поддерживается")
	}
	return nil
}
func parseSS(raw string) (Object, string, error) {
	u, e := url.Parse(raw)
	if e != nil {
		return nil, "", errors.New("некорректная Shadowsocks ссылка")
	}
	name, _ := url.PathUnescape(u.Fragment)
	q := u.Query()
	if q.Get("plugin") != "" {
		return nil, name, errors.New("Shadowsocks plugin: используйте JSON sing-box")
	}
	var method, pass, host string
	if u.User == nil {
		decoded, e := unbase(u.Host)
		if e != nil {
			return nil, name, e
		}
		s := string(decoded)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, name, errors.New("неполная Shadowsocks ссылка")
		}
		host = s[at+1:]
		method, pass, _ = strings.Cut(s[:at], ":")
	} else {
		host = u.Host
		method = u.User.Username()
		pass, _ = u.User.Password()
		if pass == "" {
			b, e := unbase(method)
			if e != nil {
				return nil, name, e
			}
			method, pass, _ = strings.Cut(string(b), ":")
		}
	}
	h, p, e := net.SplitHostPort(host)
	if e != nil {
		return nil, name, errors.New("неполный адрес Shadowsocks")
	}
	port, e := number(p)
	if e != nil {
		return nil, name, e
	}
	return Object{"type": "shadowsocks", "server": h, "server_port": port, "method": method, "password": pass}, name, nil
}
func clashNode(c Object) (Object, error) {
	typ := str(c, "type")
	if typ == "ss" {
		typ = "shadowsocks"
	}
	if typ == "socks5" {
		typ = "socks"
	}
	if typ == "hy2" {
		typ = "hysteria2"
	}
	switch typ {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls", "socks", "http":
	default:
		return nil, errors.New("тип Clash не поддерживается преобразованием")
	}
	for _, k := range []string{"plugin", "smux", "ech-opts", "dialer-proxy", "ip-version", "servername-override"} {
		if v, ok := c[k]; ok && v != nil && v != "" {
			return nil, fmt.Errorf("параметр Clash %s требует JSON sing-box", k)
		}
	}
	o := Object{"type": typ, "server": c["server"], "server_port": c["port"]}
	mapping := map[string]string{"uuid": "uuid", "password": "password", "username": "username", "flow": "flow", "cipher": "method", "alterId": "alter_id", "encryption": "encryption", "congestion-controller": "congestion_control"}
	for k, v := range mapping {
		if val, ok := c[k]; ok {
			o[v] = val
		}
	}
	if typ == "vmess" {
		o["security"] = c["cipher"]
		delete(o, "method")
	}
	enabled, _ := c["tls"].(bool)
	if enabled || typ == "trojan" || typ == "hysteria2" || typ == "tuic" || typ == "anytls" {
		tls := Object{"enabled": true}
		if s := str(c, "servername"); s != "" {
			tls["server_name"] = s
		} else if s = str(c, "sni"); s != "" {
			tls["server_name"] = s
		}
		if v, ok := c["skip-cert-verify"]; ok {
			tls["insecure"] = v
		}
		if v, ok := c["alpn"]; ok {
			tls["alpn"] = v
		}
		if fp := str(c, "client-fingerprint"); fp != "" {
			tls["utls"] = Object{"enabled": true, "fingerprint": fp}
		}
		if r, ok := c["reality-opts"].(map[string]any); ok {
			tls["reality"] = Object{"enabled": true, "public_key": r["public-key"], "short_id": r["short-id"]}
		}
		o["tls"] = tls
	}
	switch str(c, "network") {
	case "", "tcp":
	case "ws":
		t := Object{"type": "ws"}
		if opts, ok := c["ws-opts"].(map[string]any); ok {
			for _, k := range []string{"path", "headers"} {
				if v, ok := opts[k]; ok {
					t[k] = v
				}
			}
			if v, ok := opts["max-early-data"]; ok {
				t["max_early_data"] = v
			}
			if v, ok := opts["early-data-header-name"]; ok {
				t["early_data_header_name"] = v
			}
		}
		o["transport"] = t
	case "grpc":
		t := Object{"type": "grpc"}
		if opts, ok := c["grpc-opts"].(map[string]any); ok {
			t["service_name"] = opts["grpc-service-name"]
		}
		o["transport"] = t
	default:
		return nil, errors.New("транспорт Clash требует JSON sing-box")
	}
	if typ == "hysteria2" && str(c, "obfs") != "" {
		o["obfs"] = Object{"type": c["obfs"], "password": c["obfs-password"]}
	}
	return o, nil
}

// Options that bind a server to the router's own network stack. A subscription only
// describes a remote server, so these are removed instead of trusted.
var hostDialOptions = []string{"bind_interface", "inet4_bind_address", "inet6_bind_address", "bind_address_no_port", "protect_path", "routing_mark", "reuse_addr", "netns", "network_strategy", "network_type", "fallback_network_type", "domain_resolver"}

// Endpoint options that create system interfaces or listen on router ports.
var hostEndpointOptions = []string{"system", "name", "listen_port", "dtls_local_port", "system_interface", "system_interface_name", "system_interface_mtu"}

func stripHostOptions(o Object, endpoint bool) {
	for _, k := range hostDialOptions {
		delete(o, k)
	}
	if endpoint {
		for _, k := range hostEndpointOptions {
			delete(o, k)
		}
	}
}

// Host-check hooks of OpenConnect run an external program (wrapper_path) or a check
// script on the router; they are never accepted from a subscription.
var hostScriptOptions = map[string]bool{"csd": true, "hip": true, "tncc": true, "fortinet_host_check": true}

// nodeSafety rejects anything that reads router files, runs programs or reaches the
// router's own network. It is checked at import and again before a config is started,
// so servers saved by older versions cannot bypass it.
func nodeSafety(o Object, endpoint bool) error {
	switch str(o, "type") {
	case "tailscale":
		return errors.New("Tailscale из подписки не поддерживается: он даёт удалённый доступ к сети роутера")
	}
	for _, k := range hostDialOptions {
		if k == "domain_resolver" {
			continue
		}
		if present(o[k]) {
			return errors.New("сервер задаёт сетевые параметры самого роутера")
		}
	}
	if endpoint {
		for _, k := range hostEndpointOptions {
			if present(o[k]) {
				return errors.New("сервер создаёт системный интерфейс или открывает порт на роутере")
			}
		}
	}
	return unsafeReference(o)
}
func present(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case int:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
func unsafeReference(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if hostScriptOptions[key] && present(item) {
				return errors.New("подписка не может запускать программы проверки хоста на роутере")
			}
			if localFileKey(key) && present(item) {
				return errors.New("подписка не может ссылаться на локальные файлы роутера")
			}
			if e := unsafeReference(item); e != nil {
				return e
			}
		}
	case []any:
		for _, item := range v {
			if e := unsafeReference(item); e != nil {
				return e
			}
		}
	}
	return nil
}

// Any *_path / *_file / *_directory option names a file on the router. Transport
// fields named plain "path" (WebSocket, HTTP) are URL paths and stay allowed.
func localFileKey(key string) bool {
	if key == "tcp_multi_path" {
		return false
	}
	for _, suffix := range []string{"_path", "_file", "_directory", "_dir"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return key == "directory" || key == "password_file" || key == "hostcheck"
}

// configSafety checks servers inside a full core config, e.g. last-good.json written
// by an older version, before it is started.
func configSafety(config Object) error {
	for _, section := range []string{"outbounds", "endpoints"} {
		items, _ := config[section].([]any)
		for _, raw := range items {
			o, _ := raw.(map[string]any)
			if !strings.HasPrefix(str(o, "tag"), "n-") {
				continue
			}
			copyOf := copyObject(o)
			delete(copyOf, "domain_resolver")
			if e := nodeSafety(copyOf, section == "endpoints"); e != nil {
				return e
			}
		}
	}
	return nil
}
