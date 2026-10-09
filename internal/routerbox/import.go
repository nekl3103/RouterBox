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
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria", "tuic", "anytls", "socks", "http", "ssh", "shadowtls", "naive", "snell", "masque", "wireguard", "tailscale", "openvpn", "openconnect":
	default:
		return Node{}, errors.New("протокол не поддерживается импортом")
	}
	o = copyObject(o)
	if localFileReference(o) {
		return Node{}, errors.New("подписка не может ссылаться на локальные файлы роутера")
	}
	delete(o, "tag")
	if str(o, "detour") != "" {
		return Node{}, errors.New("сервер зависит от detour; вложенную цепочку нельзя импортировать отдельно")
	}
	delete(o, "detour")
	delete(o, "bind_interface")
	delete(o, "routing_mark")
	delete(o, "domain_resolver")
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
			outs, _ = v["outbounds"].([]any)
			eps, _ = v["endpoints"].([]any)
			if str(v, "type") != "" {
				outs = []any{v}
			}
		case []any:
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

func localFileReference(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			switch key {
			case "certificate_path", "certificate_directory_path", "private_key_path", "public_key_path", "key_path", "client_key_path", "client_certificate_path", "known_hosts_path", "password_file", "plugin_path":
				if text, ok := item.(string); ok && text != "" {
					return true
				}
				if list, ok := item.([]any); ok && len(list) > 0 {
					return true
				}
			}
			if localFileReference(item) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if localFileReference(item) {
				return true
			}
		}
	}
	return false
}
