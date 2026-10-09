package routerbox

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func obj(v any) Object { m, _ := v.(map[string]any); return m }
func isXrayProfile(v Object) bool {
	outs, _ := v["outbounds"].([]any)
	for _, raw := range outs {
		if str(obj(raw), "protocol") != "" {
			return true
		}
	}
	return false
}

// Import independent connection entries, never provider inbounds, routing or chains.
func parseXrayProfiles(profiles []any, sub string) ([]Node, []Rejection, error) {
	nodes := []Node{}
	bad := []Rejection{}
	seen := map[string]bool{}
	for _, raw := range profiles {
		profile := obj(raw)
		name := str(profile, "remarks")
		outs, _ := profile["outbounds"].([]any)
		for i, rawOut := range outs {
			x := obj(rawOut)
			typ := str(x, "protocol")
			if typ == "freedom" || typ == "blackhole" || typ == "dns" {
				continue
			}
			label := name
			if label == "" {
				label = str(x, "tag")
			}
			if len(outs) > 3 {
				label += fmt.Sprintf(" · %d", i+1)
			}
			if strings.Contains(name, "Устройство не поддерживается") {
				bad = append(bad, Rejection{Name: label, Reason: "провайдер требует идентификацию устройства; проверьте User-Agent и HWID"})
				continue
			}
			o, err := xrayVLESS(x)
			if err != nil {
				bad = append(bad, Rejection{Name: label, Reason: err.Error()})
				continue
			}
			n, err := makeNode(o, label, sub, false)
			if err != nil {
				bad = append(bad, Rejection{Name: label, Reason: err.Error()})
				continue
			}
			if !seen[n.ID] {
				nodes = append(nodes, n)
				seen[n.ID] = true
			}
		}
	}
	if len(nodes) > 512 {
		return nil, nil, errors.New("в подписке больше 512 серверов")
	}
	if len(nodes) == 0 && len(bad) == 0 {
		return nil, nil, errors.New("серверы не найдены")
	}
	return nodes, bad, nil
}
func xrayVLESS(x Object) (Object, error) {
	if str(x, "protocol") != "vless" {
		return nil, errors.New("Xray JSON: пока поддерживается VLESS")
	}
	if len(obj(x["proxySettings"])) > 0 || len(obj(obj(x["streamSettings"])["sockopt"])) > 0 {
		return nil, errors.New("Xray цепочки и sockopt нельзя импортировать как отдельный сервер")
	}
	if mux := obj(x["mux"]); mux["enabled"] == true {
		return nil, errors.New("Xray mux не поддерживается импортом")
	}
	settings := obj(x["settings"])
	next, _ := settings["vnext"].([]any)
	if len(next) != 1 {
		return nil, errors.New("VLESS: нужен один адрес сервера")
	}
	v := obj(next[0])
	users, _ := v["users"].([]any)
	if len(users) != 1 {
		return nil, errors.New("VLESS: нужен один пользователь")
	}
	u := obj(users[0])
	if encryption := str(u, "encryption"); encryption != "" && encryption != "none" {
		return nil, errors.New("VLESS encryption не поддерживается импортом")
	}
	port, err := number(fmt.Sprint(v["port"]))
	if err != nil {
		return nil, err
	}
	if str(u, "id") == "" {
		return nil, errors.New("VLESS: отсутствует UUID")
	}
	o := Object{"type": "vless", "server": str(v, "address"), "server_port": port, "uuid": str(u, "id")}
	if flow := str(u, "flow"); flow != "" {
		o["flow"] = flow
	}
	stream := obj(x["streamSettings"])
	network := str(stream, "network")
	q := url.Values{"type": {network}, "security": {str(stream, "security")}}
	tls := obj(stream["tlsSettings"])
	if q.Get("security") == "reality" {
		tls = obj(stream["realitySettings"])
		q.Set("pbk", str(tls, "publicKey"))
		q.Set("sid", str(tls, "shortId"))
	}
	q.Set("sni", str(tls, "serverName"))
	q.Set("fp", str(tls, "fingerprint"))
	if tls["allowInsecure"] == true {
		q.Set("insecure", "true")
	}
	if alpn, ok := tls["alpn"].([]any); ok {
		a := []string{}
		for _, v := range alpn {
			s, ok := v.(string)
			if !ok {
				return nil, errors.New("некорректный ALPN")
			}
			a = append(a, s)
		}
		q.Set("alpn", strings.Join(a, ","))
	}
	transport := obj(stream[network+"Settings"])
	switch network {
	case "", "tcp":
		if h := obj(transport["header"]); str(h, "type") != "" && str(h, "type") != "none" {
			return nil, errors.New("TCP header camouflage не поддерживается")
		}
	case "ws":
		q.Set("path", str(transport, "path"))
		q.Set("host", str(obj(transport["headers"]), "Host"))
	case "grpc":
		if str(transport, "authority") != "" || str(transport, "mode") == "multi" {
			return nil, errors.New("gRPC authority/multi не поддерживается импортом")
		}
		q.Set("serviceName", str(transport, "serviceName"))
	case "xhttp", "splithttp":
		q.Set("path", str(transport, "path"))
		q.Set("host", str(transport, "host"))
		q.Set("mode", str(transport, "mode"))
	default:
		return nil, errors.New("неподдерживаемый Xray transport")
	}
	if err = linkTransport(o, q); err != nil {
		return nil, err
	}
	if network == "ws" {
		if h := obj(transport["headers"]); len(h) > 0 {
			obj(o["transport"])["headers"] = h
		}
	}
	if network == "xhttp" || network == "splithttp" {
		extra := obj(transport["extra"])
		for key, value := range extra {
			if key != "xmux" {
				return nil, errors.New("неподдерживаемый XHTTP extra")
			}
			xmux := Object{}
			mapping := map[string]string{"maxConcurrency": "max_concurrency", "maxConnections": "max_connections", "cMaxReuseTimes": "c_max_reuse_times", "hMaxRequestTimes": "h_max_request_times", "hMaxReusableSecs": "h_max_reusable_secs", "hKeepAlivePeriod": "h_keep_alive_period"}
			for k, v := range obj(value) {
				mapped := mapping[k]
				if mapped == "" {
					return nil, errors.New("неподдерживаемый XHTTP xmux")
				}
				if k == "hKeepAlivePeriod" {
					xmux[mapped] = v
				} else {
					switch vv := v.(type) {
					case float64:
						xmux[mapped] = strconv.FormatFloat(vv, 'f', -1, 64)
					default:
						xmux[mapped] = v
					}
				}
			}
			obj(o["transport"])["xmux"] = xmux
		}
	}
	return o, nil
}
