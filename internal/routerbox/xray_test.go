package routerbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestXrayProfilesAndCore(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "grpc", "xhttp"} {
		t.Run(network, func(t *testing.T) {
			st := Object{"network": network, "security": "tls", "tlsSettings": Object{"serverName": "example.com", "fingerprint": "chrome", "alpn": []string{"h2", "http/1.1"}}}
			switch network {
			case "ws":
				st["wsSettings"] = Object{"path": "/ws", "headers": Object{"Host": "example.com", "X-Test": "value"}}
			case "grpc":
				st["grpcSettings"] = Object{"serviceName": "grpc", "mode": "gun"}
			case "xhttp":
				st["xhttpSettings"] = Object{"path": "/xhttp", "mode": "auto", "extra": Object{"xmux": Object{"maxConcurrency": 16, "hMaxRequestTimes": "100-200"}}}
			}
			out := Object{"protocol": "vless", "tag": "proxy", "settings": Object{"vnext": []Object{{"address": "example.com", "port": 443, "users": []Object{{"id": "11111111-1111-4111-8111-111111111111", "encryption": "none"}}}}}, "streamSettings": st}
			profile := Object{"remarks": "Fixture", "inbounds": []Object{{"listen": "0.0.0.0"}}, "routing": Object{"domainStrategy": "AsIs"}, "outbounds": []Object{out, {"protocol": "freedom"}}}
			body, _ := json.Marshal([]Object{profile, profile})
			nodes, bad, err := ParseSubscription(body, "fixture")
			if err != nil || len(nodes) != 1 || len(bad) != 0 {
				t.Fatalf("counts=%d/%d error=%v", len(nodes), len(bad), err)
			}
			if nodes[0].Config["routing"] != nil || nodes[0].Config["inbounds"] != nil {
				t.Fatal("provider routing imported")
			}
			if core := os.Getenv("ROUTERBOX_TEST_CORE"); core != "" {
				m, e := NewManager(t.TempDir(), t.TempDir(), core)
				if e != nil {
					t.Fatal(e)
				}
				if e = m.checkNode(nodes[0]); e != nil {
					t.Fatal(e)
				}
			}
			out["proxySettings"] = Object{"tag": "hop"}
			body, _ = json.Marshal(profile)
			nodes, bad, err = ParseSubscription(body, "fixture")
			if err != nil || len(nodes) != 0 || len(bad) != 1 {
				t.Fatal("chain must be rejected")
			}
			delete(out, "proxySettings")
			profile["remarks"] = "Устройство не поддерживается"
			body, _ = json.Marshal(profile)
			nodes, bad, _ = ParseSubscription(body, "fixture")
			if len(nodes) != 0 || len(bad) != 1 || !strings.Contains(bad[0].Reason, "HWID") {
				t.Fatal("provider placeholder was imported")
			}
		})
	}
}
func TestHWIDHeaderAndRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Hwid") != "fixture-device" {
			t.Error("HWID absent")
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://localhost:1/", 302)
			return
		}
		w.Write([]byte("fixture"))
	}))
	defer server.Close()
	_, _, err := fetchDocumentOptions(context.Background(), server.URL, 100, downloadOptions{HWID: "fixture-device"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = fetchDocumentOptions(context.Background(), server.URL+"/redirect", 100, downloadOptions{HWID: "fixture-device"})
	if err == nil || strings.Contains(err.Error(), "fixture-device") {
		t.Fatal("redirect must fail without leaking HWID")
	}
	if validateSubscriptionOptions(Subscription{URL: server.URL, HWID: "fixture-device"}) == nil {
		t.Fatal("HWID requires HTTPS")
	}
	if validateSubscriptionOptions(Subscription{URL: "https://example.com", HWID: "x\r\ny"}) == nil {
		t.Fatal("header injection accepted")
	}
	m, e := NewManager(t.TempDir(), t.TempDir(), "")
	if e != nil {
		t.Fatal(e)
	}
	m.Settings.Subscriptions = []Subscription{{ID: "test", HWID: "fixture-device"}}
	m.publish()
	raw, _ := json.Marshal(m.State())
	if strings.Contains(string(raw), "fixture-device") {
		t.Fatal("HWID leaked in state")
	}
	if !strings.Contains(string(raw), "has_hwid") {
		t.Fatal("saved indicator missing")
	}
}
