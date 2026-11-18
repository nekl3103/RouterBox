package routerbox

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func parseOne(t *testing.T, server string) ([]Node, []Rejection) {
	t.Helper()
	nodes, bad, err := ParseSubscription([]byte(`{"outbounds":[`+server+`]}`), "sub")
	if err != nil {
		t.Fatal(err)
	}
	return nodes, bad
}
func parseEndpoint(t *testing.T, endpoint string) ([]Node, []Rejection) {
	t.Helper()
	nodes, bad, err := ParseSubscription([]byte(`{"endpoints":[`+endpoint+`]}`), "sub")
	if err != nil {
		t.Fatal(err)
	}
	return nodes, bad
}

// Every one of these would let a subscription run a program, read router files or
// expose the LAN. They must be rejected, not silently imported.
func TestSubscriptionCannotReachRouterHost(t *testing.T) {
	cases := map[string]string{
		"openconnect CSD wrapper":   `{"type":"openconnect","tag":"x","server":"vpn.example.com","csd":{"wrapper_path":"/tmp/evil.sh"}}`,
		"openconnect TNCC":          `{"type":"openconnect","tag":"x","server":"vpn.example.com","tncc":{"device_id":"a"}}`,
		"openconnect host check":    `{"type":"openconnect","tag":"x","server":"vpn.example.com","fortinet_host_check":{"hostcheck":"x"}}`,
		"openconnect token secret":  `{"type":"openconnect","tag":"x","server":"vpn.example.com","token":{"mode":"totp","secret_path":"/etc/shadow"}}`,
		"openconnect CA file":       `{"type":"openconnect","tag":"x","server":"vpn.example.com","tls":{"certificate_authority_path":"/etc/ssl/x"}}`,
		"openvpn static key file":   `{"type":"openvpn","tag":"x","servers":[{"server":"vpn.example.com","server_port":1194}],"static_key_path":"/etc/shadow"}`,
		"openvpn CRL file":          `{"type":"openvpn","tag":"x","servers":[{"server":"vpn.example.com","server_port":1194}],"tls":{"crl_path":"/etc/x"}}`,
		"ECH config file":           `{"type":"trojan","tag":"x","server":"example.com","server_port":443,"password":"p","tls":{"enabled":true,"ech":{"enabled":true,"config_path":"/etc/shadow"}}}`,
		"tailscale advertise LAN":   `{"type":"tailscale","tag":"x","auth_key":"k","advertise_routes":["192.168.1.0/24"]}`,
		"tailscale state directory": `{"type":"tailscale","tag":"x","state_directory":"/etc"}`,
	}
	for name, server := range cases {
		nodes, bad := parseEndpoint(t, server)
		if len(nodes) != 0 || len(bad) != 1 {
			t.Fatal(name, "accepted", nodes)
		}
	}
}

// Options that only bind to the router's own network are removed, the server is kept.
func TestHostNetworkOptionsAreStripped(t *testing.T) {
	nodes, bad := parseOne(t, `{"type":"trojan","tag":"x","server":"example.com","server_port":443,"password":"p","bind_interface":"wan","inet4_bind_address":"10.0.0.1","routing_mark":1,"reuse_addr":true,"netns":"/run/netns/x","network_strategy":"fallback","tcp_multi_path":true,"transport":{"type":"ws","path":"/ws"}}`)
	if len(nodes) != 1 || len(bad) != 0 {
		t.Fatal("trojan rejected", bad)
	}
	c := nodes[0].Config
	for _, k := range []string{"bind_interface", "inet4_bind_address", "routing_mark", "reuse_addr", "netns", "network_strategy"} {
		if _, ok := c[k]; ok {
			t.Fatal("host option kept", k)
		}
	}
	if c["tcp_multi_path"] != true || obj(c["transport"])["path"] != "/ws" {
		t.Fatal("legitimate options lost", c)
	}
	nodes, bad = parseEndpoint(t, `{"type":"wireguard","tag":"wg","system":true,"name":"wg0","listen_port":51820,"address":["10.7.0.2/32"],"private_key":"YNXtAzepDqRv9H52osJVDQnznT5AM11eCK3ESpwSt04=","peers":[{"address":"wg.example.com","port":51820,"public_key":"Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=","allowed_ips":["0.0.0.0/0"]}]}`)
	if len(nodes) != 1 || len(bad) != 0 {
		t.Fatal("wireguard rejected", bad)
	}
	for _, k := range []string{"system", "name", "listen_port"} {
		if _, ok := nodes[0].Config[k]; ok {
			t.Fatal("endpoint host option kept", k)
		}
	}
}

// Servers saved by older versions are checked again before they reach the core.
func TestStoredUnsafeServerIsNotStarted(t *testing.T) {
	s := Defaults()
	s.Subscriptions = []Subscription{{ID: "sub", Enabled: true, Interval: 24, URL: "https://example.com/s"}}
	s.Final = "vpn"
	evil := Node{ID: "evil", Name: "Evil", Subscription: "sub", Endpoint: true, Config: Object{"type": "openconnect", "server": "vpn.example.com", "csd": map[string]any{"wrapper_path": "/tmp/evil.sh"}}}
	s.FinalNodes = []string{"evil"}
	if _, err := Generate(s, []Node{evil}, nil, t.TempDir(), "secret", true); err == nil || !strings.Contains(err.Error(), "Evil") {
		t.Fatal("unsafe stored server generated", err)
	}
	legacy := Node{ID: "old", Name: "Old", Subscription: "sub", Config: Object{"type": "trojan", "server": "example.com", "server_port": 443, "password": "p", "reuse_addr": true}}
	s.FinalNodes = []string{"old"}
	config, err := Generate(s, []Node{legacy}, nil, t.TempDir(), "secret", true)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(config)
	if strings.Contains(string(b), "reuse_addr") {
		t.Fatal("host option of stored server reached the core")
	}
	var saved Object
	_ = json.Unmarshal([]byte(`{"outbounds":[{"type":"direct","tag":"direct"},{"type":"socks","tag":"unavailable","server":"127.0.0.1","server_port":1},{"type":"trojan","tag":"n-old","server":"example.com","server_port":443,"password":"p","domain_resolver":"bootstrap"}],"endpoints":[{"type":"openconnect","tag":"n-evil","server":"x","hip":{"wrapper_path":"/tmp/x"}}]}`), &saved)
	if configSafety(saved) == nil {
		t.Fatal("unsafe last-good accepted")
	}
	saved["endpoints"] = []any{}
	if err = configSafety(saved); err != nil {
		t.Fatal("generated outbounds rejected", err)
	}
}

// Stripping must not break servers the core accepts.
func TestSanitizedServersPassCoreCheck(t *testing.T) {
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Skip("native core required")
	}
	m, err := NewManager(t.TempDir(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	defer m.cancel()
	trojan, _ := parseOne(t, `{"type":"trojan","tag":"x","server":"example.com","server_port":443,"password":"p","bind_interface":"wan","reuse_addr":true,"tcp_multi_path":true,"tls":{"enabled":true,"server_name":"example.com"}}`)
	wg, _ := parseEndpoint(t, `{"type":"wireguard","tag":"wg","system":true,"name":"wg0","listen_port":51820,"address":["10.7.0.2/32"],"private_key":"YNXtAzepDqRv9H52osJVDQnznT5AM11eCK3ESpwSt04=","peers":[{"address":"wg.example.com","port":51820,"public_key":"Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=","allowed_ips":["0.0.0.0/0"]}]}`)
	ovpn, bad := parseEndpoint(t, `{"type":"openvpn","tag":"ov","servers":[{"server":"vpn.example.com","server_port":1194}],"username":"u","password":"p","tls":{"certificate":["-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ0lz\n-----END CERTIFICATE-----"]}}`)
	nodes := append(append(trojan, wg...), ovpn...)
	if len(nodes) != 3 {
		t.Fatal("servers lost", len(nodes), bad)
	}
	checked := trojan
	// Userspace WireGuard needs gVisor; the router build has it, a host test build may not.
	if out, _ := exec.Command(core, "version").Output(); strings.Contains(string(out), "with_gvisor") {
		checked = append(checked, wg...)
	}
	for i, e := range m.checkNodeBatch(checked) {
		if e != nil {
			t.Fatal(checked[i].Name, e)
		}
	}
}
