package routerbox

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDownloadRetriesAgentAndRedaction(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.UserAgent() != "TestClient" {
			t.Error("custom agent missing")
		}
		if attempts < 3 {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer server.Close()
	b, _, err := fetchDocumentOptions(context.Background(), server.URL, 20, downloadOptions{UserAgent: "TestClient"})
	if err != nil || string(b) != "ok" || attempts != 3 {
		t.Fatalf("retry: %d %s %v", attempts, b, err)
	}
	denied := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { denied++; w.WriteHeader(401) }))
	defer s.Close()
	_, _, err = fetchDocument(context.Background(), s.URL, 20)
	if denied != 1 || err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatal("permanent HTTP errors must not retry")
	}
	err = downloadError(&net.DNSError{Err: "private-subscription-token", Name: "private-host"})
	if strings.Contains(err.Error(), "private") {
		t.Fatal("secrets exposed")
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tls.Close()
	_, _, err = fetchDocument(context.Background(), tls.URL, 20)
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatal("certificate diagnostic missing", err)
	}
}
func TestSubscriptionFilterAndRetainedSelections(t *testing.T) {
	p := Subscription{ID: "sub", FilterMode: "whitelist", FilterPatterns: []string{"(?i)germany|netherlands"}}
	nodes := []Node{{ID: "a", Name: "Germany", Subscription: "sub"}, {ID: "a", Name: "Germany duplicate", Subscription: "sub"}, {ID: "b", Name: "USA", Subscription: "sub"}}
	filtered, duplicates := filterSubscription(nodes, p)
	if len(filtered) != 1 || duplicates != 1 {
		t.Fatal(filtered, duplicates)
	}
	old := []Node{{ID: "selected", Subscription: "sub"}, {ID: "unused", Subscription: "sub"}}
	s := Defaults()
	s.Rules = []Rule{{Nodes: []string{"selected"}}}
	candidate := subscriptionCandidate(old, filtered, &s, &p)
	if len(candidate) != 2 || p.Added != 1 || p.Removed != 1 || p.Warning == "" {
		t.Fatal(candidate, p)
	}
	if err := validateSubscriptionOptions(Subscription{FilterPatterns: []string{"["}}); err == nil {
		t.Fatal("invalid regex accepted")
	}
	if err := validateSubscriptionOptions(Subscription{UserAgent: "x\r\nAuthorization: secret"}); err == nil {
		t.Fatal("header injection accepted")
	}
}
func TestFailedSubscriptionApplyPreservesDiskAndMemory(t *testing.T) {
	root, run := t.TempDir(), t.TempDir()
	fake := filepath.Join(run, "check-core")
	os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0700)
	m, err := NewManager(root, run, fake)
	if err != nil {
		t.Fatal(err)
	}
	defer m.cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("socks://127.0.0.1:1080#new")) }))
	defer server.Close()
	m.Settings.Enabled = true
	m.Settings.Subscriptions = []Subscription{{ID: "sub", URL: server.URL, Interval: 24, Enabled: true, Updated: 1}}
	m.Settings.Rules = []Rule{{ID: "r", Name: "r", Enabled: true, Target: "vpn", Domains: []string{"example.com"}, Nodes: []string{"absent"}}}
	m.Nodes = []Node{{ID: "old", Name: "old", Subscription: "sub", Config: Object{"type": "socks", "server": "127.0.0.1", "server_port": 1081}}}
	before := append([]Node{}, m.Nodes...)
	writeJSON(filepath.Join(root, "nodes.json"), before)
	if err = m.refresh("sub"); err == nil {
		t.Fatal("expected apply failure")
	}
	if !reflect.DeepEqual(m.Nodes, before) {
		t.Fatal("in-memory nodes replaced after failure")
	}
	var disk []Node
	if err = loadJSON(filepath.Join(root, "nodes.json"), &disk); err != nil || disk[0].ID != "old" {
		t.Fatal("disk nodes replaced", err)
	}
	if m.Settings.Subscriptions[0].Updated != 1 || m.Settings.Subscriptions[0].Error == "" {
		t.Fatal("successful timestamp advanced despite rollback")
	}
}
func TestUDPAndDNSConfigWithRealCore(t *testing.T) {
	s := Defaults()
	s.Enabled = true
	s.DNSTimeout = 4
	s.DNSErrorTTL = 30
	s.DNSWinTTL = 60
	s.Subscriptions = []Subscription{{ID: "sub", URL: "https://example.com/sub", Enabled: true, Interval: 24}}
	s.Rules = []Rule{{ID: "video", Name: "video", Target: "vpn", Enabled: true, Domains: []string{"example.com"}, Nodes: []string{"tcp"}, Mode: "manual", Selected: "tcp", SeparateUDP: true, UDPNodes: []string{"udp"}, UDPMode: "manual", UDPSelected: "udp"}}
	nodes := []Node{{ID: "tcp", Subscription: "sub", Config: Object{"type": "socks", "server": "127.0.0.1", "server_port": 1080}}, {ID: "udp", Subscription: "sub", Config: Object{"type": "socks", "server": "127.0.0.1", "server_port": 1081}}}
	effective, err := resolveRouting(s, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(effective.Rules) != 2 || effective.Rules[0].Network != "udp" || effective.Rules[1].Network != "tcp" || effective.Groups[0].Selected != "udp" {
		t.Fatal("separate UDP route missing")
	}
	config, err := Generate(s, nodes, nil, t.TempDir(), "test", true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(config)
	if !strings.Contains(string(encoded), `"timeout":"4s"`) || !strings.Contains(string(encoded), `"error_ttl":"30s"`) {
		t.Fatal("DNS timings missing")
	}
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		return
	}
	m, err := NewManager(t.TempDir(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	defer m.cancel()
	path := filepath.Join(m.Run, "config-check.json")
	writeJSON(path, config)
	if err = m.command(30, core, "check", "-c", path); err != nil {
		t.Fatal("real core rejected UDP/DNS config", err)
	}
	if _, _, err = m.subscriptionDownload(Subscription{DownloadVia: "vpn", URL: "https://example.com"}); err == nil {
		t.Fatal("VPN download without core accepted")
	}
}
func TestConnectionsExcludeInternalAndBoundSize(t *testing.T) {
	m, _ := NewManager(t.TempDir(), t.TempDir(), "/bin/true")
	defer m.cancel()
	items := []any{}
	for i := 0; i < 50; i++ {
		items = append(items, Object{"metadata": Object{"host": "example.com", "sourceIP": "192.0.2.2", "network": "udp"}, "chains": []any{"direct"}, "password": "hidden"})
	}
	rows := m.connectionRows(Object{"connections": items})
	b, _ := json.Marshal(rows)
	internal := m.connectionRows(Object{"connections": []any{Object{"metadata": Object{"host": "secret-subscription.example", "type": "mixed/subscription-in"}}}})
	if len(internal) != 0 {
		t.Fatal("internal subscription connection exposed")
	}
	if len(rows) != 32 || strings.Contains(string(b), "hidden") {
		t.Fatal("connection output is unbounded or leaks data")
	}
}

func TestSubscriptionDownloadThroughRealCore(t *testing.T) {
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Skip("native core required")
	}
	socks, port := startSOCKS(t)
	defer socks.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "VPN-Test" {
			t.Error("agent lost through proxy")
		}
		w.Write([]byte("subscription-body"))
	}))
	defer target.Close()
	m, err := NewManager(t.TempDir(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	defer m.cancel()
	s := Defaults()
	s.Enabled = true
	s.Subscriptions = []Subscription{{ID: "sub", Enabled: true, Interval: 24, URL: target.URL}}
	s.Rules = []Rule{{ID: "r", Name: "VPN", Enabled: true, Target: "vpn", Domains: []string{"example.com"}, Nodes: []string{"a"}, Mode: "manual", Selected: "a"}}
	m.Settings = s
	m.Nodes = []Node{{ID: "a", Subscription: "sub", Config: Object{"type": "socks", "server": "127.0.0.1", "server_port": port}}}
	config, err := Generate(s, m.Nodes, nil, m.Run, m.secret, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.startCore(config); err != nil {
		t.Fatal(err)
	}
	defer m.stopCore()
	b, _, err := m.subscriptionDownload(Subscription{URL: target.URL, DownloadVia: "vpn", UserAgent: "VPN-Test"})
	if err != nil || string(b) != "subscription-body" {
		t.Fatal("authenticated VPN download failed", err)
	}
}

func TestSelectionRemapRequiresUniqueEndpoint(t *testing.T) {
	old := Node{ID: "old", Name: "Germany", Subscription: "sub", Config: Object{"type": "trojan", "server": "de.example.com", "server_port": 443, "password": "old"}}
	next := Node{ID: "next", Name: old.Name, Subscription: "sub", Config: Object{"type": "trojan", "server": "de.example.com", "server_port": 443, "password": "new"}}
	s := Defaults()
	s.FinalNodes = []string{"old"}
	s.FinalSelected = "old"
	s.Rules = []Rule{{Nodes: []string{"old"}, Selected: "old", UDPNodes: []string{"old"}, UDPSelected: "old"}}
	p := Subscription{ID: "sub"}
	list := subscriptionCandidate([]Node{old}, []Node{next}, &s, &p)
	if len(list) != 1 || s.FinalSelected != "next" || s.Rules[0].UDPSelected != "next" || p.Warning != "" {
		t.Fatal("unique endpoint rotation lost selection")
	}
	other := next
	other.ID = "ambiguous"
	s.FinalNodes = []string{"old"}
	s.FinalSelected = "old"
	list = subscriptionCandidate([]Node{old}, []Node{next, other}, &s, &p)
	if len(list) != 3 || s.FinalSelected != "old" || p.Warning == "" {
		t.Fatal("ambiguous endpoint must retain previous selection")
	}
}

func TestDNSFallbackWithRealCore(t *testing.T) {
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Skip("native core required")
	}
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	healthy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := healthy.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			reply := append([]byte{}, buf[:n]...)
			reply[2] = 0x81
			reply[3] = 0x80
			reply[6] = 0
			reply[7] = 1
			reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 7)
			healthy.WriteTo(reply, addr)
		}
	}()
	s := Defaults()
	s.DNSTimeout = 2
	s.DNS = []Resolver{{ID: "silent", Address: "udp://" + silent.LocalAddr().String(), Detour: "direct"}, {ID: "healthy", Address: "udp://" + healthy.LocalAddr().String(), Detour: "direct"}}
	m, err := NewManager(t.TempDir(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	defer m.cancel()
	config, err := Generate(s, nil, nil, m.Run, m.secret, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.startCore(config); err != nil {
		t.Fatal(err)
	}
	defer m.stopCore()
	conn, err := net.Dial("udp", "127.0.0.1:5354")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	conn.Write(query)
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil || n < 4 || !reflect.DeepEqual(response[n-4:n], []byte{203, 0, 113, 7}) {
		t.Fatal("DNS did not fall back within configured budget", err)
	}
}
