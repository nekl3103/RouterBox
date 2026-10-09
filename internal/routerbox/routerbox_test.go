package routerbox

import (
	"archive/zip"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testGroup() Group {
	return Group{ID: "main", Name: "Main", Nodes: []string{"a", "b"}, Mode: "fastest", Interval: 300, Timeout: 3, Tolerance: 50, Hold: 300, Failures: 3, Recovery: 2, Window: 30, TestURL: "https://example.com/", Failure: "block"}
}
func TestSubscriptionFormats(t *testing.T) {
	link := "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&type=xhttp&path=%2Fx&mode=stream-one#Demo"
	for _, data := range []string{link, base64.StdEncoding.EncodeToString([]byte(link))} {
		nodes, bad, e := ParseSubscription([]byte(data), "sub")
		if e != nil || len(nodes) != 1 || len(bad) != 0 {
			t.Fatalf("%v %v %v", nodes, bad, e)
		}
		tr := nodes[0].Config["transport"].(map[string]any)
		if tr["type"] != "xhttp" || tr["mode"] != "stream-one" {
			t.Fatal(tr)
		}
	}
	a, _, _ := ParseSubscription([]byte(link), "sub")
	b, _, _ := ParseSubscription([]byte(strings.Replace(link, "#Demo", "#Renamed", 1)), "sub")
	if a[0].ID != b[0].ID {
		t.Fatal("rename changed server identity")
	}
	yaml := `proxies:
 - name: SS
   type: ss
   server: example.com
   port: 443
   cipher: aes-128-gcm
   password: placeholder
 - name: Unsupported
   type: imaginary
`
	nodes, bad, e := ParseSubscription([]byte(yaml), "sub")
	if e != nil || len(nodes) != 1 || len(bad) != 1 || str(nodes[0].Config, "type") != "shadowsocks" {
		t.Fatalf("%v %v %v", nodes, bad, e)
	}
	jsonData := `{"inbounds":[{"type":"mixed","listen":"0.0.0.0"}],"route":{"final":"evil"},"outbounds":[{"type":"direct","tag":"d"},{"type":"trojan","server":"example.com","server_port":443,"password":"placeholder","tag":"T","bind_interface":"wan"}]}`
	nodes, _, e = ParseSubscription([]byte(jsonData), "sub")
	if e != nil || len(nodes) != 1 {
		t.Fatal(e)
	}
	if _, ok := nodes[0].Config["detour"]; ok {
		t.Fatal("injected detour")
	}
	if _, ok := nodes[0].Config["bind_interface"]; ok {
		t.Fatal("injected interface")
	}
	_, bad, e = ParseSubscription([]byte("vless://id@example.com:443?security=reality&pqv=unsupported"), "sub")
	if e != nil || len(bad) != 1 {
		t.Fatal("unsupported extension imported")
	}
}
func TestShadowsocksIPv6AndVMess(t *testing.T) {
	user := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:placeholder"))
	nodes, _, e := ParseSubscription([]byte("ss://"+user+"@[2001:db8::1]:443#SS"), "s")
	if e != nil || len(nodes) != 1 || str(nodes[0].Config, "server") != "2001:db8::1" {
		t.Fatal(e, nodes)
	}
	v := `{"v":"2","ps":"VM","add":"example.com","port":"443","id":"00000000-0000-0000-0000-000000000001","aid":"0","net":"ws","tls":"tls","path":"/x","host":"example.com"}`
	nodes, bad, e := ParseSubscription([]byte("vmess://"+base64.StdEncoding.EncodeToString([]byte(v))), "s")
	if e != nil || len(nodes) != 1 || len(bad) > 0 {
		t.Fatal(e, bad)
	}
}
func archive(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "domains.zip")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	for n, v := range files {
		w, _ := z.Create("domain-list-community-rev/data/" + n)
		_, _ = w.Write([]byte(v))
	}
	_ = z.Close()
	_ = f.Close()
	return path
}
func TestDomainIncludesFiltersAndAffiliations(t *testing.T) {
	db, e := ParseDomainArchive(archive(t, map[string]string{"root": "include:child @ads\nfull:root.example\n", "child": "domain:example.com @ads &virtual\nfull:clean.example @clean\nregexp:^ad[0-9]+\\.example$ @ads\n"}))
	if e != nil {
		t.Fatal(e)
	}
	o, e := db.Resolve("root")
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(o["domain_suffix"], []string{"example.com"}) {
		t.Fatal(o)
	}
	if !reflect.DeepEqual(o["domain"], []string{"root.example"}) {
		t.Fatal("attribute filter", o)
	}
	o, e = db.Resolve("virtual@ads")
	if e != nil || len(o) == 0 {
		t.Fatal("affiliation lost", e)
	}
	if _, e = db.Resolve("root@absent"); e == nil {
		t.Fatal("empty list accepted")
	}
	if !contains(db.Catalogue(), "virtual") {
		t.Fatal("virtual category absent")
	}
	db.Lists["a"] = &DomainList{Includes: []DomainInclude{{Name: "b"}}}
	db.Lists["b"] = &DomainList{Includes: []DomainInclude{{Name: "a"}}}
	if _, e = db.Resolve("a"); e == nil {
		t.Fatal("cycle accepted")
	}
}
func TestSelectionHistoryAndHysteresis(t *testing.T) {
	g := testGroup()
	m := &Manager{health: map[string]*Health{"a": {Up: true, Delay: 100, Success: 1, Jitter: 10}, "b": {Up: true, Delay: 30, Success: 1, Jitter: 20}}, selections: map[string]string{"main": "a"}, switched: map[string]int64{"main": 1000}}
	if got := m.choose(g, 1100); got != "a" {
		t.Fatal("hold ignored", got)
	}
	if got := m.choose(g, 1400); got != "b" {
		t.Fatal("fastest wrong", got)
	}
	g.Mode = "stable"
	if got := m.choose(g, 1400); got != "a" {
		t.Fatal("stability wrong", got)
	}
	g.Mode = "failover"
	if got := m.choose(g, 1400); got != "a" {
		t.Fatal("primary changed", got)
	}
	m.health["a"].Up = false
	if got := m.choose(g, 1400); got != "b" {
		t.Fatal("fallback wrong", got)
	}
	m.health["b"].Up = false
	if got := m.choose(g, 1400); got != "unavailable" {
		t.Fatal("no server must block", got)
	}
	g.Failure = "direct"
	if got := m.choose(g, 1400); got != "direct" {
		t.Fatal("direct fallback ignored", got)
	}
}
func TestMissingServersAndSecretRedaction(t *testing.T) {
	s := Defaults()
	s.Subscriptions = []Subscription{{ID: "sub", URL: "https://example.com/private", Enabled: true, Interval: 24}}
	g := testGroup()
	g.Nodes = []string{"missing"}
	s.Groups = []Group{g}
	if _, e := Generate(s, nil, nil, "/tmp/rb", "secret", true); e == nil {
		t.Fatal("missing server replaced")
	}
	m, e := NewManager(t.TempDir(), t.TempDir(), "missing-core")
	if e != nil {
		t.Fatal(e)
	}
	m.Settings = s
	m.publish()
	b, _ := json.Marshal(m.State())
	if !strings.Contains(string(b), "example.com/private") {
		t.Fatal("subscription URL must be editable as plain text")
	}
	if strings.Contains(string(b), "\"config\"") {
		t.Fatal("node credentials exposed")
	}
}
func TestAtomicPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subdir", "settings.json")
	if e := writeJSON(path, Object{"key": "value"}); e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	var o Object
	if e := loadJSON(path, &o); e != nil || o["key"] != "value" {
		t.Fatal(e, o)
	}
}
func TestGeneratedConfigWithRealCore(t *testing.T) {
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Skip("native core validation")
	}
	s := Defaults()
	s.Subscriptions = []Subscription{{ID: "sub", URL: "https://example.com/sub", Enabled: true, Interval: 24}}
	n, e := makeNode(Object{"type": "shadowsocks", "server": "127.0.0.1", "server_port": 443, "method": "aes-128-gcm", "password": "placeholder"}, "SS", "sub", false)
	if e != nil {
		t.Fatal(e)
	}
	g := testGroup()
	g.Nodes = []string{n.ID}
	g.Selected = n.ID
	s.Groups = []Group{g}
	s.Final = g.ID
	s.Rules = []Rule{{Name: "Test", Enabled: true, Categories: []string{"demo"}, Domains: []string{"*.example.com"}, Sources: []string{"192.168.1.2"}, MACs: []string{"00:11:22:33:44:55"}, Target: g.ID}}
	s.Rules = append(s.Rules, Rule{Name: "DNS test", Enabled: true, Categories: []string{"demo"}, Domains: []string{"example.com"}, Target: g.ID, DNS: "cloudflare"})
	dir := t.TempDir()
	source := filepath.Join(dir, "demo.json")
	_ = writeJSON(source, Object{"version": 3, "rules": []Object{{"domain_suffix": []string{"example.org"}}}})
	binary := filepath.Join(dir, "demo.srs")
	if b, e := exec.Command(core, "rule-set", "compile", "--output", binary, source).CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	for _, mode := range []string{"manual", "fastest", "stable", "failover", "round_robin"} {
		s.Groups[0].Mode = mode
		c, e := Generate(s, []Node{n}, map[string]string{"demo": binary}, dir, "placeholder-secret", true)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(dir, "config.json")
		_ = writeJSON(path, c)
		if b, e := exec.Command(core, "check", "-c", path).CombinedOutput(); e != nil {
			t.Fatalf("%s: %s %v", mode, b, e)
		}
	}
}
func startSOCKS(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				header := make([]byte, 2)
				if _, e := io.ReadFull(c, header); e != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				_, _ = io.ReadFull(c, methods)
				_, _ = c.Write([]byte{5, 0})
				h := make([]byte, 4)
				if _, e = io.ReadFull(c, h); e != nil {
					return
				}
				var host string
				switch h[3] {
				case 1:
					b := make([]byte, 4)
					_, _ = io.ReadFull(c, b)
					host = net.IP(b).String()
				case 3:
					b := make([]byte, 1)
					_, _ = io.ReadFull(c, b)
					name := make([]byte, int(b[0]))
					_, _ = io.ReadFull(c, name)
					host = string(name)
				default:
					return
				}
				p := make([]byte, 2)
				_, _ = io.ReadFull(c, p)
				remote, e := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p)))), time.Second)
				if e != nil {
					return
				}
				defer remote.Close()
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				go io.Copy(remote, c)
				_, _ = io.Copy(c, remote)
			}(conn)
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}
func TestRealCoreHealthAndFailover(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux integration verifies system trust roots")
	}
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Skip("native integration")
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(3 * time.Millisecond); w.WriteHeader(204) }))
	defer target.Close()
	socks, port := startSOCKS(t)
	defer socks.Close()
	m, e := NewManager(t.TempDir(), t.TempDir(), core)
	if e != nil {
		t.Fatal(e)
	}
	m.Settings.Subscriptions = []Subscription{{ID: "sub", URL: "https://example.com/sub", Enabled: true, Interval: 24}}
	n, _ := makeNode(Object{"type": "socks", "server": "127.0.0.1", "server_port": port, "version": "5"}, "live", "sub", false)
	m.Nodes = []Node{n}
	g := testGroup()
	g.Nodes = []string{n.ID}
	g.Mode = "failover"
	g.TestURL = target.URL
	g.Recovery = 1
	g.Failures = 2
	m.Settings.Groups = []Group{g}
	config, e := Generate(m.Settings, m.Nodes, nil, m.Run, m.secret, true)
	if e != nil {
		t.Fatal(e)
	}
	certFile := filepath.Join(m.Run, "test-ca.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600)
	t.Setenv("SSL_CERT_FILE", certFile)
	config["certificate"] = Object{"store": "none", "certificate": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}))}}
	if e = m.startCore(config); e != nil {
		t.Fatal(e)
	}
	defer m.stopCore()
	m.probe(n.ID, g)
	if !m.health[n.ID].Up {
		t.Fatal("real URL test failed", m.health[n.ID])
	}
	if selected := m.choose(g, time.Now().Unix()); selected != n.ID {
		t.Fatal(selected)
	}
	socks.Close()
	m.probe(n.ID, g)
	if !m.health[n.ID].Up {
		t.Fatal("threshold ignored")
	}
	m.probe(n.ID, g)
	if m.health[n.ID].Up {
		t.Fatal("endpoint stayed live")
	}
	if got := m.choose(g, time.Now().Unix()); got != "unavailable" {
		t.Fatal(got)
	}
}

func TestActualDomainCatalogue(t *testing.T) {
	path := os.Getenv("ROUTERBOX_TEST_DOMAINS")
	if path == "" {
		t.Skip("downloaded catalogue")
	}
	db, e := ParseDomainArchive(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []string{"youtube", "telegram", "google", "category-ads-all"} {
		o, e := db.Resolve(c)
		if e != nil || len(o) == 0 {
			t.Fatal(c, e)
		}
	}
	t.Logf("catalogue entries: %d", len(db.Catalogue()))
}
func TestExampleSubscriptionCompatibility(t *testing.T) {
	path, core := os.Getenv("ROUTERBOX_TEST_SUBSCRIPTION"), os.Getenv("ROUTERBOX_TEST_CORE")
	if path == "" || core == "" {
		t.Skip("private example")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	nodes, bad, e := ParseSubscription(b, "private")
	if e != nil || len(nodes) == 0 {
		t.Fatal(e)
	}
	m, e := NewManager(t.TempDir(), t.TempDir(), core)
	if e != nil {
		t.Fatal(e)
	}
	valid := 0
	for _, n := range nodes {
		if m.checkNode(n) == nil {
			valid++
		}
	}
	if valid == 0 {
		t.Fatal("no compatible nodes")
	}
	t.Logf("example: %d imported, %d core-compatible, %d rejected", len(nodes), valid, len(bad))
}

func TestArchiveRevisionChanges(t *testing.T) {
	a, e := ParseDomainArchive(archive(t, map[string]string{"a": "domain:a.example"}))
	if e != nil {
		t.Fatal(e)
	}
	b, e := ParseDomainArchive(archive(t, map[string]string{"a": "domain:b.example"}))
	if e != nil {
		t.Fatal(e)
	}
	if a.Revision == b.Revision {
		t.Fatal("changed upstream lists reused an old generation")
	}
}

func TestSubscriptionCannotReadRouterKeys(t *testing.T) {
	nodes, bad, e := ParseSubscription([]byte(`{"outbounds":[{"type":"ssh","server":"example.com","server_port":22,"private_key_path":"/etc/private"}]}`), "sub")
	if e != nil || len(nodes) != 0 || len(bad) != 1 {
		t.Fatal("local file reference imported", e)
	}
}

func TestRuleScopedAutomaticServers(t *testing.T) {
	s := Defaults()
	s.Subscriptions = []Subscription{{ID: "sub", URL: "https://example.com/sub", Enabled: true, Interval: 24}, {ID: "off", URL: "https://example.com/off", Enabled: false, Interval: 24}}
	s.Rules = []Rule{{ID: "youtube", Name: "YouTube", Enabled: true, Target: "vpn", Mode: "stable", Domains: []string{"youtube.com"}}}
	nodes := []Node{{ID: "a", Subscription: "sub", Config: Object{"type": "socks", "server": "example.com", "server_port": 443}}, {ID: "b", Subscription: "off", Config: Object{"type": "socks", "server": "example.net", "server_port": 443}}}
	effective, err := resolveRouting(s, nodes)
	if err != nil || len(effective.Groups) != 1 || !reflect.DeepEqual(effective.Groups[0].Nodes, []string{"a"}) {
		t.Fatalf("enabled subscriptions: %#v %v", effective.Groups, err)
	}
	if len(s.Groups) != 0 || s.Rules[0].Target != "vpn" {
		t.Fatal("mutated public settings")
	}
	nodes = append(nodes, Node{ID: "c", Subscription: "sub", Config: Object{"type": "socks", "server": "example.org", "server_port": 443}})
	effective, err = resolveRouting(s, nodes)
	if err != nil || !reflect.DeepEqual(effective.Groups[0].Nodes, []string{"a", "c"}) {
		t.Fatal("new subscription server not included")
	}
	config, err := Generate(s, nodes, nil, "/tmp/rb", "secret", true)
	if err != nil {
		t.Fatal(err)
	}
	rules := config["route"].(Object)["rules"].([]Object)
	if rules[len(rules)-1]["outbound"] != "g-route-youtube" {
		t.Fatal("rule-specific selector missing")
	}
	s.Rules[0].Nodes = []string{"b"}
	if _, err = resolveRouting(s, nodes); err == nil {
		t.Fatal("disabled subscription explicitly selected")
	}
}
func TestLegacyRoutingMigration(t *testing.T) {
	s := Defaults()
	g := testGroup()
	s.Groups = []Group{g}
	s.Final = "main"
	s.Rules = []Rule{{Name: "YouTube", Target: "main", Enabled: true, Domains: []string{"youtube.com"}}}
	migrateRouting(&s)
	if len(s.Groups) != 0 || s.Final != "vpn" || s.Rules[0].Target != "vpn" || s.Rules[0].ID == "" || !reflect.DeepEqual(s.Rules[0].Nodes, g.Nodes) {
		t.Fatalf("migration: %#v", s)
	}
	before, _ := json.Marshal(s)
	migrateRouting(&s)
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("migration is not idempotent")
	}
}
func TestSubscriptionTitlesAndServiceValidation(t *testing.T) {
	h := http.Header{"Profile-Title": []string{"base64:" + base64.StdEncoding.EncodeToString([]byte("Моя подписка"))}}
	if subscriptionTitle(h, nil, "https://example.com/sub") != "Моя подписка" {
		t.Fatal("profile title")
	}
	if subscriptionTitle(http.Header{}, []byte(`{"name":"Provider"}`), "https://example.com/sub") != "Provider" {
		t.Fatal("JSON title")
	}
	if subscriptionTitle(http.Header{}, nil, "https://example.com/sub") != "example.com" {
		t.Fatal("hostname fallback")
	}
	if _, err := parseServiceList([]byte("youtube.com\n# comment\nyoutube.com\n"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := parseServiceList([]byte("include:bad"), false); err == nil {
		t.Fatal("untrusted list syntax accepted")
	}
	if _, err := parseServiceList([]byte("149.154.160.0/20\n"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := parseServiceList([]byte("not-a-prefix"), true); err == nil {
		t.Fatal("invalid subnet accepted")
	}
}

func TestActualServiceRules(t *testing.T) {
	if os.Getenv("ROUTERBOX_TEST_SERVICES") == "" {
		t.Skip("optional live upstream test")
	}
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Fatal("core required")
	}
	m, err := NewManager(t.TempDir(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	s := Defaults()
	s.Subscriptions = []Subscription{{ID: "sub", URL: "https://example.com/sub", Enabled: true, Interval: 24}}
	for i, c := range []string{"allow-youtube", "allow-telegram", "allow-meta", "instagram", "openai", "allow-google-ai"} {
		s.Rules = append(s.Rules, Rule{ID: fmt.Sprint(i), Name: c, Enabled: true, Target: "vpn", Categories: []string{c}})
	}
	m.Settings = s
	m.Nodes = []Node{{ID: "a", Subscription: "sub", Config: Object{"type": "socks", "server": "127.0.0.1", "server_port": 1080}}}
	telegram, err := m.resolveService("allow-telegram")
	if err != nil {
		t.Fatal(err)
	}
	alternatives := telegram["rules"].([]Object)
	if !contains(alternatives[0]["domain_suffix"].([]string), "toncenter.com") {
		t.Fatal("extended Telegram domains missing")
	}
	if !contains(alternatives[1]["ip_cidr"].([]string), "2001:67c:4e8::/48") {
		t.Fatal("Telegram IPv6 missing")
	}
	paths, err := m.compileRules(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 6 {
		t.Fatal("selected service sets missing")
	}
	config, err := Generate(s, m.Nodes, paths, m.Run, "secret", true)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(m.Run, "check-services.json")
	if err = writeJSON(file, config); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(core, "check", "-c", file).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
}

func TestAddSubscriptionImportsWithoutEnablingVPN(t *testing.T) {
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Skip("real core needed")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Profile-Title", "Test provider")
		io.WriteString(w, "socks5://127.0.0.1:1080#Demo")
	}))
	defer server.Close()
	m, err := NewManager(t.TempDir(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(Subscription{ID: "new", URL: server.URL, Enabled: false, Interval: 12})
	if err = m.addSubscription(data); err != nil {
		t.Fatal(err)
	}
	if len(m.Nodes) != 1 || m.Settings.Subscriptions[0].Name != "Test provider" || m.Settings.Subscriptions[0].Interval != 12 {
		t.Fatalf("import result: %#v", m.Settings.Subscriptions)
	}
	if m.Settings.Enabled || m.process != nil {
		t.Fatal("subscription import enabled VPN")
	}
	m.publish()
	state := m.State()
	settings := state["settings"].(map[string]any)
	subs := settings["subscriptions"].([]any)
	if subs[0].(map[string]any)["url"] != server.URL {
		t.Fatal("plain URL missing from settings")
	}
}
