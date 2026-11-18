package routerbox

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeDNS answers every A query with 203.0.113.7.
func fakeDNS(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			reply := append([]byte{}, buf[:n]...)
			reply[2], reply[3], reply[6], reply[7] = 0x81, 0x80, 0, 1
			reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 7)
			pc.WriteTo(reply, addr)
		}
	}()
	return pc
}

// resolves reports whether the core's DNS inbound answers the name with the fake address.
func resolves(t *testing.T, name string) bool {
	t.Helper()
	conn, err := net.Dial("udp", "127.0.0.1:5354")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	conn.Write(q)
	r := make([]byte, 512)
	n, err := conn.Read(r)
	return err == nil && n >= 4 && r[3]&0x0f == 0 && string(r[n-4:n]) == string([]byte{203, 0, 113, 7})
}

func testCatalogue(domain string) *DomainDB {
	return &DomainDB{Lists: map[string]*DomainList{"testcat": {Entries: []DomainEntry{{Kind: "domain", Value: domain, Attrs: map[string]bool{}}}}}}
}

// A changed domain list is swapped into the running core: same process, same config,
// new rules active within a second.
func TestDomainListUpdateWithoutCoreRestart(t *testing.T) {
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Skip("native core required")
	}
	dns := fakeDNS(t)
	defer dns.Close()
	m, err := NewManager(t.TempDir(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	defer m.cancel()
	s := Defaults()
	s.Enabled = true
	s.DNSCache = false
	s.DNS = []Resolver{{ID: "fake", Name: "Fake", Address: "udp://" + dns.LocalAddr().String(), Detour: "direct"}}
	s.Rules = []Rule{{ID: "r", Name: "Block test", Enabled: true, Target: "block", Categories: []string{"testcat"}}}
	m.Settings = s

	m.domains = testCatalogue("first.example")
	paths, err := m.compileRules(s)
	if err != nil {
		t.Fatal(err)
	}
	if paths["testcat"] != m.liveRulePath("testcat") {
		t.Fatal("rule-set is not at its stable path", paths)
	}
	probeConfig, _ := Generate(s, nil, paths, m.Run, m.secret, true)
	if err = m.startCore(probeConfig); err != nil {
		t.Fatal(err)
	}
	defer m.stopCore()
	// apply compares against the config the core runs; record the production form of it.
	running, _ := Generate(s, nil, paths, m.Run, m.secret, false)
	if err = writeJSON(filepath.Join(m.Run, "config.json"), running); err != nil {
		t.Fatal(err)
	}
	pid := m.process.Process.Pid
	if resolves(t, "first.example") || !resolves(t, "second.example") {
		t.Fatal("initial rule-set not active")
	}

	// Daily update: the category content changes.
	m.domains = testCatalogue("second.example")
	if err = m.apply(s); err != nil {
		t.Fatal(err)
	}
	if m.process == nil || m.process.Process.Pid != pid {
		t.Fatal("core was restarted for a list update")
	}
	if last := m.events[len(m.events)-1]; !strings.Contains(last, "без перезапуска ядра: 1") {
		t.Fatal("hot swap not reported:", last)
	}
	var after Object
	_ = loadJSON(filepath.Join(m.Run, "config.json"), &after)
	a, _ := json.Marshal(after)
	b, _ := json.Marshal(running)
	if string(a) != string(b) {
		t.Fatal("config changed")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !(resolves(t, "first.example") && !resolves(t, "second.example")) {
		if time.Now().After(deadline) {
			t.Fatal("running core did not reload the new list")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Unchanged content: nothing is recompiled or rewritten on flash.
	info, _ := os.Stat(m.liveRulePath("testcat"))
	m.domains = testCatalogue("second.example")
	if _, err = m.compileRules(s); err != nil || m.rulesSwapped != 0 {
		t.Fatal("unchanged list rewritten", err, m.rulesSwapped)
	}
	again, _ := os.Stat(m.liveRulePath("testcat"))
	if !again.ModTime().Equal(info.ModTime()) {
		t.Fatal("unchanged list touched flash")
	}
}

// Old content-hash directories are removed once the live layout is in use.
func TestLegacyRuleDirectoriesAreCleaned(t *testing.T) {
	m := &Manager{Root: t.TempDir()}
	legacy := filepath.Join(m.Root, "rules", "0123abcd", "rs-x.srs")
	live := m.liveRulePath("testcat")
	for _, p := range []string{legacy, live, live + ".source", filepath.Join(m.Root, "rules", "live", "rs-gone.srs"), filepath.Join(m.Root, "rules", "live", "rs-gone.srs.source")} {
		if err := atomicWrite(p, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m.cleanRules(map[string]string{"testcat": live})
	for _, p := range []string{legacy, filepath.Dir(legacy), filepath.Join(m.Root, "rules", "live", "rs-gone.srs"), filepath.Join(m.Root, "rules", "live", "rs-gone.srs.source")} {
		if fileExists(p) {
			t.Fatal("stale rule data kept", p)
		}
	}
	if !fileExists(live) || !fileExists(live+".source") {
		t.Fatal("live rule-set removed")
	}
}
