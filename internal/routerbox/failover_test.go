package routerbox

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func newSelectionManager() *Manager {
	return &Manager{groupHealth: map[string]*Health{}, health: map[string]*Health{}, selections: map[string]string{}, switched: map[string]int64{}, nextCheck: map[string]int64{}}
}

// After boot or a core restart nothing has been probed yet: traffic must go to a
// server instead of the blocking "unavailable" placeholder.
func TestUncheckedServersAreUsedOptimistically(t *testing.T) {
	g := testGroup()
	m := newSelectionManager()
	if got := m.choose(g, 1000); got != "a" {
		t.Fatal("unchecked group must not block", got)
	}
	m.selections[g.ID] = "b"
	if got := m.choose(g, 1000); got != "b" {
		t.Fatal("previous selection must be kept while unchecked", got)
	}
	g.Mode = "manual"
	g.Selected = "b"
	if got := m.choose(g, 1000); got != "b" {
		t.Fatal("manual server must be used before the first probe", got)
	}
	// Once a server is known to be down the kill switch still applies.
	g.Mode = "fastest"
	m.health["a"] = &Health{Up: false, Failures: 3}
	m.health["b"] = &Health{Up: false, Failures: 3}
	if got := m.choose(g, 1000); got != "unavailable" {
		t.Fatal("known dead servers must block", got)
	}
	g.Mode = "manual"
	if got := m.choose(g, 1000); got != "unavailable" {
		t.Fatal("known dead manual server must block", got)
	}
}

func TestDegradedGroupIsRecheckedQuickly(t *testing.T) {
	g := testGroup()
	m := newSelectionManager()
	m.health["a"] = &Health{Up: true}
	m.selections[g.ID] = "a"
	if got := m.checkDelay(g); got != int64(g.Interval) {
		t.Fatal("healthy group must use its interval", got)
	}
	m.health["a"].Failures = 1
	if got := m.checkDelay(g); got != degradedRecheck {
		t.Fatal("failing selected server must be rechecked quickly", got)
	}
	m.health["a"].Failures = 0
	for _, selected := range []string{"unavailable", "direct", ""} {
		m.selections[g.ID] = selected
		if got := m.checkDelay(g); got != degradedRecheck {
			t.Fatal("group without a live server must recover quickly", selected, got)
		}
	}
	m.selections[g.ID] = "pool-" + g.ID
	if got := m.checkDelay(g); got != int64(g.Interval) {
		t.Fatal("round-robin pool is not degraded", got)
	}
	g.Interval = 10
	m.selections[g.ID] = "unavailable"
	if got := m.checkDelay(g); got != 10 {
		t.Fatal("short interval must not be lengthened", got)
	}
}

func TestRecoveryWithinSecondsAfterOutage(t *testing.T) {
	g := testGroup()
	m := newSelectionManager()
	for i := 0; i < g.Failures; i++ {
		m.recordProbe("a", g, 0, errors.New("down"))
		m.recordProbe("b", g, 0, errors.New("down"))
	}
	if got := m.choose(g, 1000); got != "unavailable" {
		t.Fatal(got)
	}
	m.selections[g.ID] = "unavailable"
	if m.checkDelay(g) != degradedRecheck {
		t.Fatal("outage must switch to quick rechecks")
	}
	for i := 0; i < g.Recovery; i++ {
		m.recordProbe("a", g, 80, nil)
	}
	if got := m.choose(g, 1000); got != "a" {
		t.Fatal("recovered server not selected", got)
	}
}

func TestExitReasonHintsAtMemory(t *testing.T) {
	if got := exitReason(errors.New("signal: killed")); !strings.Contains(got, "памяти") {
		t.Fatal(got)
	}
	if exitReason(nil) != "" {
		t.Fatal("clean exit must have no reason")
	}
}

func TestBatchNodeCheckIsolatesBadServer(t *testing.T) {
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Skip("native core required")
	}
	m, err := NewManager(t.TempDir(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	defer m.cancel()
	nodes := []Node{}
	for i := 0; i < 5; i++ {
		n, _ := makeNode(Object{"type": "socks", "server": "127.0.0.1", "server_port": 1000 + i, "version": "5"}, fmt.Sprint("ok", i), "sub", false)
		nodes = append(nodes, n)
	}
	bad, _ := makeNode(Object{"type": "shadowsocks", "server": "127.0.0.1", "server_port": 8388, "method": "no-such-cipher", "password": "x"}, "bad", "sub", false)
	nodes = append(nodes[:2], append([]Node{bad}, nodes[2:]...)...)
	errs := m.checkNodeBatch(nodes)
	for i, e := range errs {
		if (nodes[i].Name == "bad") != (e != nil) {
			t.Fatal("wrong verdict", nodes[i].Name, e)
		}
	}
}

// A core restart must not leave traffic on the "unavailable" placeholder.
func TestRestartRestoresSelectorImmediately(t *testing.T) {
	core := os.Getenv("ROUTERBOX_TEST_CORE")
	if core == "" {
		t.Skip("native core required")
	}
	m, err := NewManager(t.TempDir(), t.TempDir(), core)
	if err != nil {
		t.Fatal(err)
	}
	defer m.cancel()
	s := Defaults()
	s.Enabled = true
	s.Subscriptions = []Subscription{{ID: "sub", Enabled: true, Interval: 24, URL: "https://example.com/sub"}}
	a, _ := makeNode(Object{"type": "socks", "server": "127.0.0.1", "server_port": 1081, "version": "5"}, "a", "sub", false)
	b, _ := makeNode(Object{"type": "socks", "server": "127.0.0.1", "server_port": 1082, "version": "5"}, "b", "sub", false)
	m.Nodes = []Node{a, b}
	s.Final = "vpn"
	s.FinalNodes = []string{a.ID, b.ID}
	m.Settings = s
	config, err := Generate(s, m.Nodes, nil, m.Run, m.secret, true)
	if err != nil {
		t.Fatal(err)
	}
	// b was the live server before the restart; a is known dead.
	m.groupHealth["vpn-default/"+a.ID] = &Health{Up: false, Failures: 3}
	m.groupHealth["vpn-default/"+b.ID] = &Health{Up: true, Delay: 50, Success: 1}
	m.selections["vpn-default"] = b.ID
	if err = m.startCore(config); err != nil {
		t.Fatal(err)
	}
	defer m.stopCore()
	m.restoreSelections()
	o, err := m.coreAPI("GET", "/proxies/g-vpn-default", nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if now := str(o, "now"); now != "n-"+b.ID {
		t.Fatal("selector left at", now)
	}
}
