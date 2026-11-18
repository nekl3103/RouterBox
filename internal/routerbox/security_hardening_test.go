package routerbox

import (
	"encoding/json"
	"strings"
	"testing"
)

const secretURL = "https://panel.example.com:8443/sub/7f3c9e1d-token?flag=1"

// LuCI read access must not reveal the subscription token, and saving from the UI
// (which only has the redacted form) must keep the stored URL.
func TestSubscriptionURLIsNotPublished(t *testing.T) {
	m, err := NewManager(t.TempDir(), t.TempDir(), "missing-core")
	if err != nil {
		t.Fatal(err)
	}
	m.Settings.Subscriptions = []Subscription{{ID: "sub", Name: "Main", URL: secretURL, Enabled: true, Interval: 24}}
	m.publish()
	raw, _ := json.Marshal(m.State())
	if strings.Contains(string(raw), "7f3c9e1d-token") || strings.Contains(string(raw), "/sub/") {
		t.Fatal("subscription token published:", string(raw))
	}
	var state struct {
		Settings Settings `json:"settings"`
	}
	_ = json.Unmarshal(raw, &state)
	ui := state.Settings
	if !ui.Subscriptions[0].HasURL || ui.Subscriptions[0].URLHost != "https://panel.example.com:8443" {
		t.Fatal("host summary missing", ui.Subscriptions[0])
	}
	// The UI sends back what it received, with a changed interval.
	ui.Subscriptions[0].Interval = 12
	data, _ := json.Marshal(ui)
	if err = m.perform("save", data); err != nil {
		t.Fatal(err)
	}
	saved := m.Settings.Subscriptions[0]
	if saved.URL != secretURL || saved.Interval != 12 || saved.URLHost != "" || saved.HasURL {
		t.Fatal("stored URL lost or display fields persisted", saved)
	}
	// A new URL typed in the dialog replaces the stored one.
	ui.Subscriptions[0].URL = "https://other.example.com/new"
	data, _ = json.Marshal(ui)
	if err = m.perform("save", data); err != nil {
		t.Fatal(err)
	}
	if m.Settings.Subscriptions[0].URL != "https://other.example.com/new" {
		t.Fatal("URL change ignored")
	}
}

func TestSubscriptionTransportWarnings(t *testing.T) {
	secure := Node{Config: Object{"type": "trojan", "tls": map[string]any{"enabled": true}}}
	insecure := Node{Config: Object{"type": "trojan", "tls": map[string]any{"enabled": true, "insecure": true}}}
	if got := subscriptionRisks(Subscription{URL: "https://example.com/s"}, []Node{secure}); got != "" {
		t.Fatal("false warning", got)
	}
	got := subscriptionRisks(Subscription{URL: "HTTP://example.com/s"}, []Node{secure, insecure, insecure})
	if !strings.Contains(got, "HTTP без шифрования") || !strings.Contains(got, "TLS-сертификата: 2") {
		t.Fatal("warnings missing", got)
	}
}
