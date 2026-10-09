package routerbox

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Sample struct {
	Time  int64 `json:"time"`
	Delay int   `json:"delay"`
	OK    bool  `json:"ok"`
}
type Health struct {
	Samples  []Sample `json:"samples"`
	Delay    int      `json:"delay"`
	Success  float64  `json:"success"`
	Jitter   float64  `json:"jitter"`
	Failures int      `json:"failures"`
	Recovery int      `json:"recovery"`
	Checked  int64    `json:"checked"`
	Up       bool     `json:"up"`
}
type Job struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}
type Manager struct {
	groupHealth             map[string]*Health
	ctx                     context.Context
	cancel                  context.CancelFunc
	Root, Run, CoreOverride string
	Settings                Settings
	Nodes                   []Node
	domains                 *DomainDB
	op                      sync.Mutex
	jobsMu                  sync.Mutex
	job                     Job
	snapshot                atomic.Value
	health                  map[string]*Health
	selections              map[string]string
	switched                map[string]int64
	nextCheck               map[string]int64
	nextRefresh             int64
	lastRules               int64
	process                 *exec.Cmd
	exited                  chan error
	secret                  string
	events                  []string
	traffic                 Object
	connections             []Object
	stopping                bool
	lastRetry               int64
}

func NewManager(root, run, core string) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{ctx: ctx, cancel: cancel, groupHealth: map[string]*Health{}, Root: root, Run: run, CoreOverride: core, Settings: Defaults(), health: map[string]*Health{}, selections: map[string]string{}, switched: map[string]int64{}, nextCheck: map[string]int64{}}
	if e := os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(run, 0700); e != nil {
		return nil, e
	}
	if e := loadJSON(filepath.Join(root, "settings.json"), &m.Settings); e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if e := loadJSON(filepath.Join(root, "nodes.json"), &m.Nodes); e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return nil, e
	}
	m.secret = hex.EncodeToString(b)
	m.loadUCI()
	migrateRouting(&m.Settings)
	m.publish()
	return m, nil
}
func fetchContext(ctx context.Context, address string, limit int64) ([]byte, error) {
	b, _, err := fetchDocument(ctx, address, limit)
	return b, err
}
func (m *Manager) commandContext() context.Context {
	if m.stopping {
		return context.Background()
	}
	return m.ctx
}
func (m *Manager) command(seconds int, bin string, args ...string) error {
	ctx, cancel := context.WithTimeout(m.commandContext(), time.Duration(seconds)*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bin, args...).Run()
}
func (m *Manager) fetch(address string, limit int64) ([]byte, error) {
	return fetchContext(m.ctx, address, limit)
}
func freeBytes(path string) uint64 {
	var s syscall.Statfs_t
	if syscall.Statfs(path, &s) != nil {
		return 0
	}
	return uint64(s.Bavail) * uint64(s.Bsize)
}
func availableMemory(fallback uint64) uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return fallback
	}
	for _, line := range strings.Split(string(data), "\n") {
		var kb uint64
		if strings.HasPrefix(line, "MemAvailable:") {
			if _, err := fmt.Sscanf(line, "MemAvailable: %d kB", &kb); err == nil {
				return kb * 1024
			}
		}
	}
	return fallback
}
func (m *Manager) corePath() string {
	if m.CoreOverride != "" {
		return m.CoreOverride
	}
	return filepath.Join(m.Run, "sing-box")
}
func (m *Manager) ensureCore() error {
	if m.CoreOverride != "" {
		if _, e := os.Stat(m.CoreOverride); e == nil {
			return nil
		}
		return errors.New("ядро не найдено")
	}
	var info struct {
		SHA  string `json:"sha256"`
		Size int64  `json:"size"`
	}
	if e := loadJSON("/usr/share/routerbox/core.json", &info); e != nil {
		return errors.New("нет описания ядра")
	}
	if m.Settings.Storage == "ram" {
		info.SHA = m.Settings.CoreSHA
		info.Size = m.Settings.CoreSize
	}
	marker := filepath.Join(m.Run, "core.sha")
	if b, e := os.ReadFile(marker); e == nil && string(b) == info.SHA {
		if st, e := os.Stat(m.corePath()); e == nil && st.Size() == info.Size {
			return nil
		}
	}
	archive := "/usr/lib/routerbox/sing-box.gz"
	if m.Settings.Storage == "ram" {
		if m.Settings.CoreURL == "" {
			return errors.New("для RAM задайте URL, SHA256 архива и размер распакованного ядра")
		}
		info.SHA = m.Settings.CoreSHA
		info.Size = m.Settings.CoreSize
		if freeBytes(m.Run) < uint64(info.Size+32<<20) {
			return errors.New("недостаточно RAM для загрузки ядра")
		}
		b, e := m.fetch(m.Settings.CoreURL, 40<<20)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != info.SHA {
			return errors.New("SHA256 архива ядра не совпадает")
		}
		archive = filepath.Join(m.Run, "core.gz")
		if e = atomicWrite(archive, b, 0600); e != nil {
			return e
		}
		defer os.Remove(archive)
	}
	if info.Size < 1 || freeBytes(m.Run) < uint64(info.Size+24<<20) {
		return errors.New("недостаточно свободной RAM для распаковки ядра")
	}
	f, e := os.Open(archive)
	if e != nil {
		return errors.New("нет архива ядра: установите пакет ядра или настройте RAM-загрузку")
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return e
	}
	if hex.EncodeToString(h.Sum(nil)) != info.SHA {
		return errors.New("SHA256 ядра не совпадает")
	}
	if _, e = f.Seek(0, 0); e != nil {
		return e
	}
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tmp := m.corePath() + ".new"
	out, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
	if e != nil {
		return e
	}
	defer os.Remove(tmp)
	n, e := io.Copy(out, io.LimitReader(gz, info.Size+1))
	ce := out.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if n != info.Size {
		return errors.New("размер ядра не совпадает")
	}
	if e := os.Rename(tmp, m.corePath()); e != nil {
		return e
	}
	return atomicWrite(marker, []byte(info.SHA), 0600)
}
func (m *Manager) event(s string) {
	m.events = append(m.events, time.Now().Format("15:04:05")+" "+s)
	if len(m.events) > 100 {
		m.events = m.events[len(m.events)-100:]
	}
}
func (m *Manager) publish() {
	s := m.Settings
	s.Subscriptions = append([]Subscription{}, s.Subscriptions...)
	for i := range s.Subscriptions {
		s.Subscriptions[i].HasURL = s.Subscriptions[i].URL != ""
	}
	s.CoreURL = ""
	visible := []Object{}
	for _, n := range m.Nodes {
		h := m.health[n.ID]
		if h == nil {
			h = &Health{Samples: []Sample{}}
		}
		server, port := str(n.Config, "server"), n.Config["server_port"]
		if n.Endpoint {
			if peers, ok := n.Config["peers"].([]any); ok && len(peers) > 0 {
				if peer, ok := peers[0].(map[string]any); ok {
					server = str(peer, "address")
					port = peer["port"]
				}
			}
		}
		visible = append(visible, Object{"id": n.ID, "name": n.Name, "subscription": n.Subscription, "protocol": str(n.Config, "type"), "server": server, "port": port, "health": h})
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	catalogue := Object{}
	_ = loadJSON(filepath.Join(m.Root, "catalogue.json"), &catalogue)
	devices := []Object{}
	if b, e := os.ReadFile("/tmp/dhcp.leases"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				devices = append(devices, Object{"mac": fields[1], "ip": fields[2], "name": fields[3]})
			}
		}
	}
	b, _ := json.Marshal(Object{"version": Version, "core_version": CoreVersion, "running": m.process != nil, "settings": s, "nodes": visible, "selections": m.selections, "events": append([]string{}, m.events...), "devices": devices, "traffic": nonNilObject(m.traffic), "connections": m.connections, "catalogue": catalogue, "storage": Object{"flash_free": freeBytes(m.Root), "ram_free": freeBytes(m.Run), "mem_available": availableMemory(freeBytes(m.Run)), "controller_heap": mem.HeapAlloc}})
	m.snapshot.Store(b)
}
func (m *Manager) State() Object {
	var o Object
	_ = json.Unmarshal(m.snapshot.Load().([]byte), &o)
	m.jobsMu.Lock()
	o["job"] = m.job
	m.jobsMu.Unlock()
	return o
}
func (m *Manager) Submit(action string, data json.RawMessage) (Object, error) {
	m.jobsMu.Lock()
	if m.job.Status == "running" {
		m.jobsMu.Unlock()
		return nil, errors.New("дождитесь завершения текущей операции")
	}
	m.job = Job{ID: fmt.Sprint(time.Now().UnixNano()), Action: action, Status: "running"}
	job := m.job
	m.jobsMu.Unlock()
	go func() {
		m.op.Lock()
		defer m.op.Unlock()
		e := m.perform(action, data)
		if e != nil {
			m.event(e.Error())
		}
		m.publish()
		m.jobsMu.Lock()
		m.job.Status = "done"
		if e != nil {
			m.job.Status = "error"
			m.job.Error = e.Error()
		}
		m.jobsMu.Unlock()
	}()
	return Object{"job": job}, nil
}
func (m *Manager) perform(action string, data json.RawMessage) error {
	switch action {
	case "subscription":
		return m.addSubscription(data)
	case "save":
		var s Settings
		if e := json.Unmarshal(data, &s); e != nil {
			return errors.New("некорректные настройки")
		}
		for i := range s.Subscriptions {
			for _, old := range m.Settings.Subscriptions {
				if old.ID == s.Subscriptions[i].ID {
					if s.Subscriptions[i].URL == "" {
						s.Subscriptions[i].URL = old.URL
					}
					s.Subscriptions[i].Updated = old.Updated
					s.Subscriptions[i].Rejected = old.Rejected
					s.Subscriptions[i].Error = old.Error
					s.Subscriptions[i].Attempted = old.Attempted
					s.Subscriptions[i].Added = old.Added
					s.Subscriptions[i].Removed = old.Removed
					s.Subscriptions[i].Duplicates = old.Duplicates
					s.Subscriptions[i].Warning = old.Warning
				}
			}
		}
		if s.CoreURL == "" {
			s.CoreURL = m.Settings.CoreURL
		}
		if e := validate(s); e != nil {
			return e
		}
		if e := m.apply(s); e != nil {
			return e
		}
		subs := map[string]bool{}
		for _, p := range s.Subscriptions {
			subs[p.ID] = true
		}
		filtered := []Node{}
		for _, node := range m.Nodes {
			if subs[node.Subscription] {
				filtered = append(filtered, node)
			}
		}
		m.Nodes = filtered
		return writeJSON(filepath.Join(m.Root, "nodes.json"), m.Nodes)
	case "refresh":
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(data, &p)
		return m.refresh(p.ID)
	case "catalogue":
		if e := m.ensureDomainDB(); e != nil {
			return e
		}
		m.domains = nil
		m.event("Каталог доменов загружен")
		return nil
	case "rules":
		m.domains = nil
		os.Remove(filepath.Join(m.Run, "domains.zip"))
		if e := m.apply(m.Settings); e != nil {
			return e
		}
		m.lastRules = time.Now().Unix()
		return nil
	case "check":
		var p struct {
			IDs []string `json:"ids"`
		}
		_ = json.Unmarshal(data, &p)
		if m.process == nil {
			return errors.New("сначала запустите службу с выбранными серверами")
		}
		return m.checkNodes(p.IDs)
	case "start":
		s := m.Settings
		s.Enabled = true
		return m.apply(s)
	case "stop":
		s := m.Settings
		s.Enabled = false
		return m.apply(s)
	default:
		return errors.New("неизвестная операция")
	}
}
func (m *Manager) checkNode(n Node) error {
	o := copyObject(n.Config)
	o["tag"] = "test"
	c := Object{"log": Object{"disabled": true}, "outbounds": []Object{{"type": "direct", "tag": "direct"}}}
	if n.Endpoint {
		c["endpoints"] = []Object{o}
	} else {
		c["outbounds"] = []Object{o}
	}
	path := filepath.Join(m.Run, "node-check.json")
	defer os.Remove(path)
	if e := writeJSON(path, c); e != nil {
		return e
	}
	if e := m.command(15, m.corePath(), "check", "-c", path); e != nil {
		return errors.New("параметры не поддерживаются установленной сборкой ядра")
	}
	return nil
}
func (m *Manager) network(action string, s Settings) error {
	if m.CoreOverride != "" {
		return nil
	}
	if e := writeJSON(filepath.Join(m.Run, "network.json"), s); e != nil {
		return e
	}
	return m.command(25, "/usr/lib/routerbox/network", action)
}
func (m *Manager) stopCore() {
	m.connections = nil
	if m.process == nil {
		return
	}
	_ = m.process.Process.Signal(syscall.SIGTERM)
	select {
	case <-m.exited:
	case <-time.After(5 * time.Second):
		_ = m.process.Process.Kill()
		<-m.exited
	}
	m.process = nil
	m.exited = nil
}
func (m *Manager) startCore(config Object) error {
	path := filepath.Join(m.Run, "config.json")
	if e := writeJSON(path, config); e != nil {
		return e
	}
	cmd := exec.Command(m.corePath(), "run", "-c", path)
	log := &coreLog{}
	cmd.Stderr = log
	cmd.Env = append(os.Environ(), "GOMEMLIMIT=80MiB", "GOGC=50", "GOMAXPROCS=2")
	if e := cmd.Start(); e != nil {
		return errors.New("не удалось запустить ядро")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	m.process = cmd
	m.exited = done
	for i := 0; i < 60; i++ {
		select {
		case <-done:
			_ = atomicWrite(filepath.Join(m.Run, "core-error.log"), log.data(), 0600)
			m.process = nil
			m.exited = nil
			return errors.New("ядро завершилось при запуске")
		default:
		}
		if _, e := m.coreAPI("GET", "/version", nil, 2); e == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	m.stopCore()
	return errors.New("ядро не прошло проверку запуска")
}

// Keep startup diagnostics bounded and in RAM; do not expose server credentials in RPC.
type coreLog struct {
	sync.Mutex
	buffer bytes.Buffer
}

func (l *coreLog) Write(p []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	n := len(p)
	remaining := (64 << 10) - l.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = l.buffer.Write(p)
	}
	return n, nil
}
func (l *coreLog) data() []byte {
	l.Lock()
	defer l.Unlock()
	return append([]byte{}, l.buffer.Bytes()...)
}
func (m *Manager) apply(s Settings) error {
	old := m.Settings
	var oldConfig Object
	_ = loadJSON(filepath.Join(m.Run, "config.json"), &oldConfig)
	if !s.Enabled {
		m.stopCore()
		if e := m.configureDNS(false); e != nil {
			return e
		}
		if e := m.network("stop", s); e != nil {
			return errors.New("не удалось восстановить сеть")
		}
		if e := m.persistSettings(s); e != nil {
			return e
		}
		m.Settings = s
		m.pruneHealth(s)
		m.event("Служба отключена")
		return nil
	}
	if e := validate(s); e != nil {
		return e
	}
	m.Settings = s
	beforeSHA, _ := os.ReadFile(filepath.Join(m.Run, "core.sha"))
	if e := m.ensureCore(); e != nil {
		m.Settings = old
		return e
	}
	committedRules := false
	preserve := map[string]string{}
	var diskGood Object
	_ = loadJSON(filepath.Join(m.Root, "last-good.json"), &diskGood)
	for _, cfg := range []Object{oldConfig, diskGood} {
		if route, ok := cfg["route"].(map[string]any); ok {
			if sets, ok := route["rule_set"].([]any); ok {
				for _, v := range sets {
					if set, ok := v.(map[string]any); ok {
						path := str(set, "path")
						if path != "" {
							preserve[path] = path
						}
					}
				}
			}
		}
	}
	defer func() {
		if !committedRules {
			m.cleanRules(preserve)
		}
	}()
	paths, e := m.compileRules(s)
	if e != nil {
		m.Settings = old
		return e
	}
	config, e := Generate(s, m.Nodes, paths, m.Run, m.secret, false)
	if e != nil {
		m.Settings = old
		return e
	}
	afterSHA, _ := os.ReadFile(filepath.Join(m.Run, "core.sha"))
	nextBytes, _ := json.Marshal(config)
	oldBytes, _ := json.Marshal(oldConfig)
	if m.process != nil && string(beforeSHA) == string(afterSHA) && string(nextBytes) == string(oldBytes) {
		if e = m.persistSettings(s); e != nil {
			m.Settings = old
			return e
		}
		m.Settings = s
		m.pruneHealth(s)
		m.nextCheck = map[string]int64{}
		m.lastRules = time.Now().Unix()
		committedRules = true
		m.event("Настройки сохранены; конфигурация ядра не изменилась")
		return nil
	}
	candidate := filepath.Join(m.Run, "candidate.json")
	defer os.Remove(candidate)
	if e = writeJSON(candidate, config); e != nil {
		m.Settings = old
		return e
	}
	if e = m.command(30, m.corePath(), "check", "-c", candidate); e != nil {
		m.Settings = old
		return errors.New("ядро отклонило конфигурацию")
	}
	if e = m.network("guard", s); e != nil {
		m.Settings = old
		return errors.New("не удалось установить защитные правила")
	}
	m.stopCore()
	e = m.startCore(config)
	if e == nil {
		e = m.network("start", s)
	}
	if e == nil {
		e = m.configureDNS(true)
	}
	if e == nil {
		e = m.persistSettings(s)
	}
	if e != nil {
		m.stopCore()
		m.Settings = old
		if old.Enabled && oldConfig != nil {
			_ = m.network("guard", old)
			if rollback := m.startCore(oldConfig); rollback == nil {
				_ = m.network("start", old)
				_ = m.configureDNS(true)
				m.event("Восстановлена предыдущая конфигурация")
			}
		} else {
			_ = m.configureDNS(false)
			_ = m.network("stop", old)
		}
		return errors.New("применение не удалось; выполнен возврат к предыдущей конфигурации")
	}
	if e = writeJSON(filepath.Join(m.Root, "last-good.json"), config); e != nil {
		m.event("Не удалось сохранить конфигурацию восстановления")
	}
	m.Settings = s
	m.pruneHealth(s)
	m.lastRules = time.Now().Unix()
	m.selections = map[string]string{}
	m.nextCheck = map[string]int64{}
	m.event("Настройки применены")
	committedRules = true
	m.cleanRules(paths)
	return nil
}
func (m *Manager) cleanRules(paths map[string]string) {
	keep := map[string]bool{}
	for _, p := range paths {
		keep[p] = true
	}
	_ = filepath.WalkDir(filepath.Join(m.Root, "rules"), func(path string, d os.DirEntry, e error) error {
		if e == nil && !d.IsDir() && strings.HasSuffix(path, ".srs") && !keep[path] {
			_ = os.Remove(path)
		}
		return nil
	})
}
func (m *Manager) coreAPI(method, path string, body any, timeout int) (Object, error) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
	}
	req, _ := http.NewRequestWithContext(m.ctx, method, "http://127.0.0.1:9097"+path, reader)
	req.Header.Set("Authorization", "Bearer "+m.secret)
	req.Header.Set("Content-Type", "application/json")
	res, e := (&http.Client{Timeout: time.Duration(timeout) * time.Second}).Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return nil, errors.New("ошибка API ядра")
	}
	o := Object{}
	if res.StatusCode != 204 {
		_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&o)
	}
	return o, nil
}
func (m *Manager) checkNodes(ids []string) error {
	known := map[string]bool{}
	for _, g := range m.runtimeGroups() {
		for _, id := range g.Nodes {
			known[id] = true
		}
	}
	if len(ids) == 0 {
		for id := range known {
			ids = append(ids, id)
		}
	}
	if len(ids) > 256 {
		return errors.New("слишком много серверов для проверки")
	}
	for _, id := range ids {
		if !known[id] {
			return errors.New("проверять можно серверы сохранённых VPN-правил")
		}
		g := Group{}
		for _, candidate := range m.runtimeGroups() {
			if contains(candidate.Nodes, id) {
				g = candidate
				break
			}
		}
		m.probe(id, g)
	}
	m.event("Проверка серверов завершена")
	return nil
}
func (m *Manager) probe(id string, g Group) {
	o, e := m.coreAPI("GET", "/proxies/"+url.PathEscape("n-"+id)+"/delay?timeout="+fmt.Sprint(g.Timeout*1000)+"&url="+url.QueryEscape(g.TestURL), nil, g.Timeout+2)
	delay := 0
	if e == nil {
		if n, ok := o["delay"].(float64); ok && n > 0 {
			delay = int(n)
		} else {
			e = errors.New("нет результата")
		}
	}
	key := g.ID + "/" + id
	h := m.groupHealth[key]
	if h == nil {
		h = &Health{}
		m.groupHealth[key] = h
	}
	m.health[id] = h
	h.Samples = append(h.Samples, Sample{Time: time.Now().Unix(), Delay: delay, OK: e == nil})
	if len(h.Samples) > 120 {
		h.Samples = h.Samples[len(h.Samples)-120:]
	}
	h.Checked = time.Now().Unix()
	h.Delay = delay
	if e != nil {
		h.Failures++
		h.Recovery = 0
	} else {
		h.Failures = 0
		h.Recovery++
	}
	if h.Failures >= g.Failures {
		h.Up = false
	}
	if h.Recovery >= g.Recovery {
		h.Up = true
	}
	summarize(h, g.Window)
}
func summarize(h *Health, window int) {
	samples := h.Samples
	if len(samples) > window {
		samples = samples[len(samples)-window:]
	}
	if len(samples) == 0 {
		return
	}
	success, total, previous, jitter := 0, 0, 0, 0
	for _, s := range samples {
		if s.OK {
			success++
			total += s.Delay
			if previous > 0 {
				d := s.Delay - previous
				if d < 0 {
					d = -d
				}
				jitter += d
			}
			previous = s.Delay
		}
	}
	h.Success = float64(success) / float64(len(samples))
	if success > 0 {
		h.Delay = total / success
	}
	if success > 1 {
		h.Jitter = float64(jitter) / float64(success-1)
	}
}
func (m *Manager) healthFor(group, id string) *Health {
	if h := m.groupHealth[group+"/"+id]; h != nil {
		return h
	}
	return m.health[id]
}
func (m *Manager) choose(g Group, now int64) string {
	live := []string{}
	for _, id := range g.Nodes {
		h := m.healthFor(g.ID, id)
		if h != nil && h.Up {
			live = append(live, id)
		}
	}
	current := m.selections[g.ID]
	if g.Mode == "manual" {
		if contains(live, g.Selected) {
			return g.Selected
		}
		if g.Failure == "direct" {
			return "direct"
		}
		return "unavailable"
	}
	if len(live) == 0 {
		if g.Failure == "direct" {
			return "direct"
		}
		return "unavailable"
	}
	if g.Mode == "failover" {
		if contains(live, current) {
			return current
		}
		return live[0]
	}
	sort.SliceStable(live, func(i, j int) bool {
		a, b := m.healthFor(g.ID, live[i]), m.healthFor(g.ID, live[j])
		if g.Mode == "stable" {
			if a.Success != b.Success {
				return a.Success > b.Success
			}
			if a.Jitter != b.Jitter {
				return a.Jitter < b.Jitter
			}
		}
		return a.Delay < b.Delay
	})
	best := live[0]
	if contains(live, current) && current != best {
		if now-m.switched[g.ID] < int64(g.Hold) {
			return current
		}
		a, b := m.healthFor(g.ID, current), m.healthFor(g.ID, best)
		if g.Mode == "fastest" && a.Delay-b.Delay < g.Tolerance {
			return current
		}
		if g.Mode == "stable" && b.Success-a.Success < 0.03 && a.Jitter-b.Jitter < float64(g.Tolerance) && a.Delay-b.Delay < g.Tolerance {
			return current
		}
	}
	return best
}
func (m *Manager) tick() {
	select {
	case <-m.ctx.Done():
		return
	default:
	}
	if !m.op.TryLock() {
		return
	}
	defer m.op.Unlock()
	now := time.Now().Unix()
	if m.process != nil {
		select {
		case <-m.exited:
			m.process = nil
			m.exited = nil
			m.event("Ядро завершилось; применяется политика отказа")
			_ = m.network("crash", m.Settings)
			if m.Settings.Failure == "direct" {
				_ = m.configureDNS(false)
			}
		default:
		}
	}
	if m.Settings.Enabled && m.process == nil && now-m.lastRetry >= 30 {
		m.lastRetry = now
		if e := m.apply(m.Settings); e != nil {
			m.event(e.Error())
			var good Object
			if m.process == nil && loadJSON(filepath.Join(m.Root, "last-good.json"), &good) == nil {
				if api, ok := good["experimental"].(map[string]any); ok {
					if clash, ok := api["clash_api"].(map[string]any); ok {
						clash["secret"] = m.secret
					}
				}
				_ = m.network("guard", m.Settings)
				if m.startCore(good) == nil {
					_ = m.configureDNS(true)
					m.event("Запущена последняя рабочая конфигурация")
				}
			}
		}
	}
	if m.process != nil {
		for _, g := range m.runtimeGroups() {

			if now < m.nextCheck[g.ID] {
				continue
			}
			m.nextCheck[g.ID] = now + int64(g.Interval)
			for _, id := range g.Nodes {
				m.probe(id, g)
				if h := m.health[id]; len(h.Samples) == 1 && h.Failures == 0 {
					for i := 1; i < g.Recovery; i++ {
						m.probe(id, g)
					}
				}
			}
			m.nextCheck[g.ID] = time.Now().Unix() + int64(g.Interval)
			selected := m.choose(g, now)
			tag := "n-" + selected
			if g.Mode == "round_robin" && selected != "direct" && selected != "unavailable" {
				selected = "pool-" + g.ID
				tag = selected
			}
			if selected == "direct" || selected == "unavailable" {
				tag = selected
			}
			if selected != m.selections[g.ID] {
				if _, e := m.coreAPI("PUT", "/proxies/"+url.PathEscape(groupTag(g.ID)), Object{"name": tag}, 3); e == nil {
					m.selections[g.ID] = selected
					m.switched[g.ID] = now
					m.event("Группа «" + g.Name + "»: сервер переключён")
				}
			}
		}
	}
	if m.process != nil {
		if o, e := m.coreAPI("GET", "/connections", nil, 2); e == nil {
			m.traffic = Object{"upload": o["uploadTotal"], "download": o["downloadTotal"], "core_memory": o["memory"]}
			m.connections = m.connectionRows(o)
		}
	}
	due := false
	for _, p := range m.Settings.Subscriptions {
		if p.Enabled && now-p.Updated >= int64(p.Interval)*3600 {
			due = true
		}
	}
	if due && now >= m.nextRefresh {
		m.nextRefresh = now + 300
		_ = m.refresh("__due__")
	}
	if m.Settings.Enabled && len(selectedCategories(m.Settings)) > 0 && now-m.lastRules >= int64(m.Settings.RulesInterval)*3600 {
		m.lastRules = now
		m.domains = nil
		os.Remove(filepath.Join(m.Run, "domains.zip"))
		if e := m.apply(m.Settings); e != nil {
			m.event(e.Error())
			var good Object
			if m.process == nil && loadJSON(filepath.Join(m.Root, "last-good.json"), &good) == nil {
				if api, ok := good["experimental"].(map[string]any); ok {
					if clash, ok := api["clash_api"].(map[string]any); ok {
						clash["secret"] = m.secret
					}
				}
				_ = m.network("guard", m.Settings)
				if m.startCore(good) == nil {
					_ = m.configureDNS(true)
					m.event("Запущена последняя рабочая конфигурация")
				}
			}
		}
	}
	m.publish()
}
func (m *Manager) Serve() error {
	socket := filepath.Join(m.Run, "control.sock")
	os.Remove(socket)
	ln, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer ln.Close()
	os.Chmod(socket, 0600)
	server := &http.Server{ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		method := strings.TrimPrefix(r.URL.Path, "/")
		if method == "state" {
			_ = json.NewEncoder(w).Encode(m.State())
			return
		}
		data, e := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		if e != nil || len(data) > 1<<20 {
			_ = json.NewEncoder(w).Encode(Object{"error": "слишком большой запрос"})
			return
		}
		o, e := m.Submit(method, data)
		if e != nil {
			o = Object{"error": e.Error()}
		}
		_ = json.NewEncoder(w).Encode(o)
	})}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			m.tick()
		}
	}()
	if m.Settings.Enabled {
		m.op.Lock()
		// Restore the validated configuration before downloading lists: dnsmasq may
		// already use this core as its upstream after a restart or power loss.
		var good Object
		if m.ensureCore() == nil && loadJSON(filepath.Join(m.Root, "last-good.json"), &good) == nil {
			if experimental, ok := good["experimental"].(map[string]any); ok {
				if api, ok := experimental["clash_api"].(map[string]any); ok {
					api["secret"] = m.secret
				}
			}
			_ = m.network("guard", m.Settings)
			if m.startCore(good) == nil {
				_ = m.configureDNS(true)
			}
		}
		m.publish()
		m.op.Unlock()
		_, _ = m.Submit("start", nil)
	}
	return server.Serve(ln)
}
func (m *Manager) Shutdown() {
	m.cancel()
	m.op.Lock()
	defer m.op.Unlock()
	m.stopping = true
	m.stopCore()
	_ = m.network("crash", m.Settings)
	if m.Settings.Failure == "direct" {
		_ = m.configureDNS(false)
	}
}
func Relay(run, method string, b []byte) ([]byte, error) {
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(run, "control.sock"))
	}}}
	res, e := client.Post("http://localhost/"+method, "application/json", strings.NewReader(string(b)))
	if e != nil {
		return nil, errors.New("служба RouterBox не запущена")
	}
	defer res.Body.Close()
	return io.ReadAll(io.LimitReader(res.Body, 2<<20))
}

// Cleanup restores only options and firewall state owned by RouterBox.
func (m *Manager) Cleanup() error {
	m.stopCore()
	if e := m.configureDNS(false); e != nil {
		return e
	}
	s := m.Settings
	s.Enabled = false
	if e := m.network("stop", s); e != nil {
		return e
	}
	return m.persistSettings(s)
}

func (m *Manager) pruneHealth(s Settings) {
	if effective, err := resolveRouting(s, m.Nodes); err == nil {
		s = effective
	}
	keys, nodes, groups := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, g := range s.Groups {
		groups[g.ID] = true
		for _, id := range g.Nodes {
			keys[g.ID+"/"+id] = true
			nodes[id] = true
		}
	}
	for key := range m.groupHealth {
		if !keys[key] {
			delete(m.groupHealth, key)
		}
	}
	for id := range m.health {
		if !nodes[id] {
			delete(m.health, id)
		}
	}
	for id := range m.switched {
		if !groups[id] {
			delete(m.switched, id)
		}
	}
}
