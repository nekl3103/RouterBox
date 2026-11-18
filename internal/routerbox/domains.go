package routerbox

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type DomainEntry struct {
	Kind  string
	Value string
	Attrs map[string]bool
}
type DomainInclude struct {
	Name    string
	Filters []string
}
type DomainList struct {
	Entries  []DomainEntry
	Includes []DomainInclude
}
type DomainDB struct {
	Lists    map[string]*DomainList
	Revision string
}

func ParseDomainArchive(path string) (*DomainDB, error) {
	z, e := zip.OpenReader(path)
	if e != nil {
		return nil, e
	}
	defer z.Close()
	db := &DomainDB{Lists: map[string]*DomainList{}}
	var total int64
	for _, f := range z.File {
		parts := strings.Split(f.Name, "/")
		if len(parts) != 3 || parts[1] != "data" || f.FileInfo().IsDir() {
			continue
		}
		name := parts[2]
		if !validCategory.MatchString(name) || strings.Contains(name, "@") {
			continue
		}
		if f.UncompressedSize64 > 2<<20 {
			return nil, errors.New("слишком большой файл доменов")
		}
		total += int64(f.UncompressedSize64)
		if total > 32<<20 {
			return nil, errors.New("слишком большой каталог доменов")
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(r, 2<<20))
		r.Close()
		if e != nil {
			return nil, e
		}
		db.Revision = parts[0]
		list := db.Lists[name]
		if list == nil {
			list = &DomainList{}
			db.Lists[name] = list
		}
		if e = db.parse(name, string(b)); e != nil {
			return nil, fmt.Errorf("категория %s: %w", name, e)
		}
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	hash := sha256.New()
	_, e = io.Copy(hash, f)
	f.Close()
	if e != nil {
		return nil, e
	}
	db.Revision += "-" + hex.EncodeToString(hash.Sum(nil))[:24]
	if len(db.Lists) == 0 {
		return nil, errors.New("каталог пуст")
	}
	return db, nil
}
func (db *DomainDB) parse(name, text string) error {
	list := db.Lists[name]
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		kind, value, ok := strings.Cut(fields[0], ":")
		if !ok {
			kind = "domain"
			value = fields[0]
		}
		if kind == "include" {
			if !validCategory.MatchString(value) || strings.Contains(value, "@") {
				return errors.New("некорректный include")
			}
			inc := DomainInclude{Name: value}
			for _, f := range fields[1:] {
				if strings.HasPrefix(f, "@") {
					inc.Filters = append(inc.Filters, f[1:])
				} else {
					return errors.New("неизвестный атрибут include")
				}
			}
			list.Includes = append(list.Includes, inc)
			continue
		}
		switch kind {
		case "domain", "full", "keyword", "regexp":
		default:
			return errors.New("неизвестный тип доменного правила")
		}
		if kind == "regexp" {
			if _, e := regexp.Compile(value); e != nil {
				return errors.New("некорректное регулярное выражение")
			}
		}
		entry := DomainEntry{Kind: kind, Value: value, Attrs: map[string]bool{}}
		var affiliates []string
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "@") {
				entry.Attrs[f[1:]] = true
			} else if strings.HasPrefix(f, "&") {
				a := f[1:]
				if !validCategory.MatchString(a) {
					return errors.New("некорректная affiliation")
				}
				affiliates = append(affiliates, a)
			} else {
				return errors.New("неизвестный атрибут")
			}
		}
		list.Entries = append(list.Entries, entry)
		for _, a := range affiliates {
			dest := db.Lists[a]
			if dest == nil {
				dest = &DomainList{}
				db.Lists[a] = dest
			}
			dest.Entries = append(dest.Entries, entry)
		}
	}
	return nil
}
func attrMatch(e DomainEntry, filters []string) bool {
	for _, f := range filters {
		if strings.HasPrefix(f, "-") {
			if e.Attrs[f[1:]] {
				return false
			}
		} else if !e.Attrs[f] {
			return false
		}
	}
	return true
}
func (db *DomainDB) Resolve(category string) (Object, error) {
	name, attr, _ := strings.Cut(category, "@")
	if !validCategory.MatchString(category) {
		return nil, errors.New("некорректная категория")
	}
	var filters []string
	if attr != "" {
		filters = []string{attr}
	}
	result := map[string]map[string]bool{}
	keys := map[string]string{"domain": "domain_suffix", "full": "domain", "keyword": "domain_keyword", "regexp": "domain_regex"}
	count := 0
	var visit func(string, []string, map[string]bool) error
	visit = func(n string, f []string, stack map[string]bool) error {
		if stack[n] {
			return errors.New("цикл include")
		}
		list := db.Lists[n]
		if list == nil {
			return fmt.Errorf("категория %s не найдена", n)
		}
		stack[n] = true
		defer delete(stack, n)
		for _, e := range list.Entries {
			if !attrMatch(e, f) {
				continue
			}
			k := keys[e.Kind]
			if result[k] == nil {
				result[k] = map[string]bool{}
			}
			if !result[k][e.Value] {
				result[k][e.Value] = true
				count++
				if count > 200000 {
					return errors.New("слишком большой набор правил")
				}
			}
		}
		for _, i := range list.Includes {
			fs := append(append([]string{}, f...), i.Filters...)
			if e := visit(i.Name, fs, stack); e != nil {
				return e
			}
		}
		return nil
	}
	if e := visit(name, filters, map[string]bool{}); e != nil {
		return nil, e
	}
	if count == 0 {
		return nil, errors.New("категория не содержит правил")
	}
	o := Object{}
	for k, m := range result {
		var values []string
		for v := range m {
			values = append(values, v)
		}
		sort.Strings(values)
		o[k] = values
	}
	return o, nil
}
func (db *DomainDB) Catalogue() []string {
	names := []string{}
	attrs := map[string]map[string]bool{}
	for n, list := range db.Lists {
		attrs[n] = map[string]bool{}
		for _, e := range list.Entries {
			for a := range e.Attrs {
				attrs[n][a] = true
			}
		}
	}
	for rounds := 0; rounds < len(db.Lists); rounds++ {
		changed := false
		for n, list := range db.Lists {
			for _, inc := range list.Includes {
				for a := range attrs[inc.Name] {
					if !attrs[n][a] {
						attrs[n][a] = true
						changed = true
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	for n := range db.Lists {
		names = append(names, n)
		for a := range attrs[n] {
			if _, e := db.Resolve(n + "@" + a); e == nil {
				names = append(names, n+"@"+a)
			}
		}
	}
	sort.Strings(names)
	return names
}

func selectedCategories(s Settings) []string {
	m := map[string]bool{}
	for _, r := range s.Rules {
		if r.Enabled {
			for _, c := range r.Categories {
				m[c] = true
			}
		}
	}
	out := []string{}
	for c := range m {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
func categoryTag(c string) string { return "rs-" + hashID([]byte(c)) }
func (m *Manager) ensureDomainDB() error {
	if m.domains != nil {
		return nil
	}
	archive := filepath.Join(m.Run, "domains.zip")
	if _, e := os.Stat(archive); e != nil {
		b, e := m.fetch("https://codeload.github.com/v2fly/domain-list-community/zip/refs/heads/master", 16<<20)
		if e != nil {
			return e
		}
		if e = atomicWrite(archive, b, 0600); e != nil {
			return e
		}
	}
	db, e := ParseDomainArchive(archive)
	if e != nil {
		os.Remove(archive)
		return e
	}
	m.domains = db
	return writeJSON(filepath.Join(m.Root, "catalogue.json"), Object{"revision": db.Revision, "categories": db.Catalogue()})
}

// Rule-set files live at a stable path per category. The core watches that directory
// and reloads a set when its file is replaced, so a daily list update no longer changes
// the config and no longer restarts the core. New files are built and verified in RAM
// first; only changed files are written to flash, by atomic rename.
func (m *Manager) liveRulePath(category string) string {
	return filepath.Join(m.Root, "rules", "live", categoryTag(category)+".srs")
}
func (m *Manager) stagingRulePath(category string) string {
	return filepath.Join(m.Run, "rules-staging", categoryTag(category)+".srs")
}
func fileEquals(path string, data []byte) bool {
	old, err := os.ReadFile(path)
	return err == nil && bytes.Equal(old, data)
}

// compileRules returns live rule-set paths. m.rulesSwapped reports how many live files
// were replaced, i.e. how many sets a running core reloaded in place.
func (m *Manager) compileRules(s Settings) (map[string]string, error) {
	m.rulesSwapped = 0
	staged := map[string]string{}
	sources := map[string]string{}
	defer func() {
		m.domains = nil
		_ = os.RemoveAll(filepath.Join(m.Run, "rules-staging"))
	}()
	categories := selectedCategories(s)
	if len(categories) == 0 {
		return map[string]string{}, nil
	}
	for _, c := range categories {
		if !strings.HasPrefix(c, "allow-") && !prebuiltCategory(c) {
			if e := m.ensureDomainDB(); e != nil {
				return nil, e
			}
			break
		}
	}
	var total int64
	for _, c := range categories {
		live := m.liveRulePath(c)
		var path string
		if prebuiltCategory(c) {
			var err error
			if path, err = m.prebuiltRule(c); err != nil {
				return nil, err
			}
		} else {
			var o Object
			var e error
			if strings.HasPrefix(c, "allow-") {
				o, e = m.resolveService(c)
			} else {
				o, e = m.domains.Resolve(c)
			}
			if e != nil {
				return nil, e
			}
			data, _ := json.Marshal(Object{"version": 3, "rules": []Object{o}})
			source := hashID(data)
			if marker, err := os.ReadFile(live + ".source"); err == nil && string(marker) == source && fileExists(live) {
				path = live
			} else {
				path = m.stagingRulePath(c)
				input := strings.TrimSuffix(path, ".srs") + ".json"
				if e = atomicWrite(input, data, 0600); e != nil {
					return nil, e
				}
				e = m.command(45, m.corePath(), "rule-set", "compile", "--output", path, input)
				os.Remove(input)
				if e != nil {
					return nil, errors.New("не удалось скомпилировать список доменов")
				}
				sources[c] = source
			}
		}
		info, e := os.Stat(path)
		if e != nil {
			return nil, e
		}
		total += info.Size()
		if total > 8<<20 {
			return nil, errors.New("выбранные правила превышают 8 МБ")
		}
		staged[c] = path
	}
	// Every set is valid; only now touch the live files the core is watching.
	paths := map[string]string{}
	for _, c := range categories {
		live := m.liveRulePath(c)
		if staged[c] != live {
			data, e := os.ReadFile(staged[c])
			if e != nil {
				return nil, e
			}
			if !fileEquals(live, data) {
				if e = atomicWrite(live, data, 0600); e != nil {
					return nil, e
				}
				m.rulesSwapped++
			}
		}
		if source := sources[c]; source != "" {
			_ = atomicWrite(live+".source", []byte(source), 0600)
		}
		paths[c] = live
	}
	return paths, nil
}
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
