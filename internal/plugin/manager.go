package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sc-checker-go/internal/model"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Plugin struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Author    string   `json:"author"`
	Enabled   bool     `json:"enabled"`
	Hooks     []string `json:"hooks"`
	Condition string   `json:"condition"`
	Action    string   `json:"action"`
	Severity  string   `json:"severity"`
	Message   string   `json:"message"`
	Field     string   `json:"field"`
	Value     string   `json:"value"`
}

type ExecPlugin struct {
	Name    string
	Path    string
	Enabled bool
}

type CustomListKey string

const (
	KeyHeaders    CustomListKey = "headers"
	KeyPayloads   CustomListKey = "payloads"
	KeyPorts      CustomListKey = "ports"
	KeySubdomains CustomListKey = "subdomains"
	KeyUserAgents CustomListKey = "useragents"
	KeyBlacklist  CustomListKey = "blacklist"
	KeyWordlist   CustomListKey = "wordlist"
)

var AllListKeys = []CustomListKey{KeyHeaders, KeyPayloads, KeyPorts, KeySubdomains, KeyUserAgents, KeyBlacklist, KeyWordlist}

var ListLabels = map[CustomListKey]string{
	KeyHeaders:    "Custom Headers",
	KeyPayloads:   "SQLi/XSS Payloads",
	KeyPorts:      "Custom Ports",
	KeySubdomains: "Subdomain Wordlist",
	KeyUserAgents: "User Agents",
	KeyBlacklist:  "Blacklist Paths",
	KeyWordlist:   "Custom Wordlist",
}

type Manager struct {
	mu          sync.RWMutex
	Plugins     []*Plugin
	ExecPlugins []*ExecPlugin
	State       map[string]bool
	Dir         string
	DSLFile     string
	CustomLists map[CustomListKey][]string
}

var execExtensions = map[string]bool{
	".exe": true, ".bat": true, ".ps1": true, ".cmd": true,
}

func NewManager(dir string) *Manager {
	os.MkdirAll(dir, 0755)

	m := &Manager{
		Plugins:     make([]*Plugin, 0),
		ExecPlugins: make([]*ExecPlugin, 0),
		State:       make(map[string]bool),
		CustomLists: make(map[CustomListKey][]string),
		Dir:         dir,
		DSLFile:     "dsl_rules.json",
	}

	m.loadState()
	m.loadCustomLists()
	m.scanPlugins()
	return m
}

func (m *Manager) loadState() {
	data, err := os.ReadFile(filepath.Join(m.Dir, "state.json"))
	if err != nil {
		return
	}
	json.Unmarshal(data, &m.State)
}

func (m *Manager) saveState() {
	data, _ := json.MarshalIndent(m.State, "", "  ")
	os.WriteFile(filepath.Join(m.Dir, "state.json"), data, 0644)
}

func (m *Manager) loadCustomLists() {
	customDir := filepath.Join(m.Dir, "custom")
	os.MkdirAll(customDir, 0755)

	for _, key := range AllListKeys {
		f := filepath.Join(customDir, string(key)+".txt")
		data, err := os.ReadFile(f)
		if err != nil {
			m.CustomLists[key] = []string{}
			continue
		}
		lines := []string{}
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				lines = append(lines, l)
			}
		}
		m.CustomLists[key] = lines
	}
}

func (m *Manager) SaveCustomList(key CustomListKey, lines []string) error {
	m.mu.Lock()
	m.CustomLists[key] = lines
	m.mu.Unlock()

	customDir := filepath.Join(m.Dir, "custom")
	os.MkdirAll(customDir, 0755)
	f := filepath.Join(customDir, string(key)+".txt")
	return os.WriteFile(f, []byte(strings.Join(lines, "\n")), 0644)
}

func (m *Manager) GetCustomList(key CustomListKey) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.CustomLists[key]...)
}

func (m *Manager) AppendCustomList(key CustomListKey, items []string) error {
	m.mu.Lock()
	existing := m.CustomLists[key]
	seen := make(map[string]bool)
	for _, e := range existing {
		seen[e] = true
	}
	for _, item := range items {
		if !seen[item] {
			existing = append(existing, item)
			seen[item] = true
		}
	}
	m.CustomLists[key] = existing
	m.mu.Unlock()

	customDir := filepath.Join(m.Dir, "custom")
	os.MkdirAll(customDir, 0755)
	f := filepath.Join(customDir, string(key)+".txt")
	return os.WriteFile(f, []byte(strings.Join(existing, "\n")), 0644)
}

func (m *Manager) scanPlugins() {
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		return
	}

	m.mu.Lock()
	m.Plugins = make([]*Plugin, 0)
	m.ExecPlugins = make([]*ExecPlugin, 0)
	m.mu.Unlock()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))

		if ext == ".json" {
			name := strings.TrimSuffix(entry.Name(), ".json")
			if name == "state" || name == "dsl_rules" {
				continue
			}

			data, err := os.ReadFile(filepath.Join(m.Dir, entry.Name()))
			if err != nil {
				continue
			}

			var p Plugin
			if err := json.Unmarshal(data, &p); err != nil {
				continue
			}

			if p.Name == "" {
				p.Name = name
			}
			if enabled, ok := m.State[p.Name]; ok {
				p.Enabled = enabled
			} else {
				p.Enabled = true
			}

			if len(p.Hooks) == 0 {
				p.Hooks = []string{"on_scan_complete"}
			}

			m.mu.Lock()
			m.Plugins = append(m.Plugins, &p)
			m.mu.Unlock()
		}

		if execExtensions[ext] {
			name := strings.TrimSuffix(entry.Name(), ext)
			ep := &ExecPlugin{
				Name:    name,
				Path:    filepath.Join(m.Dir, entry.Name()),
				Enabled: true,
			}
			if enabled, ok := m.State["exec:"+name]; ok {
				ep.Enabled = enabled
			}

			m.mu.Lock()
			m.ExecPlugins = append(m.ExecPlugins, ep)
			m.mu.Unlock()
		}
	}
}

func (m *Manager) Enable(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.State[name] = true
	m.saveState()
}

func (m *Manager) Disable(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.State[name] = false
	m.saveState()
}

func (m *Manager) List() []*Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Plugins
}

func (m *Manager) ListExec() []*ExecPlugin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ExecPlugins
}

func (m *Manager) FireHook(hook string, r *model.Report) []map[string]any {
	m.mu.RLock()
	plugins := make([]*Plugin, len(m.Plugins))
	copy(plugins, m.Plugins)
	execPlugins := make([]*ExecPlugin, len(m.ExecPlugins))
	copy(execPlugins, m.ExecPlugins)
	m.mu.RUnlock()

	var results []map[string]any

	for _, p := range plugins {
		if !p.Enabled {
			continue
		}

		hasHook := false
		for _, h := range p.Hooks {
			if strings.EqualFold(h, hook) {
				hasHook = true
				break
			}
		}
		if !hasHook {
			continue
		}

		if p.Condition != "" && r != nil {
			if !EvalCondition(p.Condition, r) {
				continue
			}
		}

		msg := p.Message
		if msg != "" && r != nil {
			msg = interpolateString(msg, r)
		}

		result := map[string]any{
			"plugin":   p.Name,
			"hook":     hook,
			"severity": p.Severity,
			"action":   p.Action,
			"message":  msg,
		}

		switch p.Action {
		case "set_field":
			if p.Field != "" && r != nil {
				SetReportField(r, p.Field, p.Value)
			}
		case "append_finding":
			results = append(results, result)
		default:
			results = append(results, result)
		}
	}

	for _, ep := range execPlugins {
		if !ep.Enabled {
			continue
		}

		findings := runExecPlugin(ep.Path, hook, r)
		for _, f := range findings {
			f["plugin"] = ep.Name
			f["hook"] = hook
			results = append(results, f)
		}
	}

	return results
}

func (m *Manager) FireHookArgs(hook string, args ...any) []map[string]any {
	var r *model.Report
	for _, a := range args {
		if report, ok := a.(*model.Report); ok {
			r = report
			break
		}
	}
	return m.FireHook(hook, r)
}

func (m *Manager) FireHookWithData(hook string, r *model.Report, extraData map[string]any) []map[string]any {
	m.mu.RLock()
	plugins := make([]*Plugin, len(m.Plugins))
	copy(plugins, m.Plugins)
	execPlugins := make([]*ExecPlugin, len(m.ExecPlugins))
	copy(execPlugins, m.ExecPlugins)
	m.mu.RUnlock()

	var results []map[string]any

	for _, p := range plugins {
		if !p.Enabled {
			continue
		}

		hasHook := false
		for _, h := range p.Hooks {
			if strings.EqualFold(h, hook) {
				hasHook = true
				break
			}
		}
		if !hasHook {
			continue
		}

		if p.Condition != "" && r != nil {
			if !EvalCondition(p.Condition, r) {
				continue
			}
		}

		msg := p.Message
		if msg != "" && r != nil {
			msg = interpolateString(msg, r)
		}

		result := map[string]any{
			"plugin":   p.Name,
			"hook":     hook,
			"severity": p.Severity,
			"action":   p.Action,
			"message":  msg,
		}

		if extraData != nil {
			for k, v := range extraData {
				result[k] = v
			}
		}

		switch p.Action {
		case "set_field":
			if p.Field != "" && r != nil {
				SetReportField(r, p.Field, p.Value)
			}
		case "append_finding":
			results = append(results, result)
		default:
			results = append(results, result)
		}
	}

	for _, ep := range execPlugins {
		if !ep.Enabled {
			continue
		}

		findings := runExecPlugin(ep.Path, hook, r)
		for _, f := range findings {
			f["plugin"] = ep.Name
			f["hook"] = hook
			if extraData != nil {
				for k, v := range extraData {
					f[k] = v
				}
			}
			results = append(results, f)
		}
	}

	return results
}

func runExecPlugin(path, hook string, r *model.Report) []map[string]any {
	var cmd *exec.Cmd

	input := map[string]any{
		"hook":   hook,
		"target": "",
		"report": r,
	}
	if r != nil {
		input["target"] = r.Target
	}

	inData, err := json.Marshal(input)
	if err != nil {
		return nil
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch {
	case ext == ".ps1":
		cmd = exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path)
	case ext == ".bat" || ext == ".cmd":
		cmd = exec.Command("cmd", "/C", path)
	default:
		cmd = exec.Command(path)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	cmd.Stdin = bytes.NewReader(inData)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	timeout := 30 * time.Second
	if runtime.GOOS == "windows" {
		timeout = 60 * time.Second
	}

	select {
	case <-done:
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil
	}

	var findings []map[string]any
	if stdout.Len() > 0 {
		json.Unmarshal(stdout.Bytes(), &findings)
	}

	return findings
}

func (m *Manager) CreatePlugin(name, version, author string) error {
	p := &Plugin{
		Name:    name,
		Version: version,
		Author:  author,
		Enabled: true,
		Hooks:   []string{"on_scan_complete"},
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(m.Dir, fmt.Sprintf("%s.json", name))
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	m.mu.Lock()
	m.Plugins = append(m.Plugins, p)
	m.State[name] = true
	m.mu.Unlock()

	m.saveState()
	return nil
}

func interpolateString(s string, r *model.Report) string {
	if r == nil {
		return s
	}
	replacements := map[string]string{
		"{target}":                r.Target,
		"{risk_score}":            fmt.Sprintf("%d", r.RiskScore),
		"{risk_level}":            r.RiskLevel,
		"{critical_paths_count}":  fmt.Sprintf("%d", safeLen(r.CriticalPaths)),
		"{open_ports_count}":      fmt.Sprintf("%d", safeLen(r.OpenPorts)),
		"{subdomains_count}":      fmt.Sprintf("%d", safeLen(r.Subdomains)),
		"{cve_count}":             fmt.Sprintf("%d", safeLen(r.CVEFindings)),
		"{status_code}":           fmt.Sprintf("%d", r.StatusCode),
		"{ip}":                    r.IP,
	}

	for k, v := range replacements {
		s = strings.ReplaceAll(s, k, v)
	}
	return s
}

func safeLen[T any](s []T) int {
	if s == nil {
		return 0
	}
	return len(s)
}
