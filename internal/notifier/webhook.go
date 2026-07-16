package notifier

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sc-checker-go/internal/model"
	"strings"
	"time"
)

type Config struct {
	Discords  []Webhook `json:"discords"`
	Slacks    []Webhook `json:"slacks"`
	Telegrams []Webhook `json:"telegrams"`
	Pushovers []Webhook `json:"pushovers"`
	Customs   []Webhook `json:"customs"`
}

type Webhook struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

func NotifyAll(r *model.Report, cfgs ...Config) {
	for _, cfg := range cfgs {
		for _, wh := range cfg.Discords {
			sendDiscord(wh.URL, r)
		}
		for _, wh := range cfg.Slacks {
			sendSlack(wh.URL, r)
		}
		for _, wh := range cfg.Telegrams {
			sendTelegram(wh.URL, r)
		}
		for _, wh := range cfg.Pushovers {
			sendPushover(wh.URL, r)
		}
		for _, wh := range cfg.Customs {
			sendCustom(wh.URL, wh.Name, r)
		}
	}
}

func sendDiscord(webhookURL string, r *model.Report) {
	embed := map[string]any{
		"title":       fmt.Sprintf("SC Checker — %s", r.Target),
		"description": fmtSummary(r, 2000),
		"color":       discordColor(r.RiskLevel),
		"fields": []map[string]any{
			{"name": "Risk", "value": fmt.Sprintf("%d/100 (%s)", r.RiskScore, strings.ToUpper(r.RiskLevel)), "inline": true},
			{"name": "Status", "value": fmt.Sprintf("%d", r.StatusCode), "inline": true},
			{"name": "Duration", "value": fmt.Sprintf("%dms", r.ScanDurationMs), "inline": true},
			{"name": "Ports", "value": fmtPorts(r.OpenPorts), "inline": true},
			{"name": "WAF", "value": joinStr(r.WAFDetected, "none"), "inline": true},
			{"name": "Critical", "value": fmt.Sprintf("%d", len(r.CriticalPaths)), "inline": true},
		},
	}
	body := map[string]any{"embeds": []map[string]any{embed}}
	data, _ := json.Marshal(body)
	sendSafePost(webhookURL, data, "application/json")
}

func sendSlack(webhookURL string, r *model.Report) {
	text := fmt.Sprintf("*SC Checker — %s*\nRisk: %s (%d/100)\nStatus: %d | Duration: %dms\nPorts: %s | WAF: %s | Critical: %d",
		r.Target, strings.ToUpper(r.RiskLevel), r.RiskScore, r.StatusCode, r.ScanDurationMs,
		fmtPorts(r.OpenPorts), joinStr(r.WAFDetected, "none"), len(r.CriticalPaths))
	body := map[string]string{"text": text}
	data, _ := json.Marshal(body)
	sendSafePost(webhookURL, data, "application/json")
}

func sendTelegram(botToken string, r *model.Report) {
	chatID := ""
	if idx := strings.Index(botToken, "|"); idx > 0 {
		chatID = botToken[idx+1:]
		botToken = botToken[:idx]
	}
	if chatID == "" {
		return
	}
	text := fmt.Sprintf("\U0001F50D *SC Checker — %s*\n\nRisk: *%s* (%d/100)\nStatus: %d\nDuration: %dms\nPorts: %s\nWAF: %s\nCritical paths: %d",
		r.Target, strings.ToUpper(r.RiskLevel), r.RiskScore, r.StatusCode, r.ScanDurationMs,
		fmtPorts(r.OpenPorts), joinStr(r.WAFDetected, "none"), len(r.CriticalPaths))

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	body := map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	data, _ := json.Marshal(body)
	sendSafePost(apiURL, data, "application/json")
}

func sendPushover(token string, r *model.Report) {
	userKey := ""
	if idx := strings.Index(token, "|"); idx > 0 {
		userKey = token[idx+1:]
		token = token[:idx]
	}
	if userKey == "" {
		return
	}
	body := map[string]string{
		"token":   token,
		"user":    userKey,
		"title":   fmt.Sprintf("SC Checker — %s", r.Target),
		"message": fmt.Sprint("Risk: ", strings.ToUpper(r.RiskLevel), " (", r.RiskScore, "/100) | Status: ", r.StatusCode, " | Duration: ", r.ScanDurationMs, "ms"),
		"priority": riskPriority(r.RiskLevel),
	}
	data, _ := json.Marshal(body)
	sendSafePost("https://api.pushover.net/1/messages.json", data, "application/x-www-form-urlencoded")
}

func sendCustom(webhookURL, name string, r *model.Report) {
	body := map[string]any{
		"event":      "scan_complete",
		"checker":    name,
		"target":     r.Target,
		"risk":       r.RiskScore,
		"risk_level": r.RiskLevel,
		"status":     r.StatusCode,
		"duration":   r.ScanDurationMs,
		"critical":   len(r.CriticalPaths),
		"ports":      r.OpenPorts,
		"waf":        r.WAFDetected,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(body)
	sendSafePost(webhookURL, data, "application/json")
}

func sendSafePost(rawURL string, data []byte, contentType string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	host := parsed.Hostname()
	port := parsed.Port()
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}

	isStandardPort := false
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") || port == "" {
		isStandardPort = true
	}

	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		httpPost(rawURL, data, contentType)
		return
	}

	var pinnedIP string
	for _, addr := range addrs {
		ip := addr.IP
		if isPrivateIP(ip) {
			continue
		}
		pinnedIP = ip.String()
		if ip.To4() != nil {
			break
		}
	}
	if pinnedIP == "" {
		return
	}

	pinnedURL := fmt.Sprintf("%s://%s", scheme, pinnedIP)
	if !isStandardPort {
		pinnedURL = fmt.Sprintf("%s://%s:%s", scheme, pinnedIP, port)
	}

	req, err := http.NewRequest("POST", pinnedURL, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Host = host
	req.Header.Set("Content-Type", contentType)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 8 * time.Second}
			targetAddr := pinnedIP
			if port != "" && !isStandardPort {
				targetAddr = net.JoinHostPort(pinnedIP, port)
			} else {
				targetAddr = net.JoinHostPort(pinnedIP, "443")
				if scheme == "http" {
					targetAddr = net.JoinHostPort(pinnedIP, "80")
				}
			}
			return dialer.DialContext(ctx, network, targetAddr)
		},
	}

	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	if ip.To4() != nil {
		parts := strings.Split(ip.String(), ".")
		if len(parts) == 4 {
			if parts[0] == "0" || parts[0] == "127" {
				return true
			}
		}
	}
	return false
}

func httpPost(url string, data []byte, contentType string) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", contentType)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

func fmtSummary(r *model.Report, maxLen int) string {
	var parts []string
	if len(r.CriticalPaths) > 0 {
		end := len(r.CriticalPaths)
		if end > 5 {
			end = 5
		}
		parts = append(parts, fmt.Sprintf("**%d critical paths:** %s", len(r.CriticalPaths), strings.Join(r.CriticalPaths[:end], ", ")))
	}
	if r.XSSReflection {
		parts = append(parts, "**XSS reflection detected**")
	}
	if len(r.SQLErrors) > 0 {
		parts = append(parts, "**SQL errors found**")
	}
	if !r.HSTSEnabled {
		parts = append(parts, "**HSTS missing**")
	}
	if r.SSLWeakCipher {
		parts = append(parts, "**Weak SSL cipher**")
	}
	if len(parts) == 0 {
		return "No critical issues found"
	}
	result := strings.Join(parts, "\n")
	if len(result) > maxLen {
		result = result[:maxLen-3] + "..."
	}
	return result
}

func discordColor(level string) int {
	switch strings.ToUpper(level) {
	case "CRITICAL":
		return 0xFF0000
	case "HIGH":
		return 0xFF8C00
	case "MEDIUM":
		return 0xFFD700
	case "LOW":
		return 0x00FF00
	default:
		return 0x808080
	}
}

func riskPriority(level string) string {
	switch strings.ToUpper(level) {
	case "CRITICAL":
		return "2"
	case "HIGH":
		return "1"
	default:
		return "0"
	}
}

func fmtPorts(ports []int) string {
	if len(ports) == 0 {
		return "none"
	}
	var s []string
	for i, p := range ports {
		if i >= 10 {
			s = append(s, "...")
			break
		}
		s = append(s, fmt.Sprintf("%d", p))
	}
	return strings.Join(s, ", ")
}

func joinStr(s []string, def string) string {
	if len(s) == 0 {
		return def
	}
	return strings.Join(s, ", ")
}
