package engine

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"sc-checker-go/internal/model"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func WebSocketAnalyze(base string, body string) []model.WSTestResult {
	var results []model.WSTestResult

	parsed, _ := url.Parse(base)
	scheme := "ws"
	if parsed.Scheme == "https" {
		scheme = "wss"
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}

	endpoints := []string{
		fmt.Sprintf("%s://%s:%s/ws", scheme, host, port),
		fmt.Sprintf("%s://%s:%s/socket", scheme, host, port),
		fmt.Sprintf("%s://%s:%s/websocket", scheme, host, port),
		fmt.Sprintf("%s://%s/ws", scheme, host),
		fmt.Sprintf("%s://%s/socket", scheme, host),
	}

	seen := make(map[string]bool)
	for _, ep := range endpoints {
		if seen[ep] {
			continue
		}
		seen[ep] = true

		entry := model.WSTestResult{URL: ep}

		dialer := websocket.Dialer{
			HandshakeTimeout: 3 * time.Second,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		}

		conn, resp, err := dialer.Dial(ep, nil)
		if err != nil {
			entry.Connected = false
			errMsg := err.Error()
			if len(errMsg) > 200 {
				errMsg = errMsg[:200]
			}
			entry.Tests = append(entry.Tests, model.WSTestEntry{
				Type: "Connection Failed", Detail: errMsg, Severity: "INFO",
			})
			results = append(results, entry)
			continue
		}

		entry.Connected = true
		if resp != nil {
			resp.Body.Close()
		}

		xssPayloads := []string{
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
		}
		for _, payload := range xssPayloads {
			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte(payload)); err != nil {
				continue
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, msg, err := conn.ReadMessage()
			if err == nil && strings.Contains(string(msg), payload) {
				entry.Tests = append(entry.Tests, model.WSTestEntry{
					Type: "XSS Reflection", Payload: payload, Severity: "HIGH",
					Detail: "Payload reflected in WebSocket response",
				})
			}
		}

		injectPayloads := []string{
			"' OR 1=1",
			"{{7*7}}",
			"${7*7}",
		}
		for _, payload := range injectPayloads {
			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte(payload)); err != nil {
				continue
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, msg, err := conn.ReadMessage()
			msgStr := string(msg)
			if err == nil {
				if strings.Contains(msgStr, "49") || strings.Contains(msgStr, "error") {
					entry.Tests = append(entry.Tests, model.WSTestEntry{
						Type: "Template Injection", Payload: payload, Severity: "CRITICAL",
						Detail: fmt.Sprintf("Payload reflected with interesting response: %.100s", msgStr),
					})
				}
			}
		}

		large := strings.Repeat("A", 65536)
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, []byte(large)); err != nil {
			entry.Tests = append(entry.Tests, model.WSTestEntry{
				Type: "DoS Protection", Detail: "Server rejected large payload (65KB)", Severity: "INFO",
			})
		} else {
			entry.Tests = append(entry.Tests, model.WSTestEntry{
				Type: "Large Payload", Detail: "Server accepted 65KB payload — potential DoS vector", Severity: "MEDIUM",
			})
		}

		conn.Close()
		results = append(results, entry)
	}

	return results
}
