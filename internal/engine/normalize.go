package engine

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	blockedSchemes    = regexp.MustCompile(`^(?i:file|ftp|javascript|data|gopher|vbscript|dict):`)
	hostPattern       = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	privateMap        = map[string]bool{"localhost": true, "127.0.0.1": true, "0.0.0.0": true, "::1": true, "[::1]": true}
)

func NormalizeTarget(raw string) (normalizedURL, scheme, host string, port int, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", 0, fmt.Errorf("empty target")
	}
	if blockedSchemes.MatchString(raw) {
		return "", "", "", 0, fmt.Errorf("blocked scheme: %s", strings.Split(raw, ":")[0])
	}

	if ip := net.ParseIP(raw); ip != nil {
		if isPrivateIP(ip) {
			return "", "", "", 0, fmt.Errorf("private IP blocked: %s", raw)
		}
		port = 80
		return fmt.Sprintf("http://%s", raw), "http", raw, port, nil
	}

	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Hostname() == "" {
		return "", "", "", 0, fmt.Errorf("invalid host")
	}

	scheme = u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host = u.Hostname()

	if privateMap[strings.ToLower(host)] {
		return "", "", "", 0, fmt.Errorf("blocked host: %s", host)
	}
	if strings.HasSuffix(strings.ToLower(host), ".local") || strings.HasSuffix(strings.ToLower(host), ".internal") {
		return "", "", "", 0, fmt.Errorf("blocked host: %s", host)
	}

	if ip := net.ParseIP(host); ip != nil && isPrivateIP(ip) {
		return "", "", "", 0, fmt.Errorf("private IP blocked: %s", host)
	}

	portStr := u.Port()
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	} else if scheme == "https" {
		port = 443
	} else {
		port = 80
	}

	if port < 1 || port > 65535 {
		return "", "", "", 0, fmt.Errorf("invalid port: %d", port)
	}

	if u.Port() != "" {
		normalizedURL = fmt.Sprintf("%s://%s:%d%s", scheme, host, port, u.Path)
	} else {
		normalizedURL = fmt.Sprintf("%s://%s%s", scheme, host, u.Path)
	}
	if u.RawQuery != "" {
		normalizedURL += "?" + u.RawQuery
	}

	return normalizedURL, scheme, host, port, nil
}

func BaseURL(scheme, host string, port int) string {
	if port == 80 || port == 443 {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}

func IsValidHost(host string) bool {
	if len(host) > 253 {
		return false
	}
	return hostPattern.MatchString(host)
}
