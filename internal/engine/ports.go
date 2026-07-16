package engine

import (
	"fmt"
	"net"
	"sc-checker-go/internal/config"
	"sort"
	"strings"
	"sync"
	"time"
)

func ScanPorts(ip string, customPorts []int, stopCh <-chan struct{}) []int {
	allPorts := make(map[int]bool)
	for _, p := range config.CommonPorts {
		allPorts[p] = true
	}
	for _, p := range customPorts {
		if p >= 1 && p <= 65535 {
			allPorts[p] = true
		}
	}

	var portList []int
	for p := range allPorts {
		portList = append(portList, p)
	}
	sort.Ints(portList)

	var found []int
	var mu sync.Mutex
	sem := make(chan struct{}, config.PortWorkers)
	var wg sync.WaitGroup

	for _, port := range portList {
		select {
		case <-stopCh:
			return found
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			if verifyPort(ip, p) {
				mu.Lock()
				found = append(found, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sort.Ints(found)
	return found
}

func verifyPort(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	switch port {
	case 80, 8080, 8000, 8888, 9000, 9090, 5000, 3000:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		return n > 0 && strings.Contains(string(buf[:n]), "HTTP/")

	case 443, 8443:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			return true
		}
		return n > 0

	case 22, 21, 25, 110, 143, 993, 995, 465, 587:
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		return n > 0

	case 6379:
		fmt.Fprintf(conn, "PING\r\n")
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		return n > 0 && strings.Contains(string(buf[:n]), "PONG")

	case 11211:
		fmt.Fprintf(conn, "stats\r\n")
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		return n > 0

	case 9200:
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		return n > 0 && (strings.Contains(string(buf[:n]), "HTTP/") || strings.Contains(string(buf[:n]), "cluster_name"))

	default:
		buf := make([]byte, 128)
		conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			fmt.Fprintf(conn, "\r\n")
			conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			n, err = conn.Read(buf)
			return n > 0
		}
		return n > 0
	}
}

func GrabBanner(ip string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 1024)
	var banner string

	switch port {
	case 80, 8080, 8000, 443, 8443:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
		n, _ := conn.Read(buf)
		lines := string(buf[:n])
		for _, line := range splitLines(lines) {
			banner = line[:min(120, len(line))]
			break
		}
	case 22, 21:
		n, _ := conn.Read(buf)
		banner = string(buf[:n])
	case 25:
		fmt.Fprintf(conn, "EHLO test\r\n")
		n, _ := conn.Read(buf)
		lines := string(buf[:n])
		for _, line := range splitLines(lines) {
			banner = line[:min(120, len(line))]
			break
		}
	default:
		fmt.Fprintf(conn, "\r\n")
		n, _ := conn.Read(buf)
		banner = string(buf[:n])
	}

	banner = banner[:min(120, len(banner))]
	return banner
}

func GrabBanners(ip string, ports []int, stopCh <-chan struct{}) map[int]string {
	banners := make(map[int]string)
	var mu sync.Mutex
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	for _, p := range ports {
		select {
		case <-stopCh:
			return banners
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			banner := GrabBanner(ip, port)
			if banner != "" {
				mu.Lock()
				banners[port] = banner
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return banners
}

func ProbeConnectivity(host string, primaryPort int, stopCh <-chan struct{}) (int, string, bool) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, primaryPort), config.ConnectTimeout*time.Second)
	if err == nil {
		conn.Close()
		scheme := "http"
		if primaryPort == 443 || primaryPort == 8443 {
			scheme = "https"
		}
		return primaryPort, scheme, true
	}

	for _, p := range config.AltHTTPPorts {
		if p == primaryPort {
			continue
		}
		select {
		case <-stopCh:
			return 0, "", false
		default:
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), config.AltPortTimeout*time.Second)
		if err == nil {
			conn.Close()
			scheme := "http"
			if p == 443 || p == 8443 {
				scheme = "https"
			}
			return p, scheme, true
		}
	}

	return 0, "", false
}

func ProbeAltPorts(host string, stopCh <-chan struct{}) []struct {
	Port   int
	URL    string
	Scheme string
} {
	var found []struct {
		Port   int
		URL    string
		Scheme string
	}
	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for _, p := range config.AltHTTPPorts {
		select {
		case <-stopCh:
			return found
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			scheme := "https"
			if port != 443 && port != 8443 {
				scheme = "http"
			}
			u := BaseURL(scheme, host, port)

			client, _ := NewHTTPClient("", 3)
			if client == nil {
				return
			}
			defer client.Close()
			resp, _, err := client.Get(u, nil)
			if err != nil || resp == nil || resp.StatusCode >= 500 {
				return
			}

			mu.Lock()
			found = append(found, struct {
				Port   int
				URL    string
				Scheme string
			}{port, u, scheme})
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return found
}

func splitLines(s string) []string {
	var lines []string
	current := ""
	for _, ch := range s {
		if ch == '\n' || ch == '\r' {
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
