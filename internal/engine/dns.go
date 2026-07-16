package engine

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sc-checker-go/internal/config"
	"sc-checker-go/internal/model"
	"strings"
	"sync"
	"syscall"
	"time"
)

type DNSResult struct {
	Records map[string][]string
	IP      string
	RevDNS  string
	IPGeo   map[string]any
	ASN     map[string]any
}

func ResolveIP(host string) (string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return host, err
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil && ip.To4() != nil && !isPrivateIP(ip) {
			return addr, nil
		}
	}
	return host, fmt.Errorf("no valid IP found for %s", host)
}

func CheckDNSRecords(host string) map[string][]string {
	if !IsValidHost(host) {
		return nil
	}
	records := make(map[string][]string)

	recordTypes := []string{"MX", "TXT", "NS"}
	for _, rt := range recordTypes {
		entries, err := net.LookupHost(host)
		if err == nil && rt == "NS" && len(entries) > 0 {
			nss, nsErr := net.LookupNS(host)
			if nsErr == nil {
				for _, ns := range nss {
					records[rt] = append(records[rt], ns.Host)
				}
			}
		}

		if rt == "MX" {
			mxs, err := net.LookupMX(host)
			if err == nil {
				for _, mx := range mxs {
					records[rt] = append(records[rt], fmt.Sprintf("%s (pref %d)", mx.Host, mx.Pref))
				}
			}
		}

		if rt == "TXT" {
			txts, err := net.LookupTXT(host)
			if err == nil {
				for _, txt := range txts {
					if len(txt) > 3 {
						records[rt] = append(records[rt], txt[:min(200, len(txt))])
					}
				}
			}
		}
	}

	return records
}

func ReverseDNS(ip string) string {
	if ip == "" {
		return ""
	}
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}

func IPGeo(ip string) map[string]any {
	return IPGeoLookup(ip)
}

func CheckSubdomains(host string, customSubs []string, stopCh <-chan struct{}) []string {
	subs := append(SubdomainWordlist, customSubs...)
	seen := make(map[string]bool)
	var uniqueSubs []string
	for _, s := range subs {
		if !seen[s] {
			seen[s] = true
			uniqueSubs = append(uniqueSubs, s)
		}
	}

	parts := strings.Split(host, ".")
	var domain string
	if len(parts) >= 2 {
		domain = strings.Join(parts[len(parts)-2:], ".")
	} else {
		domain = host
	}

	var found []string
	var mu sync.Mutex
	sem := make(chan struct{}, config.SubdomainWorkers)
	var wg sync.WaitGroup

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	for _, sub := range uniqueSubs {
		select {
		case <-stopCh:
			return found
		default:
		}
		fqdn := sub + "." + domain
		if fqdn == host {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(fqdn string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := resolver.LookupHost(ctx, fqdn)
			if err == nil {
				mu.Lock()
				found = append(found, fqdn)
				mu.Unlock()
			}
		}(fqdn)
	}
	wg.Wait()
	return found
}

func ZoneTransfer(host string) []model.ZoneFinding {
	if !IsValidHost(host) {
		return nil
	}
	var findings []model.ZoneFinding

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nslookup", "-type=NS", host)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()
	nsRegex := regexp.MustCompile(`nameserver\s*=\s*([\d.]+)`)
	matches := nsRegex.FindAllStringSubmatch(string(out), -1)

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		ns := m[1]
		ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel2()

		cmd2 := exec.CommandContext(ctx2, "nslookup", "-type=AXFR", host, ns)
		cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out2, _ := cmd2.Output()
		if strings.Contains(strings.ToLower(string(out2)), "xfr") {
			findings = append(findings, model.ZoneFinding{
				Server:   ns,
				Severity: "CRITICAL",
				Detail:   "Zone transfer successful",
			})
		}
	}
	return findings
}
