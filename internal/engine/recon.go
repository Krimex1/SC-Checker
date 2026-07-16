package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sc-checker-go/internal/model"
	"strings"
	"time"
)

func IPGeoLookup(ip string) map[string]any {
	cl, _ := NewHTTPClient("", 5)
	if cl == nil {
		return nil
	}
	defer cl.Close()

	resp, _, err := cl.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=country,regionName,city,lat,lon,isp,org,as", ip), nil)
	if err != nil || resp == nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)

	var result map[string]any
	if err := json.Unmarshal(buf[:n], &result); err != nil {
		return nil
	}
	return result
}

func ASNLookup(ip string) map[string]any {
	cl, _ := NewHTTPClient("", 5)
	if cl == nil {
		return nil
	}
	defer cl.Close()

	resp, _, err := cl.Get(fmt.Sprintf("https://ipinfo.io/%s/json", ip), nil)
	if err != nil || resp == nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)

	var raw map[string]any
	if err := json.Unmarshal(buf[:n], &raw); err != nil {
		return nil
	}
	return raw
}

func WhoisLookup(ip string) model.WhoisResult {
	result := model.WhoisResult{}
	if ip == "" {
		return result
	}

	cl, _ := NewHTTPClient("", 10)
	if cl == nil {
		return result
	}
	defer cl.Close()

	resp, _, err := cl.Get(fmt.Sprintf("https://rdap.org/ip/%s", ip), nil)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		buf := make([]byte, 16384)
		n, _ := resp.Body.Read(buf)

		var data map[string]any
		if json.Unmarshal(buf[:n], &data) == nil {
			if events, ok := data["events"].([]any); ok {
				for _, e := range events {
					ev, _ := e.(map[string]any)
					action, _ := ev["eventAction"].(string)
					date, _ := ev["eventDate"].(string)
					if action == "registration" {
						result.Created = date
					}
					if action == "expiration" {
						result.Expires = date
					}
				}
			}
			result.Registrar, _ = data["ldhName"].(string)
			if ns, ok := data["nameservers"].([]any); ok {
				var servers []string
				for _, n := range ns {
					nsMap, _ := n.(map[string]any)
					if name, ok := nsMap["ldhName"].(string); ok && len(servers) < 5 {
						servers = append(servers, name)
					}
				}
				result.NameServers = strings.Join(servers, ", ")
			}
		}
	}

	ws := "whois.iana.org"
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:43", ws), 5*time.Second)
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "%s\r\n", ip)
		buf := make([]byte, 4096)
		total := 0
		for {
			n, err := conn.Read(buf[total:])
			if n > 0 {
				total += n
			}
			if err != nil || total >= 4096 || total >= 1024*1024 {
				break
			}
		}
		text := string(buf[:total])
		if len(text) > 500 {
			text = text[:500]
		}
		result.Raw = text
		if result.Registrar == "" {
			re := regexp.MustCompile(`(?i)organisation:\s*(.+)`)
			if m := re.FindStringSubmatch(text); len(m) > 1 {
				result.Registrar = strings.TrimSpace(m[1])
			}
		}
	}

	return result
}

func ShodanLookup(ip string) model.ShodanResult {
	result := model.ShodanResult{IP: ip}
	if ip == "" {
		return result
	}

	cl, _ := NewHTTPClient("", 10)
	if cl == nil {
		return result
	}
	defer cl.Close()

	resp, _, err := cl.Get(fmt.Sprintf("https://internetdb.shodan.io/%s", ip), nil)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		defer resp.Body.Close()

		buf := make([]byte, 32768)
		n, _ := resp.Body.Read(buf)

		var data map[string]any
		if json.Unmarshal(buf[:n], &data) == nil {
			if ports, ok := data["ports"].([]any); ok {
				for _, p := range ports {
					if pi, ok := p.(float64); ok {
						result.Ports = append(result.Ports, int(pi))
					}
				}
			}
			result.OS, _ = data["os"].(string)
			if org, ok := data["org"].(string); ok {
				result.Org = org
			}
			if vulns, ok := data["vulns"].([]any); ok {
				for i, v := range vulns {
					if i >= 10 {
						break
					}
					if s, ok := v.(string); ok {
						result.Vulns = append(result.Vulns, s)
					}
				}
			}
		}
	}
	return result
}
