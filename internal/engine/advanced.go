package engine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sc-checker-go/internal/model"
	"strings"
	"sync"
	"time"
)

var (
	cisaKEVCache     []string
	cisaKEVCacheMu   sync.Mutex
	cisaKEVCacheTime time.Time
	epssCache        map[string]float64
	epssCacheMu      sync.Mutex
)

func DecodeJWT(token, source string) *model.JWTToken {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	header := decodeB64(parts[0])
	payload := decodeB64(parts[1])

	var headerMap map[string]any
	if json.Unmarshal([]byte(header), &headerMap) != nil {
		return nil
	}

	var payloadMap map[string]any
	if json.Unmarshal([]byte(payload), &payloadMap) != nil {
		return nil
	}

	alg, _ := headerMap["alg"].(string)
	if alg == "" {
		alg = "none"
	}

	var issues []string
	if alg == "none" {
		issues = append(issues, "Algorithm 'none' — signature bypass possible")
	} else if strings.HasPrefix(alg, "HS") {
		issues = append(issues, fmt.Sprintf("HMAC algorithm %s — brute-forceable if secret is weak", alg))
	}

	smallPayload := make(map[string]string)
	count := 0
	for k, v := range payloadMap {
		s := fmt.Sprintf("%v", v)
		if len(s) > 50 {
			s = s[:50]
		}
		smallPayload[k] = s
		count++
		if count >= 10 {
			break
		}
	}

	sensitive := []string{"password", "secret", "token", "key", "ssn", "credit"}
	for _, sk := range sensitive {
		for k := range payloadMap {
			if strings.Contains(strings.ToLower(k), sk) {
				issues = append(issues, fmt.Sprintf("Sensitive data in payload: '%s'", sk))
				break
			}
		}
	}

	severity := "INFO"
	if len(issues) > 0 {
		severity = "HIGH"
	}

	displayToken := token
	if len(displayToken) > 50 {
		displayToken = token[:50] + "..."
	}

	return &model.JWTToken{
		Token:          displayToken,
		Source:         source,
		Algorithm:      alg,
		Header:         headerMap,
		PayloadPreview: smallPayload,
		Issues:         issues,
		Severity:       severity,
	}
}

func decodeB64(s string) string {
	s = strings.TrimRight(s, "=")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "{}"
		}
	}
	return string(decoded)
}

func JWTScan(headers map[string]string, body string, client *HTTPClient) []model.JWTToken {
	var tokens []model.JWTToken

	for name, val := range headers {
		if strings.HasPrefix(val, "eyJ") {
			t := DecodeJWT(val, "Header: "+name)
			if t != nil {
				tokens = append(tokens, *t)
			}
		}
	}

	jwtRe := regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)
	matches := jwtRe.FindAllString(body, -1)
	seen := make(map[string]bool)
	for _, m := range matches {
		short := m[:min(50, len(m))]
		if !seen[short] {
			seen[short] = true
			t := DecodeJWT(m, "Response body")
			if t != nil {
				tokens = append(tokens, *t)
			}
		}
	}
	return tokens
}

func GraphQLScan(base string, client *HTTPClient) (map[string]any, []model.GraphQLVuln) {
	endpoints := []string{"/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/query", "/gql"}
	var foundEndpoint string

	for _, ep := range endpoints {
		u := strings.TrimSuffix(base, "/") + ep
		body := `{"query":"{__typename}"}`
		headers := map[string]string{"Content-Type": "application/json"}
		resp, _, err := client.Post(u, headers, body)
		if err != nil || resp == nil {
			continue
		}
		respBody := make([]byte, 500)
		n, _ := resp.Body.Read(respBody)
		if strings.Contains(string(respBody[:n]), "__typename") || strings.Contains(string(respBody[:n]), "data") {
			foundEndpoint = u
			break
		}
	}

	if foundEndpoint == "" {
		return nil, nil
	}

	var vulns []model.GraphQLVuln
	schema := make(map[string]any)

	introQuery := `{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } } } } }"}`
	resp, _, err := client.Post(foundEndpoint, map[string]string{"Content-Type": "application/json"}, introQuery)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		respBody := make([]byte, 65536)
		n, _ := resp.Body.Read(respBody)

		var data map[string]any
		if json.Unmarshal(respBody[:n], &data) == nil {
			schema = data
			vulns = append(vulns, model.GraphQLVuln{
				Type:     "Info Disclosure",
				Endpoint: foundEndpoint,
				Detail:   "Introspection enabled — full schema exposed",
			})
		}
	}

	return schema, vulns
}

func SupplyChainAnalyze(body, host string, client *HTTPClient) []model.SupplyItem {
	scriptRe := regexp.MustCompile(`(?is)<script[^>]+(?:src|href)=["']([^"']+)["']`)
	linkRe := regexp.MustCompile(`(?is)<link[^>]+href=["']([^"']+\.css(?:\?[^"']*)?)["']`)

	var urls []string
	for _, m := range scriptRe.FindAllStringSubmatch(body, -1) {
		urls = append(urls, m[1])
	}
	for _, m := range linkRe.FindAllStringSubmatch(body, -1) {
		urls = append(urls, m[1])
	}

	seen := make(map[string]bool)
	var external []string
	for _, u := range urls {
		if strings.HasPrefix(u, "//") {
			u = "https:" + u
		}
		if !strings.HasPrefix(u, "http") {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil || parsed.Hostname() == host {
			continue
		}
		if !seen[u] && len(external) < 30 {
			seen[u] = true
			external = append(external, u)
		}
	}

	var items []model.SupplyItem
	knownCDNs := map[string]string{
		"cdnjs.cloudflare.com": "Cloudflare CDN",
		"cdn.jsdelivr.net":     "jsDelivr",
		"unpkg.com":            "unpkg",
		"ajax.googleapis.com":  "Google CDN",
		"code.jquery.com":      "jQuery CDN",
	}

	for _, eu := range external {
		item := model.SupplyItem{URL: eu}
		parsed, _ := url.Parse(eu)
		domain := parsed.Hostname()

		if parsed.Scheme == "http" {
			item.Issues = append(item.Issues, "HTTP (not HTTPS)")
		}
		for cdn, name := range knownCDNs {
			if strings.Contains(domain, cdn) {
				item.CDN = name
				break
			}
		}

		resp, _, err := client.Get(eu, nil)
		if err == nil && resp != nil {
			item.Status = resp.StatusCode
			item.ContentType = resp.Header.Get("Content-Type")
			respBody := make([]byte, 5000)
			n, _ := resp.Body.Read(respBody)
			respStr := string(respBody[:n])

			vulnPatterns := map[string]string{
				`jquery[\-/.]([0-6])\.`:        "jQuery < 1.7 (XSS)",
				`angular[\-/.]([0-5])\.`:       "AngularJS 1.x (EOL)",
				`moment[\-/.]([0-1][0-9])\.`:   "Moment.js (deprecated)",
				`bootstrap[\-/.](3)\.`:         "Bootstrap 3 (EOL)",
				`lodash[\-/.]4\.`:              "Lodash 4.0 (prototype poll)",
			}
			for pat, msg := range vulnPatterns {
				if re, _ := regexp.Compile(pat); re.MatchString(respStr) {
					item.Issues = append(item.Issues, msg)
				}
			}

			if resp.Header.Get("Access-Control-Allow-Origin") == "*" {
				item.Issues = append(item.Issues, "CORS wildcard")
			}
		}

		if len(item.Issues) > 0 || item.CDN != "" {
			items = append(items, item)
		}
	}

	return items
}

func JSLibrariesDetect(body string) []string {
	patterns := map[string]string{
		`jquery[/.-]([0-9.]+)`:   "jQuery",
		`react[/.-]([0-9.]+)`:    "React",
		`vue[/.-]([0-9.]+)`:      "Vue.js",
		`angular[/.-]([0-9.]+)`:  "Angular",
		`bootstrap[/.-]([0-9.]+)`: "Bootstrap",
		`lodash[/.-]([0-9.]+)`:   "Lodash",
		`moment[/.-]([0-9.]+)`:   "Moment.js",
		`axios[/.-]([0-9.]+)`:    "Axios",
		`webpack[/.-]([0-9.]+)`:  "Webpack",
		`chart\.js[/.-]([0-9.]+)`: "Chart.js",
		`d3[/.-]v([0-9.]+)`:      "D3.js",
		`tailwindcss`:            "Tailwind CSS",
		`sweetalert[/.-]([0-9.]+)`: "SweetAlert",
		`fontawesome[/.-]([0-9.]+)`: "Font Awesome",
	}

	var libs []string
	for pat, name := range patterns {
		re := regexp.MustCompile(`(?i)` + pat)
		m := re.FindStringSubmatch(body)
		if m != nil {
			version := ""
			if len(m) > 1 {
				version = m[1]
			}
			libs = append(libs, strings.TrimSpace(name+" "+version))
		}
	}
	return libs
}

func HiddenEndpoints(base, body string, client *HTTPClient) []model.EndpointItem {
	var endpoints []model.EndpointItem

	jsRe := regexp.MustCompile(`["'](/[a-zA-Z0-9/_-]+(?:\?[^"']*)?)["']`)
	apiRe := regexp.MustCompile(`["'](?:https?://[^"']+/(?:api|v1|v2|graphql|rest)/[^"']+)["']`)

	allUrls := make(map[string]bool)
	for _, m := range jsRe.FindAllStringSubmatch(body, -1) {
		allUrls[m[1]] = true
	}
	for _, m := range apiRe.FindAllStringSubmatch(body, -1) {
		allUrls[m[1]] = true
	}

	count := 0
	for u := range allUrls {
		if count >= 50 {
			break
		}
		count++

		fullURL := u
		if !strings.HasPrefix(u, "http") {
			fullURL = strings.TrimSuffix(base, "/") + u
		}

		resp, _, err := client.Get(fullURL, nil)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			bodySize := 0
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			bodySize = n

			severity := "MEDIUM"
			if resp.StatusCode != 200 {
				severity = "LOW"
			}

			endpoints = append(endpoints, model.EndpointItem{
				URL:      fullURL,
				Status:   resp.StatusCode,
				Size:     bodySize,
				Severity: severity,
				Detail:   fmt.Sprintf("HTTP %d", resp.StatusCode),
			})
		}
	}

	return endpoints
}

func RateLimitDetect(base string, client *HTTPClient) model.RateLimitInfo {
	result := model.RateLimitInfo{Headers: make(map[string]string)}

	rlHeaders := []string{
		"x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
		"retry-after", "x-rate-limit-limit", "x-rate-limit-remaining",
	}

	resp, _, err := client.Get(base, nil)
	if err != nil || resp == nil {
		return result
	}

	for _, rh := range rlHeaders {
		for k, v := range resp.Header {
			if strings.Contains(strings.ToLower(k), strings.ToLower(rh)) {
				result.Headers[k] = v[0]
				result.Detected = true
			}
		}
	}

	if !result.Detected {
		burstClient, _ := NewHTTPClient("", 3)
		if burstClient != nil {
			defer burstClient.Close()
			rateLimited := false
			for i := 0; i < 10; i++ {
				r, _, err := burstClient.Get(base, nil)
				if err != nil {
					break
				}
				if r != nil {
					if r.StatusCode == 429 || r.StatusCode == 503 {
						result.Detected = true
						result.Headers["status"] = fmt.Sprintf("%d Too Many Requests", r.StatusCode)
						ra := r.Header.Get("Retry-After")
						if ra != "" {
							result.Reset = ra
						}
						rateLimited = true
						break
					}
					r.Body.Close()
				}
			}
			if !rateLimited {
				result.Note = "No rate limiting detected after 10 rapid requests"
			}
		}
	}

	return result
}

func CORSDeepTest(base string, client *HTTPClient) []model.CORSDeepResult {
	var results []model.CORSDeepResult

	parsed, _ := url.Parse(base)
	host := parsed.Host

	tests := []struct {
		name   string
		origin map[string]string
	}{
		{"null origin", map[string]string{"Origin": "null"}},
		{"localhost", map[string]string{"Origin": "http://localhost"}},
		{"evil.com", map[string]string{"Origin": "https://evil.com"}},
		{"subdomain", map[string]string{"Origin": "https://test." + host}},
		{"double hostname", map[string]string{"Origin": strings.TrimSuffix(base, "/") + ".evil.com"}},
		{"http downgrade", map[string]string{"Origin": strings.Replace(base, "https://", "http://", 1)}},
	}

	for _, test := range tests {
		resp, _, err := client.Get(base, test.origin)
		if err != nil || resp == nil {
			continue
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		if acao == "" {
			continue
		}

		vuln := false
		detail := fmt.Sprintf("ACAO: %s", acao)

		if acao == "*" && strings.ToLower(acac) == "true" {
			vuln = true
			detail += " | wildcard + credentials"
		} else if acao == "null" && strings.ToLower(acac) == "true" {
			vuln = true
			detail += " | null origin accepted"
		} else if test.name == "evil.com" && acao == test.origin["Origin"] {
			vuln = true
			detail += " | reflects arbitrary origin"
		}

		severity := "INFO"
		if vuln {
			severity = "HIGH"
		}

		results = append(results, model.CORSDeepResult{
			Test:       test.name,
			Vulnerable: vuln,
			ACAO:       acao,
			ACAC:       acac,
			Detail:     detail,
			Severity:   severity,
		})
	}
	return results
}

func WAFFingerprintDeep(r *model.Report, body string) model.WAFFingerprint {
	result := model.WAFFingerprint{}

	if len(r.WAFDetected) > 0 {
		result.Detected = true
		result.Name = r.WAFDetected[0]

		for h, v := range r.Headers {
			if strings.HasPrefix(strings.ToLower(h), "x-") && strings.Contains(strings.ToLower(v), "version") {
				if len(v) > 50 {
					v = v[:50]
				}
				result.Version = v
				break
			}
		}
	}

	return result
}

func JSAnalysis(body string, client *HTTPClient) model.JSAnalysisResult {
	result := model.JSAnalysisResult{}

	scriptRe := regexp.MustCompile(`(?i)<script[^>]*src=["']([^"']+)["']`)
	scripts := scriptRe.FindAllStringSubmatch(body, -1)

	for i, m := range scripts {
		if i >= 20 {
			break
		}
		result.Scripts = append(result.Scripts, m[1])
	}

	secretPatterns := []struct {
		re    *regexp.Regexp
		label string
	}{
		{regexp.MustCompile(`(?i)["'](?:api[_-]?key|apikey|api_secret|secret[_-]?key)["']?\s*[:=]\s*["']([^"']{8,})["']`), "API Key"},
		{regexp.MustCompile(`(?i)["'](?:password|passwd|pwd)["']?\s*[:=]\s*["']([^"']{4,})["']`), "Password"},
		{regexp.MustCompile(`(?i)["'](?:token|auth_token|access_token|bearer)["']?\s*[:=]\s*["']([^"']{8,})["']`), "Token"},
		{regexp.MustCompile(`(?i)(?:sk|pk|rk)_[a-zA-Z0-9]{20,}`), "Stripe Key"},
	}

	for _, sp := range secretPatterns {
		matches := sp.re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			value := m[0]
			if len(m) > 1 && m[1] != "" {
				value = m[1]
			}
			if len(value) > 40 {
				value = value[:40] + "..."
			}
			if len(result.Secrets) < 10 {
				result.Secrets = append(result.Secrets, model.JSSecret{
					Type:   sp.label,
					Value:  value,
					Source: "inline",
				})
			}
		}
	}

	if strings.Contains(body, "<script") {
		scriptTags := regexp.MustCompile(`(?i)<script[^>]*>`).FindAllString(body, -1)
		for _, tag := range scriptTags {
			if strings.Contains(tag, "src=") && !strings.Contains(strings.ToLower(tag), "integrity=") {
				result.SRIMissing++
			}
		}
	}

	return result
}

func HTTPSmugglingCheck(base string, client *HTTPClient) []model.SmugglingResult {
	var results []model.SmugglingResult

	payloads := []struct {
		name    string
		headers map[string]string
		body    string
		detect  string
	}{
		{
			name:    "CL.TE",
			headers: map[string]string{"Transfer-Encoding": "chunked", "Content-Length": "6"},
			body:    "0\r\n\r\nSMUGGLED",
			detect:  "SMUGGLED",
		},
		{
			name:    "TE.CL",
			headers: map[string]string{"Transfer-Encoding": "chunked", "Content-Length": "3"},
			body:    "8\r\nSMUGGLED\r\n0\r\n\r\n",
			detect:  "SMUGGLED",
		},
	}

	for _, pl := range payloads {
		resp, _, err := client.Post(base, pl.headers, pl.body)
		if err != nil || resp == nil {
			continue
		}
		respBody := make([]byte, 5000)
		n, _ := resp.Body.Read(respBody)
		if strings.Contains(string(respBody[:n]), pl.detect) {
			results = append(results, model.SmugglingResult{
				Type:     pl.name,
				Severity: "CRITICAL",
				Detail:   fmt.Sprintf("HTTP Request Smuggling (%s) confirmed", pl.name),
			})
		}
	}
	return results
}

func SessionManipulation(base string, client *HTTPClient) []string {
	var issues []string

	resp1, _, _ := client.Get(base, nil)
	resp2, _, _ := client.Get(base, nil)
	if resp1 == nil || resp2 == nil {
		return issues
	}

	for _, cookie := range resp1.Cookies() {
		for _, sc := range []string{"session", "sid", "token", "auth", "jwt"} {
			if strings.Contains(strings.ToLower(cookie.Name), sc) {
				for _, cookie2 := range resp2.Cookies() {
					if cookie2.Name == cookie.Name && cookie2.Value == cookie.Value {
						issues = append(issues, fmt.Sprintf("Fixed session '%s' across requests", cookie.Name))
					}
				}
				break
			}
		}
	}
	return issues
}

func TechStackDeep(r *model.Report, client *HTTPClient) []model.TechItem {
	var techs []model.TechItem

	if r.ServerBanner != "" {
		sv := strings.ToLower(r.ServerBanner)
		if strings.Contains(sv, "apache") {
			techs = append(techs, model.TechItem{Name: "Apache", Detail: r.ServerBanner})
		}
		if strings.Contains(sv, "nginx") {
			techs = append(techs, model.TechItem{Name: "Nginx", Detail: r.ServerBanner})
		}
		if strings.Contains(sv, "iis") {
			techs = append(techs, model.TechItem{Name: "IIS", Detail: r.ServerBanner})
		}
		if strings.Contains(sv, "cloudflare") {
			techs = append(techs, model.TechItem{Name: "Cloudflare", Detail: r.ServerBanner})
		}
	}

	powered := strings.ToLower(r.Headers["x-powered-by"])
	if powered != "" {
		techs = append(techs, model.TechItem{Name: "X-Powered-By", Detail: powered})
	}

	resp, _, _ := client.Get(r.NormalizedURL, nil)
	if resp != nil {
		respBody := make([]byte, 5000)
		n, _ := resp.Body.Read(respBody)
		b := strings.ToLower(string(respBody[:n]))

		if strings.Contains(b, "wp-content") || strings.Contains(b, "wp-includes") {
			techs = append(techs, model.TechItem{Name: "WordPress", Detail: "wp-content/includes detected"})
		}
		if strings.Contains(b, "laravel") || strings.Contains(b, "xsrf-token") {
			techs = append(techs, model.TechItem{Name: "Laravel", Detail: "Laravel signatures detected"})
		}
		if strings.Contains(b, "__next") || strings.Contains(b, "_next/static") {
			techs = append(techs, model.TechItem{Name: "Next.js", Detail: "Next.js SSR detected"})
		}
		if strings.Contains(b, "__nuxt") {
			techs = append(techs, model.TechItem{Name: "Nuxt.js", Detail: "Nuxt SSR detected"})
		}
		if strings.Contains(b, "ng-version") {
			techs = append(techs, model.TechItem{Name: "Angular", Detail: "Angular detected"})
		}
		if strings.Contains(b, ".php") || strings.Contains(b, "phpsessid") {
			techs = append(techs, model.TechItem{Name: "PHP", Detail: "PHP signatures detected"})
		}
	}
	return techs
}

func EmailSecurityCheck(host string) model.EmailSecurity {
	result := model.EmailSecurity{}
	if !IsValidHost(host) {
		return result
	}

	spfRecords, _ := net.LookupTXT(host)
	for _, txt := range spfRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			result.SPF = txt
			break
		}
	}
	if result.SPF == "" {
		result.Issues = append(result.Issues, "SPF record not found")
	}

	dmarcRecords, _ := net.LookupTXT(fmt.Sprintf("_dmarc.%s", host))
	for _, txt := range dmarcRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			result.DMARC = txt
			if strings.Contains(txt, "p=none") {
				result.Issues = append(result.Issues, "DMARC policy is 'none' (monitoring only)")
			}
			break
		}
	}
	if result.DMARC == "" {
		result.Issues = append(result.Issues, "DMARC record not found")
	}

	dkimSelectors := []string{"default", "google", "selector1", "k1", "dkim", "mail"}
	for _, sel := range dkimSelectors {
		records, _ := net.LookupTXT(fmt.Sprintf("%s._domainkey.%s", sel, host))
		for _, txt := range records {
			if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "p=") {
				result.DKIM = fmt.Sprintf("%s._domainkey.%s", sel, host)
				break
			}
		}
		if result.DKIM != "" {
			break
		}
	}
	if result.DKIM == "" {
		result.Issues = append(result.Issues, "DKIM record not found")
	}

	return result
}

func SubdomainTakeoverCheck(subdomains []string, client *HTTPClient) []model.TakeoverFinding {
	if len(subdomains) == 0 {
		return nil
	}
	var findings []model.TakeoverFinding

	takeoverSignatures := map[string]string{
		"herokuapp.com":     "Heroku",
		"github.io":         "GitHub Pages",
		"surge.sh":          "Surge.sh",
		"s3.amazonaws.com":  "AWS S3",
	}

	for _, sub := range subdomains {
		safeClient, _ := NewHTTPClient("", 3)
		if safeClient == nil {
			continue
		}

		for _, service := range takeoverSignatures {
			resp, _, err := safeClient.Get(fmt.Sprintf("http://%s", sub), nil)
			if err != nil || resp == nil {
				continue
			}
			respBody := make([]byte, 2000)
			n, _ := resp.Body.Read(respBody)
			resp.Body.Close()
			bodyStr := strings.ToLower(string(respBody[:n]))

			markers := []string{"no such app", "there isn't a github pages site here", "project not found", "no such bucket"}
			for _, marker := range markers {
				if strings.Contains(bodyStr, marker) {
					findings = append(findings, model.TakeoverFinding{
						Subdomain: sub,
						Service:   service,
						Severity:  "HIGH",
						Detail:    fmt.Sprintf("Potential %s subdomain takeover", service),
					})
					break
				}
			}
		}
		safeClient.Close()
	}
	return findings
}

func ChaosScan(base string, client *HTTPClient) []model.ChaosFinding {
	var findings []model.ChaosFinding

	bodies := []struct {
		body        string
		contentType string
	}{
		{"null", "application/json"},
		{`{"query":"SELECT 1"}`, "application/json"},
		{"admin=true", "application/x-www-form-urlencoded"},
		{"id=1 OR 1=1", "application/x-www-form-urlencoded"},
	}

	for _, b := range bodies {
		headers := map[string]string{"Content-Type": b.contentType}
		resp, _, err := client.Post(base, headers, b.body)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 {
			respBody := make([]byte, 200)
			n, _ := resp.Body.Read(respBody)
			if n > 200 {
				findings = append(findings, model.ChaosFinding{
					Type:     "POST Body Accepted",
					Detail:   fmt.Sprintf("Server returned 200 with %d bytes", n),
					Severity: "MEDIUM",
					Preview:  string(respBody),
				})
			}
		}
	}

	paramNames := []string{"debug", "test", "admin", "mode", "cmd", "eval"}
	for _, param := range paramNames {
		u := fmt.Sprintf("%s?%s=test", base, param)
		resp, _, err := client.Get(u, nil)
		if err != nil || resp == nil {
			continue
		}
		respBody := make([]byte, 2000)
		n, _ := resp.Body.Read(respBody)
		bodyStr := strings.ToLower(string(respBody[:n]))
		for _, kw := range []string{"debug", "info", "phpinfo", "config", "env"} {
			if strings.Contains(bodyStr, kw) {
				findings = append(findings, model.ChaosFinding{
					Type:     "Debug Endpoint",
					Detail:   fmt.Sprintf("Parameter '%s' exposed debug info", param),
					Severity: "HIGH",
				})
				break
			}
		}
	}

	if len(findings) > 30 {
		return findings[:30]
	}
	return findings
}

func CVELookup(versions []model.VersionHint) []model.CVEFinding {
	var findings []model.CVEFinding

	cl, _ := NewHTTPClient("", 8)
	if cl == nil {
		return findings
	}
	defer cl.Close()

	kevSet := fetchCISAKEV(cl)
	seen := make(map[string]bool)

	productQueries := make(map[string]bool)
	for _, v := range versions {
		productQueries[strings.ToLower(v.Name)] = true
	}

	for productName := range productQueries {
		var matchedVersions []string
		for _, v := range versions {
			if strings.EqualFold(v.Name, productName) {
				matchedVersions = append(matchedVersions, v.Version)
			}
		}

		query := url.QueryEscape(productName)
		apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=20", query)

		resp, _, err := cl.Get(apiURL, nil)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		respBody := make([]byte, 131072)
		n, _ := resp.Body.Read(respBody)

		var data map[string]any
		if json.Unmarshal(respBody[:n], &data) != nil {
			continue
		}

		vulns, _ := data["vulnerabilities"].([]any)
		for _, vuln := range vulns {
			vulnMap, _ := vuln.(map[string]any)
			cveData, _ := vulnMap["cve"].(map[string]any)
			cveID, _ := cveData["id"].(string)
			if cveID == "" || seen[cveID] {
				continue
			}

			if !cveMatchesProduct(cveData, productName, matchedVersions) {
				continue
			}
			seen[cveID] = true

			desc := ""
			if descs, ok := cveData["descriptions"].([]any); ok {
				for _, d := range descs {
					dMap, _ := d.(map[string]any)
					if lang, _ := dMap["lang"].(string); lang == "en" {
						desc, _ = dMap["value"].(string)
						if len(desc) > 150 {
							desc = desc[:150]
						}
						break
					}
				}
			}

			cweID := ""
			if weaknesses, ok := cveData["weaknesses"].([]any); ok {
				for _, w := range weaknesses {
					wMap, _ := w.(map[string]any)
					if descs, ok := wMap["description"].([]any); ok {
						for _, d := range descs {
							dMap, _ := d.(map[string]any)
							if val, _ := dMap["value"].(string); val != "" {
								cweID = val
								break
							}
						}
					}
					if cweID != "" {
						break
					}
				}
			}

			score := 0.0
			severity := ""
			metrics, _ := cveData["metrics"].(map[string]any)
			for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
				if mList, ok := metrics[key].([]any); ok && len(mList) > 0 {
					if mMap, ok := mList[0].(map[string]any); ok {
						if cvssData, ok := mMap["cvssData"].(map[string]any); ok {
							if baseScore, ok := cvssData["baseScore"].(float64); ok {
								score = baseScore
								severity, _ = cvssData["baseSeverity"].(string)
								break
							}
						}
					}
				}
			}
			if severity == "" {
				severity = cvssSeverityLabel(score)
			}

			inKEV := kevSet[cveID]

			findings = append(findings, model.CVEFinding{
				Product:            productName,
				Version:            strings.Join(matchedVersions, ", "),
				CVE:                cveID,
				Score:              score,
				Severity:           severity,
				Desc:               desc,
				CWE:                cweID,
				CISAKnownExploited: inKEV,
			})

			if len(findings) >= 30 {
				break
			}
		}
		if len(findings) >= 30 {
			break
		}
	}

	if len(findings) == 0 {
		return findings
	}

	var cveIDs []string
	for _, f := range findings {
		cveIDs = append(cveIDs, f.CVE)
	}

	epssMap := fetchEPSS(cl, cveIDs)
	exploitMap := fetchExploitDB(cl, cveIDs)

	for i := range findings {
		if ep, ok := epssMap[findings[i].CVE]; ok {
			findings[i].EPSS = ep
		}
		if ex, ok := exploitMap[findings[i].CVE]; ok {
			findings[i].ExploitAvailable = true
			findings[i].ExploitLinks = ex
		}
	}

	return findings
}

var productAliases = map[string][]string{
	"nginx":         {"nginx"},
	"apache":        {"apache", "apache_http_server"},
	"php":           {"php"},
	"wordpress":     {"wordpress"},
	"mysql":         {"mysql"},
	"postgresql":    {"postgresql"},
	"redis":         {"redis"},
	"node.js":       {"node.js", "nodejs"},
	"express":       {"express"},
	"next.js":       {"next.js", "nextjs"},
	"react":         {"react", "reactjs"},
	"vue.js":        {"vue.js", "vuejs"},
	"angular":       {"angular"},
	"jquery":        {"jquery"},
	"django":        {"django"},
	"flask":         {"flask"},
	"laravel":       {"laravel"},
	"drupal":        {"drupal"},
	"joomla":        {"joomla"},
	"tomcat":        {"tomcat", "apache_tomcat"},
	"iis":           {"iis", "internet_information_services"},
	"openssl":       {"openssl"},
	"jenkins":       {"jenkins"},
	"grafana":       {"grafana"},
}

func cveMatchesProduct(cveData map[string]any, productName string, detectedVersions []string) bool {
	productLower := strings.ToLower(strings.TrimSpace(productName))

	aliases, ok := productAliases[productLower]
	if !ok {
		aliases = []string{productLower}
	}
	aliasSet := make(map[string]bool)
	for _, a := range aliases {
		aliasSet[a] = true
	}

	configurations, _ := cveData["configurations"].([]any)
	hasProductCPE := false
	hasVersionMatch := false

	for _, config := range configurations {
		configMap, _ := config.(map[string]any)
		nodes, _ := configMap["nodes"].([]any)
		for _, node := range nodes {
			nodeMap, _ := node.(map[string]any)
			cpeMatches, _ := nodeMap["cpeMatch"].([]any)
			for _, cpm := range cpeMatches {
				cpmMap, _ := cpm.(map[string]any)
				criteria, _ := cpmMap["criteria"].(string)
				if criteria == "" {
					continue
				}

				cpeParts := strings.Split(criteria, ":")
				if len(cpeParts) < 6 {
					continue
				}
				cpeProduct := strings.ToLower(cpeParts[4])

				if !aliasSet[cpeProduct] {
					continue
				}

				hasProductCPE = true
				cpeVersion := cpeParts[5]

				if cpeVersion == "*" || cpeVersion == "-" {
					hasVersionMatch = true
					continue
				}

				if len(detectedVersions) == 0 {
					hasVersionMatch = true
					continue
				}

				for _, dv := range detectedVersions {
					dvClean := strings.Split(strings.TrimSpace(dv), " ")[0]

					if cpeVersion == dvClean {
						hasVersionMatch = true
						break
					}

					vStart, _ := cpmMap["versionStartIncluding"].(string)
					vEnd, _ := cpmMap["versionEndExcluding"].(string)
					vEndInc, _ := cpmMap["versionEndIncluding"].(string)

					if vStart != "" {
						if compareVersions(dvClean, vStart) >= 0 {
							if vEnd != "" {
								if compareVersions(dvClean, vEnd) < 0 {
									hasVersionMatch = true
								}
							} else if vEndInc != "" {
								if compareVersions(dvClean, vEndInc) <= 0 {
									hasVersionMatch = true
								}
							} else {
								hasVersionMatch = true
							}
						}
					} else if vEnd != "" {
						if compareVersions(dvClean, vEnd) < 0 {
							hasVersionMatch = true
						}
					} else if vEndInc != "" {
						if compareVersions(dvClean, vEndInc) <= 0 {
							hasVersionMatch = true
						}
					}
				}
			}
		}
	}

	if !hasProductCPE {
		return false
	}

	if hasVersionMatch {
		return true
	}

	if len(detectedVersions) == 0 && hasProductCPE {
		return true
	}

	return false
}

func fetchCISAKEV(cl *HTTPClient) map[string]bool {
	cisaKEVCacheMu.Lock()
	defer cisaKEVCacheMu.Unlock()

	if time.Since(cisaKEVCacheTime) < 1*time.Hour && cisaKEVCache != nil {
		set := make(map[string]bool, len(cisaKEVCache))
		for _, id := range cisaKEVCache {
			set[id] = true
		}
		return set
	}

	result := map[string]bool{}
	resp, _, err := cl.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil)
	if err != nil || resp == nil || resp.StatusCode != 200 {
		return result
	}
	respBody := make([]byte, 1048576)
	n, _ := resp.Body.Read(respBody)

	var data map[string]any
	if json.Unmarshal(respBody[:n], &data) != nil {
		return result
	}
	vulns, _ := data["vulnerabilities"].([]any)
	var ids []string
	for _, v := range vulns {
		vMap, _ := v.(map[string]any)
		if id, _ := vMap["cveID"].(string); id != "" {
			result[id] = true
			ids = append(ids, id)
		}
	}
	cisaKEVCache = ids
	cisaKEVCacheTime = time.Now()
	return result
}

func fetchEPSS(cl *HTTPClient, cveIDs []string) map[string]float64 {
	result := map[string]float64{}

	for i := 0; i < len(cveIDs); i += 100 {
		end := i + 100
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]
		query := url.QueryEscape(strings.Join(batch, ","))
		apiURL := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", query)
		resp, _, err := cl.Get(apiURL, nil)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		respBody := make([]byte, 32768)
		n, _ := resp.Body.Read(respBody)
		var data map[string]any
		if json.Unmarshal(respBody[:n], &data) != nil {
			continue
		}
		items, _ := data["data"].([]any)
		for _, item := range items {
			im, _ := item.(map[string]any)
			id, _ := im["cve"].(string)
			if epssStr, ok := im["epss"].(string); ok {
				var epss float64
				fmt.Sscanf(epssStr, "%f", &epss)
				result[id] = epss
			}
		}
	}
	return result
}

func fetchExploitDB(cl *HTTPClient, cveIDs []string) map[string][]string {
	result := map[string][]string{}
	for _, cveID := range cveIDs {
		apiURL := fmt.Sprintf("https://www.exploit-db.com/search?cve=%s", cveID)
		resp, _, err := cl.Get(apiURL, nil)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		respBody := make([]byte, 65536)
		n, _ := resp.Body.Read(respBody)
		body := strings.ToLower(string(respBody[:n]))
		if strings.Contains(body, "exploit") || strings.Contains(body, "edb-id") {
			result[cveID] = append(result[cveID], fmt.Sprintf("https://www.exploit-db.com/search?cve=%s", cveID))
		}
	}
	return result
}

func cvssSeverityLabel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func CVSSScoring(r *model.Report) []model.CVSSScore {
	cvssBase := map[string]float64{
		"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.0,
	}

	var scores []model.CVSSScore

	findingsMap := []struct {
		name, severity string
	}{
		{"SQL Injection", condSeverity(len(r.SQLErrors) > 0, "CRITICAL", "")},
		{"XSS Reflected", condSeverity(r.XSSReflection, "HIGH", "")},
		{"Open Redirect", condSeverity(len(r.OpenRedirect) > 0, "MEDIUM", "")},
		{"Directory Listing", condSeverity(len(r.DirectoryListing) > 0, "MEDIUM", "")},
		{"Missing HSTS", condSeverity(!r.HSTSEnabled, "MEDIUM", "")},
		{"Missing Clickjacking", condSeverity(!r.ClickjackingProtected, "MEDIUM", "")},
		{"SSL Weak Cipher", condSeverity(r.SSLWeakCipher, "HIGH", "")},
		{"TRACE Enabled", condSeverity(r.TraceEnabled, "LOW", "")},
	}

	for _, f := range findingsMap {
		if f.severity != "" {
			scores = append(scores, model.CVSSScore{
				Finding:  f.name,
				Severity: f.severity,
				CVSS:     cvssBase[f.severity],
			})
		}
	}

	for _, j := range r.JWTTokens {
		if j.Algorithm == "none" {
			scores = append(scores, model.CVSSScore{
				Finding:  "JWT None Algorithm",
				Severity: "CRITICAL",
				CVSS:     9.8,
			})
		}
	}

	if !r.WAFFingerprint.Detected {
		scores = append(scores, model.CVSSScore{
			Finding: "No WAF Detected", Severity: "INFO", CVSS: 0.0,
		})
	}
	if !r.RateLimit.Detected {
		scores = append(scores, model.CVSSScore{
			Finding: "No Rate Limiting", Severity: "LOW", CVSS: 2.0,
		})
	}

	for _, c := range r.CORSDeep {
		if c.Vulnerable {
			scores = append(scores, model.CVSSScore{
				Finding: fmt.Sprintf("CORS: %s", c.Test), Severity: "HIGH", CVSS: 7.0,
			})
		}
	}

	return scores
}

func condSeverity(cond bool, sev string, _ string) string {
	if cond {
		return sev
	}
	return ""
}
