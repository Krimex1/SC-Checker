package engine

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sc-checker-go/internal/config"
	"sc-checker-go/internal/model"
	"strings"
	"time"
)

func CollectHeaders(resp *http.Response) map[string]string {
	h := make(map[string]string)
	if resp == nil {
		return h
	}
	for k, v := range resp.Header {
		h[k] = v[0]
	}
	return h
}

func MissingHeaders(headers map[string]string) []string {
	lower := make(map[string]string)
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}
	var missing []string
	for _, h := range config.SecurityHeaders {
		if _, ok := lower[h]; !ok {
			missing = append(missing, h)
		}
	}
	return missing
}

func FingerprintTech(headers map[string]string) []string {
	lower := make(map[string]string)
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}
	var hints []string
	for h, lbl := range config.TechFingerprint {
		if v, ok := lower[h]; ok {
			if len(v) > 100 {
				v = v[:100]
			}
			hints = append(hints, fmt.Sprintf("%s: %s", lbl, v))
		}
	}
	return hints
}

func CheckCookies(resp *http.Response) (issues, names []string) {
	if resp == nil {
		return nil, nil
	}
	seen := make(map[string]bool)
	for _, raw := range resp.Header["Set-Cookie"] {
		if raw == "" {
			continue
		}
		parts := strings.Split(raw, ";")
		for i, part := range parts {
			part = strings.TrimSpace(part)
			eqIdx := strings.Index(part, "=")
			if eqIdx == -1 {
				continue
			}
			name := part[:eqIdx]
			if name == "" || name == "(unset)" {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)

			if !isSensitiveCookie(name) {
				continue
			}

			attrs := make(map[string]bool)
			if i == 0 {
				attrs[http.CanonicalHeaderKey(name)] = true
			}
			for j := 1; j < len(parts); j++ {
				attr := strings.TrimSpace(parts[j])
				attrLower := strings.ToLower(attr)
				if attrLower == "httponly" {
					attrs["httponly"] = true
				} else if attrLower == "secure" {
					attrs["secure"] = true
				} else if strings.HasPrefix(attrLower, "samesite") {
					attrs["samesite"] = true
				}
			}

			if !attrs["httponly"] {
				issues = append(issues, fmt.Sprintf("'%s' missing HttpOnly", name))
			}
			if !attrs["secure"] {
				issues = append(issues, fmt.Sprintf("'%s' missing Secure", name))
			}
			if !attrs["samesite"] {
				issues = append(issues, fmt.Sprintf("'%s' missing SameSite", name))
			}
		}
	}
	return
}

func isSensitiveCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, pat := range SensitiveCookiePatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func CheckHSTS(headers map[string]string, resp *http.Response, host string) bool {
	lower := make(map[string]string)
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}
	if _, ok := lower["strict-transport-security"]; ok {
		return true
	}
	return hstsPreloaded(host)
}

func hstsPreloaded(host string) bool {
	h := strings.ToLower(strings.TrimLeft(host, "."))
	for _, d := range HSTSPreloadList {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

func CheckClickjacking(headers map[string]string) bool {
	lower := make(map[string]string)
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}
	xfo := strings.ToUpper(lower["x-frame-options"])
	if xfo == "DENY" || xfo == "SAMEORIGIN" {
		return true
	}
	csp := lower["content-security-policy"]
	return strings.Contains(csp, "frame-ancestors")
}

func CheckHTTPToHTTPS(host string, port int, client *HTTPClient) bool {
	if port == 443 {
		return true
	}
	httpURL := fmt.Sprintf("http://%s", host)
	if port != 80 {
		httpURL = fmt.Sprintf("http://%s:%d", host, port)
	}

	client.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, _, err := client.Get(httpURL, nil)
	if err != nil || resp == nil {
		return false
	}
	loc := resp.Header.Get("Location")
	return (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308) && strings.Contains(strings.ToLower(loc), "https")
}

func CheckCORS(u string, client *HTTPClient) []string {
	var issues []string
	origins := []string{"https://evil.com", "null"}
	for _, origin := range origins {
		headers := map[string]string{"Origin": origin}
		resp, _, err := client.Get(u, headers)
		if err != nil || resp == nil {
			continue
		}
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		if acao == "*" {
			issues = append(issues, "CORS wildcard (*)")
			break
		}
		if strings.EqualFold(acao, origin) {
			issues = append(issues, fmt.Sprintf("CORS reflects: %s", acao))
			if strings.ToLower(acac) == "true" {
				issues = append(issues, "CORS credentials=true")
			}
			break
		}
	}
	return issues
}

func DetectWAF(resp *http.Response) []string {
	if resp == nil {
		return nil
	}
	lowerHeaders := make(map[string]string)
	for k, v := range resp.Header {
		lowerHeaders[strings.ToLower(k)] = strings.ToLower(v[0])
	}

	bodyLower := ""
	if resp.Body != nil {
		buf := make([]byte, 10000)
		n, _ := resp.Body.Read(buf)
		bodyLower = strings.ToLower(string(buf[:n]))
	}

	var wafs []string
	for name, sigs := range WAFFingerprints {
		found := false
		for _, h := range sigs.Headers {
			if _, ok := lowerHeaders[strings.ToLower(h)]; ok {
				found = true
				break
			}
		}
		if !found {
			for _, b := range sigs.Body {
				if strings.Contains(bodyLower, b) {
					found = true
					break
				}
			}
		}
		if found {
			wafs = append(wafs, name)
		}
	}
	return wafs
}

func DetectCMS(resp *http.Response, body string) (hints, cms, frameworks []string) {
	if resp == nil {
		return nil, nil, nil
	}
	lowerHeaders := make(map[string]string)
	for k, v := range resp.Header {
		lowerHeaders[strings.ToLower(k)] = v[0]
	}

	for _, h := range []string{"server", "x-powered-by", "x-generator"} {
		if v, ok := lowerHeaders[h]; ok {
			if len(v) > 100 {
				v = v[:100]
			}
			hints = append(hints, fmt.Sprintf("%s: %s", h, v))
		}
	}

	allText := lowerHeaders["server"] + " " + lowerHeaders["x-powered-by"] + " " + body
	if len(allText) > 50000 {
		allText = allText[:50000]
	}
	allText = strings.ToLower(allText)

	for name, pats := range CMSSignatures {
		for _, pat := range pats {
			re := regexp.MustCompile(strings.ToLower(pat))
			if re.MatchString(allText) {
				switch name {
				case "WordPress", "Joomla", "Drupal", "Ghost", "Shopify":
					cms = append(cms, name)
				default:
					frameworks = append(frameworks, name)
				}
				break
			}
		}
	}

	return uniqStr(hints), uniqStr(cms), uniqStr(frameworks)
}

func DetectVersions(resp *http.Response, body string) []model.VersionHint {
	if resp == nil {
		return nil
	}
	lowerHeaders := make(map[string]string)
	for k, v := range resp.Header {
		lowerHeaders[strings.ToLower(k)] = v[0]
	}
	allText := lowerHeaders["server"] + " " + lowerHeaders["x-powered-by"] + " " + body
	if len(allText) > 50000 {
		allText = allText[:50000]
	}
	allText = strings.ToLower(allText)

	var versions []model.VersionHint
	for pat, name := range VersionPatterns {
		re := regexp.MustCompile(pat)
		matches := re.FindStringSubmatch(allText)
		if matches != nil {
			version := "detected"
			if len(matches) > 1 {
				version = matches[1]
			}
			versions = append(versions, model.VersionHint{Name: name, Version: version})
		}
	}
	return versions
}

func ProbeMethods(u string, client *HTTPClient) (allowed []string, traceEnabled bool) {
	resp, _, err := client.do("OPTIONS", u, nil, nil)
	if err == nil && resp != nil {
		allow := resp.Header.Get("Allow")
		if allow != "" {
			for _, m := range strings.Split(allow, ",") {
				m = strings.TrimSpace(strings.ToUpper(m))
				if m != "" {
					allowed = append(allowed, m)
				}
			}
		}
	}

	resp2, _, err2 := client.do("TRACE", u, nil, nil)
	if err2 == nil && resp2 != nil && resp2.StatusCode < 400 {
		traceEnabled = true
	}
	return
}

type TLSResult struct {
	ExpiryDays int
	ExpiryDate string
	WeakCipher bool
	Version    string
	Cipher     string
	Bits       string
	Subject    string
	Issuer     string
	NotAfter   string
	NotBefore  string
	Error      string
	Deep       map[string]any
}

func SSLCheck(host string, port int, timeout int) *TLSResult {
	r := &TLSResult{Deep: make(map[string]any)}

	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer conn.Close()

	state := conn.ConnectionState()
	r.Version = tlsVersion(state.Version)
	r.Cipher = tls.CipherSuiteName(state.CipherSuite)
	r.Bits = fmt.Sprintf("%d", state.CipherSuite)

	weakCiphers := []string{"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}
	for _, wc := range weakCiphers {
		if strings.Contains(strings.ToUpper(r.Cipher), wc) {
			r.WeakCipher = true
		}
	}
	if state.Version <= tls.VersionTLS11 {
		r.WeakCipher = true
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		r.Subject = cert.Subject.String()
		r.Issuer = cert.Issuer.String()
		r.NotAfter = cert.NotAfter.Format(time.RFC3339)
		r.NotBefore = cert.NotBefore.Format(time.RFC3339)
		r.ExpiryDays = int(time.Until(cert.NotAfter).Hours() / 24)
		r.ExpiryDate = r.NotAfter

		var san []string
		san = append(san, cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			san = append(san, ip.String())
		}

		r.Deep = map[string]any{
			"protocol":      r.Version,
			"cipher_name":   r.Cipher,
			"cipher_bits":   r.Bits,
			"subject":       r.Subject,
			"issuer":        r.Issuer,
			"not_before":    r.NotBefore,
			"not_after":     r.NotAfter,
			"san":           san,
			"serial":        fmt.Sprintf("%x", cert.SerialNumber),
			"weak_protocol": state.Version <= tls.VersionTLS11,
		}
	}

	return r
}

func CertificateTransparency(host string) []model.CTLogEntry {
	var results []model.CTLogEntry
	cl, _ := NewHTTPClient("", 10)
	if cl == nil {
		return results
	}
	defer cl.Close()

	resp, _, err := cl.Get(fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", host), nil)
	if err != nil || resp == nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	body := make([]byte, 50000)
	n, _ := resp.Body.Read(body)

	nameRe := regexp.MustCompile(`"name_value"\s*:\s*"([^"]+)"`)
	issuerRe := regexp.MustCompile(`"issuer_name"\s*:\s*"([^"]+)"`)
	dateRe := regexp.MustCompile(`"not_before"\s*:\s*"([^"]+)"`)

	names := nameRe.FindAllStringSubmatch(string(body[:n]), -1)
	issuers := issuerRe.FindAllStringSubmatch(string(body[:n]), -1)
	dates := dateRe.FindAllStringSubmatch(string(body[:n]), -1)

	seen := make(map[string]bool)
	maxResults := min(30, min(len(names), min(len(issuers), len(dates))))
	for i := 0; i < maxResults; i++ {
		name := names[i][1]
		name = strings.ReplaceAll(name, "\\n", ", ")
		name = strings.ReplaceAll(name, "\n", ", ")
		name = strings.TrimSpace(name)
		issuer := issuers[i][1]
		if len(issuer) > 60 {
			issuer = issuer[:60]
		}
		notBefore := dates[i][1]
		key := fmt.Sprintf("%s|%s", name, notBefore)
		if !seen[key] {
			seen[key] = true
			results = append(results, model.CTLogEntry{Name: name, Issuer: issuer, NotBefore: notBefore})
		}
	}
	return results
}

func AnalyzeCSP(csp string) string {
	if csp == "" {
		return "NOT SET"
	}
	var issues []string
	if strings.Contains(csp, "'unsafe-inline'") {
		issues = append(issues, "unsafe-inline")
	}
	if strings.Contains(csp, "'unsafe-eval'") {
		issues = append(issues, "unsafe-eval")
	}
	if strings.Contains(csp, "*") {
		issues = append(issues, "wildcard source")
	}
	if strings.Contains(csp, "data:") {
		issues = append(issues, "data: source")
	}
	if !strings.Contains(csp, "frame-ancestors") {
		issues = append(issues, "no frame-ancestors")
	}
	if !strings.Contains(csp, "report-uri") && !strings.Contains(csp, "report-to") {
		issues = append(issues, "no reporting")
	}
	if len(issues) == 0 {
		if len(csp) > 120 {
			csp = csp[:120]
		}
		return "OK — " + csp
	}
	detail := strings.Join(issues, ", ")
	if len(csp) > 100 {
		csp = csp[:100]
	}
	return fmt.Sprintf("Issues: %s | %s", detail, csp)
}

func MeasurePerf(u string, client *HTTPClient) (ttfb, size int, encoding string) {
	resp, elapsed, err := client.Get(u, nil)
	if err != nil {
		return
	}
	ttfb = int(elapsed.Milliseconds())

	if resp != nil {
		cl := resp.Header.Get("Content-Length")
		if cl != "" {
			fmt.Sscanf(cl, "%d", &size)
		}
		if size == 0 {
			body := make([]byte, 100000)
			n, _ := resp.Body.Read(body)
			size = n
		}
		encoding = resp.Header.Get("Content-Encoding")
	}
	return
}

func TraceRedirects(u string, client *HTTPClient) []model.RedirectEntry {
	var chain []model.RedirectEntry
	client.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		chain = append(chain, model.RedirectEntry{
			URL:    via[len(via)-1].URL.String(),
			Status: via[len(via)-1].Response.StatusCode,
		})
		return nil
	}
	resp, _, _ := client.Get(u, nil)
	if resp != nil {
		chain = append(chain, model.RedirectEntry{
			URL:    resp.Request.URL.String(),
			Status: resp.StatusCode,
			Final:  true,
		})
	}
	return chain
}

func CheckDirectoryListing(body string) []string {
	if len(body) < 100 {
		return nil
	}
	bodyLower := body
	if len(bodyLower) > 5000 {
		bodyLower = bodyLower[:5000]
	}
	bodyLower = strings.ToLower(bodyLower)
	if strings.Contains(bodyLower, "index of") || strings.Contains(bodyLower, "directory listing") {
		return []string{"Directory listing detected"}
	}
	return nil
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return "Unknown"
	}
}

func uniqStr(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
