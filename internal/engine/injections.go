package engine

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sc-checker-go/internal/model"
	"strings"
)

var (
	sqlErrorIndicators = []string{
		"you have an error in your sql", "mysql_fetch", "pg_query",
		"sqlstate", "incorrect syntax near", "ORA-",
		"SQLite/JDBCDriver", "mysql_num_rows",
	}

	xssStripScript   = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	xssStripStyle    = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	xssStripNoscript = regexp.MustCompile(`(?is)<noscript[^>]*>.*?</noscript>`)
	xssAttrDQ        = regexp.MustCompile(`(?i)\b\w[\w-]*\s*=\s*"[^"]*"`)
	xssAttrSQ        = regexp.MustCompile(`(?i)\b\w[\w-]*\s*=\s*'[^']*'`)
	xssAttrUQ        = regexp.MustCompile(`(?i)\b\w[\w-]*\s*=\s*[^\s>"\'>]+`)
	xssStripURLs     = regexp.MustCompile(`https?://[^\s"'<>]*`)
	xssStripMeta     = regexp.MustCompile(`(?i)<(?:meta|link|img|iframe|embed|object|source|video|audio)\b[^>]*\s*/?>`)
	xssStripComments = regexp.MustCompile(`(?s)<!--.*?-->`)

	mixedScript   = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	mixedStyle    = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	mixedNoscript = regexp.MustCompile(`(?is)<noscript[^>]*>.*?</noscript>`)
	mixedComments = regexp.MustCompile(`(?s)<!--.*?-->`)
	mixedHTTP     = regexp.MustCompile(`(?is)(?:img|script|iframe|link|video|audio|source|embed|object)\b[^>]*\b(?:src|href|poster)\s*=\s*["']http://([^"'\s>]+)`)
	mixedCSSURL   = regexp.MustCompile(`(?is)\bstyle\s*=\s*["'][^"']*\burl\s*\(\s*["']?http://([^"'\s)>]+)`)

	emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phonePattern = regexp.MustCompile(`(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}`)
	socialPattern = regexp.MustCompile(`https?://(?:www\.)?(?:facebook|twitter|x|instagram|linkedin|youtube|tiktok|github|telegram|vk)\.[^\s"'<>]+`)

	jsLibPatterns = map[string]string{
		`jquery[/.-]([0-9.]+)`:  "jQuery",
		`react[/.-]([0-9.]+)`:   "React",
		`vue[/.-]([0-9.]+)`:     "Vue.js",
		`bootstrap[/.-]([0-9.]+)`: "Bootstrap",
		`lodash[/.-]([0-9.]+)`:  "Lodash",
		`axios[/.-]([0-9.]+)`:   "Axios",
	}

	sstiPayloads = []struct {
		Payload  string
		Expected string
		Engine   string
	}{
		{"{{7*1337}}", "9359", "Jinja2/Twig"},
		{"${7*1337}", "9359", "FreeMarker/Velocity"},
		{"<%= 7*1337 %>", "9359", "ERB"},
		{"#{7*1337}", "9359", "Ruby/Slim"},
	}
)

func CheckSQLErrors(u string, client *HTTPClient) []string {
	sep := "&"
	if !strings.Contains(u, "?") {
		sep = "?"
	}
	payloads := []struct {
		payload string
		label   string
	}{
		{"'", "SQL syntax"},
		{"%27", "SQL syntax"},
	}

	for _, pl := range payloads {
		testURL := fmt.Sprintf("%s%sid=%s", u, sep, url.QueryEscape(pl.payload))
		resp, _, err := client.Get(testURL, nil)
		if err != nil || resp == nil {
			continue
		}
		body := make([]byte, 5000)
		n, _ := resp.Body.Read(body)
		bodyLower := strings.ToLower(string(body[:n]))

		for _, ind := range sqlErrorIndicators {
			if strings.Contains(bodyLower, ind) {
				return []string{fmt.Sprintf("SQL error (%s)", pl.label)}
			}
		}
	}
	return nil
}

func CheckXSS(u string, client *HTTPClient) bool {
	token := "chk_xss_7f3a"
	sep := "&"
	if !strings.Contains(u, "?") {
		sep = "?"
	}

	baselineResp, _, _ := client.Get(u, nil)
	baseline := ""
	if baselineResp != nil {
		body := make([]byte, 50000)
		n, _ := baselineResp.Body.Read(body)
		baseline = string(body[:n])
	}

	payloads := []string{token}
	for _, payload := range payloads {
		testURL := fmt.Sprintf("%s%sxss=%s", u, sep, url.QueryEscape(payload))
		resp, _, err := client.Get(testURL, nil)
		if err != nil || resp == nil {
			continue
		}
		body := make([]byte, 100000)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])

		if !strings.Contains(bodyStr, payload) {
			continue
		}
		if strings.Contains(baseline, payload) {
			continue
		}

		cleaned := xssStripScript.ReplaceAllString(bodyStr, "")
		cleaned = xssStripStyle.ReplaceAllString(cleaned, "")
		cleaned = xssStripNoscript.ReplaceAllString(cleaned, "")
		cleaned = xssAttrDQ.ReplaceAllString(cleaned, "")
		cleaned = xssAttrSQ.ReplaceAllString(cleaned, "")
		cleaned = xssAttrUQ.ReplaceAllString(cleaned, "")
		cleaned = xssStripURLs.ReplaceAllString(cleaned, "")
		cleaned = xssStripMeta.ReplaceAllString(cleaned, "")
		cleaned = xssStripComments.ReplaceAllString(cleaned, "")

		if strings.Contains(cleaned, payload) {
			return true
		}
	}
	return false
}

func CheckMixedContent(resp *http.Response) bool {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return false
	}
	reqURL := resp.Request.URL.String()
	if !strings.HasPrefix(reqURL, "https://") {
		return false
	}

	body := make([]byte, 100000)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	stripped := mixedScript.ReplaceAllString(bodyStr, "")
	stripped = mixedStyle.ReplaceAllString(stripped, "")
	stripped = mixedNoscript.ReplaceAllString(stripped, "")
	stripped = mixedComments.ReplaceAllString(stripped, "")

	matches := mixedHTTP.FindAllStringSubmatch(stripped, -1)
	cssMatches := mixedCSSURL.FindAllStringSubmatch(stripped, -1)

	for _, m := range matches {
		if len(m) > 1 {
			if !isTrackingDomain(m[1]) {
				return true
			}
		}
	}
	for _, m := range cssMatches {
		if len(m) > 1 {
			if !isTrackingDomain(m[1]) {
				return true
			}
		}
	}
	return false
}

func isTrackingDomain(ref string) bool {
	for td := range TrackingDomains {
		if strings.Contains(ref, td) {
			return true
		}
	}
	return false
}

func CheckCRLF(u string, client *HTTPClient) []string {
	var results []string
	payloads := []string{"%0d%0aInjected-Header:1", "%0D%0AX-Injected:1"}
	for _, p := range payloads {
		testURL := fmt.Sprintf("%s/?test=%s", u, p)
		resp, _, err := client.Get(testURL, nil)
		if err != nil || resp == nil {
			continue
		}
		for k := range resp.Header {
			if strings.Contains(strings.ToLower(k), "injected") {
				results = append(results, fmt.Sprintf("CRLF via %s... -> header reflected", p[:10]))
				break
			}
		}
	}
	return results
}

func CheckOpenRedirect(u string, client *HTTPClient) []string {
	var results []string
	params := []string{"redirect", "url", "next", "return"}
	for _, p := range params {
		testURL := fmt.Sprintf("%s/?%s=https://evil.com", u, p)
		resp, _, err := client.Get(testURL, nil)
		if err != nil || resp == nil {
			continue
		}
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "evil.com") {
			results = append(results, fmt.Sprintf("Open redirect via ?%s=...", p))
		}
	}
	return results
}

func CheckDirTraversal(u string, client *HTTPClient) []string {
	var results []string
	payloads := []string{"../../../etc/passwd", "..\\..\\..\\windows\\win.ini"}
	for _, p := range payloads {
		testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(u, "/"), p)
		resp, _, err := client.Get(testURL, nil)
		if err != nil || resp == nil {
			continue
		}
		body := make([]byte, 500)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])
		if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "[extensions]") {
			results = append(results, fmt.Sprintf("Directory traversal: %s", p))
		}
	}
	return results
}

func CheckHostHeaderInjection(u string, client *HTTPClient) string {
	headers := map[string]string{"Host": "evil.com"}
	resp, _, err := client.do("GET", u, headers, nil)
	if err != nil || resp == nil {
		return "SAFE"
	}
	body := make([]byte, 5000)
	n, _ := resp.Body.Read(body)
	if strings.Contains(string(body[:n]), "evil.com") {
		return "VULNERABLE — Host header reflected"
	}
	if resp.StatusCode == 200 {
		return "Host header accepted (200 OK)"
	}
	return "SAFE"
}

func CheckSSTI(u string, client *HTTPClient) []model.SSTIFinding {
	var findings []model.SSTIFinding

	baselineResp, _, _ := client.Get(u, nil)
	baselineBody := ""
	if baselineResp != nil {
		body := make([]byte, 50000)
		n, _ := baselineResp.Body.Read(body)
		baselineBody = string(body[:n])
		baselineResp.Body.Close()
	}

	controlURL := fmt.Sprintf("%s/?name=%s", strings.TrimSuffix(u, "/"), url.QueryEscape("NOTSSTI_9359_marker"))
	controlResp, _, _ := client.Get(controlURL, nil)
	controlBody := ""
	if controlResp != nil {
		body := make([]byte, 50000)
		n, _ := controlResp.Body.Read(body)
		controlBody = string(body[:n])
		controlResp.Body.Close()
	}
	if strings.Contains(baselineBody, "9359") || strings.Contains(controlBody, "9359") {
		return findings
	}

	confirmedEngines := make(map[string]bool)

	for _, tpl := range sstiPayloads {
		testURL := fmt.Sprintf("%s/?name=%s", strings.TrimSuffix(u, "/"), url.QueryEscape(tpl.Payload))
		resp, _, err := client.Get(testURL, nil)
		if err != nil || resp == nil {
			continue
		}
		body := make([]byte, 50000)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])
		resp.Body.Close()

		if !strings.Contains(bodyStr, tpl.Expected) {
			continue
		}

		if strings.Contains(bodyStr, tpl.Payload) {
			continue
		}

		if confirmedEngines[tpl.Engine] {
			continue
		}
		confirmedEngines[tpl.Engine] = true

		findings = append(findings, model.SSTIFinding{
			Payload:  tpl.Payload,
			Engine:   tpl.Engine,
			Severity: "CRITICAL",
			Detail:   fmt.Sprintf("SSTI confirmed with %s engine (payload evaluated, not reflected)", tpl.Engine),
		})
		break
	}

	if len(findings) == 0 {
		for _, tpl := range sstiPayloads {
			if confirmedEngines[tpl.Engine] {
				continue
			}
			resp, _, err := client.Post(u, map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				fmt.Sprintf("name=%s", url.QueryEscape(tpl.Payload)))
			if err != nil || resp == nil {
				continue
			}
			body := make([]byte, 50000)
			n, _ := resp.Body.Read(body)
			bodyStr := string(body[:n])
			resp.Body.Close()

			if !strings.Contains(bodyStr, tpl.Expected) {
				continue
			}
			if strings.Contains(bodyStr, tpl.Payload) {
				continue
			}

			findings = append(findings, model.SSTIFinding{
				Payload:  tpl.Payload,
				Engine:   tpl.Engine,
				Method:   "POST",
				Severity: "CRITICAL",
				Detail:   fmt.Sprintf("SSTI via POST body with %s (payload evaluated)", tpl.Engine),
			})
			break
		}
	}

	return findings
}

func ExtractRecon(body, host string) (emails, phones, social, external []string) {
	emailMatches := emailPattern.FindAllString(body, -1)
	phoneMatches := phonePattern.FindAllString(body, -1)
	socialMatches := socialPattern.FindAllString(body, -1)

	seen := make(map[string]bool)
	for _, e := range emailMatches {
		if !seen[e] && len(emails) < 20 {
			seen[e] = true
			emails = append(emails, e)
		}
	}
	seen = make(map[string]bool)
	for _, p := range phoneMatches {
		if !seen[p] && len(phones) < 15 {
			seen[p] = true
			phones = append(phones, p)
		}
	}
	seen = make(map[string]bool)
	for _, s := range socialMatches {
		if !seen[s] && len(social) < 15 {
			seen[s] = true
			social = append(social, s)
		}
	}

	hrefRe := regexp.MustCompile(`(?i)href\s*=\s*["']?(https?://[^"'>\s]+)`)
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		u := m[1]
		if !strings.Contains(u, host) {
			if !seen[u] && len(external) < 30 {
				seen[u] = true
				external = append(external, u)
			}
		}
	}
	return
}

func DetectJSLibraries(body string) []string {
	var libs []string
	for pat, name := range jsLibPatterns {
		re := regexp.MustCompile(`(?i)` + pat)
		matches := re.FindStringSubmatch(body)
		if matches != nil {
			version := ""
			if len(matches) > 1 {
				version = matches[1]
			}
			libs = append(libs, fmt.Sprintf("%s %s", name, version))
		}
	}
	return libs
}

func CheckBackupFiles(u string, client *HTTPClient) []string {
	var found []string
	baks := []string{".bak", ".old", ".swp", ".save"}
	files := []string{"config", ".env", "web.config", "index", "settings"}

	base := strings.TrimSuffix(u, "/")
	for _, f := range files {
		for _, b := range baks {
			testURL := fmt.Sprintf("%s/%s%s", base, f, b)
			resp, _, err := client.Get(testURL, nil)
			if err == nil && resp != nil && resp.StatusCode == 200 {
				body := make([]byte, 50)
				n, _ := resp.Body.Read(body)
				if n > 50 {
					found = append(found, fmt.Sprintf("/%s%s", f, b))
				}
			}
		}
	}
	return found
}

func CheckSourceLeak(u string, client *HTTPClient) []string {
	var found []string
	leaks := []string{".git/HEAD", ".env", ".DS_Store", "composer.json", "package.json", "phpinfo.php", "debug.log"}
	for _, l := range leaks {
		testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(u, "/"), l)
		resp, _, err := client.Get(testURL, nil)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		body := make([]byte, 500)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])
		for _, sig := range []string{"[core]", "APP_KEY=", "DB_PASSWORD", "<?xml", "composer", "node_modules"} {
			if strings.Contains(bodyStr, sig) {
				found = append(found, "/"+l)
				break
			}
		}
	}
	return found
}

func CheckAdminPanels(u string, client *HTTPClient) []string {
	var found []string
	paths := []string{"admin", "wp-admin", "cpanel", "phpmyadmin", "manager", "panel"}
	for _, p := range paths {
		testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(u, "/"), p)
		resp, _, err := client.Get(testURL, nil)
		if err == nil && resp != nil {
			status := resp.StatusCode
			if status == 200 || status == 301 || status == 302 || status == 401 || status == 403 {
				found = append(found, fmt.Sprintf("/%s [%d]", p, status))
			}
		}
	}
	return found
}

func CheckLoginPages(u string, client *HTTPClient) []string {
	var found []string
	paths := []string{"login", "signin", "auth", "wp-login.php", "user/login"}
	for _, p := range paths {
		testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(u, "/"), p)
		resp, _, err := client.Get(testURL, nil)
		if err == nil && resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302) {
			body := make([]byte, 5000)
			n, _ := resp.Body.Read(body)
			bodyStr := strings.ToLower(string(body[:n]))
			for _, kw := range []string{"password", "login", "sign in", "authenticate"} {
				if strings.Contains(bodyStr, kw) {
					found = append(found, "/"+p)
					break
				}
			}
		}
	}
	return found
}

func CheckAPIEndpoints(u, body string, client *HTTPClient) []string {
	paths := []string{"api", "api/v1", "graphql", "swagger", "openapi.json"}
	var found []string
	for _, p := range paths {
		testURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(u, "/"), p)
		resp, _, err := client.Get(testURL, nil)
		if err == nil && resp != nil {
			status := resp.StatusCode
			if status == 200 || status == 301 || status == 302 || status == 401 || status == 403 {
				found = append(found, fmt.Sprintf("/%s [%d]", p, status))
			}
		}
	}
	bodyURLsRe := regexp.MustCompile(`["'](?:https?://[^"']*|/api/[^"']*)["']`)
	for _, m := range bodyURLsRe.FindAllString(body, -1) {
		u := strings.Trim(m, "\"'")
		if strings.Contains(u, "/api/") || strings.Contains(u, "graphql") {
			if len(u) > 100 {
				u = u[:100]
			}
			found = append(found, u)
		}
	}
	return uniqStr(found)
}
