package engine

import (
	"fmt"
	"net/url"
	"regexp"
	"sc-checker-go/internal/model"
	"strings"
)

func PayloadMutation(body, base string, client *HTTPClient) []model.MutationResult {
	basePayloads := []string{
		"' OR 1=1 --",
		"<script>alert(1)</script>",
		"{{7*7}}",
		"${7*7}",
		"1; DROP TABLE users",
		"../../etc/passwd",
	}

	var results []model.MutationResult
	target := strings.TrimSuffix(base, "/") + "/"

	for _, payload := range basePayloads[:2] {
		variants := mutatePayload(payload)
		for _, v := range variants[:3] {
			u := fmt.Sprintf("%s?q=%s", target, url.QueryEscape(v))
			resp, _, err := client.Get(u, nil)
			if err != nil || resp == nil {
				continue
			}
			respBody := make([]byte, 10000)
			n, _ := resp.Body.Read(respBody)
			if resp.StatusCode == 200 && n > 100 {
				results = append(results, model.MutationResult{
					Original: payload,
					Mutated:  v,
					Status:   resp.StatusCode,
					Len:      n,
					Verdict:  "POSSIBLE_BYPASS",
				})
			}
		}
	}
	return results
}

func mutatePayload(payload string) []string {
	variants := []string{payload}
	variants = append(variants, url.QueryEscape(payload))
	variants = append(variants, url.QueryEscape(url.QueryEscape(payload)))
	variants = append(variants, strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(payload, "'", "&#39;"),
			"\"", "&quot;"),
		"<", "&lt;"))
	variants = append(variants, strings.ReplaceAll(payload, " ", "/**/"))
	variants = append(variants, payload+"%00")
	variants = append(variants, strings.ReplaceAll(payload, "'", "`"))
	return uniqStr(variants)
}

func VerifyExploits(r *model.Report, client *HTTPClient) []model.VerifiedExploit {
	var verified []model.VerifiedExploit
	base := BaseURL(r.Scheme, r.Host, r.Port)

	if r.XSSReflection {
		payload := "<scrIpt>alert(document.domain)</scrIpt>"
		for _, path := range []string{"/", "/search", "/q"} {
			u := strings.TrimSuffix(base, "/") + path + "?xss=" + url.QueryEscape(payload)
			resp, _, err := client.Get(u, nil)
			if err == nil && resp != nil {
				respBody := make([]byte, 50000)
				n, _ := resp.Body.Read(respBody)
				if strings.Contains(strings.ToLower(string(respBody[:n])), strings.ToLower(payload)) {
					verified = append(verified, model.VerifiedExploit{
						Type: "XSS", Severity: "CRITICAL", URL: u,
						Detail: "Reflected XSS confirmed",
					})
					break
				}
			}
		}
	}

	if len(r.SQLErrors) > 0 {
		payload := "' OR '1'='1"
		for _, path := range []string{"/", "/index"} {
			u := fmt.Sprintf("%s/%s?id=%s", strings.TrimSuffix(base, "/"), strings.TrimPrefix(path, "/"), url.QueryEscape(payload))
			resp, _, err := client.Get(u, nil)
			if err == nil && resp != nil {
				respBody := make([]byte, 5000)
				n, _ := resp.Body.Read(respBody)
				bodyStr := strings.ToLower(string(respBody[:n]))
				for _, ind := range []string{"sql syntax", "mysql_fetch", "ORA-", "unclosed quotation"} {
					if strings.Contains(bodyStr, ind) {
						verified = append(verified, model.VerifiedExploit{
							Type: "SQLi", Severity: "CRITICAL", URL: u,
							Detail: fmt.Sprintf("SQL error confirmed: %s", ind),
						})
						break
					}
				}
			}
		}
	}

	if len(r.OpenRedirect) > 0 {
		u := fmt.Sprintf("%s/redirect?url=%s", strings.TrimSuffix(base, "/"), url.QueryEscape("//evil.com"))
		resp, _, err := client.Get(u, nil)
		if err == nil && resp != nil {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "evil.com") {
				verified = append(verified, model.VerifiedExploit{
					Type: "Open Redirect", Severity: "HIGH", URL: u,
					Detail: fmt.Sprintf("Redirects to: %s", loc),
				})
			}
		}
	}

	if r.HostHeaderInject != "SAFE" && r.HostHeaderInject != "" {
		headers := map[string]string{"Host": "evil.com"}
		resp, _, err := client.do("GET", base, headers, nil)
		if err == nil && resp != nil {
			respBody := make([]byte, 5000)
			n, _ := resp.Body.Read(respBody)
			if strings.Contains(string(respBody[:n]), "evil.com") {
				verified = append(verified, model.VerifiedExploit{
					Type: "Host Header Injection", Severity: "HIGH", URL: base,
					Detail: "Host header reflected in response",
				})
			}
		}
	}

	return verified
}

func extractMetaTags(body string) []model.MetaTag {
	var tags []model.MetaTag
	re := regexp.MustCompile(`(?i)<meta\s+([^>]+)>`)

	for _, m := range re.FindAllStringSubmatch(body, -1) {
		attrs := m[1]
		nameRe := regexp.MustCompile(`(?i)(?:name|property|http-equiv)\s*=\s*["']([^"']*)["']`)
		contentRe := regexp.MustCompile(`(?i)content\s*=\s*["']([^"']*)["']`)

		nameMatch := nameRe.FindStringSubmatch(attrs)
		contentMatch := contentRe.FindStringSubmatch(attrs)

		if nameMatch != nil {
			content := ""
			if contentMatch != nil {
				content = contentMatch[1]
				if len(content) > 100 {
					content = content[:100]
				}
			}
			tags = append(tags, model.MetaTag{Name: nameMatch[1], Content: content})
			if len(tags) >= 25 {
				break
			}
		}
	}
	return tags
}

func extractForms(body string) []model.HiddenForm {
	var forms []model.HiddenForm
	re := regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)

	for _, m := range re.FindAllStringSubmatch(body, -1) {
		attrs := m[1]
		inner := m[2]

		actionRe := regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
		methodRe := regexp.MustCompile(`(?i)method\s*=\s*["']([^"']*)["']`)
		hiddenRe := regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']hidden["']`)

		action := ""
		if am := actionRe.FindStringSubmatch(attrs); am != nil {
			action = am[1]
		}
		method := "GET"
		if mm := methodRe.FindStringSubmatch(attrs); mm != nil {
			method = strings.ToUpper(mm[1])
		}
		hiddenCount := len(hiddenRe.FindAllString(inner, -1))

		forms = append(forms, model.HiddenForm{
			Action:       action,
			Method:       method,
			HiddenInputs: hiddenCount,
		})
		if len(forms) >= 15 {
			break
		}
	}
	return forms
}

func httpMethodsFull(u string, client *HTTPClient) []model.MethodResult {
	var methods []model.MethodResult
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"} {
		resp, _, err := client.do(m, u, nil, nil)
		if err != nil || resp == nil {
			methods = append(methods, model.MethodResult{Method: m, Status: 0, Allowed: false})
			continue
		}
		methods = append(methods, model.MethodResult{
			Method:  m,
			Status:  resp.StatusCode,
			Allowed: resp.StatusCode < 405,
		})
	}
	return methods
}
