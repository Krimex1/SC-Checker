package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sc-checker-go/internal/model"
	"strings"
)

type DSLRule struct {
	Name      string `json:"name"`
	Condition string `json:"condition"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
}

func DefaultDSLRules() []DSLRule {
	return []DSLRule{
		{Name: "No HSTS", Condition: "hsts_enabled == false", Severity: "HIGH", Message: "HSTS not enabled"},
		{Name: "HTTP Redirect Missing", Condition: "http_to_https_redirect == false", Severity: "MEDIUM", Message: "No HTTP->HTTPS redirect"},
		{Name: "SSL Expiring Soon", Condition: "ssl_expiry_days < 30", Severity: "HIGH", Message: "SSL certificate expires within 30 days"},
		{Name: "Clickjacking", Condition: "clickjacking_protected == false", Severity: "MEDIUM", Message: "Clickjacking not prevented"},
		{Name: "Directory Listing", Condition: "directory_listing == true", Severity: "HIGH", Message: "Directory listing enabled"},
		{Name: "XSS Reflection", Condition: "xss_reflection == true", Severity: "CRITICAL", Message: "XSS reflection detected"},
		{Name: "TRACE Enabled", Condition: "trace_enabled == true", Severity: "MEDIUM", Message: "TRACE method enabled"},
		{Name: "Open Redirect", Condition: "open_redirect != ''", Severity: "HIGH", Message: "Open redirect found"},
		{Name: "Admin Panel", Condition: "admin_panels_count > 0", Severity: "HIGH", Message: "Admin panels discovered"},
		{Name: "Source Leak", Condition: "source_leak_count > 0", Severity: "HIGH", Message: "Source code/backup files leaked"},
		{Name: "GraphQL Exposed", Condition: "graphql_vulns_count > 0", Severity: "HIGH", Message: "GraphQL vulnerabilities found"},
	}
}

func DSLScan(r *model.Report) []model.DSLResult {
	var rules []DSLRule
	dslPath := "dsl_rules.json"
	if data, err := os.ReadFile(dslPath); err == nil {
		if json.Unmarshal(data, &rules) != nil {
			rules = DefaultDSLRules()
		}
	} else {
		rules = DefaultDSLRules()
	}

	var results []model.DSLResult
	for _, rule := range rules {
		if evalDSLRule(rule, r) {
			results = append(results, model.DSLResult{
				Rule:      rule.Name,
				Severity:  rule.Severity,
				Detail:    rule.Message,
				Condition: rule.Condition,
			})
		}
	}
	return results
}

func evalDSLRule(rule DSLRule, r *model.Report) bool {
	condition := rule.Condition
	if condition == "" {
		return false
	}

	parts := regexp.MustCompile(`(?i)\s+AND\s+`).Split(condition, -1)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		parts2 := regexp.MustCompile(`(?i)\s+OR\s+`).Split(part, -1)
		if len(parts2) > 1 {
			anyMatch := false
			for _, orPart := range parts2 {
				if evalDSLSingle(strings.TrimSpace(orPart), r) {
					anyMatch = true
					break
				}
			}
			if !anyMatch {
				return false
			}
			continue
		}

		notMatch := regexp.MustCompile(`(?i)^NOT\s+(.+)`).FindStringSubmatch(part)
		if notMatch != nil {
			if evalDSLSingle(strings.TrimSpace(notMatch[1]), r) {
				return false
			}
			continue
		}

		if !evalDSLSingle(part, r) {
			return false
		}
	}
	return true
}

func evalDSLSingle(cond string, r *model.Report) bool {
	re := regexp.MustCompile(`([\w_]+)\s*(==|!=|>|<|>=|<=|contains)\s*(.+)`)
	m := re.FindStringSubmatch(cond)
	if len(m) < 4 {
		return false
	}

	field := strings.TrimSpace(m[1])
	op := strings.TrimSpace(m[2])
	rawExpected := strings.TrimSpace(m[3])
	expected := strings.Trim(rawExpected, `"'`)

	var actual any
	if strings.HasSuffix(field, "_count") {
		baseField := strings.TrimSuffix(field, "_count")
		actual = getDSLFieldLen(r, baseField)
	} else {
		actual = getDSLField(r, field)
	}

	if actual == nil {
		return false
	}

	switch op {
	case "==":
		return dslEqual(actual, expected)
	case "!=":
		return !dslEqual(actual, expected)
	case ">":
		return dslNumeric(actual) > dslParseNum(expected)
	case "<":
		return dslNumeric(actual) < dslParseNum(expected)
	case ">=":
		return dslNumeric(actual) >= dslParseNum(expected)
	case "<=":
		return dslNumeric(actual) <= dslParseNum(expected)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", expected))
	}
	return false
}

func getDSLField(r *model.Report, field string) any {
	switch field {
	case "hsts_enabled":
		return r.HSTSEnabled
	case "http_to_https_redirect":
		return r.HTTPToHTTPSRedirect
	case "clickjacking_protected":
		return r.ClickjackingProtected
	case "xss_reflection":
		return r.XSSReflection
	case "trace_enabled":
		return r.TraceEnabled
	case "ssl_weak_cipher":
		return r.SSLWeakCipher
	case "mixed_content":
		return r.MixedContent
	case "ssl_expiry_days":
		return r.SSLExpiryDays
	case "open_redirect":
		return strings.Join(r.OpenRedirect, ", ")
	case "directory_listing":
		return len(r.DirectoryListing) > 0
	case "waf_detected":
		return strings.Join(r.WAFDetected, ", ")
	case "risk_score":
		return r.RiskScore
	case "risk_level":
		return r.RiskLevel
	case "status_code":
		return r.StatusCode
	}
	return nil
}

func getDSLFieldLen(r *model.Report, baseField string) any {
	switch baseField {
	case "admin_panels":
		return len(r.AdminPanels)
	case "source_leak":
		return len(r.SourceLeak)
	case "critical_paths":
		return len(r.CriticalPaths)
	case "sql_errors":
		return len(r.SQLErrors)
	case "cors_issues":
		return len(r.CORSIssues)
	case "cookie_issues":
		return len(r.CookieIssues)
	case "open_ports":
		return len(r.OpenPorts)
	case "subdomains":
		return len(r.Subdomains)
	case "ssti_results":
		return len(r.SSTIResults)
	case "graphql_vulns":
		return len(r.GraphQLVulns)
	case "mutated_payloads":
		return len(r.MutatedPayloads)
	case "cve_findings":
		return len(r.CVEFindings)
	case "exploit_verified":
		return len(r.ExploitVerified)
	case "jwt_tokens":
		return len(r.JWTTokens)
	case "anomaly_hints":
		return len(r.AnomalyHints)
	}
	return 0
}

func dslEqual(actual any, expected string) bool {
	switch v := actual.(type) {
	case bool:
		if expected == "true" || expected == "1" || expected == "yes" {
			return v
		}
		return !v
	case int:
		n := 0
		fmt.Sscanf(expected, "%d", &n)
		return v == n
	case []string:
		if expected == "" || expected == "null" || expected == "[]" {
			return len(v) == 0
		}
		return false
	case string:
		return v == expected
	}
	return fmt.Sprintf("%v", actual) == expected
}

func dslNumeric(v any) float64 {
	switch val := v.(type) {
	case int:
		return float64(val)
	case float64:
		return val
	case bool:
		if val {
			return 1
		}
		return 0
	default:
		n := 0.0
		fmt.Sscanf(fmt.Sprintf("%v", val), "%f", &n)
		return n
	}
}

func dslParseNum(s string) float64 {
	n := 0.0
	fmt.Sscanf(s, "%f", &n)
	return n
}
