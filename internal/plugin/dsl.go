package plugin

import (
	"fmt"
	"regexp"
	"sc-checker-go/internal/model"
	"strconv"
	"strings"
)

func EvalCondition(cond string, r *model.Report) bool {
	if r == nil {
		return false
	}
	cond = strings.TrimSpace(cond)

	orParts := regexp.MustCompile(`(?i)\s+OR\s+`).Split(cond, -1)
	if len(orParts) > 1 {
		for _, part := range orParts {
			if EvalCondition(strings.TrimSpace(part), r) {
				return true
			}
		}
		return false
	}

	andParts := regexp.MustCompile(`(?i)\s+AND\s+`).Split(cond, -1)
	if len(andParts) > 1 {
		for _, part := range andParts {
			if !EvalCondition(strings.TrimSpace(part), r) {
				return false
			}
		}
		return true
	}

	notMatch := regexp.MustCompile(`(?i)^NOT\s+(.+)`).FindStringSubmatch(cond)
	if notMatch != nil {
		return !EvalCondition(strings.TrimSpace(notMatch[1]), r)
	}

	re := regexp.MustCompile(`([\w_]+)\s*(==|!=|>|<|>=|<=|contains)\s*(.+)`)
	m := re.FindStringSubmatch(cond)
	if len(m) < 4 {
		return false
	}

	field := strings.TrimSpace(m[1])
	op := strings.TrimSpace(m[2])
	expected := strings.Trim(m[3], `"'`)

	actual := GetField(r, field)

	switch op {
	case "==":
		return equal(actual, expected)
	case "!=":
		return !equal(actual, expected)
	case ">":
		return numeric(actual) > parseNum(expected)
	case "<":
		return numeric(actual) < parseNum(expected)
	case ">=":
		return numeric(actual) >= parseNum(expected)
	case "<=":
		return numeric(actual) <= parseNum(expected)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", actual), expected)
	}
	return false
}

func GetField(r *model.Report, field string) any {
	if strings.HasSuffix(field, "_count") {
		base := strings.TrimSuffix(field, "_count")
		return getListLen(r, base)
	}

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
	case "directory_listing":
		return r.DirectoryListing
	case "ssl_expiry_days":
		return r.SSLExpiryDays
	case "risk_score":
		return r.RiskScore
	case "risk_level":
		return r.RiskLevel
	case "status_code":
		return r.StatusCode
	case "server_node":
		return r.ServerNode
	case "waf_detected":
		return r.WAFDetected
	case "open_redirect":
		return r.OpenRedirect
	case "host_header_inject":
		return r.HostHeaderInject
	case "detected_cms":
		return r.DetectedCMS
	case "detected_frameworks":
		return r.DetectedFrameworks
	case "subdomains":
		return r.Subdomains
	default:
		return nil
	}
}

func getListLen(r *model.Report, base string) int {
	switch base {
	case "critical_paths":
		return len(r.CriticalPaths)
	case "open_ports":
		return len(r.OpenPorts)
	case "subdomains":
		return len(r.Subdomains)
	case "sql_errors":
		return len(r.SQLErrors)
	case "cors_issues":
		return len(r.CORSIssues)
	case "cookie_issues":
		return len(r.CookieIssues)
	case "missing_security_headers":
		return len(r.MissingSecurityHeaders)
	case "discovered_paths":
		return len(r.DiscoveredPaths)
	case "cve_findings":
		return len(r.CVEFindings)
	case "cvss_scores":
		return len(r.CVSSScores)
	case "ssti_results":
		return len(r.SSTIResults)
	case "graphql_vulns":
		return len(r.GraphQLVulns)
	case "dsl_results":
		return len(r.DSLResults)
	case "jwt_tokens":
		return len(r.JWTTokens)
	case "admin_panels":
		return len(r.AdminPanels)
	case "source_leak":
		return len(r.SourceLeak)
	case "backup_files":
		return len(r.BackupFiles)
	case "supply_chain":
		return len(r.SupplyChain)
	case "emails_found":
		return len(r.EmailsFound)
	case "hidden_endpoints":
		return len(r.HiddenEndpoints)
	case "screenshots":
		return len(r.Screenshots)
	case "exploit_verified":
		return len(r.ExploitVerified)
	case "session_issues":
		return len(r.SessionIssues)
	case "anomaly_hints":
		return len(r.AnomalyHints)
	case "mutated_payloads":
		return len(r.MutatedPayloads)
	case "chaos_findings":
		return len(r.ChaosFindings)
	}
	return 0
}

func equal(actual any, expected string) bool {
	switch v := actual.(type) {
	case bool:
		if expected == "true" || expected == "1" {
			return v
		}
		return !v
	case int:
		n, _ := strconv.Atoi(expected)
		return v == n
	case string:
		return v == expected
	case []string:
		if expected == "" || expected == "null" {
			return len(v) == 0
		}
		if expected == "true" {
			return len(v) > 0
		}
		return false
	}
	return fmt.Sprintf("%v", actual) == expected
}

func numeric(v any) float64 {
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
	}
	n, _ := strconv.ParseFloat(fmt.Sprintf("%v", v), 64)
	return n
}

func parseNum(s string) float64 {
	n, _ := strconv.ParseFloat(s, 64)
	return n
}

func SetReportField(r *model.Report, field, value string) {
	switch field {
	case "risk_level":
		r.RiskLevel = value
	}
}
