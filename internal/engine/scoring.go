package engine

import (
	"sc-checker-go/internal/model"
)

func ScoreRisk(r *model.Report) (int, string) {
	s := 0

	s += min(len(r.CriticalPaths)*15, 30)
	s += min(len(r.MissingSecurityHeaders)*4, 20)
	s += min(len(r.OpenPorts)*2, 12)
	if r.TraceEnabled {
		s += 8
	}
	for _, m := range r.AllowedMethods {
		if m == "PUT" || m == "DELETE" {
			s += 8
			break
		}
	}
	s += min(len(r.CookieIssues)*3, 9)
	s += min(len(r.CORSIssues)*6, 12)
	s += min(len(r.SQLErrors)*10, 20)
	if r.XSSReflection {
		s += 10
	}
	if !r.ServerNode {
		if !r.HSTSEnabled {
			s += 5
		}
		if !r.HTTPToHTTPSRedirect {
			s += 5
		}
	}
	if r.SSLExpiryDays > 0 && r.SSLExpiryDays < 30 {
		s += 8
	}
	if r.SSLWeakCipher {
		s += 8
	}
	if len(r.DirectoryListing) > 0 {
		s += 6
	}

	if !r.ClickjackingProtected {
		s += 6
	}
	if r.MixedContent {
		s += 5
	}
	if r.CSPAnalysis == "" || r.CSPAnalysis == "NOT SET" {
		s += 6
	}
	if r.PermissionsPolicy == "" {
		s += 4
	}
	if r.ReferrerPolicy == "" {
		s += 3
	}
	if !r.RateLimit.Detected {
		s += 5
	}

	if r.SecurityTxt == "" {
		s += 2
	}

	kevCount := 0
	exploitCount := 0
	for _, c := range r.CVEFindings {
		if c.CISAKnownExploited {
			kevCount++
		}
		if c.ExploitAvailable {
			exploitCount++
		}
	}

	s += min(kevCount*10, 20)
	s += min(exploitCount*5, 10)
	s += min(len(r.CVEFindings)*3, 12)
	s += min(len(r.SSTIResults)*8, 16)
	s += min(len(r.HTTPSmuggling)*10, 20)
	s += min(len(r.GraphQLVulns)*5, 10)
	s += min(len(r.SourceLeak)*10, 20)
	s += min(len(r.BackupFiles)*5, 10)
	s += min(len(r.AdminPanels)*5, 10)
	s += min(len(r.JWTTokens)*3, 6)
	s += min(len(r.CRLFInjection)*6, 12)
	if len(r.OpenRedirect) > 0 {
		s += 5
	}
	if r.HostHeaderInject != "" && r.HostHeaderInject != "SAFE" {
		s += 5
	}
	s += min(len(r.ExploitVerified)*8, 16)

	if s > 100 {
		s = 100
	}

	switch {
	case s >= 70:
		return s, "critical"
	case s >= 50:
		return s, "high"
	case s >= 30:
		return s, "medium"
	case s >= 10:
		return s, "low"
	default:
		return s, "info"
	}
}

func BuildAnomalyHints(r *model.Report) {
	if r.TraceEnabled {
		r.AnomalyHints = append(r.AnomalyHints, "TRACE enabled")
	}
	for _, m := range r.AllowedMethods {
		if m == "PUT" || m == "DELETE" {
			r.AnomalyHints = append(r.AnomalyHints, "Risky methods: "+m)
		}
	}
	if !r.ServerNode {
		if !r.HSTSEnabled {
			r.AnomalyHints = append(r.AnomalyHints, "HSTS missing")
		}
		if !r.HTTPToHTTPSRedirect {
			r.AnomalyHints = append(r.AnomalyHints, "No HTTPS redirect")
		}
		if len(r.DirectoryListing) > 0 {
			r.AnomalyHints = append(r.AnomalyHints, "Directory listing")
		}
		if r.XSSReflection {
			r.AnomalyHints = append(r.AnomalyHints, "XSS reflection")
		}
	}
	if r.SSLExpiryDays > 0 && r.SSLExpiryDays < 30 {
		r.AnomalyHints = append(r.AnomalyHints, "SSL expires within 30 days!")
	}
	if r.SSLWeakCipher {
		r.AnomalyHints = append(r.AnomalyHints, "Weak SSL cipher")
	}
	if r.MixedContent {
		r.AnomalyHints = append(r.AnomalyHints, "Mixed content detected")
	}
	if !r.ClickjackingProtected {
		r.AnomalyHints = append(r.AnomalyHints, "Clickjacking vulnerable")
	}
	if len(r.SourceLeak) > 0 {
		r.AnomalyHints = append(r.AnomalyHints, "Source leaks found")
	}
	if len(r.BackupFiles) > 0 {
		r.AnomalyHints = append(r.AnomalyHints, "Backup files exposed")
	}
	if len(r.HTTPSmuggling) > 0 {
		r.AnomalyHints = append(r.AnomalyHints, "HTTP smuggling possible")
	}
	if len(r.SSTIResults) > 0 {
		r.AnomalyHints = append(r.AnomalyHints, "SSTI detected")
	}
	if len(r.CRLFInjection) > 0 {
		r.AnomalyHints = append(r.AnomalyHints, "CRLF injection")
	}
	if len(r.OpenRedirect) > 0 {
		r.AnomalyHints = append(r.AnomalyHints, "Open redirect found")
	}
	if r.HostHeaderInject != "" {
		r.AnomalyHints = append(r.AnomalyHints, "Host header injection")
	}
	for _, c := range r.CVEFindings {
		if c.CISAKnownExploited {
			r.AnomalyHints = append(r.AnomalyHints, "CISA KEV: "+c.CVE+" in "+c.Product+" "+c.Version)
		}
	}
	for _, c := range r.CVEFindings {
		if c.ExploitAvailable {
			r.AnomalyHints = append(r.AnomalyHints, "Exploit available: "+c.CVE)
			break
		}
	}
}
