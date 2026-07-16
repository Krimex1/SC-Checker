package export

import (
	"fmt"
	"html"
	"sc-checker-go/internal/config"
	"sc-checker-go/internal/model"
	"strings"
)

func ToTXT(r *model.Report) string {
	var b strings.Builder
	write := func(f string, args ...any) { b.WriteString(fmt.Sprintf(f, args...)) }

	write("═══════════════════════════════════════════\n")
	write("  SC Checker v%s — Scan Report\n", config.Version)
	write("═══════════════════════════════════════════\n\n")
	write("Generated: %s\n", r.GeneratedAt)
	write("Duration:  %dms\n", r.ScanDurationMs)
	write("Target:    %s\n", r.Target)
	write("IP:        %s:%d\n", r.IP, r.Port)
	write("URL:       %s\n", r.NormalizedURL)
	write("Status:    %d (%dms)\n", r.StatusCode, r.ResponseTimeMs)
	write("Proxy:     %s\n\n", orStr(r.ProxyUsed, "none"))

	if r.ServerBanner != "" {
		write("Server:    %s\n", r.ServerBanner)
	}
	write("Risk:      %d/100 [%s]\n\n", r.RiskScore, strings.ToUpper(r.RiskLevel))

	write("───────────────────────────────────────────\n")
	write("  SECURITY CHECKS\n")
	write("───────────────────────────────────────────\n")
	addTXTLine(&b, r.HSTSEnabled, "HSTS")
	addTXTLine(&b, r.ClickjackingProtected, "Clickjacking Protected")
	addTXTLine(&b, r.HTTPToHTTPSRedirect, "HTTP→HTTPS Redirect")
	addTXTLine(&b, !r.SSLWeakCipher, "SSL Cipher")
	addTXTLine(&b, !r.XSSReflection, "XSS Reflection")
	addTXTLine(&b, !r.TraceEnabled, "TRACE Disabled")
	addTXTLine(&b, r.RateLimit.Detected, "Rate Limiting")

	if len(r.MissingSecurityHeaders) > 0 {
		write("\nMissing Headers:\n")
		for _, h := range r.MissingSecurityHeaders { write("  ✗ %s\n", h) }
	}
	if len(r.CORSIssues) > 0 {
		write("\nCORS Issues:\n")
		for _, c := range r.CORSIssues { write("  ✗ %s\n", c) }
	}
	if len(r.CookieIssues) > 0 {
		write("\nCookie Issues:\n")
		for _, c := range r.CookieIssues { write("  ✗ %s\n", c) }
	}
	if len(r.WAFDetected) > 0 {
		write("\nWAF: %s\n", strings.Join(r.WAFDetected, ", "))
	}
	if len(r.DetectedCMS) > 0 {
		write("CMS: %s\n", strings.Join(r.DetectedCMS, ", "))
	}
	if len(r.DetectedFrameworks) > 0 {
		write("Framework: %s\n", strings.Join(r.DetectedFrameworks, ", "))
	}

	write("\n───────────────────────────────────────────\n  SSL / TLS\n───────────────────────────────────────────\n")
	if v, ok := r.TLSSummary["version"]; ok { write("Version:    %s\n", v) }
	if v, ok := r.TLSSummary["cipher"]; ok { write("Cipher:     %s\n", v) }
	write("Expiry:     %s (%d days)\n", r.SSLExpiryDate, r.SSLExpiryDays)
	if s, ok := r.SSLDeep["subject"].(string); ok { write("Subject:    %s\n", s) }
	if s, ok := r.SSLDeep["issuer"].(string); ok { write("Issuer:     %s\n", s) }
	if sans, ok := r.SSLDeep["san"].([]string); ok && len(sans) > 0 {
		if len(sans) > 5 {
			write("SAN:        (%d entries)\n", len(sans))
			for _, s := range sans {
				write("            - %s\n", s)
			}
		} else {
			write("SAN:        %s\n", strings.Join(sans, ", "))
		}
	}

	write("\n───────────────────────────────────────────\n  OPEN PORTS (%d)\n───────────────────────────────────────────\n", len(r.OpenPorts))
	for _, p := range r.OpenPorts {
		svc := config.PortServices[p]
		banner := ""
		if r.PortBanners != nil { banner = r.PortBanners[fmt.Sprintf("%d", p)] }
		if banner != "" { write("  %-5d  %-12s  %s\n", p, svc, banner) } else { write("  %-5d  %s\n", p, svc) }
	}

	if r.ReverseDNS != "" { write("\nReverse DNS: %s\n", r.ReverseDNS) }

	if len(r.DiscoveredPaths) > 0 {
		write("\n───────────────────────────────────────────\n  DISCOVERED PATHS (%d/%d)\n───────────────────────────────────────────\n", len(r.DiscoveredPaths), r.TotalPathsScanned)
		for _, p := range r.DiscoveredPaths {
			write("  %-40s  %d  %d bytes\n", truncate(p.Path, 40), p.Status, p.Size)
		}
	}
	if len(r.CriticalPaths) > 0 {
		write("\n  CRITICAL PATHS:\n")
		for _, p := range r.CriticalPaths { write("  ✗ %s\n", p) }
	}
	if len(r.Subdomains) > 0 {
		write("\n───────────────────────────────────────────\n  SUBDOMAINS (%d)\n───────────────────────────────────────────\n", len(r.Subdomains))
		for _, s := range r.Subdomains { write("  %s\n", s) }
	}
	if len(r.DNSRecords) > 0 {
		write("\n───────────────────────────────────────────\n  DNS RECORDS\n───────────────────────────────────────────\n")
		for rt, entries := range r.DNSRecords {
			write("\n%s:\n", rt)
			for _, e := range entries { write("  %s\n", e) }
		}
	}
	if r.ZoneTransfer != nil && len(r.ZoneTransfer) > 0 {
		write("\nZone Transfer:\n")
		for _, z := range r.ZoneTransfer { write("  [%s] %s\n", z.Severity, z.Detail) }
	}

	if len(r.CVEFindings) > 0 {
		write("\n───────────────────────────────────────────\n  CVE FINDINGS (%d)\n───────────────────────────────────────────\n", len(r.CVEFindings))
		for _, c := range r.CVEFindings {
			kev := ""
			if c.CISAKnownExploited { kev = " [KEV]" }
			epss := ""
			if c.EPSS > 0 { epss = fmt.Sprintf(" EPSS:%.1f%%", c.EPSS*100) }
			exp := ""
			if c.ExploitAvailable { exp = " [EXPLOIT]" }
			write("  %s  %.1f  %-7s%s%s%s  %s %s\n", c.CVE, c.Score, c.Severity, kev, exp, epss, c.Product, c.Version)
			if c.Desc != "" { write("    %s\n", c.Desc) }
			if c.CWE != "" { write("    %s\n", c.CWE) }
		}
	}
	if len(r.SSTIResults) > 0 {
		write("\n───────────────────────────────────────────\n  SSTI FINDINGS (%d)\n───────────────────────────────────────────\n", len(r.SSTIResults))
		for _, s := range r.SSTIResults { write("  [%s] %s — %s\n", s.Severity, s.Engine, s.Detail) }
	}
	if len(r.JWTTokens) > 0 { write("\n  JWT Tokens: %d found\n", len(r.JWTTokens)) }
	if len(r.GraphQLVulns) > 0 { write("\n  GraphQL Vulns: %d\n", len(r.GraphQLVulns)) }
	if len(r.HTTPSmuggling) > 0 { write("\n  HTTP Smuggling: %d findings\n", len(r.HTTPSmuggling)) }
	if r.RateLimit.Detected { write("\n  Rate Limit: Detected\n") }

	if r.Whois.Registrar != "" {
		write("\n───────────────────────────────────────────\n  WHOIS\n───────────────────────────────────────────\n")
		write("Registrar:    %s\n", r.Whois.Registrar)
		if r.Whois.Created != "" { write("Created:      %s\n", r.Whois.Created) }
		if r.Whois.Expires != "" { write("Expires:      %s\n", r.Whois.Expires) }
		if r.Whois.NameServers != "" { write("NS:           %s\n", r.Whois.NameServers) }
	}
	if s := r.Shodan; len(s.Ports) > 0 || s.Org != "" || s.OS != "" {
		write("\n───────────────────────────────────────────\n  SHODAN\n───────────────────────────────────────────\n")
		if s.Org != "" { write("Org:    %s\n", s.Org) }
		if s.OS != "" { write("OS:     %s\n", s.OS) }
		if len(s.Ports) > 0 { write("Ports:  %v\n", s.Ports) }
	}
	if len(r.CTLogs) > 0 {
		write("\n───────────────────────────────────────────\n  CT LOGS (%d)\n───────────────────────────────────────────\n", len(r.CTLogs))
		for _, c := range r.CTLogs { write("  %s — %s\n", c.Name, c.Issuer) }
	}
	if len(r.AnomalyHints) > 0 {
		write("\n───────────────────────────────────────────\n  ANOMALIES\n───────────────────────────────────────────\n")
		for _, a := range r.AnomalyHints { write("  %s\n", a) }
	}
	if len(r.PluginGraphNodes) > 0 {
		write("\n───────────────────────────────────────────\n  PLUGIN FINDINGS (%d)\n───────────────────────────────────────────\n", len(r.PluginGraphNodes))
		for _, p := range r.PluginGraphNodes {
			if m, ok := p.(map[string]any); ok {
				write("  [%s] %s: %s\n", m["severity"], m["plugin"], m["message"])
			}
		}
	}
	write("\n═══════════════════════════════════════════\n  Generated by SC Checker v%s\n═══════════════════════════════════════════\n", config.Version)
	return b.String()
}

func addTXTLine(b *strings.Builder, ok bool, name string) {
	if ok { b.WriteString(fmt.Sprintf("  ✓  %s\n", name)) } else { b.WriteString(fmt.Sprintf("  ✗  %s\n", name)) }
}

func ToHTML(r *model.Report) string {
	colors := map[string]string{
		"critical": "#f7768e", "high": "#ff9e64", "medium": "#e0af68", "low": "#9ece6a", "info": "#7dcfff",
	}
	riskColor := colors["critical"]
	if c, ok := colors[r.RiskLevel]; ok { riskColor = c }

	var b strings.Builder
	es := html.EscapeString

	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SC Checker Report — ` + es(r.Target) + `</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1a1b26;color:#c0caf5;font-family:Segoe UI,sans-serif;padding:20px}
.container{max-width:1200px;margin:0 auto}
h1{color:#7aa2f7;margin-bottom:5px;font-size:24px}
h2{color:#bb9af7;margin:30px 0 10px;border-bottom:2px solid #3b4261;padding-bottom:8px;font-size:18px}
h3{color:#7dcfff;margin:15px 0 8px;font-size:14px}
.meta{color:#565f89;font-size:12px;margin-bottom:20px}
.risk-badge{display:inline-block;padding:4px 12px;border-radius:6px;font-weight:bold;color:#1a1b26;background:` + riskColor + `}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:15px 0}
.card{background:#24283b;border-radius:10px;padding:16px;border:1px solid #3b4261}
.card h3{color:#7dcfff;font-size:13px;margin:0 0 8px;font-weight:600}
.stat{font-size:26px;font-weight:bold;color:#c0caf5}
.sub{font-size:12px;color:#787c99;margin-top:4px}
.pass{color:#9ece6a} .fail{color:#f7768e} .warn{color:#e0af68}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:10px 0}
.grid3{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}
th{background:#2f3347;color:#7dcfff;text-align:left;padding:8px 10px;font-weight:600}
td{padding:8px 10px;border-bottom:1px solid #2f3347}
tr:hover td{background:#2f3347}
.tag{display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;margin:2px 4px 2px 0;background:#2f3347;color:#c0caf5}
.tag-red{background:#3b2030;color:#f7768e} .tag-green{background:#1e3020;color:#9ece6a}
.tag-yellow{background:#303020;color:#e0af68} .tag-blue{background:#1e2a40;color:#7dcfff} .tag-purple{background:#2a1e40;color:#bb9af7}
.severity-critical{color:#f7768e;font-weight:bold} .severity-high{color:#ff9e64;font-weight:bold}
.severity-medium{color:#e0af68} .severity-low{color:#9ece6a} .severity-info{color:#7dcfff}
pre{background:#1e2030;padding:12px;border-radius:8px;font-family:Consolas,monospace;font-size:12px;overflow-x:auto;white-space:pre-wrap;border:1px solid #3b4261}
ul{padding-left:20px} li{margin:4px 0}
</style></head><body><div class="container">`)

	b.WriteString(`<h1>SC Checker Report</h1>`)
	b.WriteString(`<div class="meta">Generated: ` + es(r.GeneratedAt) + ` | Target: <b>` + es(r.Target) + `</b> | IP: ` + es(r.IP) +
		` | Duration: ` + fmtInt(r.ScanDurationMs) + `ms | SC Checker v` + config.Version + `</div>`)

	b.WriteString(`<div class="summary-grid">`)
	b.WriteString(`<div class="card"><h3>Risk Score</h3><div class="stat">` + fmtInt(r.RiskScore) + `/100 <span class="risk-badge">` + es(strings.ToUpper(r.RiskLevel)) + `</span></div></div>`)
	b.WriteString(`<div class="card"><h3>HTTP Status</h3><div class="stat">` + fmtInt(r.StatusCode) + `</div><div class="sub">` + fmtInt(r.ResponseTimeMs) + `ms</div></div>`)
	b.WriteString(`<div class="card"><h3>Paths</h3><div class="stat">` + fmtInt(len(r.DiscoveredPaths)) + `/` + fmtInt(r.TotalPathsScanned) + `</div><div class="sub">Critical: ` + fmtInt(len(r.CriticalPaths)) + `</div></div>`)
	b.WriteString(`<div class="card"><h3>Network</h3><div class="stat">` + fmtInt(len(r.OpenPorts)) + ` ports</div><div class="sub">` + fmtInt(len(r.Subdomains)) + ` subs · ` + fmtInt(len(r.CVEFindings)) + ` CVEs</div></div>`)
	b.WriteString(`</div>`)

	b.WriteString(`<div class="grid2">`)
	b.WriteString(`<div class="card"><h3>Fingerprint</h3>`)
	for _, c := range r.DetectedCMS { b.WriteString(`<span class="tag tag-blue">` + es(c) + `</span>`) }
	for _, f := range r.DetectedFrameworks { b.WriteString(`<span class="tag tag-purple">` + es(f) + `</span>`) }
	if len(r.WAFDetected) > 0 {
		b.WriteString(`<br><b>WAF:</b> `)
		for _, w := range r.WAFDetected { b.WriteString(`<span class="tag tag-red">` + es(w) + `</span>`) }
	}
	if r.ServerBanner != "" { b.WriteString(`<br>Server: ` + es(r.ServerBanner)) }
	b.WriteString(`</div>`)
	b.WriteString(`<div class="card"><h3>Technology</h3>`)
	for _, v := range r.VersionHints { b.WriteString(`<span class="tag">` + es(v.Name) + ` ` + es(v.Version) + `</span>`) }
	b.WriteString(`</div></div>`)

	b.WriteString(`<h2>Security Checks</h2><table><tr><th>Check</th><th>Result</th></tr>`)
	addCheck(&b, "HSTS Enabled", r.HSTSEnabled)
	addCheck(&b, "Clickjacking Protected", r.ClickjackingProtected)
	addCheck(&b, "HTTP→HTTPS Redirect", r.HTTPToHTTPSRedirect)
	addCheck(&b, "SSL Strong Cipher", !r.SSLWeakCipher)
	addCheck(&b, "No XSS Reflection", !r.XSSReflection)
	addCheck(&b, "TRACE Disabled", !r.TraceEnabled)
	addCheck(&b, "No Mixed Content", !r.MixedContent)
	if r.RateLimit.Detected { addCheck(&b, "Rate Limiting", true) }
	b.WriteString(`</table>`)

	if len(r.MissingSecurityHeaders) > 0 {
		b.WriteString(`<h2>Missing Security Headers</h2><table><tr><th>Header</th><th>Importance</th></tr>`)
		for _, h := range r.MissingSecurityHeaders {
			imp := "Recommended"
			if strings.HasPrefix(h, "strict-transport") || strings.HasPrefix(h, "content-security") { imp = "Critical" }
			b.WriteString(`<tr><td class="fail">` + es(h) + `</td><td>` + imp + `</td></tr>`)
		}
		b.WriteString(`</table>`)
	}
	if len(r.CookieIssues) > 0 {
		b.WriteString(`<h2>Cookie Issues</h2><ul>`)
		for _, c := range r.CookieIssues { b.WriteString(`<li class="fail">` + es(c) + `</li>`) }
		b.WriteString(`</ul>`)
	}
	if len(r.CORSIssues) > 0 {
		b.WriteString(`<h2>CORS Issues</h2><ul>`)
		for _, c := range r.CORSIssues { b.WriteString(`<li class="fail">` + es(c) + `</li>`) }
		b.WriteString(`</ul>`)
	}

	writeSSLSectionHTML(&b, r)
	writeRedirectChainHTML(&b, r)

	if r.ReverseDNS != "" || r.EmailSecurity.SPF != "" || len(r.DNSRecords) > 0 {
		b.WriteString(`<h2>DNS Information</h2>`)
		if r.ReverseDNS != "" { b.WriteString(`<p><b>Reverse DNS:</b> ` + es(r.ReverseDNS) + `</p>`) }
		if r.EmailSecurity.SPF != "" || r.EmailSecurity.DMARC != "" || r.EmailSecurity.DKIM != "" {
			b.WriteString(`<div class="grid3">`)
			if r.EmailSecurity.SPF != "" { b.WriteString(`<div class="card"><h3>SPF</h3>` + es(r.EmailSecurity.SPF) + `</div>`) }
			if r.EmailSecurity.DMARC != "" { b.WriteString(`<div class="card"><h3>DMARC</h3>` + es(r.EmailSecurity.DMARC) + `</div>`) }
			if r.EmailSecurity.DKIM != "" { b.WriteString(`<div class="card"><h3>DKIM</h3>` + es(r.EmailSecurity.DKIM) + `</div>`) }
			b.WriteString(`</div>`)
		}
		for rt, entries := range r.DNSRecords {
			if len(entries) == 0 { continue }
			b.WriteString(`<h3>` + es(rt) + ` Records</h3><ul>`)
			for _, e := range entries { b.WriteString(`<li>` + es(e) + `</li>`) }
			b.WriteString(`</ul>`)
		}
	}

	if len(r.ZoneTransfer) > 0 {
		b.WriteString(`<h2>Zone Transfer</h2><table><tr><th>Server</th><th>Severity</th><th>Detail</th></tr>`)
		for _, z := range r.ZoneTransfer {
			b.WriteString(`<tr><td>` + es(z.Server) + `</td><td class="severity-` + z.Severity + `">` + es(strings.ToUpper(z.Severity)) + `</td><td>` + es(z.Detail) + `</td></tr>`)
		}
		b.WriteString(`</table>`)
	}

	if len(r.Subdomains) > 0 {
		b.WriteString(`<h2>Subdomains (` + fmtInt(len(r.Subdomains)) + `)</h2><div class="grid3">`)
		for _, s := range r.Subdomains { b.WriteString(`<div class="tag tag-blue">` + es(s) + `</div>`) }
		b.WriteString(`</div>`)
	}

	if len(r.OpenPorts) > 0 {
		b.WriteString(`<h2>Open Ports</h2><table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>`)
		for _, p := range r.OpenPorts {
			svc := config.PortServices[p]
			banner := ""
			if r.PortBanners != nil { banner = r.PortBanners[fmt.Sprintf("%d", p)] }
			b.WriteString(`<tr><td><b>` + fmtInt(p) + `</b></td><td>` + es(svc) + `</td><td class="sub">` + es(banner) + `</td></tr>`)
		}
		b.WriteString(`</table>`)
	}

	writePathsHTML(&b, r)
	writeCriticalHTML(&b, r)
	writeCVEsHTML(&b, r)
	writeInjectionsHTML(&b, r)
	writeAdvancedHTML(&b, r)

	if len(r.AnomalyHints) > 0 {
		b.WriteString(`<h2>Anomalies</h2><ul>`)
		for _, a := range r.AnomalyHints { b.WriteString(`<li class="warn">` + es(a) + `</li>`) }
		b.WriteString(`</ul>`)
	}

	writeReconHTML(&b, r)
	writePluginHTML(&b, r)

	if r.CSPAnalysis != "" {
		b.WriteString(`<h2>CSP Analysis</h2><pre>` + es(r.CSPAnalysis) + `</pre>`)
	}
	if r.SecurityTxt != "" && r.SecurityTxt != "NOT FOUND" {
		b.WriteString(`<h2>security.txt</h2><pre>` + es(r.SecurityTxt) + `</pre>`)
	}

	b.WriteString(`<div class="meta" style="margin-top:40px;text-align:center;padding:20px">Generated by SC Checker v` + config.Version + `</div>`)
	b.WriteString(`</div></body></html>`)
	return b.String()
}

func addCheck(b *strings.Builder, name string, ok bool) {
	if ok { b.WriteString(`<tr><td>` + name + `</td><td class="pass">✓ PASS</td></tr>`) } else { b.WriteString(`<tr><td>` + name + `</td><td class="fail">✗ FAIL</td></tr>`) }
}

func writeSSLSectionHTML(b *strings.Builder, r *model.Report) {
	b.WriteString(`<h2>SSL / TLS</h2><table><tr><th>Property</th><th>Value</th></tr>`)
	if v, ok := r.TLSSummary["version"]; ok && v != "" { b.WriteString(`<tr><td>Version</td><td>` + es(v) + `</td></tr>`) }
	if v, ok := r.TLSSummary["cipher"]; ok && v != "" { b.WriteString(`<tr><td>Cipher</td><td>` + es(v) + `</td></tr>`) }
	b.WriteString(`<tr><td>Expiry</td><td>` + es(r.SSLExpiryDate) + ` (` + fmtInt(r.SSLExpiryDays) + ` days)</td></tr>`)
	if s, ok := r.SSLDeep["subject"].(string); ok && s != "" { b.WriteString(`<tr><td>Subject</td><td>` + es(s) + `</td></tr>`) }
	if s, ok := r.SSLDeep["issuer"].(string); ok && s != "" { b.WriteString(`<tr><td>Issuer</td><td>` + es(s) + `</td></tr>`) }
	if sans, ok := r.SSLDeep["san"].([]string); ok && len(sans) > 0 {
		if len(sans) > 5 {
			b.WriteString(`<tr><td>SAN</td><td>(` + fmtInt(len(sans)) + ` entries)<ul>`)
			for _, s := range sans {
				b.WriteString(`<li>` + es(s) + `</li>`)
			}
			b.WriteString(`</ul></td></tr>`)
		} else {
			b.WriteString(`<tr><td>SAN</td><td>` + es(strings.Join(sans, ", ")) + `</td></tr>`)
		}
	}
	b.WriteString(`</table>`)
}

func writeRedirectChainHTML(b *strings.Builder, r *model.Report) {
	if len(r.RedirectChain) == 0 { return }
	b.WriteString(`<h2>Redirect Chain</h2><table><tr><th>#</th><th>URL</th><th>Status</th></tr>`)
	for i, rc := range r.RedirectChain {
		final := ""
		if rc.Final { final = " (FINAL)" }
		b.WriteString(`<tr><td>` + fmtInt(i+1) + `</td><td>` + es(rc.URL) + `</td><td>` + fmtInt(rc.Status) + final + `</td></tr>`)
	}
	b.WriteString(`</table>`)
}

func writePathsHTML(b *strings.Builder, r *model.Report) {
	if len(r.DiscoveredPaths) == 0 { return }
	limit := 50
	count := len(r.DiscoveredPaths)
	b.WriteString(`<h2>Discovered Paths (` + fmtInt(count) + `)</h2><table><tr><th>Path</th><th>Status</th><th>Size</th></tr>`)
	for i, p := range r.DiscoveredPaths {
		if i >= limit { b.WriteString(`<tr><td colspan="3" class="sub">... and ` + fmtInt(count-limit) + ` more</td></tr>`); break }
		b.WriteString(`<tr><td>` + es(p.Path) + `</td><td>` + fmtInt(p.Status) + `</td><td>` + fmtInt(p.Size) + ` bytes</td></tr>`)
	}
	b.WriteString(`</table>`)
}

func writeCriticalHTML(b *strings.Builder, r *model.Report) {
	if len(r.CriticalPaths) == 0 { return }
	b.WriteString(`<h2>Critical Findings</h2><table><tr><th>Path</th><th>Severity</th></tr>`)
	for _, p := range r.CriticalPaths {
		sev, label := "severity-medium", "MEDIUM"
		if strings.Contains(p, ".env") || strings.Contains(p, ".git") || strings.Contains(p, "id_rsa") { sev, label = "severity-critical", "CRITICAL" } else if strings.Contains(p, "sql") || strings.Contains(p, "config") || strings.Contains(p, "admin") { sev, label = "severity-high", "HIGH" }
		b.WriteString(`<tr><td>` + es(p) + `</td><td class="` + sev + `">` + label + `</td></tr>`)
	}
	b.WriteString(`</table>`)
}

func writeCVEsHTML(b *strings.Builder, r *model.Report) {
	if len(r.CVEFindings) == 0 { return }
	b.WriteString(`<h2>CVE Findings (` + fmtInt(len(r.CVEFindings)) + `)</h2>`)
	b.WriteString(`<table><tr><th>CVE</th><th>Score</th><th>Severity</th><th>KEV</th><th>EPSS</th><th>Exploit</th><th>Product</th><th>Version</th><th>CWE</th></tr>`)
	for _, c := range r.CVEFindings {
		sevClass := "severity-low"
		if c.Score >= 9.0 { sevClass = "severity-critical" } else if c.Score >= 7.0 { sevClass = "severity-high" } else if c.Score >= 4.0 { sevClass = "severity-medium" }
		kev := ""
		if c.CISAKnownExploited { kev = `<span class="severity-critical">YES</span>` }
		epss := ""
		if c.EPSS > 0 { epss = fmt.Sprintf("%.1f%%", c.EPSS*100) }
		exp := ""
		if c.ExploitAvailable { exp = `<span class="severity-high">YES</span>` }
		cwe := es(c.CWE)
		desc := es(c.Desc)

		b.WriteString(`<tr>` +
			`<td class="` + sevClass + `"><a href="https://nvd.nist.gov/vuln/detail/` + es(c.CVE) + `" target="_blank">` + es(c.CVE) + `</a></td>` +
			`<td><b>` + fmt.Sprintf("%.1f", c.Score) + `</b></td>` +
			`<td class="` + sevClass + `">` + c.Severity + `</td>` +
			`<td>` + kev + `</td>` +
			`<td>` + epss + `</td>` +
			`<td>` + exp + `</td>` +
			`<td>` + es(c.Product) + `</td>` +
			`<td>` + es(c.Version) + `</td>` +
			`<td>` + cwe + `</td>` +
			`</tr>`)
		if desc != "" {
			b.WriteString(`<tr><td colspan="9" style="font-size:0.85em;color:#aaa;padding:0 8px 8px 8px;">` + desc + `</td></tr>`)
		}
	}
	b.WriteString(`</table>`)
}

func writeInjectionsHTML(b *strings.Builder, r *model.Report) {
	has := len(r.SSTIResults) > 0 || len(r.SQLErrors) > 0 || r.XSSReflection || len(r.OpenRedirect) > 0 || len(r.DirTraversal) > 0 || len(r.CRLFInjection) > 0
	if !has { return }
	b.WriteString(`<h2>Injection Tests</h2><table><tr><th>Test</th><th>Result</th></tr>`)
	addCheck(b, "XSS Reflection", !r.XSSReflection)
	addCheck(b, "SQL Errors", len(r.SQLErrors) == 0)
	addCheck(b, "Open Redirect", len(r.OpenRedirect) == 0)
	addCheck(b, "Directory Traversal", len(r.DirTraversal) == 0)
	addCheck(b, "CRLF Injection", len(r.CRLFInjection) == 0)
	b.WriteString(`</table>`)
	if len(r.SSTIResults) > 0 {
		b.WriteString(`<h3>SSTI</h3><table><tr><th>Severity</th><th>Engine</th><th>Detail</th></tr>`)
		for _, s := range r.SSTIResults {
			b.WriteString(`<tr><td class="severity-` + s.Severity + `">` + es(strings.ToUpper(s.Severity)) + `</td><td>` + es(s.Engine) + `</td><td>` + es(s.Detail) + `</td></tr>`)
		}
		b.WriteString(`</table>`)
	}
}

func writeAdvancedHTML(b *strings.Builder, r *model.Report) {
	has := len(r.JWTTokens) > 0 || len(r.GraphQLVulns) > 0 || len(r.WebSocketResults) > 0 || len(r.HTTPSmuggling) > 0 || len(r.SessionIssues) > 0 || len(r.SupplyChain) > 0 || r.RateLimit.Detected || r.WAFFingerprint.Detected || len(r.ExploitVerified) > 0
	if !has { return }
	b.WriteString(`<h2>Advanced Findings</h2><table><tr><th>Type</th><th>Count</th></tr>`)
	addCountRow(b, "JWT Tokens", len(r.JWTTokens), "high")
	addCountRow(b, "GraphQL Vulns", len(r.GraphQLVulns), "high")
	addCountRow(b, "WebSocket Findings", len(r.WebSocketResults), "medium")
	addCountRow(b, "HTTP Smuggling", len(r.HTTPSmuggling), "critical")
	addCountRow(b, "Session Issues", len(r.SessionIssues), "medium")
	addCountRow(b, "Supply Chain", len(r.SupplyChain), "high")
	addCountRow(b, "Exploits Verified", len(r.ExploitVerified), "critical")
	b.WriteString(`</table>`)
	if r.WAFFingerprint.Detected {
		b.WriteString(`<div class="card" style="margin-top:8px"><h3>WAF Fingerprint</h3>` + es(r.WAFFingerprint.Name) + ` ` + es(r.WAFFingerprint.Version) + `</div>`)
	}
}

func addCountRow(b *strings.Builder, name string, count int, severity string) {
	if count <= 0 { return }
	b.WriteString(`<tr><td>` + name + `</td><td class="severity-` + severity + `"><b>` + fmtInt(count) + `</b></td></tr>`)
}

func writeReconHTML(b *strings.Builder, r *model.Report) {
	b.WriteString(`<h2>Reconnaissance</h2><div class="grid3">`)
	if len(r.EmailsFound) > 0 { b.WriteString(`<div class="card"><h3>Emails (` + fmtInt(len(r.EmailsFound)) + `)</h3>` + es(strings.Join(r.EmailsFound, "<br>")) + `</div>`) }
	if len(r.PhonesFound) > 0 { b.WriteString(`<div class="card"><h3>Phones (` + fmtInt(len(r.PhonesFound)) + `)</h3>` + es(strings.Join(r.PhonesFound, "<br>")) + `</div>`) }
	if len(r.SocialLinks) > 0 { b.WriteString(`<div class="card"><h3>Social</h3>` + es(strings.Join(r.SocialLinks, "<br>")) + `</div>`) }
	if len(r.JSLibraries) > 0 { b.WriteString(`<div class="card"><h3>JS Libraries</h3>` + es(strings.Join(r.JSLibraries, "<br>")) + `</div>`) }
	if len(r.CTLogs) > 0 {
		b.WriteString(`<div class="card"><h3>CT Logs (` + fmtInt(len(r.CTLogs)) + `)</h3>`)
		for i, c := range r.CTLogs {
			if i >= 5 { b.WriteString(`...`); break }
			b.WriteString(es(c.Name) + ` — ` + es(c.Issuer) + `<br>`)
		}
		b.WriteString(`</div>`)
	}
	if r.Whois.Registrar != "" {
		b.WriteString(`<div class="card"><h3>WHOIS</h3>`)
		b.WriteString(`Reg: ` + es(r.Whois.Registrar) + `<br>`)
		if r.Whois.Created != "" { b.WriteString(`Created: ` + es(r.Whois.Created) + `<br>`) }
		if r.Whois.Expires != "" { b.WriteString(`Expires: ` + es(r.Whois.Expires) + `<br>`) }
		b.WriteString(`</div>`)
	}
	if s := r.Shodan; s.Org != "" || s.OS != "" || len(s.Ports) > 0 {
		b.WriteString(`<div class="card"><h3>Shodan</h3>`)
		if s.Org != "" { b.WriteString(`Org: ` + es(s.Org) + `<br>`) }
		if s.OS != "" { b.WriteString(`OS: ` + es(s.OS) + `<br>`) }
		if len(s.Ports) > 0 { b.WriteString(`Ports: ` + es(fmt.Sprintf("%v", s.Ports)) + `<br>`) }
		b.WriteString(`</div>`)
	}
	if g := r.IPGeo; len(g) > 0 {
		b.WriteString(`<div class="card"><h3>Location</h3>`)
		if c, ok := g["city"]; ok { b.WriteString(fmt.Sprintf("%v, ", c)) }
		if c, ok := g["country"]; ok { b.WriteString(fmt.Sprintf("%v", c)) }
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
}

func writePluginHTML(b *strings.Builder, r *model.Report) {
	if len(r.PluginGraphNodes) == 0 { return }
	b.WriteString(`<h2>Plugin Findings (` + fmtInt(len(r.PluginGraphNodes)) + `)</h2><table><tr><th>Plugin</th><th>Severity</th><th>Hook</th><th>Message</th></tr>`)
	for _, p := range r.PluginGraphNodes {
		if m, ok := p.(map[string]any); ok {
			sev := fmt.Sprintf("%v", m["severity"])
			b.WriteString(`<tr><td>` + es(fmt.Sprintf("%v", m["plugin"])) + `</td><td class="severity-` + sev + `">` + es(strings.ToUpper(sev)) + `</td><td>` + es(fmt.Sprintf("%v", m["hook"])) + `</td><td>` + es(fmt.Sprintf("%v", m["message"])) + `</td></tr>`)
		}
	}
	b.WriteString(`</table>`)
}

func fmtInt(i int) string {
	var buf [12]byte
	pos := len(buf)
	if i == 0 { return "0" }
	for i > 0 { pos--; buf[pos] = byte('0' + i%10); i /= 10 }
	return string(buf[pos:])
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen { return s }
	return s[:maxLen-3] + "..."
}

func orStr(s, def string) string { if s == "" { return def }; return s }

var htmlEsc = html.EscapeString

func es(s string) string { return htmlEsc(s) }
