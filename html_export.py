import html as _h
from pathlib import Path
from engine import PORT_SERVICES

# ──────────────── DISPLAY LIMITS ────────────────
DISCOVERED_PATHS_DISPLAY = 40
CVE_FINDINGS_DISPLAY = 10
CVSS_SCORES_DISPLAY = 15
CT_LOGS_DISPLAY = 15
JS_ENDPOINTS_DISPLAY = 10
JS_SECRETS_DISPLAY = 5

# ──────────────── HTML EXPORT ────────────────

def _e(text):
    """Escape HTML entities to prevent XSS."""
    if text is None:
        return ""
    return _h.escape(str(text))

def export_html(report, path, plugin_manager=None):
    risk_colors = {"critical": "#f7768e", "high": "#ff9e64", "medium": "#e0af68", "low": "#9ece6a", "info": "#7dcfff"}
    rc = risk_colors.get(report.risk_level, "#c0caf5")
    parts = []
    p = parts.append

    p(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Site Report — {_e(report.target)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#1a1b26;color:#c0caf5;font-family:'Segoe UI',sans-serif;padding:20px}}
.container{{max-width:1000px;margin:0 auto}}
h1{{color:#7aa2f7;margin-bottom:5px;font-size:24px}}
h2{{color:#bb9af7;margin:20px 0 10px;border-bottom:1px solid #3b4261;padding-bottom:5px;font-size:16px}}
.meta{{color:#565f89;font-size:12px;margin-bottom:20px}}
.risk-badge{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;color:#1a1b26;background:{rc}}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:10px 0}}
.card{{background:#24283b;border-radius:8px;padding:12px;border:1px solid #3b4261}}
.card h3{{color:#7dcfff;font-size:13px;margin-bottom:6px}}
.stat{{font-size:24px;font-weight:bold;color:#c0caf5}}
.pass{{color:#9ece6a}} .fail{{color:#f7768e}} .warn{{color:#e0af68}}
table{{width:100%;border-collapse:collapse;margin:8px 0;font-size:12px}}
th{{background:#2f3347;color:#7dcfff;text-align:left;padding:6px 8px}}
td{{padding:6px 8px;border-bottom:1px solid #2f3347}}
.tag{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;margin:2px;background:#2f3347;color:#c0caf5}}
.tag-red{{background:#3b2030;color:#f7768e}} .tag-green{{background:#1e3020;color:#9ece6a}}
.tag-yellow{{background:#303020;color:#e0af68}}
pre{{background:#24283b;padding:10px;border-radius:6px;font-family:Consolas,monospace;font-size:11px;overflow-x:auto;white-space:pre-wrap}}
</style></head><body><div class="container">
<h1>Site Check Report</h1>
<div class="meta">Generated: {_e(report.generated_at)} | Target: {_e(report.target)} | IP: {_e(report.ip)} | Duration: {report.scan_duration_ms}ms</div>

<div class="grid">
<div class="card"><h3>Risk Score</h3><div class="stat">{report.risk_score}/100 <span class="risk-badge">{_e(report.risk_level.upper())}</span></div></div>
<div class="card"><h3>HTTP Status</h3><div class="stat">{report.status_code or 'n/a'}</div><div>Response: {report.response_time_ms}ms</div></div>
<div class="card"><h3>Paths</h3><div class="stat">{len(report.discovered_paths)}/{report.total_paths_scanned}</div><div>Critical: {len(report.critical_paths)}</div></div>
<div class="card"><h3>Ports</h3><div class="stat">{len(report.open_ports)}</div><div>Subdomains: {len(report.subdomains)}</div></div>
</div>

<h2>Security Checks</h2>
<table><tr><th>Check</th><th>Result</th></tr>""")

    checks = [
        ("HSTS", report.hsts_enabled), ("HTTPS Redirect", report.http_to_https_redirect),
        ("Clickjacking Protection", report.clickjacking_protected),
        ("SSL Valid", report.ssl_expiry_days is not None and report.ssl_expiry_days > 0),
        ("Strong SSL", not report.ssl_weak_cipher),
        ("No CORS Issues", not report.cors_issues), ("No Cookie Issues", not report.cookie_issues),
        ("No SQL Errors", not report.sql_errors), ("No XSS", not report.xss_reflection),
        ("No Mixed Content", not report.mixed_content),
    ]
    for name, ok in checks:
        cls = "pass" if ok else "fail"
        p(f'<tr><td>{_e(name)}</td><td class="{cls}">{"PASS" if ok else "FAIL"}</td></tr>')
    p("</table>")

    if report.waf_detected:
        p("<h2>WAF Detected</h2><div>")
        for w in report.waf_detected:
            p(f'<span class="tag tag-yellow">{_e(w)}</span>')
        p("</div>")

    if report.cve_findings:
        p("<h2>CVE Findings</h2><table><tr><th>CVE</th><th>Score</th><th>Description</th></tr>")
        for c in report.cve_findings[:CVE_FINDINGS_DISPLAY]:
            try:
                score_val = float(c.get("score", 0))
            except (ValueError, TypeError):
                score_val = 0.0
            score_cls = "fail" if score_val >= 7 else "warn" if score_val >= 4 else "pass"
            p(f'<tr><td>{_e(c.get("cve",""))}</td><td class="{score_cls}">{score_val}</td><td>{_e(c.get("desc","")[:100])}</td></tr>')
        p("</table>")

    if report.critical_paths:
        p("<h2>Critical Paths</h2><div>")
        for pt in report.critical_paths:
            p(f'<span class="tag tag-red">{_e(pt)}</span>')
        p("</div>")

    if report.discovered_paths:
        p("<h2>Discovered Paths</h2><table><tr><th>Status</th><th>Path</th><th>Size</th></tr>")
        for pt in report.discovered_paths[:DISCOVERED_PATHS_DISPLAY]:
            p(f'<tr><td>{_e(str(pt["status"]))}</td><td>{_e(pt["path"])}</td><td>{_e(str(pt["size"]))}b</td></tr>')
        p("</table>")

    if report.open_ports:
        p("<h2>Open Ports</h2><table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>")
        for pt in report.open_ports:
            svc = PORT_SERVICES.get(pt, "unknown")
            banner = report.port_banners.get(str(pt), "")
            p(f'<tr><td>{_e(str(pt))}</td><td>{_e(svc)}</td><td>{_e(banner[:60])}</td></tr>')
        p("</table>")

    if report.subdomains:
        p("<h2>Subdomains</h2><div>")
        for s in report.subdomains:
            p(f'<span class="tag">{_e(s)}</span>')
        p("</div>")

    if report.dns_records:
        p("<h2>DNS Records</h2><pre>")
        for rt, entries in report.dns_records.items():
            p(f"[{_e(rt)}]\n" + "\n".join(f"  {_e(e)}" for e in entries) + "\n")
        p("</pre>")

    if report.anomaly_hints:
        p("<h2>Anomalies</h2><ul>")
        for h in report.anomaly_hints:
            p(f"<li>{_e(h)}</li>")
        p("</ul>")

    if report.jwt_tokens:
        p("<h2>JWT Tokens</h2><table><tr><th>Header</th><th>Payload</th><th>Algorithm</th><th>Expiry</th></tr>")
        for j in report.jwt_tokens:
            p(f'<tr><td>{_e(j.get("header","")[:80])}</td><td>{_e(j.get("payload","")[:80])}</td><td>{_e(j.get("algorithm",""))}</td><td>{_e(j.get("expiry",""))}</td></tr>')
        p("</table>")

    if report.ssti_results:
        p("<h2>SSTI Test Results</h2><table><tr><th>Vector</th><th>Payload</th><th>Vulnerable</th></tr>")
        for s in report.ssti_results:
            v_cls = "fail" if s.get("vulnerable") else "pass"
            p(f'<tr><td>{_e(s.get("vector",""))}</td><td>{_e(s.get("payload",""))}</td><td class="{v_cls}">{"YES" if s.get("vulnerable") else "No"}</td></tr>')
        p("</table>")

    if report.zone_transfer:
        p("<h2>DNS Zone Transfer</h2><table><tr><th>Nameserver</th><th>Result</th></tr>")
        for z in report.zone_transfer:
            p(f'<tr><td>{_e(z.get("nameserver",""))}</td><td>{_e(z.get("result",""))}</td></tr>')
        p("</table>")

    if report.subdomain_takeover:
        p("<h2>Subdomain Takeover</h2><table><tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Vulnerable</th></tr>")
        for t in report.subdomain_takeover:
            v_cls = "fail" if t.get("vulnerable") else "pass"
            p(f'<tr><td>{_e(t.get("subdomain",""))}</td><td>{_e(t.get("cname",""))}</td><td>{_e(t.get("service",""))}</td><td class="{v_cls}">{"YES" if t.get("vulnerable") else "No"}</td></tr>')
        p("</table>")

    if report.http_smuggling:
        p("<h2>HTTP Smuggling</h2><table><tr><th>Technique</th><th>Vulnerable</th><th>Details</th></tr>")
        for s in report.http_smuggling:
            v_cls = "fail" if s.get("vulnerable") else "pass"
            p(f'<tr><td>{_e(s.get("technique",""))}</td><td class="{v_cls}">{"YES" if s.get("vulnerable") else "No"}</td><td>{_e(s.get("details","")[:100])}</td></tr>')
        p("</table>")

    if report.waf_fingerprint and report.waf_fingerprint.get("detected"):
        p(f'<h2>WAF Detected</h2><div class="card"><h3>{_e(report.waf_fingerprint["name"])}</h3>')
        if report.waf_fingerprint.get("version"):
            p(f'<div>Version: {_e(report.waf_fingerprint["version"])}</div>')
        p("</div>")

    if report.cors_deep:
        p("<h2>CORS Deep Test</h2><table><tr><th>Test</th><th>Vulnerable</th><th>Detail</th></tr>")
        for c in report.cors_deep:
            v_cls = "fail" if c.get("vulnerable") else "pass"
            p(f'<tr><td>{_e(c.get("test",""))}</td><td class="{v_cls}">{"FAIL" if c.get("vulnerable") else "PASS"}</td><td>{_e(c.get("detail","")[:100])}</td></tr>')
        p("</table>")

    if report.cvss_scores:
        p("<h2>CVSS Scores</h2><table><tr><th>Score</th><th>Severity</th><th>Finding</th></tr>")
        for s in report.cvss_scores[:CVSS_SCORES_DISPLAY]:
            try:
                cvss_val = float(s.get("cvss", 0))
            except (ValueError, TypeError):
                cvss_val = 0.0
            p(f'<tr><td>{_e(str(cvss_val))}</td><td>{_e(s.get("severity",""))}</td><td>{_e(s.get("finding",""))}</td></tr>')
        p("</table>")

    if report.exploit_verified:
        p("<h2>Verified Exploits</h2><table><tr><th>Type</th><th>Severity</th><th>Detail</th></tr>")
        for e in report.exploit_verified:
            p(f'<tr><td>{_e(e.get("type",""))}</td><td class="fail">{_e(e.get("severity",""))}</td><td>{_e(e.get("detail","")[:100])}</td></tr>')
        p("</table>")

    if report.js_analysis and report.js_analysis.get("endpoints"):
        p("<h2>JS Analysis — Endpoints</h2><ul>")
        for ep in report.js_analysis["endpoints"][:JS_ENDPOINTS_DISPLAY]:
            p(f"<li>{_e(ep)}</li>")
        p("</ul>")

    if report.js_analysis and report.js_analysis.get("secrets"):
        p("<h2>JS Analysis — Secrets</h2><table><tr><th>Type</th><th>Value</th></tr>")
        for s in report.js_analysis["secrets"][:JS_SECRETS_DISPLAY]:
            p(f'<tr><td>{_e(s["type"])}</td><td>{_e(s["value"])}</td></tr>')
        p("</table>")

    if report.ct_logs:
        p(f"<h2>Certificate Transparency ({len(report.ct_logs)} certs)</h2><table><tr><th>Name</th><th>Issuer</th><th>Not Before</th></tr>")
        for c in report.ct_logs[:CT_LOGS_DISPLAY]:
            p(f'<tr><td>{_e(c["name"])}</td><td>{_e(c["issuer"][:50])}</td><td>{_e(c["not_before"])}</td></tr>')
        p("</table>")

    if report.shodan and report.shodan.get("ports"):
        p(f'<h2>Shodan — Open Ports</h2><div class="card"><h3>Ports: {_e(report.shodan["ports"])}</h3>')
        if report.shodan.get("vulns"):
            p(f'<div>CVEs: {_e(", ".join(report.shodan["vulns"][:5]))}</div>')
        p("</div>")

    if report.whois and report.whois.get("Registrar"):
        p('<h2>WHOIS</h2><div class="card">')
        p(f'<div>Registrar: {_e(report.whois.get("Registrar",""))}</div>')
        p(f'<div>Created: {_e(report.whois.get("Created",""))}</div>')
        p(f'<div>Expires: {_e(report.whois.get("Expires",""))}</div>')
        p("</div>")

    # ── Plugin Findings ──
    if plugin_manager:
        plugin_findings = plugin_manager.collect_findings()
        if plugin_findings:
            p("<h2>Plugin Findings</h2><table><tr><th>Plugin</th><th>Severity</th><th>Title</th><th>Detail</th></tr>")
            for f in plugin_findings:
                sev = f.get("severity", "info")
                sev_cls = "fail" if sev in ("critical", "high") else "warn" if sev == "medium" else "pass" if sev == "low" else ""
                p(f'<tr><td>{_e(f.get("plugin",""))}</td><td class="{sev_cls}">{_e(sev.upper())}</td><td>{_e(f.get("title",""))}</td><td>{_e(f.get("detail","")[:120])}</td></tr>')
            p("</table>")

        # Fire on_export hook for each enabled plugin
        all_plugins = plugin_manager.get_enabled()
        for pl in all_plugins:
            fn = getattr(pl, "on_export", None)
            if callable(fn):
                try:
                    extra = fn(report, "html")
                    if extra and isinstance(extra, str):
                        p(f"\n<!-- Plugin: {_e(getattr(pl, 'name', '?'))} -->\n{extra}")
                except Exception:
                    pass

    p("</div></body></html>")
    Path(path).write_text(''.join(parts), encoding="utf-8")
