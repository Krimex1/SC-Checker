# -*- coding: utf-8 -*-
"""Localization strings for SC Checker."""

LANG = {
    "en": {
        # Nav
        "nav_dashboard": "◈  Dashboard",
        "nav_security": "◈  Security",
        "nav_deep": "◈  Deep Scan",
        "nav_network": "◈  Network",
        "nav_recon": "◈  Recon",
        "nav_injection": "◈  Injection",
        "nav_advanced": "◈  Advanced",
        "nav_paths": "◈  Paths",
        "nav_ports": "◈  Ports",
        "nav_dns": "◈  DNS",
        "nav_graph": "◈  Graph",
        "nav_plugins": "◈  Plugins",
        "nav_log": "◈  Log",
        "nav_report": "◈  Report",
        "nav_ai_analysis": "◈  AI Analysis",
        "nav_settings": "⚙  Settings",
        "nav_proxy": "◈  Proxy",
        "nav_docs": "◈  Documentation",
        "section_docs": "  DOCS",
        "section_proxy": "  NETWORK",
        "section_language": "  LANGUAGE",
        "nav_language": "◈  Language",
        "select_language": "Select Language",
        # Topbar
        "placeholder_target": "Enter target — example.com  |  1.2.3.4  |  multiple",
        "btn_scan": "▶  SCAN",
        "btn_stop": "■  STOP",

        # Progress
        "ready": "◇ Ready",
        "scanning": "Scanning...",
        # Status bar
        "shortcuts": "Ctrl+Enter: Scan  •  Ctrl+S: JSON  •  Ctrl+Shift+S: HTML  •  Esc: Stop",
        "status_ready": "◇ Ready",
        # Right sidebar
        "tools_header": "TOOLS",
        "tool_headers": "  Headers",
        "tool_payloads": "  Payloads",
        "tool_ports": "  Ports List",
        "tool_subdomains": "  Subdomains",
        "tool_useragents": "  User Agents",
        "tool_blacklist": "  Blacklist",
        "tool_dsl": "  DSL Rules",
        "tool_ai": "  AI Settings",
        "tool_webhooks": "  Webhooks",
        "tool_wordlist": "  Wordlist",
        "tool_plugins": "  Plugins",
        "tool_discord": "  Discord RPC",
        "tip_discord": "Configure Discord Rich Presence — customize what shows in your profile",
        # Tooltips
        "tip_headers": "Custom HTTP headers sent with every request",
        "tip_payloads": "Custom payloads for injection testing",
        "tip_ports": "Additional ports to scan beyond defaults",
        "tip_subdomains": "Custom subdomain prefixes for enumeration",
        "tip_useragents": "Custom User-Agent strings rotation",
        "tip_blacklist": "Targets to skip during batch scanning",
        "tip_dsl": "Write custom security rules (JSON or DSL v2)",
        "tip_ai": "Configure AI provider for vulnerability analysis",
        "tip_webhooks": "Send scan results to Telegram, Discord, Slack, etc.",
        "tip_wordlist": "Edit custom wordlist for path discovery",
        "tip_plugins": "Manage scanner plugins (load, enable, disable)",
        "tip_import": "Import targets from .txt or .csv file",
        "tip_profile": "Scan profile — Quick/Normal/Deep/Custom",
        # Dashboard
        "overview": "OVERVIEW",
        "gauge_risk": "RISK",
        "gauge_score": "/ 100",
        "security_overview": "SECURITY OVERVIEW",
        "passed": "passed",
        # Security
        "sec_checks": "Security Checks",
        "sec_issues": "Issues",
        # Deep
        "deep_ssl": "SSL/TLS Deep Analysis",
        "deep_perf": "Performance",
        "deep_methods": "HTTP Methods",
        # Network
        "net_ip": "IP Information",
        "net_ssl": "SSL/TLS Details",
        "net_services": "Services & Banners",
        # Recon
        "recon_links": "External Links",
        "recon_ipinfo": "IP Geolocation",
        "recon_meta": "Recon Data",
        # Injection
        "inject_sqli": "SQL Injection",
        "inject_leaks": "Data Leaks",
        "inject_endpoints": "Endpoints",
        # Advanced
        "adv_mutation": "Payload Mutation",
        "adv_supply": "Supply Chain",
        "adv_ws": "WebSocket",
        "adv_jwt": "JWT Analysis",
        "adv_session": "Session",
        "adv_chaos": "Chaos Scan",
        "adv_dsl": "DSL Results",
        "adv_ssti": "SSTI",
        "adv_zone": "Zone Transfer",
        "adv_takeover": "Subdomain Takeover",
        "adv_email": "Email Security",
        "adv_smuggle": "HTTP Smuggling",
        "adv_tech": "Tech Stack",
        "adv_hidden": "Hidden Endpoints",
        # Plugins
        "plugins_title": "Loaded Plugins",
        # Paths
        "paths_title": "Paths",
        "paths_filter_all": "All",
        "paths_filter_crit": "Critical",
        "paths_filter_200": "200",
        "paths_filter_auth": "401/403",
        # Ports
        "ports_title": "Open Ports & Services",
        # DNS
        "dns_records": "DNS Records",
        "dns_subdomains": "Subdomains",
        # Graph
        "graph_info": "Discovered",
        "graph_help": "Scroll: zoom  |  Drag: pan  |  Double-click: reset",
        # Report
        "report_json": "JSON",
        "report_html": "HTML",
        "report_txt": "TXT",
        "report_copy": "Copy",
        "report_email": "Email",
        # Docs
        "docs_title": "Documentation",
        # Export
        "export_saved": "Saved to",
        "export_copied": "Copied!",
        # Dialogs
        "dialog_add": "+ Add",
        "dialog_save": "Save",
        "dialog_cancel": "Cancel",
        "dialog_close": "Close",
        "discord_reconnect": "Reconnect",
        "dialog_test": "Test",
        "dialog_reload": "Reload",
        "dialog_open": "Open Folder",
        "dialog_load": "Load File",
        "dialog_clear": "Clear",
        "dialog_reset": "Reset Defaults",
        "dialog_fetch": "Fetch Models",
        "dialog_send": "Send",
        # Proxy page
        "proxy_title": "PROXY CONFIGURATION",
        "proxy_desc": "Route all scan traffic through a proxy server.",
        "proxy_type": "Type",
        "proxy_host": "Host / IP",
        "proxy_port": "Port",
        "proxy_user": "Username",
        "proxy_pass": "Password",
        "proxy_add": "+ Add Proxy",
        "proxy_save": "Save",
        "proxy_delete": "Delete",
        "proxy_test": "Test Connection",
        "proxy_enable": "Enable",
        "proxy_disable": "Disable",
        "proxy_status_active": "ACTIVE",
        "proxy_status_inactive": "INACTIVE",
        "proxy_status_testing": "Testing...",
        "proxy_status_ok": "Connection OK",
        "proxy_status_fail": "Connection FAILED",
        "proxy_no_proxies": "No proxies configured.\nClick '+ Add Proxy' to get started.",
        "proxy_format_hint": "Format: type://host:port  or  type://user:pass@host:port",
        "proxy_active_label": "Active Proxy",
        "proxy_saved": "Proxy saved",
        "proxy_deleted": "Proxy deleted",
        "proxy_test_ok": "Proxy test passed — connected successfully",
        "proxy_test_fail": "Proxy test failed",
        "proxy_section": "  NETWORK",
        # AI Analysis page
        "ai_title": "AI VULNERABILITY ANALYSIS",
        "ai_desc": "AI-powered deep analysis of scan results with exploitation guides and remediation.",
        "ai_ask_placeholder": "Ask AI about this scan...",
        "ai_ask_btn": "Ask",
        "ai_summary_btn": "Summary",
        "ai_exploit_btn": "Exploits",
        "ai_remediation_btn": "Remediation",
        "ai_risk_btn": "Risk Report",
        "ai_no_findings": "Run a scan first, then come here for AI analysis.",
        "ai_models_loaded": "Models loaded:",
        "ai_query_processing": "Processing your query...",
        "ai_custom_prompt": "Custom Query",
        "ai_input_placeholder": "Type your question here...",
        "ai_severity_breakdown": "SEVERITY BREAKDOWN",
        "ai_top_risks": "TOP RISKS",
        # AI Settings extended
        "ai_temperature": "Temperature",
        "ai_max_tokens": "Max Tokens",
        "ai_system_prompt": "System Prompt",
        "ai_system_prompt_hint": "Custom instructions for the AI model...",
        "ai_presets": "Presets",
        "ai_preset_pentest": "Penetration Test",
        "ai_preset_audit": "Security Audit",
        "ai_preset_compliance": "Compliance Check",
        "ai_preset_quick": "Quick Scan",
        "ai_clear_chat": "Clear",
        "ai_clear_confirm": "Clear chat history?",
        "ai_upload_file": "Upload",
        "ai_upload_title": "Select files for AI analysis",
        "ai_no_provider": "No provider configured",
        "ai_copy_btn": "Copy",
        "ai_session_stats": "Queries",
        "settings_theme": "Theme",
        "settings_language": "Language",
        "settings_theme_neon_dark": "Neon Dark",
        "settings_theme_cyber_blue": "Cyber Blue",
        "settings_theme_midnight_purple": "Midnight Purple",
        "settings_theme_forest_green": "Forest Green",
        "settings_theme_crimson_red": "Crimson Red",
        "settings_theme_light": "Light",
        "settings_theme_restart": "Restart app to apply theme",
        "settings_theme_applied": "✓ Theme applied",
        "settings_save_btn": "Apply",
        "settings_scan_header": "Scan Settings",
        "settings_scan_subhead": "Toggle checks & set how many paths/payloads to test",
        "settings_lang_desc": "Select the interface language for the application",
        "settings_tab_core": "Core",
        "settings_tab_security": "Security",
        "settings_tab_recon": "Recon",
        "settings_tab_advanced": "Advanced",
        "settings_tab_mutation": "Mutation",
        "settings_tab_language": "Language",
        "ai_jailbreaks": "Jailbreakes for AI",
        "ai_jailbreaks_desc": "Select a jailbreak prompt to apply to the system prompt",
        "ai_jailbreak_apply": "Apply",
        "ai_welcome_title": "AI Security Assistant",
        "ai_welcome_desc": "Ask questions about your scan results.\nThe AI remembers context from previous messages.",
        "ai_welcome_tips": "Try: \"What are the critical vulnerabilities?\"\nOr click a preset button above.",
        "ai_file_added": "Added",
        "ai_no_files": "No files attached",
        "ai_provider_card": "Provider",
        "ai_model_card": "Model",
        "ai_params_card": "Parameters",
        "ai_prompt_card": "System Prompt",
        "ai_profile_card": "Current Profile",
        "ai_advanced": "Advanced",
        "ai_basic": "Basic",
        "ai_chars": "chars",
        "ai_tokens_info": "tokens",
        "ai_context_window": "Context",
        "ai_preset_active": "Active",
        "ai_test_ok": "Connected",
        "ai_test_fail": "Failed",
        "ai_provider_desc": "API provider for AI analysis",
        "ai_model_desc": "AI model to use",
        "ai_temp_desc": "0 = deterministic, 1 = creative",
        "ai_tokens_desc": "Max response length",
        "ai_prompt_desc": "Instructions for the AI model",
        "ai_attach_files": "Attach files",
        "ai_send": "Send",
        "ai_thinking": "Thinking...",
        "ai_user_avatar": "YOU",
        "ai_ai_avatar": "AI",
        "ai_code_copy": "Copy",
        "tip_ai_summary": "Generate executive security summary of scan findings",
        "tip_ai_exploits": "Get exploitation guide for discovered vulnerabilities",
        "tip_ai_remediation": "Get remediation plan with code examples",
        "tip_ai_risk": "Generate formal risk assessment report",
        "tip_ai_upload": "Attach files for AI analysis context",
        "tip_ai_clear": "Clear chat history and start fresh",
        "tip_ai_send": "Send message to AI (Enter)",
        "ai_files_delete": "Remove",
        "ai_files_clear_all": "Clear all",
        # Proxy page docs (EN)
        "doc_Overview": (
            "SC Checker\n\n"
            "SC Checker is a comprehensive web surface audit tool for security\n"
            "researchers, penetration testers, and system administrators.\n"
            "It scans websites for vulnerabilities, misconfigurations, exposed\n"
            "paths, open ports, and provides AI-powered analysis.\n\n"
            "LAYOUT:\n"
            "  Left Sidebar  \u2014 Navigation between pages\n"
            "  Top Bar       \u2014 Target input, Scan/Stop buttons, Async toggle\n"
            "  Progress Bar  \u2014 Real-time scan progress\n"
            "  Content Area  \u2014 Results for selected page\n"
            "  Right Sidebar \u2014 Tools (custom lists, settings)\n"
            "  Status Bar    \u2014 Shortcuts, status\n\n"
            "PAGES:\n"
            "  Dashboard   \u2014 Risk gauge, stats, security overview\n"
            "  Security    \u2014 Security checks and issues\n"
            "  Deep Scan   \u2014 SSL, HTTP methods, CSP, performance\n"
            "  Network     \u2014 IP info, SSL/TLS, services\n"
            "  Recon       \u2014 Subdomains, links, IP geolocation\n"
            "  Injection   \u2014 SQL/XSS injection, leak detection\n"
            "  Advanced    \u2014 JWT, SSTI, GraphQL, WebSocket, chaos\n"
            "  Paths       \u2014 Discovered paths with status codes\n"
            "  Ports       \u2014 Open ports and services\n"
            "  DNS         \u2014 DNS records and subdomains\n"
            "  Graph       \u2014 Interactive topology map (zoom/pan)\n"
            "  Report      \u2014 Full report and export (JSON/HTML/TXT)\n"
            "  Console     \u2014 Built-in terminal with commands (help, scan, show, grep)\n"
            "  AI Analysis \u2014 AI-powered security analysis and chat\n"
            "  Proxy       \u2014 Proxy configuration for scan traffic\n"
            "  Settings    \u2014 Themes, scan settings, language\n"
            "  Docs        \u2014 This documentation\n"
        ),

        "doc_Quick Start": (
            "QUICK START\n\n"
            "1. Enter a target in the top bar:\n"
            "     example.com\n"
            "     https://example.com\n"
            "     192.168.1.1\n"
            "     target1.com\\ntarget2.com  (multiple, one per line)\n\n"
            "2. Press ▶ SCAN or Enter to start scanning.\n\n"
            "3. Watch progress in the progress bar and log.\n\n"
            "4. Browse results across the pages.\n\n"
            "5. Export via Report page: JSON, HTML, TXT, Copy, Email.\n\n"
            "ASYNC MODE:\n"
            "  Enable the ⚡ checkbox to use async HTTP scanning.\n"
            "  Uses httpx.AsyncClient for ~10x faster path/port scanning.\n\n"
            "TARGET TYPES:\n"
            "  Domain:   example.com\n"
            "  IP:       1.2.3.4 (skips HTTP probe, scans directly)\n"
            "  URL:      https://example.com/path\n"
            "  Multiple: paste multiple targets, scanned sequentially\n\n"
            "CACHING:\n"
            "  DNS and TCP results are cached in reports/cache/cache.json\n"
            "  to speed up repeated scans of the same target.\n"
        ),

        "doc_Batch Scan": (
            "BATCH SCAN (MULTI-TARGET)\n\n"
            "Scan multiple targets sequentially in one session.\n\n"
            "HOW TO USE:\n\n"
            "  1. Paste multiple targets into the target field:\n"
            "     - One target per line\n"
            "     - Mix domains, IPs, and URLs freely\n"
            "     - A dialog confirms how many targets were loaded\n\n"
            "  2. Press SCAN to start the batch.\n\n"
            "  3. Each target is scanned one by one with a\n"
            "     10-second pause between them.\n\n"
            "  4. During the pause you can review the results\n"
            "     of the previous scan before the next starts.\n\n"
            "  5. Press STOP at any time to cancel the remaining\n"
            "     batch immediately.\n\n"
            "WHAT HAPPENS AFTER EACH TARGET:\n\n"
            "  - Results are displayed in the Results page\n"
            "  - Webhooks are sent (if configured)\n"
            "  - Email alerts are sent for HIGH/CRITICAL risk\n"
            "  - Discord RPC updates with party progress (X/Y)\n\n"
            "BATCH FEATURES:\n\n"
            "  - 10-second countdown between targets\n"
            "  - Countdown shown in the log panel\n"
            "  - Stop cancels mid-countdown instantly\n"
            "  - Progress bar tracks overall batch completion\n"
            "  - Blacklist: targets in the blacklist are skipped\n\n"
            "TIP:\n"
            "  You can also enter multiple targets manually\n"
            "  by typing each on a separate line in the field.\n"
        ),

        "doc_Scan Features": (
            "SCAN FEATURES (35+ checks)\n\n"
            "BASIC SCAN:\n"
            "  - HTTP/HTTPS probe with status code, response time\n"
            "  - Security headers (HSTS, CSP, X-Frame, X-XSS, etc.)\n"
            "  - Missing headers detection\n"
            "  - robots.txt & sitemap.xml parsing\n"
            "  - Cookie analysis (Secure, HttpOnly, SameSite)\n"
            "  - CORS misconfiguration detection\n"
            "  - Mixed content detection\n"
            "  - Clickjacking protection check\n"
            "  - HTTP to HTTPS redirect check\n"
            "  - Directory listing detection\n"
            "  - SQL error messages in response\n"
            "  - XSS reflection test\n"
            "  - Server banner extraction\n"
            "  - Fingerprinting (CMS, frameworks)\n\n"
            "PATH DISCOVERY:\n"
            "  - Brute-force with wordlist (default: 5000+ paths)\n"
            "  - Critical path detection (/admin, /backup, /config, etc.)\n"
            "  - Status code categorization (200, 301, 401, 403, 500)\n"
            "  - Response size analysis\n\n"
            "PORT SCANNING:\n"
            "  - Top 100 common ports (configurable)\n"
            "  - Service identification from banners\n"
            "  - Parallel scanning (64 workers)\n\n"
            "SUBDOMAIN ENUMERATION:\n"
            "  - DNS brute-force\n"
            "  - Certificate transparency logs\n"
            "  - Common subdomain prefixes\n\n"
            "WAF DETECTION:\n"
            "  - Detects Cloudflare, Akamai, AWS WAF, ModSecurity, etc.\n"
            "  - Based on headers and response patterns\n\n"
            "CVE SCANNING:\n"
            "  - Checks known CVEs for detected software\n"
            "  - Uses NVD API with local cache\n"
        ),

        "doc_Security Checks": (
            "SECURITY CHECKS\n\n"
            "HEADER ANALYSIS:\n"
            "  - Strict-Transport-Security (HSTS)\n"
            "  - Content-Security-Policy (CSP) \u2014 full analysis\n"
            "  - X-Frame-Options\n"
            "  - X-Content-Type-Options\n"
            "  - X-XSS-Protection\n"
            "  - Referrer-Policy\n"
            "  - Permissions-Policy\n"
            "  - Expect-CT\n"
            "  - X-Permitted-Cross-Domain-Policies\n\n"
            "COOKIE ISSUES:\n"
            "  - Missing Secure flag\n"
            "  - Missing HttpOnly flag\n"
            "  - Missing SameSite attribute\n"
            "  - Session cookies without HTTPS\n\n"
            "CORS ISSUES:\n"
            "  - Wildcard origin with credentials\n"
            "  - Null origin allowed\n"
            "  - Trusted origins list check\n\n"
            "INJECTION TESTS:\n"
            "  - SQL error detection in responses\n"
            "  - XSS reflection of user input\n"
            "  - Host header injection\n"
            "  - CRLF injection\n"
            "  - Open redirect\n"
            "  - Directory traversal\n\n"
            "SOURCE LEAKAGE:\n"
            "  - Backup files (.bak, .old, .swp)\n"
            "  - Source maps (.map)\n"
            "  - Git directories (.git)\n"
            "  - Admin panels (/admin, /wp-admin)\n"
            "  - Login pages (/login, /signin)\n"
            "  - API endpoints (/api, /graphql, /swagger)\n"
        ),

        "doc_Deep Scan": (
            "DEEP SCAN\n\n"
            "SSL/TLS DEEP ANALYSIS:\n"
            "  - Certificate details (issuer, validity, SAN)\n"
            "  - Expiry tracking\n"
            "  - Weak cipher detection\n"
            "  - Protocol version (TLS 1.0/1.1 vulnerable)\n"
            "  - Certificate chain validation\n\n"
            "HTTP METHODS:\n"
            "  - Tests GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE\n"
            "  - TRACE method detection (XST vulnerability)\n"
            "  - Method-based access control\n\n"
            "SECURITY HEADERS (detailed):\n"
            "  - CSP analysis (directives, sources, nonce)\n"
            "  - Permissions-Policy directives\n"
            "  - Referrer-Policy value\n"
            "  - Expect-CT status\n\n"
            "PERFORMANCE:\n"
            "  - TTFB (Time to First Byte)\n"
            "  - Content size & encoding\n"
            "  - Full redirect chain with response codes\n\n"
            "RECON:\n"
            "  - Email addresses in HTML/JS\n"
            "  - Phone numbers\n"
            "  - Social media links\n"
            "  - Meta tags (og:, twitter:)\n"
            "  - Hidden forms\n"
            "  - External links\n"
            "  - JavaScript libraries & versions\n"
            "  - IP geolocation (country, city, ISP)\n"
            "  - ASN information\n"
            "  - Reverse DNS\n"
        ),

        "doc_Advanced Features": (
            "ADVANCED FEATURES\n\n"
            "PAYLOAD MUTATION ENGINE:\n"
            "  8 base payloads x 10 mutation variants:\n"
            "  - URL encode, double encode\n"
            "  - HTML entities, unicode\n"
            "  - Case swap, whitespace injection\n"
            "  - Null byte, backtick\n"
            "  - Mixed encoding\n"
            "  Tests each variant and detects possible bypasses\n\n"
            "SUPPLY CHAIN ANALYZER:\n"
            "  - Parses <script>, <link>, <img> tags\n"
            "  - Detects CDN usage (Cloudflare, Akamai, etc.)\n"
            "  - Checks HTTPS vs HTTP resources\n"
            "  - SRI (Subresource Integrity) check\n"
            "  - Identifies outdated libraries:\n"
            "    jQuery <1.7, AngularJS 1.x, Bootstrap 3,\n"
            "    Moment.js, Lodash <4.17.21\n\n"
            "GRAPHQL DEEP SCAN:\n"
            "  - Auto-discovers /graphql, /graphiql endpoints\n"
            "  - Introspection query to extract schema\n"
            "  - Tests injection in query arguments\n"
            "  - Exposes mutations (write operations)\n\n"
            "WEBSOCKET ANALYZER:\n"
            "  - Connects to ws:// and wss:// endpoints\n"
            "  - Tests XSS reflection via WS messages\n"
            "  - Template injection detection\n"
            "  - DoS via large payloads\n\n"
            "SESSION MANIPULATION:\n"
            "  - Session fixation testing\n"
            "  - Weak token detection (entropy check)\n"
            "  - Cookie security flags\n"
            "  - Token in URL detection\n"
            "  - CORS misconfiguration\n\n"
            "CHAOS SCANNING:\n"
            "  - 15+ random/edge-case headers\n"
            "  - POST bodies: JSON, null bytes, XML XXE, binary\n"
            "  - URL params: debug, cmd, exec, callback\n\n"
            "JWT ANALYSIS:\n"
            "  - Finds tokens in headers, cookies, body\n"
            "  - Decodes header & payload\n"
            "  - Checks algorithm (none, HS256, RS256)\n"
            "  - Expiry tracking\n"
            "  - Secret entropy analysis\n"
            "  - Sensitive data in payload\n\n"
            "SSTI (Server-Side Template Injection):\n"
            "  - Tests Jinja2 ({{7*7}})\n"
            "  - Tests FreeMarker, ERB, Ruby, Java Spring\n"
            "  - Both GET and POST vectors\n\n"
            "DNS ZONE TRANSFER:\n"
            "  - Attempts AXFR through nameservers\n"
            "  - Detects zone transfer misconfiguration\n\n"
            "SUBDOMAIN TAKEOVER:\n"
            "  - Checks CNAME on vulnerable services:\n"
            "    GitHub Pages, Heroku, Azure, Netlify,\n"
            "    Shopify, Vercel, Pages.dev, Tumblr\n\n"
            "EMAIL SECURITY:\n"
            "  - SPF record validation\n"
            "  - DMARC policy check\n"
            "  - DKIM record detection\n\n"
            "HTTP SMUGGLING:\n"
            "  - CL.TE technique\n"
            "  - TE.CL technique\n"
            "  - TE.TE technique\n\n"
            "DEEP TECH STACK:\n"
            "  - WordPress, Laravel, Django, Next.js, Nuxt\n"
            "  - React, Vue, Angular, PHP, Express\n"
            "  - Version detection from headers/body\n\n"
            "HIDDEN ENDPOINTS:\n"
            "  - Parses JavaScript files for API URLs\n"
            "  - Checks robots.txt disallowed paths\n"
        ),

        "doc_DSL v2 Language": (
            "DSL v2 LANGUAGE\n\n"
            "The DSL (Domain-Specific Language) allows writing custom security\n"
            "rules. Two formats are supported: JSON rules and program text.\n\n"
            "\n  --- JSON RULES ---\n\n"
            "  [\n"
            "    {\n"
            '      "name": "No HSTS",\n'
            '      "condition": "hsts_enabled == false",\n'
            '      "severity": "HIGH",\n'
            '      "message": "HSTS not enabled"\n'
            "    }\n"
            "  ]\n\n"
            "  Operators: ==  !=  >  <  >=  <=  contains  notcontains\n"
            "  Combine:   AND, OR (uppercase)\n"
            "  Severity:  CRITICAL, HIGH, MEDIUM, LOW, INFO\n\n"
            "\n  --- PROGRAM TEXT ---\n\n"
            "VARIABLES:\n"
            "  $count = open_ports_count\n"
            "  $risk = risk_score\n"
            '  $name = "test"\n'
            "  $list = [1, 2, 3]\n\n"
            "IF/THEN/ELSE:\n"
            "  IF risk_score > 70 THEN\n"
            "    ASSERT risk_score < 100\n"
            "  ELSE\n"
            "    ASSERT risk_score >= 0\n"
            "  END\n\n"
            "FOR LOOPS:\n"
            "  FOR port IN open_ports\n"
            "    ASSERT port > 0\n"
            "  END\n\n"
            "  FOR sub IN subdomains\n"
            '    ASSERT sub contains "example.com"\n'
            "  END\n\n"
            "ASSERTIONS:\n"
            "  ASSERT hsts_enabled == true\n"
            "  ASSERT ssl_expiry_days > 30\n"
            "  ASSERT open_ports_count < 10\n"
            "  ASSERT waf_detected contains Cloudflare\n\n"
            "REGEX CAPTURE:\n"
            '  CAPTURE "\\d+\\.\\d+\\.\\d+" FROM server_banner\n'
            '  CAPTURE "v\\d+" FROM version_hints\n\n'
            "HTTP REQUESTS:\n"
            '  REQUEST "https://example.com/robots.txt" CHECK RESPONSE CONTAINS "User-agent"\n\n'
            "RESPONSE TIME:\n"
            '  HTTP_TIME "https://example.com" < 2000\n'
            '  HTTP_TIME "https://example.com" > 100\n\n'
            "COMMENTS:\n"
            "  # This is a comment\n\n"
            "\n  --- EXPRESSIONS ---\n\n"
            "  $var              \u2014 variable reference\n"
            "  42, 3.14          \u2014 numbers\n"
            '  "hello"           \u2014 strings\n'
            "  true, false       \u2014 booleans\n"
            "  [1, 2, 3]         \u2014 lists\n"
            "  open_ports_count  \u2014 computed field (len of list)\n"
            "  risk_score        \u2014 report field\n\n"
            "\n  --- AVAILABLE FIELDS ---\n\n"
            "  Basic:  status_code, response_time_ms, risk_score,\n"
            "          hsts_enabled, http_to_https_redirect,\n"
            "          clickjacking_protected, ssl_expiry_days,\n"
            "          ssl_weak_cipher, xss_reflection, mixed_content,\n"
            "          directory_listing, trace_enabled\n\n"
            "  Counts: discovered_paths, critical_paths, open_ports,\n"
            "          subdomains, cookie_issues, cors_issues,\n"
            "          sql_errors, waf_detected, cve_findings,\n"
            "          emails_found, external_links, js_libraries,\n"
            "          mutated_payloads, graphql_vulns, session_issues,\n"
            "          chaos_findings, dsl_results, ai_findings,\n"
            "          jwt_tokens, ssti_results, zone_transfer,\n"
            "          subdomain_takeover, http_smuggling\n\n"
            "  Text:   host, ip, server_banner, csp_analysis,\n"
            "          security_txt, referrer_policy, reverse_dns\n\n"
            "  Dict:   headers, dns_records, tls_summary, ip_geo,\n"
            "          asn_info, email_security\n"
        ),

        "doc_Custom Lists": (
            "CUSTOM LISTS\n\n"
            "Custom lists let you extend the scanner with your own data.\n"
            "Lists are stored in reports/custom/*.txt (one item per line).\n\n"
            "AVAILABLE LISTS:\n\n"
            "  Headers \u2014 Custom HTTP headers sent with every request\n"
            "    Format: Header-Name: value\n"
            "    Example: X-Custom: test123\n\n"
            "  Payloads \u2014 Custom payloads for injection testing\n"
            "    Format: one payload per line\n"
            "    Example: ' OR 1=1 --\n\n"
            "  Ports \u2014 Custom ports to scan\n"
            "    Format: port number per line\n"
            "    Example: 8080\n\n"
            "  Subdomains \u2014 Custom subdomain prefixes to enumerate\n"
            "    Format: prefix per line\n"
            "    Example: api\n\n"
            "  User Agents \u2014 Custom User-Agent strings\n"
            "    Format: one UA string per line\n\n"
            "  Blacklist \u2014 Targets to skip during batch scan\n"
            "    Format: one domain per line\n\n"
            "HOW TO USE:\n"
            "  1. Click the list name in the right sidebar\n"
            "  2. Edit in the dialog (add items, one per line)\n"
            "  3. Click Save\n"
            "  4. Lists are automatically used in the next scan\n\n"
            "WORDLIST:\n"
            "  Load an external wordlist via the 'Wordlist' button.\n"
            "  This overrides the default path list.\n"
            "  Format: one path per line (without leading /)\n"
            "  Example: admin\n           config\n           backup.zip\n"
        ),

        "doc_Plugins": (
            "PLUGIN SYSTEM\n\n"
            "Plugins extend the scanner with custom checks.\n\n"
            "PLUGIN FORMAT:\n"
            "  Create a .py file in the plugins/ directory.\n"
            "  The file must define a Plugin class inheriting from PluginBase:\n\n"
            '    from plugins import PluginBase\n\n'
            '    PLUGIN_NAME = "my-plugin"\n'
            '    PLUGIN_VERSION = "1.0"\n\n'
            "    class Plugin(PluginBase):\n"
            '        name = "My Plugin"\n'
            '        description = "Does something useful"\n\n'
            "        def on_request(self, engine, url, response, report):\n"
            "            pass\n\n"
            "SCANNER HOOKS (called during scan):\n"
            "  on_scan_start(self, engine, target, report)\n"
            "      — Fires at scan beginning. Initialize state here.\n\n"
            "  on_before_request(self, engine, method, url) -> dict|None\n"
            "      — Before root probe. Return dict to inject extra\n"
            "        headers/params (e.g. {'headers': {'X': 'Y'}}).\n\n"
            "  on_request(self, engine, url, response, report)\n"
            "      — After root response received. Analyze response.\n\n"
            "  on_after_headers(self, engine, headers, report)\n"
            "      — After headers are collected from response.\n"
            "        headers is a dict. report is the Report dataclass.\n\n"
            "  on_after_ssl(self, engine, ssl_data, report)\n"
            "      — After SSL/TLS analysis completes.\n"
            "        ssl_data contains 'deep', 'cert', 'chain' keys.\n\n"
            "  on_after_ports(self, engine, open_ports, report)\n"
            "      — After port scanning finishes.\n"
            "        open_ports is a list of port numbers.\n\n"
            "  on_after_paths(self, engine, paths, report)\n"
            "      — After path/directory scanning finishes.\n"
            "        paths is a list of {'path', 'status', 'size'} dicts.\n\n"
            "  on_scan_complete(self, engine, report)\n"
            "      — Final hook. Report is fully populated.\n"
            "        All report fields can be modified.\n\n"
            "  on_export(self, report, format) -> str|None\n"
            "      — Called during HTML export. Return raw HTML string\n"
            "        to append to the report. format='html' or 'json'.\n\n"
            "  get_findings(self) -> list\n"
            "      — Return list of findings: [{severity, title, detail}].\n"
            "        Called automatically; displayed in Plugin Findings.\n\n"
            "  get_graph_nodes(self, report) -> list\n"
            "      — Return custom graph nodes:\n"
            "        [{'label': str, 'color': '#hex'}].\n"
            "        Rendered on the topology graph (purple ring).\n\n"
            "SETTINGS SCHEMA (optional):\n"
            "  Define settings_schema as a dict to enable config UI:\n\n"
            '    settings_schema = {\n'
            '        "threshold": {"type": "int", "label": "Risk Threshold",\n'
            '                       "default": 50, "desc": "Min risk score"},\n'
            '        "verbose": {"type": "bool", "label": "Verbose",\n'
            '                    "default": False, "desc": "Detail logging"},\n'
            '        "urls": {"type": "list", "label": "URLs",\n'
            '                 "default": [], "desc": "One per line"},\n'
            '        "name": {"type": "str", "label": "API Name",\n'
            '                  "default": "", "desc": "API name"},\n'
            "    }\n\n"
            "  Supported types: str, int, bool, list\n"
            "  Click the gear icon (⚙) next to the plugin to configure.\n"
            "  Settings are saved to plugin_config.json.\n\n"
            "FINDINGS:\n"
            "  Use self.add_finding(severity, title, detail) in any hook.\n"
            "  severity: critical / high / medium / low / info\n\n"
            "MANAGEMENT:\n"
            "  Click 'Plugins' in the right sidebar to:\n"
            "  - View loaded plugins and active hooks\n"
            "  - Enable/disable plugins\n"
            "  - Configure plugin settings (⚙ button)\n"
            "  - Reload plugin directory\n"
        ),

        "doc_AI Integration": (
            "AI INTEGRATION\n\n"
            "The AI analyzer sends scan results to an LLM for analysis.\n\n"
            "SUPPORTED PROVIDERS:\n\n"
            "  1. OpenAI (gpt-4o, gpt-4o-mini, etc.)\n"
            "     API: https://api.openai.com/v1\n\n"
            "  2. Google Gemini (gemini-2.5-flash, etc.)\n"
            "     API: https://generativelanguage.googleapis.com/v1beta/openai\n\n"
            "  3. Anthropic Claude (claude-sonnet-4-20250514, etc.)\n"
            "     API: https://api.anthropic.com/v1\n\n"
            "  4. OpenRouter (100+ models)\n"
            "     API: https://openrouter.ai/api/v1\n\n"
            "  5. Groq (llama-3.3-70b, mixtral-8x7b, etc.)\n"
            "     API: https://api.groq.com/openai/v1\n\n"
            "  6. Mistral (mistral-large, codestral, etc.)\n"
            "     API: https://api.mistral.ai/v1\n\n"
            "  7. Deepseek (deepseek-chat, deepseek-coder)\n"
            "     API: https://api.deepseek.com/v1\n\n"
            "  8. Cloudflare Workers AI\n"
            "     API: https://api.cloudflare.com/client/v4/accounts/{id}/ai\n\n"
            "SETUP:\n"
            "  1. Click 'AI Settings' in the right sidebar\n"
            "  2. Select a provider\n"
            "  3. Enter your API key\n"
            "  4. Click 'Fetch Models' to load available models\n"
            "  5. Select a model\n"
            "  6. Click 'Test Connection' to verify\n\n"
            "AI runs automatically at the end of every scan.\n"
            "Results appear in the Advanced tab under 'AI Analysis'.\n\n"
            "ACCOUNT ID:\n"
            "  Required only for Cloudflare Workers AI.\n"
        ),

        "doc_Webhooks": (
            "WEBHOOK NOTIFICATIONS\n\n"
            "Send scan results to external services automatically.\n\n"
            "SUPPORTED CHANNELS:\n\n"
            "  1. Telegram Bot\n"
            "     Fields: bot_token, chat_id\n"
            "     Get bot_token from @BotFather\n"
            "     Get chat_id from @userinfobot\n\n"
            "  2. Discord Webhook\n"
            "     Fields: webhook_url\n"
            "     Create in Server Settings > Integrations\n\n"
            "  3. Discord Bot\n"
            "     Fields: bot_token, channel_id\n"
            "     Uses Discord Bot API\n\n"
            "  4. Slack Webhook\n"
            "     Fields: webhook_url\n"
            "     Create at api.slack.com/apps\n\n"
            "  5. Pushover\n"
            "     Fields: push_key, user_key, app_token\n"
            "     Register at pushover.net\n\n"
            "  6. Custom HTTP\n"
            "     Fields: webhook_url, auth_header (optional)\n"
            "     POST JSON payload to your endpoint\n\n"
            "SETUP:\n"
            "  1. Click 'Webhooks' in the right sidebar\n"
            "  2. Click '+ Add Webhook'\n"
            "  3. Select channel type\n"
            "  4. Fill in credentials\n"
            "  5. Click Save\n\n"
            "Webhooks fire automatically after every scan.\n"
            "Toggle on/off per webhook in the management dialog.\n\n"
            "PAYLOAD FORMAT:\n"
            '  {"target": "...", "risk_score": 45,\n'
            '   "risk_level": "MEDIUM", "status": 200,\n'
            '   "critical_paths": [...], "open_ports": [...],\n'
            '   "cve_findings": [...]}\n'
        ),

        "doc_Discord RPC": (
            "DISCORD RICH PRESENCE\n\n"
            "Show a live activity status in your Discord profile:\n"
            "idle, scanning, or scan-complete with risk level.\n\n"
            "QUICK START:\n"
            "  1. Open https://discord.com/developers/applications\n"
            "  2. Create a New Application (name = activity title)\n"
            "  3. Copy the Application ID (numbers only)\n"
            "  4. Go to Rich Presence > Art Assets > upload an image\n"
            "     named 'logo' (matches large_image_key default)\n"
            "  5. In SC Checker: right sidebar > Discord RPC\n"
            "  6. Enable, paste Application ID, click Save\n\n"
            "PRESENCE STATES:\n"
            "  Idle      \u2014 App is open, no scan running\n"
            "  Scanning  \u2014 Target, phase, progress %\n"
            "  Done      \u2014 Target, risk level & score\n\n"
            "TEMPLATE VARIABLES:\n"
            "  {version}    \u2014 SC Checker version\n"
            "  {target}     \u2014 Scanned URL/IP\n"
            "  {phase}      \u2014 Current scan phase\n"
            "  {progress}   \u2014 Progress 0-100\n"
            "  {risk_level} \u2014 LOW / MEDIUM / HIGH / CRITICAL\n"
            "  {risk_score} \u2014 Numeric score 0-100\n\n"
            "ELAPSED TIMER MODES:\n"
            "  since_launch \u2014 Real time since connection\n"
            "  frozen_time  \u2014 Always shows same time (HH:MM:SS)\n"
            "  custom_time  \u2014 Custom start timestamp\n"
            "  hidden       \u2014 No timer shown\n\n"
            "IMAGES:\n"
            "  Upload images in Discord Developer Portal,\n"
            "  section Rich Presence > Art Assets.\n"
            "  The 'name' you give the image = large_image_key.\n"
            "  Default key is 'logo' \u2014 upload asset named 'logo'.\n\n"
            "  !! UPDATED THE IMAGE BUT STILL SEE THE OLD ONE?\n"
            "     This is Discord's cache, not a SC Checker bug. Discord\n"
            "     caches assets by NAME on its CDN + in every client.\n"
            "     If you re-upload over the SAME name (replace 'logo'),\n"
            "     the key doesn't change -> Discord keeps showing the old\n"
            "     picture for hours or days.\n"
            "     FIX (instant): upload the new image under a NEW name\n"
            "     (e.g. 'logo2'), then set that name as large_image_key\n"
            "     in SC Checker and click Save. Old 'logo' can be deleted.\n"
            "     Other options: full restart of Discord (Quit in tray)\n"
            "     clears your local cache but NOT the CDN cache, so it is\n"
            "     unreliable and only fixes it for you.\n\n"
            "BUTTON:\n"
            "  Adds a clickable link under the activity.\n"
            "  Fields: Button Label (max 32 chars)\n"
            "          Button URL (max 512 chars, must be http/https)\n"
            "  SC Checker auto-adds https:// if you omit the scheme.\n\n"
            "  IMPORTANT: Discord hides the button on YOUR OWN profile.\n"
            "  Only OTHER users can see and click it. Ask a friend to\n"
            "  check your profile to verify the button works.\n\n"
            "TROUBLESHOOTING:\n"
            "  Status 'Disconnected'    \u2014 Discord client is not running.\n"
            "  Empty image              \u2014 large_image_key doesn't match\n"
            "                              any uploaded asset name.\n"
            "  Old image still showing \u2014 Discord cache. Upload under a\n"
            "                              NEW name, see IMAGES section above.\n"
            "  Button invisible to you \u2014 Normal! Others can see it.\n"
            "  Button invisible to all  \u2014 URL is invalid. Check hint.\n"
            "  Timer missing            \u2014 show_elapsed off or mode=hidden.\n"
            "  Changes not applied     \u2014 Click Save in the dialog.\n"
        ),

        "doc_Graph": (
            "GRAPH PAGE\n\n"
            "Interactive topology map showing relationships between:\n"
            "  - Host (center, blue)\n"
            "  - Subdomains (cyan)\n"
            "  - Open ports (orange)\n"
            "  - Critical paths (red)\n\n"
            "CONTROLS:\n"
            "  Scroll wheel  \u2014 Zoom in/out (0.2x to 5.0x)\n"
            "  Left mouse    \u2014 Drag to pan\n"
            "  Double-click  \u2014 Reset view\n"
            "  Right-click   \u2014 Reset view\n\n"
            "ZOOM LEVEL:\n"
            "  Displayed in top-right corner (e.g. 150%)\n\n"
            "LEGEND:\n"
            "  Shown in bottom-left corner\n\n"
            "The graph updates with each scan. Zoom and pan\n"
            "state resets on new scan.\n"
        ),

        "doc_Keyboard Shortcuts": (
            "KEYBOARD SHORTCUTS\n\n"
            "  Ctrl+Enter     Start scan\n"
            "  Escape          Stop scan\n"
            "  Ctrl+S          Export as JSON\n"
            "  Ctrl+Shift+S    Export as HTML\n"
            "  Ctrl+C          Copy report (in Report page)\n\n"
            "NAVIGATION:\n"
            "  Click sidebar buttons to switch pages.\n"
            "  The active page is highlighted in blue.\n\n"
            "GRAPH CONTROLS:\n"
            "  Mouse wheel     Zoom\n"
            "  Left drag       Pan\n"
            "  Double-click    Reset view\n"
        ),

        "doc_Proxy": (
            "PROXY CONFIGURATION\n\n"
            "Route all scan traffic through a proxy server for anonymity,\n"
            "geo-specific testing, or bypassing network restrictions.\n\n"
            "SUPPORTED PROXY TYPES:\n"
            "  - HTTP    (http://host:port)\n"
            "  - HTTPS   (https://host:port)\n"
            "  - SOCKS5  (socks5://host:port)\n\n"
            "AUTHENTICATION:\n"
            "  - Supports username/password authentication\n"
            "  - Format: type://user:pass@host:port\n"
            "  - Anonymous proxies: type://host:port\n\n"
            "HOW TO USE:\n"
            "  1. Navigate to the Proxy page in the sidebar\n"
            "  2. Click '+ Add Proxy'\n"
            "  3. Select proxy type (HTTP, HTTPS, or SOCKS5)\n"
            "  4. Enter host, port, and optional credentials\n"
            "  5. Click 'Test Connection' to verify connectivity\n"
            "  6. Click 'Save' to store the proxy\n"
            "  7. Toggle the checkbox to enable/disable\n\n"
            "ACTIVE PROXY:\n"
            "  - Only one proxy can be active at a time\n"
            "  - Enabling one proxy disables all others\n"
            "  - The active proxy is displayed at the top of the list\n"
            "  - All scan traffic routes through the active proxy\n\n"
            "WHAT GOES THROUGH PROXY:\n"
            "  - HTTP/HTTPS probe requests\n"
            "  - Path brute-force scanning\n"
            "  - Port scanning (TCP connections)\n"
            "  - CVE lookups\n"
            "  - IP geolocation queries\n"
            "  - Subdomain enumeration\n"
            "  - All other outbound scan requests\n\n"
            "STORAGE:\n"
            "  Proxy configurations are saved in proxies.json\n"
            "  in the script directory, persistent across sessions.\n"
        ),
        "doc_Terminal": (
            "CONSOLE / TERMINAL\n\n"
            "The built-in console lets you run commands without leaving the app.\n"
            "Access it from the Console page in the sidebar.\n"
            "The console supports Tab-completion, command history (Up/Down),\n"
            "and pipe filtering with grep.\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  SCANNING\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  scan <target>            Start a scan on a target\n"
            "                           Accepts domain, IP, or URL.\n"
            "                           Examples:\n"
            "                             scan example.com\n"
            "                             scan 192.168.1.1\n"
            "                             scan https://example.com\n"
            "                             scan  (uses current target field)\n\n"
            "  scan-multi <t1,t2,...>   Scan multiple targets sequentially\n"
            "                           Comma-separated list of targets.\n"
            "                           Example: scan-multi a.com,b.com,c.com\n\n"
            "  stop                     Stop the currently running scan\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  RESULTS\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  show [section]           Show results from the last scan.\n"
            "                           Default section: stats\n\n"
            "  Available sections:\n\n"
            "    stats      Overview: target, IP, status, risk, paths,\n"
            "               ports, subdomains, CVEs, WAF, CMS, SSL\n"
            "    paths      Discovered paths with HTTP status & size\n"
            "               (up to 30, color-coded by status)\n"
            "    ports      Open TCP ports with service names\n"
            "    dns        DNS records (A, AAAA, MX, NS, TXT, etc.)\n"
            "    headers    Security headers (missing vs present)\n"
            "    cve        CVE findings with CVSS scores\n"
            "    waf        Detected WAF / firewall products\n"
            "    subdomains Discovered subdomains\n"
            "    ssl        TLS certificate expiry, cipher info\n"
            "    csp        Content Security Policy analysis\n"
            "    tech       Detected technologies and frameworks\n\n"
            "  Examples:\n"
            "    show stats\n"
            "    show paths\n"
            "    show cve\n\n"
            "  stats                    Show full scan statistics\n"
            "                           (same as show stats)\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  EXPORT\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  export [json|html|txt]   Export the last scan report\n"
            "                           Default format: json\n"
            "                           Saved to: reports/report_<host>.<fmt>\n"
            "                           Examples:\n"
            "                             export json\n"
            "                             export html\n"
            "                             export txt\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  FILTERING\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  grep <pattern>           Filter the last command's output\n"
            "                           by text pattern (case-insensitive)\n"
            "                           Matches are highlighted in yellow.\n\n"
            "  Pipe operator            Combine any command with grep:\n"
            "                             show paths | grep 200\n"
            "                             show ports | grep 443\n"
            "                             show cve | grep critical\n"
            "                             stats | grep risk\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  SYSTEM\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  lang [en|ru]             Switch interface language\n"
            "                           Without argument: toggles EN/RU\n\n"
            "  proxy <url>              Set proxy for all scan requests\n"
            "                           Supports HTTP, SOCKS4, SOCKS5.\n"
            "                           Clear with: proxy\n"
            "                           Examples:\n"
            "                             proxy socks5://127.0.0.1:9050\n"
            "                             proxy http://10.0.0.1:8080\n"
            "                             proxy  (clear proxy)\n\n"
            "  theme [name]             Switch UI theme\n"
            "                           Without argument: shows available themes.\n"
            "                           Available: neon, cyber, midnight,\n"
            "                                       forest, crimson, light\n\n"
            "  update                   Check GitHub for new versions\n"
            "                           Downloads and verifies SHA256 hash.\n\n"
            "  version                  Show current version number\n\n"
            "  clear                    Clear the console output\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  UTILITIES\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  history                  Show command history (last 50)\n"
            "                           Commands are numbered.\n\n"
            "  help                     Show the help table in console\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  KEYBOARD SHORTCUTS\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  Enter ............ Execute the current command\n"
            "  Up / Down ........ Navigate command history\n"
            "  Tab .............. Autocomplete command or sub-option\n"
            "  Ctrl+Enter ....... Start scan (from any tab)\n"
            "  Escape ........... Stop running scan\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  COLOR CODING\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  Blue ............. Command echo / info\n"
            "  Green ............ Success / active\n"
            "  Yellow ........... Warning / commands\n"
            "  Red .............. Error / critical\n"
            "  Cyan ............. Headers / links\n"
            "  Purple ........... Tech / plugins\n"
            "  Gray ............. Subtle / continuation text\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  TIPS\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  - The target can also be set via the Target field on Dashboard\n"
            "  - Results always come from the most recent completed scan\n"
            "  - Type any partial command and press Tab to autocomplete\n"
            "  - Combine show + pipe for powerful filtering:\n"
            "      show paths | grep 404\n"
            "      show headers | grep Content-Security\n"
            "      show dns | grep MX\n"
        ),
        # Language
        "lang_label": "EN",
        # Doc topic labels (EN keys match English topic names, values are display text)
        "topic_Overview": "Overview",
        "topic_Quick Start": "Quick Start",
        "topic_Scan Features": "Scan Features",
        "topic_Security Checks": "Security Checks",
        "topic_Deep Scan": "Deep Scan",
        "topic_Advanced Features": "Advanced Features",
        "topic_DSL v2 Language": "DSL v2 Language",
        "topic_Custom Lists": "Custom Lists",
        "topic_Plugins": "Plugins",
        "topic_AI Integration": "AI Integration",
        "topic_Webhooks": "Webhooks",
        "topic_Discord RPC": "Discord RPC",
        "topic_Graph": "Graph",
        "topic_Keyboard Shortcuts": "Keyboard Shortcuts",
        "topic_Proxy": "Proxy",
        "topic_Terminal": "Terminal",
        # ── Hardcoded UI strings (was in site_checker_gui.py) ──
        "stop_btn": "Stop",
        "log_title": "Live Log",
        "log_clear": "Clear",
        "console_title": "Console",
        "console_clear": "Clear",
        "console_run": "Run",
        "console_placeholder": "Type command...",
        "save_settings": "Save Settings",
        "settings_saved": "Scan settings saved",
        "no_ai_data": "No AI data",
        "risk_score_label": "Risk Score",
        "status_done": "Done",
        "status_stopped": "Scan stopped",
        "status_stopped_short": "Stopped",
        "status_starting_batch": "Starting batch...",
        "status_initializing": "Initializing...",
        "status_downloading": "Downloading...",
        "status_checking": "Checking...",
        "btn_retry": "Retry",
        "report_no_data": "No data",
        # Phase names
        "phase_subdomains": "Enumerating subdomains",
        "phase_dns": "Resolving DNS records",
        "phase_headers": "Checking security headers",
        "phase_ssl": "Verifying SSL certificate",
        "phase_paths": "Scanning paths",
        "phase_ports": "Scanning ports",
        "phase_sqli": "Testing SQL injection",
        "phase_xss": "Testing XSS",
        "phase_waf": "Detecting WAF",
        "phase_cve": "Checking CVEs",
        "phase_cms": "Detecting CMS",
        # Dashboard stat labels
        "dash_status": "Status",
        "dash_paths": "Paths",
        "dash_critical": "Critical",
        "dash_ports": "Ports",
        "dash_waf": "WAF",
        "dash_cves": "CVEs",
        "dash_sub": "Sub",
        "dash_errors": "Errors",
        # Security page
        "sec_waf_fingerprint": "WAF Fingerprint",
        "sec_rate_cors": "Rate Limit & CORS",
        "sec_exploit_verified": "Exploit Verified",
        # AI Settings dialog
        "ai_account_id": "Account ID",
        "ai_top_p": "Top P",
        "ai_nucleus": "Nucleus sampling",
        "ai_freq_penalty": "Freq Penalty",
        "ai_reduce_repetition": "Reduce repetition",
        "ai_pres_penalty": "Pres Penalty",
        "ai_encourage_topics": "Encourage new topics",
        "ai_select_provider_first": "Select a provider first",
        "ai_enter_key_first": "Enter API key first",
        "ai_fetching_models": "Fetching models...",
        "ai_no_models_returned": "No models returned — check API key",
        "ai_testing_connection": "Testing connection...",
        "ai_select_model_first": "Select or fetch a model first",
        # Custom list dialogs
        "list_template": "Template:",
        "list_quick_add": "Quick Add:",
        "list_sort": "Sort",
        "list_dedup": "Dedup",
        "list_export": "Export",
        "list_entries": "entries",
        "list_from_scan": "From Scan",
        # Plugin dialog
        "plugin_no_plugins": "No plugins found\n\nPlace .py files in plugins/ directory.",
        "plugin_dir_label": "Plugin directory",
        # Email/Webhook dialogs
        "email_settings": "Email Settings",
        "webhook_title": "Webhook Notifications",
        "webhook_no_configured": "No webhooks configured.\nClick '+ Add' to get started.",
        "webhook_new": "New Webhook",
        "webhook_name": "Name",
        "webhook_channel": "Channel",
        # Paths filter
        "paths_filter": "Filter",
        # Graph
        "graph_host": "Host",
        "graph_no_data": "No data found",
        # Topology
        "topo_subdomains": "Subdomains",
        "topo_ports": "Ports",
        "topo_critical": "Critical",
        # Dialogs & messages
        "quit_title": "Quit",
        "quit_scan_confirm": "Scan in progress. Quit anyway?",
        "enter_target": "Enter a target",
        "invalid_target": "Invalid target",
        "invalid_target_msg": "Not a valid domain, IP or URL",
        "batch_info": "Pasted",
        "batch_targets": "targets",
        "batch_press_scan": "Press SCAN to scan all",
        "error": "Error",
        "import_error": "Import Error",
        "email_sent": "Report sent!",
        "email_error": "Email Error",
        "export_saved": "Saved to",
        "scan_stopped": "Scan stopped",
        "scan_stopped_user": "Scan stopped by user",
        # Update dialog
        "update_checking": "Checking...",
        "update_available": "UPDATE AVAILABLE",
        "update_install": "INSTALL NOW",
        "update_later": "LATER",
        "update_downloading": "Downloading...",
        "update_retry": "Retry",
        "update_up_to_date": "Up to date ✓",
        "update_error": "Update error",
        # Additional UI labels
        "cvss_scores": "CVSS Scores",
        "dns_records_page": "DNS Records",
        "subdomains_page": "Subdomains",
        "discovered": "Discovered",
        "email_recon": "Email",
        "optional": "optional",
        "no_targets_found": "No targets found in file",
        "plugins_label": "Plugins",
        "dsl_rules_saved": "DSL rules saved",
        "api_key": "API Key",
        "cloudflare_only": "Cloudflare only",
        "ai_disabled": "AI: disabled",
        "on_off": "On/Off",
        "webhook_example": "e.g. My Telegram",
        "tab_connection": "Connection",
        "tab_presence": "Presence",
        "tab_images_timer": "Images & Timer",
        "connected": "Connected",
        "export_title": "Export",
        "batch_title": "Batch",
        "email_title": "Email",
        # Console strings
        "console_version": "SC Checker Console",
        "console_help_hint": "Type 'help' for available commands.",
        "console_commands": "Commands:",
        "console_help_scan": "start a scan",
        "console_help_scanmulti": "scan multiple (comma-separated)",
        "console_help_stop": "stop current scan",
        "console_help_export": "export last report",
        "console_help_show": "show results",
        "console_help_stats": "show scan statistics",
        "console_help_clear": "clear console",
        "console_help_lang": "switch language",
        "console_help_proxy": "set proxy",
        "console_help_update": "check for updates",
        "console_help_version": "show version",
        "console_no_target": "No target specified.",
        "console_starting_scan": "Starting scan of",
        "console_usage_scanmulti": "Usage: scan-multi host1,host2,host3",
        "console_starting_batch": "Starting batch scan of",
        "console_scan_stopped": "Scan stopped.",
        "console_no_scan_running": "No scan running.",
        "console_no_report_export": "No report to export. Run a scan first.",
        "console_no_report": "No report. Run a scan first.",
        "console_exported": "Exported to",
        "console_no_waf": "No WAF detected.",
        "console_unknown_section": "Unknown section",
        "console_use_sections": "Use: paths|ports|dns|headers|cve|waf",
        "console_stats_title": "=== Scan Statistics ===",
        "console_target": "Target",
        "console_ip": "IP",
        "console_status": "Status",
        "console_risk": "Risk",
        "console_duration": "Duration",
        "console_paths": "Paths",
        "console_ports": "Ports",
        "console_open": "open",
        "console_subdomains": "Subdomains",
        "console_cves": "CVEs",
        "console_waf": "WAF",
        "console_none": "None",
        "console_unknown": "Unknown",
        "console_days": "days",
        "console_errors": "Errors",
        "console_lang_set": "Language set to",
        "console_usage_lang": "Usage: lang [en|ru]",
        "console_proxy_set": "Proxy set to:",
        "console_checking_updates": "Checking for updates...",
        "console_update_error": "Update check error:",
        "console_update_available": "Update available:",
        "console_no_update": "No update available. Current:",
        "console_type_help": "Type 'help' for commands.",
        "console_unknown_command": "Unknown command:",
        # Discord hints
        "discord_party_hint": "Shows 'X of Y' in Discord during batch scans",
        "discord_countdown_hint": "Show countdown timer while scanning",
        "discord_show_party": "Show batch progress (3/10)",
        "discord_show_countdown": "Show countdown timer while scanning",
        "discord_countdown_dur": "Countdown duration",
        "discord_countdown_hint2": "Format: seconds (300) or MM:SS (05:00) — resets each scan phase",
        "discord_button2_label": "Button 2 Label",
        "discord_button2_url": "Button 2 URL",
        "discord_button2_hint": "Discord allows up to 2 buttons — optional second button",
        "discord_button2_url_hint": "Optional — e.g. https://github.com/your-repo",
        "discord_idle_hint": "Playing a game",
        # Discord RPC
        "discord_title": "Discord Rich Presence",
        "discord_enabled": "Enable Discord Rich Presence",
        "discord_show_elapsed": "Show elapsed time",
        "discord_saved": "Discord settings saved!",
        "discord_reset": "Reset to defaults",
        "discord_reconnecting": "Reconnecting...",
        "discord_disconnected": "Disconnected",
        "connected": "Connected",
        "discord_portal_title": "App Name & Icon",
        "discord_portal_explain": "To show activity in Discord, you need a free Discord Application.\nFollow these steps — it takes 2 minutes:",
        "discord_portal_guide": (
            "Step 1: Click the button below to open Discord Developer Portal\n"
            "Step 2: Click 'New Application' → enter any name (e.g. 'SC Checker')\n"
            "Step 3: Copy the 'Application ID' (big number under the name)\n"
            "Step 4: Paste that ID into the 'Discord Application ID' field below\n"
            "Step 5: (Optional) Rich Presence → Art Assets → upload a 'logo' image\n"
            "Step 6: Check 'Enable' and click Save"
        ),
        "discord_open_portal": "Open Developer Portal",
        "discord_portal_steps": "1. Select your app  →  2. General Information → NAME/ICON\n3. Rich Presence → Art Assets → upload images",
        "discord_no_client_id": "No Application ID! Create one at discord.com/developers/applications",
        "discord_button_note": "Note: Discord shows the button only to OTHER users viewing your profile — you won't see it on your own. URL must start with http:// or https:// (we add https:// automatically if missing). Max 1 button, label ≤ 32 chars.",
        "discord_app_name": "Activity Name",
        "discord_app_name_hint": "Custom name shown instead of Discord app name (e.g. 'SC Checker')",
        "discord_elapsed_mode": "Elapsed time mode",
        "discord_elapsed_launch": "Since app launch",
        "discord_elapsed_frozen": "Frozen time (always shows same)",
        "discord_elapsed_custom": "Custom start time",
        "discord_elapsed_hidden": "Hidden (no timer)",
        "discord_frozen_time": "Frozen time",
        "discord_frozen_time_hint": "Format: HH:MM:SS (e.g. 11:11:11) — always shows this time",
        "discord_custom_time": "Custom start time",
        "discord_custom_time_hint": "Format: HH:MM:SS or YYYY-MM-DD HH:MM:SS or epoch timestamp",
        "discord_tab_advanced": "Advanced",
        "discord_preview": "👁  Preview",
        "discord_playing_game": "Playing a game",
        "discord_idle_preview": "Idle",
        "discord_elapsed_preview": "00:01 elapsed",
        "discord_frozen_preview": "11:11:11 elapsed",
        "elapsed_suffix": "elapsed",
        # Discord Profiles
        "discord_profiles_title": "Profiles",
        "discord_active_profile": "Active:",
        "discord_no_profile": "No Profile",
        "discord_no_profile_selected": "No profile selected",
        "discord_profile_switching": "Switching...",
        "discord_profile_switched": "Switched to: {name}",
        "discord_profile_error": "Failed to switch profile",
        "discord_switch_btn": "Switch",
        "discord_create_profile_title": "Create New Profile",
        "discord_profile_name_label": "Profile Name:",
        "discord_profile_name_hint": "e.g. Work, Gaming, Custom",
        "discord_profile_exists": "Profile already exists",
        "discord_profile_created": "Profile created: {name}",
        "discord_create_btn": "Create",
        "discord_save_profile_title": "Save Current Settings as Profile",
        "discord_profile_saved": "Profile saved: {name}",
        "discord_save_profile_btn": "Save As",
        "discord_delete_confirm_title": "Confirm Delete",
        "discord_delete_confirm_msg": "Delete profile '{name}'?",
        "discord_delete_warning": "This cannot be undone.",
        "discord_profile_deleted": "Profile deleted: {name}",
        "discord_delete_btn": "Delete",
        "dialog_create": "Create",
        "dialog_delete": "Delete",
        # Webhooks
        "webhook_title": "Webhook Notifications",
        "webhook_none": "No webhooks configured\n\nClick '+ Add Webhook' below",
        "webhook_add": "+ Add Webhook",
        "webhook_onoff": "On/Off",
        "webhook_add_title": "Add Webhook",
        "webhook_new": "New Webhook",
        "webhook_name": "Name",
        "webhook_name_ph": "e.g. My Telegram",
        "webhook_channel": "Channel",
        "webhook_save": "Save",
        # Scan / status
        "status_ai_disabled": "AI: disabled",
        "ai_enter_key_first": "Enter API key first",
        "ai_select_model_first": "Select or fetch a model first",
        "ai_testing_connection": "Testing connection...",
        "no_targets_found": "No targets found in file",
        "risk_score_label": "Risk Score",
        "scanning_dots": "Scanning",
        "status_batch": "Batch:",
        "targets_unit": "targets",
        "phase_batch_start": "Starting batch...",
        "phase_init": "Initializing...",
        "phase_done": "Done",
        "status_done_in": "Done in",
        "target_phase": "Target",
        # Results display
        "no_issues": "  No issues",
        "no_dns_records": "  No DNS records",
        "no_subdomains": "  No subdomains",
        "found_subdomains": "Found",
        "subdomains_word": "subdomains",
        "no_data": "No data",
        "no_data_found": "No data found",
        "no_ssl": "  No SSL (port 443 not open or not HTTPS)",
        "cert_expires_in": "Certificate expires in",
        "paths_label": "Paths:",
        "scanned_word": "scanned",
        "found_word": "found",
        "critical_word": "critical",
        "open_ports_label": "Open Ports:",
        "port_header": "Port",
        "service_header": "Service",
        "banner_header": "Banner",
        # Network sections
        "sec_target": "── Target ──",
        "input_word": "Input:",
        "ip_word": "IP:",
        "host_word": "Host:",
        "reverse_word": "Reverse:",
        "na_word": "n/a",
        "sec_geo": "── Geolocation ──",
        "sec_asn": "── ASN ──",
        "sec_ssl_tls": "── SSL / TLS ──",
        "sec_open_ports": "── Open Ports",
        "sec_dns": "── DNS ──",
        "sec_ssl_deep": "── SSL Deep Check ──",
        "sec_security_headers": "── Security Headers ──",
        "found_word_yes": "Found",
        "not_found_word": "Not found",
        "sec_performance": "── Performance ──",
        "ttfb_word": "TTFB:",
        "content_size_word": "Content Size:",
        "encoding_word": "Encoding:",
        "none_word": "none",
        "sec_redirect_chain": "── Redirect Chain",
        "final_mark": "[FINAL]",
        "sec_http_methods": "── HTTP Methods ──",
        "sec_emails": "── Emails",
        "sec_phones": "── Phones",
        "sec_social_links": "── Social Links",
        "sec_meta_tags": "── Meta Tags",
        "sec_hidden_forms": "── Hidden Forms",
        "hidden_inputs_word": "hidden",
        "sec_ip_info": "── IP Information ──",
        "reverse_dns_word": "Reverse DNS:",
        "ai_results_header": "── AI Analysis Results ──",
        "no_ai_data": "No AI data",
        "findings_word": "findings",
        "table_sev": "Severity",
        "table_type": "Type",
        "table_detail": "Detail",
        "ai_configure_first": "Configure AI provider in AI Settings first.",
        # Proxy / settings
        "optional": "optional",
        "lang_english": "English",
        "lang_russian": "Русский",
        # Export
        "export_title": "Export",
        "copy_title": "Copy",
        "copied": "Copied!",
        "html_word": "HTML",
        # Findings severity detail
        "exploit_word": "Exploit:",
        "fix_word": "Fix:",
        # Misc
        "waf_detected": "WAF Detected:",
        "frameworks_word": "Frameworks",
        "cms_word": "CMS",
        # Advanced results sections
        "sec_external_links": "── External Links",
        "sec_js_libs": "── JS Libraries",
        "server_word": "Server:",
        "sec_injection": "── Injection Tests ──",
        "host_header_word": "Host Header:",
        "crlf_word": "CRLF:",
        "open_redirect_word": "Open Redirect:",
        "dir_traversal_word": "Dir Traversal:",
        "sec_backup_files": "── Backup Files",
        "sec_source_leaks": "── Source Code Leaks",
        "sec_admin_panels": "── Admin Panels",
        "sec_login_pages": "── Login Pages",
        "no_leaks": "No leaks found",
        "sec_api_endpoints": "── API Endpoints",
        "no_api_endpoints": "No API endpoints found",
        "sec_mutation": "── Payload Mutation Engine ──",
        "tested_word": "Tested",
        "payload_variants": "payload variants:",
        "no_mutations": "  No mutations generated",
        "sec_supply_chain": "── Supply Chain Analysis ──",
        "found_word_lc": "Found",
        "external_resources": "external resources:",
        "ok_word": "OK",
        "no_external_resources": "  No external resources found",
        "sec_websocket": "── WebSocket Analysis ──",
        "ws_connected": "CONNECTED",
        "ws_failed": "FAILED",
        "status_word": "Status:",
        "no_ws_endpoints": "  No WebSocket endpoints found",
        "sec_session": "── Session Manipulation ──",
        "no_session_issues": "  No session issues found",
        "sec_chaos": "── Chaos Scanning ──",
        "no_chaos": "  No chaos findings",
        "sec_dsl_results": "── DSL Rule Results ──",
        "all_rules_passed": "  All rules passed",
        "sec_jwt": "── JWT Analysis ──",
        "no_jwt": "  No JWT tokens found",
        "sec_ssl_deep2": "── SSL Deep ──",
        "sec_cookie_audit": "── Cookie Audit",
        "cookies_count": "cookies,",
        "issues_word": "issues",
        "sec_headers_detail": "── Headers",
        "sec_tech": "── Technologies",
        "sec_cve": "── CVE",
        "sec_versions": "── Versions",
        "sec_anomalies": "── Anomalies",
        "sec_dns2": "── DNS",
        "invalid_word": "INVALID",
        "no_jwt_tokens": "  No JWT tokens",
        "none_found": "None found",
        "sec_ssti": "── SSTI Check ──",
        "no_ssti": "  No SSTI detected",
        "sec_dns_zone": "── DNS Zone Transfer ──",
        "zone_blocked": "  Zone transfer blocked",
        "sec_takeover": "── Subdomain Takeover ──",
        "no_takeover": "  No takeover candidates",
        "sec_email_sec": "── Email Security ──",
        "no_email_sec": "  No email security data",
        "sec_smuggling": "── HTTP Smuggling ──",
        "no_smuggling": "  No smuggling detected",
        "sec_tech_deep": "── Deep Tech Stack ──",
        "no_tech_deep": "  No additional tech detected",
        "sec_hidden_ep": "── Hidden Endpoints ──",
        "no_hidden_ep": "  No hidden endpoints found",
        "sec_cvss": "── CVSS Scores ──",
        "no_cvss": "  No CVSS scores calculated",
        "sec_waf_fp": "── WAF Fingerprint ──",
        "detected_word": "Detected:",
        "version_word": "Version:",
        "rules_word": "Rules:",
        "no_waf": "  No WAF detected",
        "sec_rate_limit": "── Rate Limiting ──",
        "limit_word": "Limit:",
        "remaining_word": "Remaining:",
        "reset_word": "Reset:",
        "no_rate_limit": "No rate limiting detected",
        "sec_cors_deep": "── CORS Deep Test ──",
        "fail_word": "FAIL",
        "pass_word": "PASS",
        "no_cors_tests": "  No CORS tests performed",
        "sec_exploit_v": "── Exploit Verification ──",
        "no_exploit_v": "  No exploits verified (no findings to verify)",
        "sec_js_analysis": "── JavaScript Analysis ──",
        "scripts_analyzed": "Scripts analyzed:",
        "endpoints_found": "Endpoints found:",
        "secrets_found": "Secrets found:",
        "sri_missing": "SRI missing:",
        "endpoints_word": "Endpoints:",
        "secrets_word": "Secrets:",
        "no_js_analysis": "  No JS analysis performed",
        "sec_ct": "── Certificate Transparency ──",
        "found_certs": "Found",
        "certificates_word": "certificates",
        "issuer_word": "Issuer:",
        "not_before_word": "Not Before:",
        "no_ct": "  No CT logs found",
        "sec_shodan": "── Shodan / InternetDB ──",
        "no_shodan": "  No Shodan data",
        "sec_whois": "── WHOIS / RDAP ──",
        "registrar_word": "Registrar:",
        "created_word": "Created:",
        "expires_word": "Expires:",
        "name_servers_word": "Name Servers:",
        "no_whois": "  No WHOIS data",
        "sec_screenshots": "── Screenshots ──",
        "error_word": "Error:",
        "saved_word": "Saved:",
        "no_screenshots": "  No screenshots taken",
        "screenshots_disabled": "  ⚠ Screenshots are disabled in Settings → Scan Settings → Recon",
        "install_playwright": "  Install Playwright: pip install playwright && playwright install chromium",
        "sec_loaded_plugins": "── Loaded Plugins",
        "no_plugins_loaded": "No plugins loaded",
        "plugins_hint1": "Put .py files in plugins/ directory",
        "sec_plugin_findings": "── Plugin Findings",
        # Server node
        "server_node": "🖥 Server Node",
        "no_http_detected": "No HTTP server detected on default port — probing alternatives",
        "na_no_http": "N/A — no HTTP server detected",
        "alt_http_found": "HTTP found on port {port}",
        "server_node_hint": "Scanning as server node (TCP/SSL/DNS only)",
    },
    "ru": {
        # Nav
        "nav_dashboard": "◈  Панель",
        "nav_security": "◈  Безопасность",
        "nav_deep": "◈  Глубокий",
        "nav_network": "◈  Сеть",
        "nav_recon": "◈  Разведка",
        "nav_injection": "◈  Инъекции",
        "nav_advanced": "◈  Продвинутые",
        "nav_paths": "◈  Пути",
        "nav_ports": "◈  Порты",
        "nav_dns": "◈  DNS",
        "nav_graph": "◈  Граф",
        "nav_plugins": "◈  Плагины",
        "nav_log": "◈  Лог",
        "nav_report": "◈  Отчёт",
        "nav_ai_analysis": "◈  AI Анализ",
        "nav_settings": "⚙  Настройки",
        "nav_proxy": "◈  Прокси",
        "nav_docs": "◈  Документация",
        "section_docs": "  ДОКУМЕНТАЦИЯ",
        "section_proxy": "  СЕТЬ",
        "section_language": "  ЯЗЫК",
        "nav_language": "◈  Язык",
        "select_language": "Выберите язык",
        # Topbar
        "placeholder_target": "Введите цель — example.com  |  1.2.3.4  |  несколько",
        "btn_scan": "▶  СКАН",
        "btn_stop": "■  СТОП",

        # Progress
        "ready": "◇ Готов",
        "scanning": "Сканирование...",
        # Status bar
        "shortcuts": "Ctrl+Enter: Скан  •  Ctrl+S: JSON  •  Ctrl+Shift+S: HTML  •  Esc: Стоп",
        "status_ready": "◇ Готов",
        # Right sidebar
        "tools_header": "ИНСТРУМЕНТЫ",
        "tool_headers": "  Заголовки",
        "tool_payloads": "  Полезные нагрузки",
        "tool_ports": "  Список портов",
        "tool_subdomains": "  Субдомены",
        "tool_useragents": "  User-Agent",
        "tool_blacklist": "  Чёрный список",
        "tool_dsl": "  DSL правила",
        "tool_ai": "  AI настройки",
        "tool_webhooks": "  Вебхуки",
        "tool_wordlist": "  Список слов",
        "tool_plugins": "  Плагины",
        "tool_discord": "  Discord RPC",
        "tip_discord": "Настройка Discord Rich Presence — настройте что показывается в профиле",
        # Tooltips (RU)
        "tip_headers": "Пользовательские HTTP-заголовки для каждого запроса",
        "tip_payloads": "Свои полезные нагрузки для тестирования инъекций",
        "tip_ports": "Дополнительные порты для сканирования",
        "tip_subdomains": "Префиксы субдоменов для перечисления",
        "tip_useragents": "Ротация пользовательских User-Agent",
        "tip_blacklist": "Цели для пропуска при пакетном скане",
        "tip_dsl": "Свои правила безопасности (JSON или DSL v2)",
        "tip_ai": "Настройка AI для анализа уязвимостей",
        "tip_webhooks": "Отправка результатов в Telegram, Discord, Slack и др.",
        "tip_wordlist": "Редактировать список путей для сканирования",
        "tip_plugins": "Управление плагинами (загрузка, включение, выключение)",
        "tip_import": "Импорт целей из .txt или .csv файла",
        "tip_profile": "Профиль сканирования — Быстрый/Нормальный/Глубокий/Пользовательский",
        # Dashboard
        "overview": "ОБЗОР",
        "gauge_risk": "РИСК",
        "gauge_score": "/ 100",
        "security_overview": "ОБЗОР БЕЗОПАСНОСТИ",
        "passed": "пройдено",
        # Security
        "sec_checks": "Проверки безопасности",
        "sec_issues": "Проблемы",
        # Deep
        "deep_ssl": "Глубокий анализ SSL/TLS",
        "deep_perf": "Производительность",
        "deep_methods": "HTTP методы",
        # Network
        "net_ip": "Информация об IP",
        "net_ssl": "Детали SSL/TLS",
        "net_services": "Сервисы и баннеры",
        # Recon
        "recon_links": "Внешние ссылки",
        "recon_ipinfo": "Геолокация IP",
        "recon_meta": "Данные разведки",
        # Injection
        "inject_sqli": "SQL инъекция",
        "inject_leaks": "Утечки данных",
        "inject_endpoints": "Эндпоинты",
        # Advanced
        "adv_mutation": "Мутация полезных нагрузок",
        "adv_supply": "Цепочка поставок",
        "adv_ws": "WebSocket",
        "adv_jwt": "Анализ JWT",
        "adv_session": "Сессия",
        "adv_chaos": "Chaos скан",
        "adv_dsl": "DSL результаты",
        "adv_ssti": "SSTI",
        "adv_zone": "Зональный трансфер",
        "adv_takeover": "Захват субдоменов",
        "adv_email": "Безопасность почты",
        "adv_smuggle": "HTTP Smuggling",
        "adv_tech": "Технологический стек",
        "adv_hidden": "Скрытые эндпоинты",
        # Plugins
        "plugins_title": "Загруженные плагины",
        # Paths
        "paths_title": "Пути",
        "paths_filter_all": "Все",
        "paths_filter_crit": "Критические",
        "paths_filter_200": "200",
        "paths_filter_auth": "401/403",
        # Ports
        "ports_title": "Открытые порты и сервисы",
        # DNS
        "dns_records": "DNS записи",
        "dns_subdomains": "Субдомены",
        # Graph
        "graph_info": "Обнаружено",
        "graph_help": "Колесо: зум  |  Тянуть: панорама  |  Двойной клик: сброс",
        # Report
        "report_json": "JSON",
        "report_html": "HTML",
        "report_txt": "TXT",
        "report_copy": "Копировать",
        "report_email": "Отправить",
        # Docs
        "docs_title": "Документация",
        # Export
        "export_saved": "Сохранено в",
        "export_copied": "Скопировано!",
        # Dialogs
        "dialog_add": "+ Добавить",
        "dialog_save": "Сохранить",
        "dialog_cancel": "Отмена",
        "dialog_close": "Закрыть",
        "discord_reconnect": "Переподключить",
        "dialog_test": "Тест",
        "dialog_reload": "Перезагрузить",
        "dialog_open": "Открыть папку",
        "dialog_load": "Загрузить файл",
        "dialog_clear": "Очистить",
        "dialog_reset": "Сбросить настройки",
        "dialog_fetch": "Получить модели",
        "dialog_send": "Отправить",
        # Discord RPC (RU)
        "discord_title": "Discord Rich Presence",
        "discord_enabled": "Включить Discord Rich Presence",
        "discord_show_elapsed": "Показывать время работы",
        "discord_saved": "Настройки Discord сохранены!",
        "discord_reset": "Сброшено по умолчанию",
        "discord_reconnecting": "Переподключение...",
        "discord_disconnected": "Отключено",
        "connected": "Подключено",
        "discord_portal_title": "Имя приложения и иконка",
        "discord_portal_explain": "Чтобы показать активность в Discord, нужно создать бесплатное приложение.\nСледуйте инструкции — это займёт 2 минуты:",
        "discord_portal_guide": (
            "Шаг 1: Нажмите кнопку ниже, чтобы открыть Discord Developer Portal\n"
            "Шаг 2: Нажмите 'New Application' → введите любое имя (напр. 'SC Checker')\n"
            "Шаг 3: Скопируйте 'Application ID' (большое число под именем)\n"
            "Шаг 4: Вставьте этот ID в поле 'Discord Application ID' ниже\n"
            "Шаг 5: (Опционально) Rich Presence → Art Assets → загрузите картинку 'logo'\n"
            "Шаг 6: Включите галочку 'Enable' и нажмите Save"
        ),
        "discord_open_portal": "Открыть Developer Portal",
        "discord_portal_steps": "1. Выберите приложение  →  2. General Information → ИМЯ/ИКОНКА\n3. Rich Presence → Art Assets → загрузите изображения",
        "discord_no_client_id": "Нет Application ID! Создайте на discord.com/developers/applications",
        "discord_button_note": "Важно: Discord показывает кнопку ТОЛЬКО другим пользователям, которые смотрят на ваш профиль — у себя вы её не увидите. URL должен начинаться с http:// или https:// (если схемы нет, мы автоматически добавим https://). Максимум 1 кнопка, длина названия ≤ 32 символа.",
        "discord_app_name": "Название активности",
        "discord_app_name_hint": "Своё имя вместо имени Discord-приложения (напр. 'SC Checker')",
        "discord_elapsed_mode": "Режим таймера",
        "discord_elapsed_launch": "С момента запуска",
        "discord_elapsed_frozen": "Застывшее время (всегда одно и то же)",
        "discord_elapsed_custom": "Своё время начала",
        "discord_elapsed_hidden": "Скрыт (без таймера)",
        "discord_frozen_time": "Застывшее время",
        "discord_frozen_time_hint": "Формат: ЧЧ:ММ:СС (напр. 11:11:11) — всегда показывает это время",
        "discord_custom_time": "Своё время начала",
        "discord_custom_time_hint": "Формат: ЧЧ:ММ:СС или ГГГГ-ММ-ДД ЧЧ:ММ:СС или epoch timestamp",
        "discord_tab_advanced": "Доп. настройки",
        "discord_preview": "👁  Предпросмотр",
        "discord_playing_game": "Играет в игру",
        "discord_idle_preview": "Простой",
        "discord_elapsed_preview": "00:01 прошло",
        "discord_frozen_preview": "11:11:11 прошло",
        "elapsed_suffix": "прошло",
        # Webhooks
        "webhook_title": "Уведомления Webhook",
        "webhook_none": "Webhook'и не настроены\n\nНажмите '+ Добавить Webhook' ниже",
        "webhook_add": "+ Добавить Webhook",
        "webhook_onoff": "Вкл/Выкл",
        "webhook_add_title": "Добавить Webhook",
        "webhook_new": "Новый Webhook",
        "webhook_name": "Имя",
        "webhook_name_ph": "напр. Мой Telegram",
        "webhook_channel": "Канал",
        "webhook_save": "Сохранить",
        # Scan / status
        "status_ai_disabled": "AI: отключено",
        "ai_enter_key_first": "Сначала введите API-ключ",
        "ai_select_model_first": "Сначала выберите или загрузите модель",
        "ai_testing_connection": "Проверка соединения...",
        "no_targets_found": "В файле не найдено целей",
        "risk_score_label": "Оценка риска",
        "scanning_dots": "Сканирование",
        "status_batch": "Пакет:",
        "targets_unit": "целей",
        "phase_batch_start": "Запуск пакета...",
        "phase_init": "Инициализация...",
        "phase_done": "Готово",
        "status_done_in": "Готово за",
        "target_phase": "Цель",
        # Results display
        "no_issues": "  Проблем нет",
        "no_dns_records": "  Нет DNS-записей",
        "no_subdomains": "  Нет субдоменов",
        "found_subdomains": "Найдено",
        "subdomains_word": "субдоменов",
        "no_data": "Нет данных",
        "no_data_found": "Данные не найдены",
        "no_ssl": "  Нет SSL (порт 443 не открыт или не HTTPS)",
        "cert_expires_in": "Сертификат истекает через",
        "paths_label": "Пути:",
        "scanned_word": "просканировано",
        "found_word": "найдено",
        "critical_word": "критических",
        "open_ports_label": "Открытые порты:",
        "port_header": "Порт",
        "service_header": "Сервис",
        "banner_header": "Баннер",
        # Network sections
        "sec_target": "── Цель ──",
        "input_word": "Ввод:",
        "ip_word": "IP:",
        "host_word": "Хост:",
        "reverse_word": "Обратный:",
        "na_word": "н/д",
        "sec_geo": "── Геолокация ──",
        "sec_asn": "── ASN ──",
        "sec_ssl_tls": "── SSL / TLS ──",
        "sec_open_ports": "── Открытые порты",
        "sec_dns": "── DNS ──",
        "sec_ssl_deep": "── Глубокая проверка SSL ──",
        "sec_security_headers": "── Заголовки безопасности ──",
        "found_word_yes": "Найдено",
        "not_found_word": "Не найдено",
        "sec_performance": "── Производительность ──",
        "ttfb_word": "TTFB:",
        "content_size_word": "Размер контента:",
        "encoding_word": "Кодирование:",
        "none_word": "нет",
        "sec_redirect_chain": "── Цепочка перенаправлений",
        "final_mark": "[ФИНАЛ]",
        "sec_http_methods": "── HTTP-методы ──",
        "sec_emails": "── Email",
        "sec_phones": "── Телефоны",
        "sec_social_links": "── Соцсети",
        "sec_meta_tags": "── Мета-теги",
        "sec_hidden_forms": "── Скрытые формы",
        "hidden_inputs_word": "скрыто",
        "sec_ip_info": "── Информация об IP ──",
        "reverse_dns_word": "Обратный DNS:",
        "ai_results_header": "── Результаты AI-анализа ──",
        "no_ai_data": "Нет данных AI",
        "findings_word": "находок",
        "table_sev": "Критичность",
        "table_type": "Тип",
        "table_detail": "Описание",
        "ai_configure_first": "Сначала настройте AI-провайдера в настройках AI.",
        # Proxy / settings
        "optional": "необязательно",
        "lang_english": "English",
        "lang_russian": "Русский",
        # Export
        "export_title": "Экспорт",
        "copy_title": "Копировать",
        "copied": "Скопировано!",
        "html_word": "HTML",
        # Findings severity detail
        "exploit_word": "Эксплойт:",
        "fix_word": "Исправление:",
        # Misc
        "waf_detected": "Обнаружен WAF:",
        "frameworks_word": "Фреймворки",
        "cms_word": "CMS",
        # Advanced results sections
        "sec_external_links": "── Внешние ссылки",
        "sec_js_libs": "── JS-библиотеки",
        "server_word": "Сервер:",
        "sec_injection": "── Тесты инъекций ──",
        "host_header_word": "Заголовок Host:",
        "crlf_word": "CRLF:",
        "open_redirect_word": "Открытый редирект:",
        "dir_traversal_word": "Обход каталогов:",
        "sec_backup_files": "── Резервные файлы",
        "sec_source_leaks": "── Утечки исходного кода",
        "sec_admin_panels": "── Админ-панели",
        "sec_login_pages": "── Страницы входа",
        "no_leaks": "Утечек не найдено",
        "sec_api_endpoints": "── API-эндпоинты",
        "no_api_endpoints": "API-эндпоинты не найдены",
        "sec_mutation": "── Движок мутации пейлоадов ──",
        "tested_word": "Проверено",
        "payload_variants": "вариантов пейлоадов:",
        "no_mutations": "  Мутации не сгенерированы",
        "sec_supply_chain": "── Анализ цепочки поставок ──",
        "found_word_lc": "Найдено",
        "external_resources": "внешних ресурсов:",
        "ok_word": "OK",
        "no_external_resources": "  Внешние ресурсы не найдены",
        "sec_websocket": "── Анализ WebSocket ──",
        "ws_connected": "ПОДКЛЮЧЕНО",
        "ws_failed": "ОШИБКА",
        "status_word": "Статус:",
        "no_ws_endpoints": "  WebSocket-эндпоинты не найдены",
        "sec_session": "── Манипуляция сессиями ──",
        "no_session_issues": "  Проблем с сессиями не найдено",
        "sec_chaos": "── Chaos-сканирование ──",
        "no_chaos": "  Chaos-находок нет",
        "sec_dsl_results": "── Результаты DSL-правил ──",
        "all_rules_passed": "  Все правила пройдены",
        "sec_jwt": "── Анализ JWT ──",
        "no_jwt": "  JWT-токены не найдены",
        "sec_ssl_deep2": "── Глубокий SSL ──",
        "sec_cookie_audit": "── Аудит cookies",
        "cookies_count": "cookies,",
        "issues_word": "проблем",
        "sec_headers_detail": "── Заголовки",
        "sec_tech": "── Технологии",
        "sec_cve": "── CVE",
        "sec_versions": "── Версии",
        "sec_anomalies": "── Аномалии",
        "sec_dns2": "── DNS",
        "invalid_word": "НЕВАЛИДНО",
        "no_jwt_tokens": "  Нет JWT-токенов",
        "none_found": "Не найдено",
        "sec_ssti": "── Проверка SSTI ──",
        "no_ssti": "  SSTI не обнаружен",
        "sec_dns_zone": "── Передача DNS-зоны ──",
        "zone_blocked": "  Передача зоны заблокирована",
        "sec_takeover": "── Перехват субдоменов ──",
        "no_takeover": "  Кандидатов на перехват нет",
        "sec_email_sec": "── Безопасность email ──",
        "no_email_sec": "  Нет данных о безопасности email",
        "sec_smuggling": "── HTTP Smuggling ──",
        "no_smuggling": "  Smuggling не обнаружен",
        "sec_tech_deep": "── Глубокий техстек ──",
        "no_tech_deep": "  Дополнительные технологии не обнаружены",
        "sec_hidden_ep": "── Скрытые эндпоинты ──",
        "no_hidden_ep": "  Скрытые эндпоинты не найдены",
        "sec_cvss": "── Оценки CVSS ──",
        "no_cvss": "  Оценки CVSS не рассчитаны",
        "sec_waf_fp": "── Отпечаток WAF ──",
        "detected_word": "Обнаружено:",
        "version_word": "Версия:",
        "rules_word": "Правила:",
        "no_waf": "  WAF не обнаружен",
        "sec_rate_limit": "── Ограничение скорости ──",
        "limit_word": "Лимит:",
        "remaining_word": "Осталось:",
        "reset_word": "Сброс:",
        "no_rate_limit": "Ограничение скорости не обнаружено",
        "sec_cors_deep": "── Глубокий тест CORS ──",
        "fail_word": "ПРОВАЛ",
        "pass_word": "OK",
        "no_cors_tests": "  Тесты CORS не выполнены",
        "sec_exploit_v": "── Проверка эксплойтов ──",
        "no_exploit_v": "  Эксплойты не проверены (нет находок для проверки)",
        "sec_js_analysis": "── Анализ JavaScript ──",
        "scripts_analyzed": "Скриптов проанализировано:",
        "endpoints_found": "Эндпоинтов найдено:",
        "secrets_found": "Секретов найдено:",
        "sri_missing": "SRI отсутствует:",
        "endpoints_word": "Эндпоинты:",
        "secrets_word": "Секреты:",
        "no_js_analysis": "  Анализ JS не выполнен",
        "sec_ct": "── Certificate Transparency ──",
        "found_certs": "Найдено",
        "certificates_word": "сертификатов",
        "issuer_word": "Эмитент:",
        "not_before_word": "Действует с:",
        "no_ct": "  CT-логи не найдены",
        "sec_shodan": "── Shodan / InternetDB ──",
        "no_shodan": "  Нет данных Shodan",
        "sec_whois": "── WHOIS / RDAP ──",
        "registrar_word": "Регистратор:",
        "created_word": "Создан:",
        "expires_word": "Истекает:",
        "name_servers_word": "Name-серверы:",
        "no_whois": "  Нет данных WHOIS",
        "sec_screenshots": "── Скриншоты ──",
        "error_word": "Ошибка:",
        "saved_word": "Сохранён:",
        "no_screenshots": "  Скриншоты не сделаны",
        "screenshots_disabled": "  ⚠ Скриншоты отключены в Настройки → Настройки сканирования → Разведка",
        "install_playwright": "  Установите Playwright: pip install playwright && playwright install chromium",
        "sec_loaded_plugins": "── Загруженные плагины",
        "no_plugins_loaded": "Плагины не загружены",
        "plugins_hint1": "Поместите .py-файлы в каталог plugins/",
        "sec_plugin_findings": "── Находки плагинов",
        # Server node
        "server_node": "🖥 Серверная нода",
        "no_http_detected": "HTTP-сервер не обнаружен на стандартном порту — проверка альтернативных",
        "na_no_http": "Н/Д — HTTP-сервер не обнаружен",
        "alt_http_found": "HTTP найден на порту {port}",
        "server_node_hint": "Сканирование как серверная нода (только TCP/SSL/DNS)",
        # Proxy page (RU)
        "proxy_title": "НАСТРОЙКА ПРОКСИ",
        "proxy_desc": "Маршрутизировать весь трафик сканирования через прокси-сервер.",
        "proxy_type": "Тип",
        "proxy_host": "Хост / IP",
        "proxy_port": "Порт",
        "proxy_user": "Имя пользователя",
        "proxy_pass": "Пароль",
        "proxy_add": "+ Добавить прокси",
        "proxy_save": "Сохранить",
        "proxy_delete": "Удалить",
        "proxy_test": "Тест соединения",
        "proxy_enable": "Включить",
        "proxy_disable": "Выключить",
        "proxy_status_active": "АКТИВЕН",
        "proxy_status_inactive": "НЕАКТИВЕН",
        "proxy_status_testing": "Проверка...",
        "proxy_status_ok": "Соединение установлено",
        "proxy_status_fail": "Соединение не установлено",
        "proxy_no_proxies": "Прокси не настроены.\nНажмите '+ Добавить прокси' для начала.",
        "proxy_format_hint": "Формат: type://host:port  или  type://user:pass@host:port",
        "proxy_active_label": "Активный прокси",
        "proxy_saved": "Прокси сохранён",
        "proxy_deleted": "Прокси удалён",
        "proxy_test_ok": "Тест прокси пройден — соединение установлено",
        "proxy_test_fail": "Тест прокси не пройден",
        "proxy_section": "  СЕТЬ",
        # AI Analysis page (RU)
        "ai_title": "AI АНАЛИЗ УЯЗВИМОСТЕЙ",
        "ai_desc": "AI-анализ результатов сканирования с гайдами по эксплуатации и исправлению.",
        "ai_ask_placeholder": "Спросите AI о сканировании...",
        "ai_ask_btn": "Спросить",
        "ai_summary_btn": "Сводка",
        "ai_exploit_btn": "Эксплойты",
        "ai_remediation_btn": "Исправление",
        "ai_risk_btn": "Отчёт о рисках",
        "ai_no_findings": "Сначала запустите скан, затем приходите сюда для AI-анализа.",
        "ai_models_loaded": "Моделей загружено:",
        "ai_query_processing": "Обработка запроса...",
        "ai_custom_prompt": "Свой запрос",
        "ai_input_placeholder": "Напишите ваш вопрос здесь...",
        "ai_severity_breakdown": "ПО УРОВНЮ СЕРЬЁЗНОСТИ",
        "ai_top_risks": "ГЛАВНЫЕ РИСКИ",
        # AI Settings extended (RU)
        "ai_temperature": "Температура",
        "ai_max_tokens": "Макс. токенов",
        "ai_system_prompt": "Системный промпт",
        "ai_system_prompt_hint": "Инструкции для AI модели...",
        "ai_presets": "Пресеты",
        "ai_preset_pentest": "Пентест",
        "ai_preset_audit": "Аудит безопасности",
        "ai_preset_compliance": "Проверка соответствия",
        "ai_preset_quick": "Быстрый скан",
        "ai_clear_chat": "Очистить",
        "ai_clear_confirm": "Очистить историю диалога?",
        "ai_upload_file": "Загрузить",
        "ai_upload_title": "Выберите файлы для AI анализа",
        "ai_no_provider": "Провайдер не настроен",
        "ai_copy_btn": "Копировать",
        "ai_session_stats": "Запросов",
        "settings_theme": "Тема",
        "settings_language": "Язык",
        "settings_theme_neon_dark": "Неон Тёмная",
        "settings_theme_cyber_blue": "Кибер Синяя",
        "settings_theme_midnight_purple": "Полночная Фиолетовая",
        "settings_theme_forest_green": "Лесная Зелёная",
        "settings_theme_crimson_red": "Багровая Красная",
        "settings_theme_light": "Светлая",
        "settings_theme_restart": "Перезапустите приложение для применения темы",
        "settings_theme_applied": "✓ Тема применена",
        "settings_save_btn": "Применить",
        "settings_scan_header": "Настройки сканирования",
        "settings_scan_subhead": "Включите/выключите проверки и задайте количество путей/полезных нагрузок",
        "settings_lang_desc": "Выберите язык интерфейса приложения",
        "settings_tab_core": "Основные",
        "settings_tab_security": "Безопасность",
        "settings_tab_recon": "Разведка",
        "settings_tab_advanced": "Продвинутые",
        "settings_tab_mutation": "Мутации",
        "settings_tab_language": "Язык",
        "ai_jailbreaks": "Джейлбрейки для AI",
        "ai_jailbreaks_desc": "Выберите джейлбрейк промпт для системного промпта",
        "ai_jailbreak_apply": "Применить",
        "ai_welcome_title": "AI Ассистент безопасности",
        "ai_welcome_desc": "Задавайте вопросы о результатах сканирования.\nAI помнит контекст предыдущих сообщений.",
        "ai_welcome_tips": "Попробуйте: \"Какие критические уязвимости?\"\nИли нажмите кнопку пресета выше.",
        "ai_file_added": "Добавлен",
        "ai_no_files": "Нет файлов",
        "ai_provider_card": "Провайдер",
        "ai_model_card": "Модель",
        "ai_params_card": "Параметры",
        "ai_prompt_card": "Системный промпт",
        "ai_profile_card": "Текущий профиль",
        "ai_advanced": "Расширенные",
        "ai_basic": "Основные",
        "ai_chars": "символов",
        "ai_tokens_info": "токенов",
        "ai_context_window": "Контекст",
        "ai_preset_active": "Активен",
        "ai_test_ok": "Подключено",
        "ai_test_fail": "Ошибка",
        "ai_provider_desc": "API провайдер для AI-анализа",
        "ai_model_desc": "Модель AI для использования",
        "ai_temp_desc": "0 = детерминированно, 1 = креативно",
        "ai_tokens_desc": "Макс. длина ответа",
        "ai_prompt_desc": "Инструкции для AI-модели",
        "ai_attach_files": "Прикрепить файлы",
        "ai_send": "Отправить",
        "ai_thinking": "Думаю...",
        "ai_user_avatar": "ВЫ",
        "ai_ai_avatar": "AI",
        "ai_code_copy": "Копировать",
        "tip_ai_summary": "Сводка по результатам сканирования",
        "tip_ai_exploits": "Гайд по эксплуатации найденных уязвимостей",
        "tip_ai_remediation": "План исправления с примерами кода",
        "tip_ai_risk": "Формальный отчёт по оценке рисков",
        "tip_ai_upload": "Прикрепить файлы для анализа AI",
        "tip_ai_clear": "Очистить историю и начать заново",
        "tip_ai_send": "Отправить сообщение AI (Enter)",
        "ai_files_delete": "Удалить",
        "ai_files_clear_all": "Очистить все",
        # Language
        "lang_label": "RU",
        # Doc topic labels (RU)
        "topic_Overview": "Обзор",
        "topic_Quick Start": "Быстрый старт",
        "topic_Scan Features": "Функции сканирования",
        "topic_Security Checks": "Проверки безопасности",
        "topic_Deep Scan": "Глубокое сканирование",
        "topic_Advanced Features": "Продвинутые функции",
        "topic_DSL v2 Language": "Язык DSL v2",
        "topic_Custom Lists": "Пользовательские списки",
        "topic_Plugins": "Плагины",
        "topic_AI Integration": "Интеграция с AI",
        "topic_Webhooks": "Вебхуки",
        "topic_Discord RPC": "Discord RPC",
        "topic_Graph": "Граф",
        "topic_Keyboard Shortcuts": "Горячие клавиши",
        "topic_Proxy": "Прокси",
        "topic_Terminal": "Терминал",
        # Docs topics
        "doc_Overview": (
            "SITE CHECKER\n\n"
            "SC Checker — комплексный инструмент аудита веб-сайтов для\n"
            "исследователей безопасности, пентестеров и системных администраторов.\n"
            "Сканирует сайты на уязвимости, ошибки конфигурации, открытые пути,\n"
            "порты и предоставляет AI-анализ.\n\n"
            "ИНТЕРФЕЙС:\n"
            "  Левый сайдбар  — навигация по страницам\n"
            "  Верхняя панель — ввод цели, кнопки Скан/Стоп, async\n"
            "  Полоса прогресса — ход сканирования\n"
            "  Область контента — результаты выбранной страницы\n"
            "  Правый сайдбар — инструменты (списки, настройки)\n"
            "  Статус-бар — версия, шорткаты, статус\n\n"
            "СТРАНИЦЫ:\n"
            "  Панель     — шкала риска, статистика, обзор безопасности\n"
            "  Безопасность — проверки и проблемы\n"
            "  Глубокий   — SSL, методы HTTP, CSP, производительность\n"
            "  Сеть       — IP, SSL/TLS, сервисы\n"
            "  Разведка   — субдомены, ссылки, геолокация IP\n"
            "  Инъекции   — SQL/XSS, утечки данных\n"
            "  Продвинутые — JWT, SSTI, GraphQL, WebSocket, chaos\n"
            "  Пути       — найденные пути с кодами статуса\n"
            "  Порты      — открытые порты и сервисы\n"
            "  DNS        — DNS записи и субдомены\n"
            "  Граф       — интерактивная топология (зум/панорама)\n"
            "  Лог        — живой лог сканирования\n"
            "  Отчёт      — полный отчёт и экспорт (JSON/HTML/TXT)\n"
            "  Документация — эта документация\n"
        ),
        "doc_Quick Start": (
            "БЫСТРЫЙ СТАРТ\n\n"
            "1. Введите цель в верхней панели:\n"
            "     example.com\n"
            "     https://example.com\n"
            "     1.2.3.4\n"
            "     target1.com\\ntarget2.com  (несколько, через перевод строки)\n\n"
            "2. Нажмите ▶ СКАН или Enter для начала сканирования.\n\n"
            "3. Наблюдайте за прогрессом в полосе прогресса и логе.\n\n"
            "4. Просматривайте результаты на разных страницах.\n\n"
            "5. Экспорт через страницу Отчёт: JSON, HTML, TXT, Копировать, Отправить.\n\n"
            "ASYNC РЕЖИМ:\n"
            "  Включите галочку ⚡ для асинхронного HTTP-сканирования.\n"
            "  Использует httpx.AsyncClient — ускорение в ~10 раз.\n\n"
            "ТИПЫ ЦЕЛЕЙ:\n"
            "  Домен:  example.com\n"
            "  IP:     1.2.3.4 (пропускает HTTP-проверку)\n"
            "  URL:    https://example.com/path\n"
            "  Несколько: вставьте несколько целей, сканируются по очереди\n\n"
            "КЭШИРОВАНИЕ:\n"
            "  DNS и TCP результаты кэшируются в reports/cache/cache.json\n"
            "  для ускорения повторных сканирований.\n"
        ),
        "doc_Batch Scan": (
            "ПАКЕТНОЕ СКАНИРОВАНИЕ (НЕСКОЛЬКО ЦЕЛЕЙ)\n\n"
            "Сканируйте несколько целей по очереди за одну сессию.\n\n"
            "КАК ИСПОЛЬЗОВАТЬ:\n\n"
            "  1. Вставьте несколько целей в поле ввода:\n"
            "     - Одна цель на строку\n"
            "     - Можно смешивать домены, IP и URL\n"
            "     - Появится диалог с подтверждением количества целей\n\n"
            "  2. Нажмите СКАН для запуска пакета.\n\n"
            "  3. Каждая цель сканируется одна за другой с паузой\n"
            "     10 секунд между ними.\n\n"
            "  4. Во время паузы вы можете просмотреть результаты\n"
            "     предыдущего сканирования перед следующим.\n\n"
            "  5. Нажмите СТОП в любое время, чтобы отменить\n"
            "     оставшиеся цели мгновенно.\n\n"
            "ЧТО ПРОИСХОДИТ ПОСЛЕ КАЖДОЙ ЦЕЛИ:\n\n"
            "  - Результаты отображаются на странице Результатов\n"
            "  - Отправляются вебхуки (если настроены)\n"
            "  - Отправляются email-оповещения для HIGH/CRITICAL\n"
            "  - Discord RPC обновляется с прогрессом (X/Y)\n\n"
            "ФУНКЦИИ ПАКЕТА:\n\n"
            "  - 10-секундный обратный отсчёт между целями\n"
            "  - Обратный отсчёт отображается в панели лога\n"
            "  - СТОП отменяет во время обратного отсчёта\n"
            "  - Полоса прогресса показывает общий прогресс\n"
            "  - Чёрный список: цели из чёрного списка пропускаются\n\n"
            "СОВЕТ:\n"
            "  Можно также ввести несколько целей вручную,\n"
            "  каждая на отдельной строке в поле ввода.\n"
        ),
        "doc_Scan Features": (
            "ФУНКЦИИ СКАНИРОВАНИЯ (35+ проверок)\n\n"
            "БАЗОВОЕ СКАНИРОВАНИЕ:\n"
            "  - HTTP/HTTPS запрос с кодом статуса, временем отклика\n"
            "  - Заголовки безопасности (HSTS, CSP, X-Frame, X-XSS и др.)\n"
            "  - Обнаружение отсутствующих заголовков\n"
            "  - Парсинг robots.txt и sitemap.xml\n"
            "  - Анализ cookies (Secure, HttpOnly, SameSite)\n"
            "  - Обнаружение ошибок CORS\n"
            "  - Обнаружение смешанного контента\n"
            "  - Проверка защиты от clickjacking\n"
            "  - Проверка редиректа HTTP на HTTPS\n"
            "  - Обнаружение листинга директорий\n"
            "  - SQL-ошибки в ответе\n"
            "  - Тест XSS-отражения\n"
            "  - Извлечение баннера сервера\n"
            "  - Фингерпринтинг (CMS, фреймворки)\n\n"
            "ПОИСК ПУТЕЙ:\n"
            "  - Брутфорс со словником (по умолчанию: 5000+ путей)\n"
            "  - Обнаружение критических путей (/admin, /backup, /config)\n"
            "  - Категоризация по кодам статуса (200, 301, 401, 403, 500)\n"
            "  - Анализ размера ответа\n\n"
            "СКАНИРОВАНИЕ ПОРТОВ:\n"
            "  - Топ 100 популярных портов (настраивается)\n"
            "  - Идентификация сервисов по баннерам\n"
            "  - Параллельное сканирование (64 потока)\n\n"
            "ПЕРЕЧИСЛЕНИЕ СУБДОМЕНОВ:\n"
            "  - DNS брутфорс\n"
            "  - Логи прозрачности сертификатов\n"
            "  - Распространённые префиксы субдоменов\n\n"
            "ОБНАРУЖЕНИЕ WAF:\n"
            "  - Cloudflare, Akamai, AWS WAF, ModSecurity и др.\n"
            "  - По заголовкам и паттернам ответа\n\n"
            "СКАНИРОВАНИЕ CVE:\n"
            "  - Проверка известных CVE для обнаруженного ПО\n"
            "  - Использует NVD API с локальным кэшем\n"
        ),
        "doc_Security Checks": (
            "ПРОВЕРКИ БЕЗОПАСНОСТИ\n\n"
            "АНАЛИЗ ЗАГОЛОВКОВ:\n"
            "  - Strict-Transport-Security (HSTS)\n"
            "  - Content-Security-Policy (CSP) — полный анализ\n"
            "  - X-Frame-Options\n"
            "  - X-Content-Type-Options\n"
            "  - X-XSS-Protection\n"
            "  - Referrer-Policy\n"
            "  - Permissions-Policy\n"
            "  - Expect-CT\n"
            "  - X-Permitted-Cross-Domain-Policies\n\n"
            "ПРОБЛЕМЫ С COOKIES:\n"
            "  - Отсутствует флаг Secure\n"
            "  - Отсутствует флаг HttpOnly\n"
            "  - Отсутствует атрибут SameSite\n"
            "  - Сессионные cookies без HTTPS\n\n"
            "ПРОБЛЕМЫ CORS:\n"
            "  - Wildcard origin с credentials\n"
            "  - Разрешён null origin\n"
            "  - Проверка списка доверенных origins\n\n"
            "ТЕСТЫ ИНЪЕКЦИЙ:\n"
            "  - Обнаружение SQL-ошибок в ответах\n"
            "  - XSS-отражение пользовательского ввода\n"
            "  - Инъекция Host-заголовка\n"
            "  - CRLF-инъекция\n"
            "  - Открытый редирект\n"
            "  - Обход директорий\n\n"
            "УТЕЧКА ИСХОДНИКОВ:\n"
            "  - Файлы резервных копий (.bak, .old, .swp)\n"
            "  - Source maps (.map)\n"
            "  - Директории Git (.git)\n"
            "  - Админ-панели (/admin, /wp-admin)\n"
            "  - Страницы входа (/login, /signin)\n"
            "  - API эндпоинты (/api, /graphql, /swagger)\n"
        ),
        "doc_Deep Scan": (
            "ГЛУБОКОЕ СКАНИРОВАНИЕ\n\n"
            "ГЛУБОКИЙ АНАЛИЗ SSL/TLS:\n"
            "  - Детали сертификата (issuer, срок действия, SAN)\n"
            "  - Отслеживание истечения срока\n"
            "  - Обнаружение слабых шифров\n"
            "  - Версия протокола (TLS 1.0/1.1 уязвимы)\n"
            "  - Валидация цепочки сертификатов\n\n"
            "HTTP МЕТОДЫ:\n"
            "  - Тесты GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE\n"
            "  - Обнаружение метода TRACE (уязвимость XST)\n"
            "  - Контроль доступа по методам\n\n"
            "ЗАГОЛОВКИ БЕЗОПАСНОСТИ (детально):\n"
            "  - Анализ CSP (директивы, источники, nonce)\n"
            "  - Директивы Permissions-Policy\n"
            "  - Значение Referrer-Policy\n"
            "  - Статус Expect-CT\n\n"
            "ПРОИЗВОДИТЕЛЬНОСТЬ:\n"
            "  - TTFB (время до первого байта)\n"
            "  - Размер и кодировка контента\n"
            "  - Полная цепочка редиректов с кодами\n\n"
            "РАЗВЕДКА:\n"
            "  - Email-адреса в HTML/JS\n"
            "  - Номера телефонов\n"
            "  - Ссылки на соцсети\n"
            "  - Meta-теги (og:, twitter:)\n"
            "  - Скрытые формы\n"
            "  - Внешние ссылки\n"
            "  - JavaScript-библиотеки и версии\n"
            "  - Геолокация IP (страна, город, ISP)\n"
            "  - Информация ASN\n"
            "  - Обратный DNS\n"
        ),
        "doc_Advanced Features": (
            "ПРОДВИНУТЫЕ ФУНКЦИИ\n\n"
            "ДВИЖОК МУТАЦИИ ПОЛЕЗНЫХ НАГРУЗОК:\n"
            "  8 базовых x 10 вариантов мутаций:\n"
            "  - URL encode, двойное кодирование\n"
            "  - HTML-сущности, unicode\n"
            "  - Смена регистра, инъекция пробелов\n"
            "  - Null-байт, обратные кавычки\n"
            "  - Смешанное кодирование\n"
            "  Тест каждого варианта и обнаружение обходов\n\n"
            "АНАЛИЗАТОР ЦЕПОЧКИ ПОСТАВОК:\n"
            "  - Парсинг тегов <script>, <link>, <img>\n"
            "  - Обнаружение CDN (Cloudflare, Akamai и др.)\n"
            "  - Проверка HTTPS vs HTTP ресурсов\n"
            "  - Проверка SRI (Subresource Integrity)\n"
            "  - Обнаружение устаревших библиотек:\n"
            "    jQuery <1.7, AngularJS 1.x, Bootstrap 3,\n"
            "    Moment.js, Lodash <4.17.21\n\n"
            "ГЛУБОКОЕ СКАНИРОВАНИЕ GRAPHQL:\n"
            "  -Автообнаружение /graphql, /graphiql\n"
            "  - Introspection-запрос для извлечения схемы\n"
            "  - Тест инъекций в аргументах запросов\n"
            "  - Раскрытие мутаций (операции записи)\n\n"
            "АНАЛИЗАТОР WEBSOCKET:\n"
            "  - Подключение к ws:// и wss://\n"
            "  - Тест XSS-отражения через WS-сообщения\n"
            "  - Обнаружение инъекций шаблонов\n"
            "  - DoS через большие полезные нагрузки\n\n"
            "МАНИПУЛЯЦИЯ СЕССИЯМИ:\n"
            "  - Тест фиксации сессий\n"
            "  - Обнаружение слабых токенов (проверка энтропии)\n"
            "  - Флаги безопасности cookies\n"
            "  - Обнаружение токена в URL\n"
            "  - Ошибки конфигурации CORS\n\n"
            "CHAOS СКАНИРОВАНИЕ:\n"
            "  - 15+ случайных/крайних заголовков\n"
            "  - POST-тела: JSON, null-байты, XML XXE, бинарные\n"
            "  - URL-параметры: debug, cmd, exec, callback\n\n"
            "АНАЛИЗ JWT:\n"
            "  - Поиск токенов в заголовках, cookies, теле\n"
            "  - Декодирование заголовка и полезной нагрузки\n"
            "  - Проверка алгоритма (none, HS256, RS256)\n"
            "  - Отслеживание истечения срока\n"
            "  - Анализ энтропии секрета\n"
            "  - Чувствительные данные в полезной нагрузке\n\n"
            "SSTI (инъекция серверных шаблонов):\n"
            "  - Тест Jinja2 ({{7*7}})\n"
            "  - Тест FreeMarker, ERB, Ruby, Java Spring\n"
            "  - Векторы GET и POST\n\n"
            "ЗОНАЛЬНЫЙ ТРАНСФЕР DNS:\n"
            "  - Попытка AXFR через nameservers\n"
            "  - Обнаружение ошибки зонального трансфера\n\n"
            "ЗАХВАТ СУБДОМЕНОВ:\n"
            "  - Проверка CNAME на уязвимых сервисах:\n"
            "    GitHub Pages, Heroku, Azure, Netlify,\n"
            "    Shopify, Vercel, Pages.dev, Tumblr\n\n"
            "БЕЗОПАСНОСТЬ ПОЧТЫ:\n"
            "  - Валидация SPF-записи\n"
            "  - Проверка политики DMARC\n"
            "  - Обнаружение DKIM-записи\n\n"
            "HTTP SMUGGLING:\n"
            "  - Техника CL.TE\n"
            "  - Техника TE.CL\n"
            "  - Техника TE.TE\n\n"
            "ГЛУБОКИЙ ТЕХНОЛОГИЧЕСКИЙ СТЕК:\n"
            "  - WordPress, Laravel, Django, Next.js, Nuxt\n"
            "  - React, Vue, Angular, PHP, Express\n"
            "  - Определение версии по заголовкам/телу\n\n"
            "СКРЫТЫЕ ЭНДПОИНТЫ:\n"
            "  - Парсинг JS-файлов на URL API\n"
            "  - Проверка запрещённых путей из robots.txt\n"
        ),
        "doc_DSL v2 Language": (
            "ЯЗЫК DSL v2\n\n"
            "DSL (язык домена) позволяет писать собственные правила\n"
            "безопасности. Поддерживаются два формата: JSON и программный текст.\n\n"
            "\n  --- JSON ПРАВИЛА ---\n\n"
            "  [\n"
            "    {\n"
            '      "name": "Нет HSTS",\n'
            '      "condition": "hsts_enabled == false",\n'
            '      "severity": "HIGH",\n'
            '      "message": "HSTS не включён"\n'
            "    }\n"
            "  ]\n\n"
            "  Операторы: ==  !=  >  <  >=  <=  contains  notcontains\n"
            "  Комбинации: AND, OR (заглавные)\n"
            "  Важность:  CRITICAL, HIGH, MEDIUM, LOW, INFO\n\n"
            "\n  --- ПРОГРАММНЫЙ ТЕКСТ ---\n\n"
            "ПЕРЕМЕННЫЕ:\n"
            "  $count = open_ports_count\n"
            "  $risk = risk_score\n"
            '  $name = "test"\n'
            "  $list = [1, 2, 3]\n\n"
            "IF/THEN/ELSE:\n"
            "  IF risk_score > 70 THEN\n"
            '    ASSERT risk_score < 100\n'
            "  ELSE\n"
            '    ASSERT risk_score >= 0\n'
            "  END\n\n"
            "ЦИКЛЫ FOR:\n"
            "  FOR port IN open_ports\n"
            "    ASSERT port > 0\n"
            "  END\n\n"
            "  FOR sub IN subdomains\n"
            '    ASSERT sub contains "example.com"\n'
            "  END\n\n"
            "УТВЕРЖДЕНИЯ:\n"
            "  ASSERT hsts_enabled == true\n"
            "  ASSERT ssl_expiry_days > 30\n"
            "  ASSERT open_ports_count < 10\n"
            "  ASSERT waf_detected contains Cloudflare\n\n"
            "ЗАХВАТ РЕГУЛЯРНЫХ ВЫРАЖЕНИЙ:\n"
            '  CAPTURE "\\d+\\.\\d+\\.\\d+" FROM server_banner\n'
            '  CAPTURE "v\\d+" FROM version_hints\n'
            "HTTP-ЗАПРОСЫ:\n"
            '  REQUEST "https://example.com/robots.txt" CHECK RESPONSE CONTAINS "User-agent"\n\n'
            "ВРЕМЯ ОТКЛИКА:\n"
            '  HTTP_TIME "https://example.com" < 2000\n'
            '  HTTP_TIME "https://example.com" > 100\n\n'
            "КОММЕНТАРИИ:\n"
            "  # Это комментарий\n\n"
            "\n  --- ВЫРАЖЕНИЯ ---\n\n"
            "  $var              — ссылка на переменную\n"
            "  42, 3.14          — числа\n"
            '  "hello"           — строки\n'
            "  true, false       — булевы значения\n"
            "  [1, 2, 3]         — списки\n"
            "  open_ports_count  — вычисляемое поле (длина списка)\n"
            "  risk_score        — поле отчёта\n\n"
            "\n  --- ДОСТУПНЫЕ ПОЛЯ ---\n\n"
            "  Базовые:  status_code, response_time_ms, risk_score,\n"
            "            hsts_enabled, http_to_https_redirect,\n"
            "            clickjacking_protected, ssl_expiry_days,\n"
            "            ssl_weak_cipher, xss_reflection, mixed_content,\n"
            "            directory_listing, trace_enabled\n\n"
            "  Счётчики: discovered_paths, critical_paths, open_ports,\n"
            "            subdomains, cookie_issues, cors_issues,\n"
            "            sql_errors, waf_detected, cve_findings,\n"
            "            emails_found, external_links, js_libraries,\n"
            "            mutated_payloads, graphql_vulns, session_issues,\n"
            "            chaos_findings, dsl_results, ai_findings,\n"
            "            jwt_tokens, ssti_results, zone_transfer,\n"
            "            subdomain_takeover, http_smuggling\n\n"
            "  Текст:    host, ip, server_banner, csp_analysis,\n"
            "            security_txt, referrer_policy, reverse_dns\n\n"
            "  Словари:  headers, dns_records, tls_summary, ip_geo,\n"
            "            asn_info, email_security\n"
        ),
        "doc_Custom Lists": (
            "ПОЛЬЗОВАТЕЛЬСКИЕ СПИСКИ\n\n"
            "Пользовательские списки позволяют расширить сканер своими данными.\n"
            "Списки хранятся в reports/custom/*.txt (одна запись на строку).\n\n"
            "ДОСТУПНЫЕ СПИСКИ:\n\n"
            "  Заголовки — пользовательские HTTP-заголовки\n"
            "    Формат: Header-Name: значение\n"
            "    Пример: X-Custom: test123\n\n"
            "  Полезные нагрузки — payloads для тестирования инъекций\n"
            "    Формат: одна нагрузка на строку\n"
            "    Пример: ' OR 1=1 --\n\n"
            "  Порты — пользовательские порты для сканирования\n"
            "    Формат: номер порта на строку\n"
            "    Пример: 8080\n\n"
            "  Субдомены — префиксы для перечисления субдоменов\n"
            "    Формат: префикс на строку\n"
            "    Пример: api\n\n"
            "  User-Agent — пользовательские строки User-Agent\n"
            "    Формат: одна строка UA на строку\n\n"
            "  Чёрный список — цели для пропуска при пакетном скане\n"
            "    Формат: один домен на строку\n\n"
            "КАК ИСПОЛЬЗОВАТЬ:\n"
            "  1. Нажмите на название списка в правом сайдбаре\n"
            "  2. Отредактируйте в диалоге (добавьте записи)\n"
            "  3. Нажмите Сохранить\n"
            "  4. Списки автоматически используются при следующем скане\n\n"
            "СЛОВНИК:\n"
            "  Загрузите внешний словник через кнопку 'Список слов'.\n"
            "  Переопределяет список путей по умолчанию.\n"
            "  Формат: один путь на строку (без ведущего /)\n"
            "  Пример: admin\n           config\n           backup.zip\n"
        ),
        "doc_Plugins": (
            "СИСТЕМА ПЛАГИНОВ\n\n"
            "Плагины расширяют сканер пользовательскими проверками.\n\n"
            "ФОРМАТ ПЛАГИНА:\n"
            "  Создайте .py файл в директории plugins/.\n"
            "  Файл должен определять класс Plugin, наследующий PluginBase:\n\n"
            '    from plugins import PluginBase\n\n'
            '    PLUGIN_NAME = "my-plugin"\n'
            '    PLUGIN_VERSION = "1.0"\n\n'
            "    class Plugin(PluginBase):\n"
            '        name = "Мой плагин"\n'
            '        description = "Полезная функциональность"\n\n'
            "        def on_request(self, engine, url, response, report):\n"
            "            pass\n\n"
            "ХУКИ СКАНЕРА (вызываются во время скана):\n"
            "  on_scan_start(self, engine, target, report)\n"
            "      — В начале скана. Инициализируйте состояние.\n\n"
            "  on_before_request(self, engine, method, url) -> dict|None\n"
            "      — Перед корневым запросом. Верните dict для\n"
            "        добавления заголовков/параметров (напр. {'headers': {'X': 'Y'}}).\n\n"
            "  on_request(self, engine, url, response, report)\n"
            "      — После ответа на корневой запрос. Анализ ответа.\n\n"
            "  on_after_headers(self, engine, headers, report)\n"
            "      — После сбора заголовков из ответа.\n"
            "        headers — dict. report — объект Report.\n\n"
            "  on_after_ssl(self, engine, ssl_data, report)\n"
            "      — После анализа SSL/TLS.\n"
            "        ssl_data содержит ключи 'deep', 'cert', 'chain'.\n\n"
            "  on_after_ports(self, engine, open_ports, report)\n"
            "      — После сканирования портов.\n"
            "        open_ports — список номеров портов.\n\n"
            "  on_after_paths(self, engine, paths, report)\n"
            "      — После сканирования путей/каталогов.\n"
            "        paths — список dict {'path', 'status', 'size'}.\n\n"
            "  on_scan_complete(self, engine, report)\n"
            "      — Финальный хук. Report полностью заполнен.\n"
            "        Все поля report доступны для модификации.\n\n"
            "  on_export(self, report, format) -> str|None\n"
            "      — Вызывается при экспорте HTML. Верните строку HTML\n"
            "        для добавления в отчёт. format='html' или 'json'.\n\n"
            "  get_findings(self) -> list\n"
            "      — Верните список находок: [{severity, title, detail}].\n"
            "        Вызывается автоматически; отображается в 'Plugin Findings'.\n\n"
            "  get_graph_nodes(self, report) -> list\n"
            "      — Верните пользовательские узлы графа:\n"
            "        [{'label': str, 'color': '#hex'}].\n"
            "        Отображаются на топологии (фиолетовое кольцо).\n\n"
            "СХЕМА НАСТРОЕК (опционально):\n"
            "  Определите settings_schema как dict для UI настроек:\n\n"
            '    settings_schema = {\n'
            '        "threshold": {"type": "int", "label": "Порог риска",\n'
            '                       "default": 50, "desc": "Мин. оценка"},\n'
            '        "verbose": {"type": "bool", "label": "Подробный лог",\n'
            '                    "default": False, "desc": "Детальное логирование"},\n'
            '        "urls": {"type": "list", "label": "URL",\n'
            '                 "default": [], "desc": "По одному на строку"},\n'
            '        "name": {"type": "str", "label": "Имя API",\n'
            '                  "default": "", "desc": "Имя сервиса"},\n'
            "    }\n\n"
            "  Поддерживаемые типы: str, int, bool, list\n"
            "  Нажмите значок шестерёнки (⚙) рядом с плагином для настройки.\n"
            "  Настройки сохраняются в plugin_config.json.\n\n"
            "НАХОДКИ:\n"
            "  Используйте self.add_finding(severity, title, detail) в любом хуке.\n"
            "  severity: critical / high / medium / low / info\n\n"
            "УПРАВЛЕНИЕ:\n"
            "  Нажмите 'Плагины' в правом сайдбаре для:\n"
            "  - Просмотра загруженных плагинов и активных хуков\n"
            "  - Включения/выключения плагинов\n"
            "  - Настройки плагина (кнопка ⚙)\n"
            "  - Перезагрузки директории плагинов\n"
        ),
        "doc_AI Integration": (
            "ИНТЕГРАЦИЯ С AI\n\n"
            "AI-анализатор отправляет результаты скана в LLM для анализа.\n\n"
            "ПОДДЕРЖИВАЕМЫЕ ПРОВАЙДЕРЫ:\n\n"
            "  1. OpenAI (gpt-4o, gpt-4o-mini и др.)\n"
            "     API: https://api.openai.com/v1\n\n"
            "  2. Google Gemini (gemini-2.5-flash и др.)\n"
            "     API: https://generativelanguage.googleapis.com/v1beta/openai\n\n"
            "  3. Anthropic Claude (claude-sonnet-4-20250514 и др.)\n"
            "     API: https://api.anthropic.com/v1\n\n"
            "  4. OpenRouter (100+ моделей)\n"
            "     API: https://openrouter.ai/api/v1\n\n"
            "  5. Groq (llama-3.3-70b, mixtral-8x7b и др.)\n"
            "     API: https://api.groq.com/openai/v1\n\n"
            "  6. Mistral (mistral-large, codestral и др.)\n"
            "     API: https://api.mistral.ai/v1\n\n"
            "  7. Deepseek (deepseek-chat, deepseek-coder)\n"
            "     API: https://api.deepseek.com/v1\n\n"
            "  8. Cloudflare Workers AI\n"
            "     API: https://api.cloudflare.com/client/v4/accounts/{id}/ai\n\n"
            "НАСТРОЙКА:\n"
            "  1. Нажмите 'AI настройки' в правом сайдбаре\n"
            "  2. Выберите провайдера\n"
            "  3. Введите API-ключ\n"
            "  4. Нажмите 'Получить модели'\n"
            "  5. Выберите модель\n"
            "  6. Нажмите 'Тест' для проверки\n\n"
            "AI запускается автоматически в конце каждого скана.\n"
            "Результаты на вкладке Продвинутые > AI Analysis.\n\n"
            "ACCOUNT ID:\n"
            "  Требуется только для Cloudflare Workers AI.\n"
        ),
        "doc_Webhooks": (
            "УВЕДОМЛЕНИЯ ЧЕРЕЗ ВЕБХУКИ\n\n"
            "Автоматическая отправка результатов скана во внешние сервисы.\n\n"
            "ПОДДЕРЖИВАЕМЫЕ КАНАЛЫ:\n\n"
            "  1. Telegram Bot\n"
            "     Поля: bot_token, chat_id\n"
            "     bot_token: @BotFather\n"
            "     chat_id: @userinfobot\n\n"
            "  2. Discord Webhook\n"
            "     Поле: webhook_url\n"
            "     Создаётся в Server Settings > Integrations\n\n"
            "  3. Discord Bot\n"
            "     Поля: bot_token, channel_id\n"
            "     Использует Discord Bot API\n\n"
            "  4. Slack Webhook\n"
            "     Поле: webhook_url\n"
            "     Создаётся на api.slack.com/apps\n\n"
            "  5. Pushover\n"
            "     Поля: push_key, user_key, app_token\n"
            "     Регистрация на pushover.net\n\n"
            "  6. Пользовательский HTTP\n"
            "     Поля: webhook_url, auth_header (опционально)\n"
            "     POST JSON-полезная нагрузка на ваш эндпоинт\n\n"
            "НАСТРОЙКА:\n"
            "  1. Нажмите 'Вебхуки' в правом сайдбаре\n"
            "  2. Нажмите '+ Добавить'\n"
            "  3. Выберите тип канала\n"
            "  4. Заполните данные\n"
            "  5. Нажмите Сохранить\n\n"
            "Вебхуки срабатывают автоматически после каждого скана.\n"
            "Включение/выключение для каждого вебхука в диалоге.\n\n"
            "ФОРМАТ ПОЛЕЗНОЙ НАГРУЗКИ:\n"
            '  {"target": "...", "risk_score": 45,\n'
            '   "risk_level": "MEDIUM", "status": 200,\n'
            '   "critical_paths": [...], "open_ports": [...],\n'
            '   "cve_findings": [...]}\n'
        ),
        "doc_Discord RPC": (
            "DISCORD RICH PRESENCE\n\n"
            "Отображение активности в вашем профиле Discord:\n"
            "idle, сканирование или завершение скана с уровнем риска.\n\n"
            "БЫСТРЫЙ СТАРТ:\n"
            "  1. Откройте https://discord.com/developers/applications\n"
            "  2. Создайте New Application (имя = заголовок активности)\n"
            "  3. Скопируйте Application ID (только цифры)\n"
            "  4. Перейдите в Rich Presence > Art Assets > загрузите картинку\n"
            "     с именем 'logo' (совпадает с large_image_key по умолчанию)\n"
            "  5. В SC Checker: правый сайдбар > Discord RPC\n"
            "  6. Включите, вставьте Application ID, нажмите Сохранить\n\n"
            "СОСТОЯНИЯ АКТИВНОСТИ:\n"
            "  Idle      \u2014 Приложение открыто, скан не запущен\n"
            "  Scanning  \u2014 Цель, фаза, прогресс %\n"
            "  Done      \u2014 Цель, уровень риска и балл\n\n"
            "ПЕРЕМЕННЫЕ ШАБЛОНОВ:\n"
            "  {version}    \u2014 Версия SC Checker\n"
            "  {target}     \u2014 Сканируемый URL/IP\n"
            "  {phase}      \u2014 Текущая фаза скана\n"
            "  {progress}   \u2014 Прогресс 0-100\n"
            "  {risk_level} \u2014 LOW / MEDIUM / HIGH / CRITICAL\n"
            "  {risk_score} \u2014 Числовой балл 0-100\n\n"
            "РЕЖИМЫ ТАЙМЕРА:\n"
            "  since_launch \u2014 Реальное время с подключения\n"
            "  frozen_time  \u2014 Всегда показывает одно время (HH:MM:SS)\n"
            "  custom_time  \u2014 Свой стартовый timestamp\n"
            "  hidden       \u2014 Таймер скрыт\n\n"
            "ИЗОБРАЖЕНИЯ:\n"
            "  Загрузите картинки в Discord Developer Portal,\n"
            "  раздел Rich Presence > Art Assets.\n"
            "  Имя (name) картинки = large_image_key.\n"
            "  По умолчанию 'logo' \u2014 загрузите ассет с именем 'logo'.\n\n"
            "  !! ОБНОВИЛИ КАРТИНКУ, А ПОКАЗЫВАЕТСЯ СТАРАЯ?\n"
            "     Это кеш Discord, а не баг SC Checker. Discord кеширует\n"
            "     ассеты по ИМЕНИ на своём CDN + в каждом клиенте.\n"
            "     Если перезалить поверх ТОГО ЖЕ имени (заменить 'logo'),\n"
            "     ключ не меняется -> Discord часами/днями показывает\n"
            "     старую картинку.\n"
            "     ФИКС (мгновенно): загрузите новую картинку под НОВЫМ\n"
            "     именем (напр. 'logo2'), затем впишите это имя в\n"
            "     large_image_key в SC Checker и нажмите Сохранить.\n"
            "     Старый 'logo' потом можно удалить.\n"
            "     Другие варианты: полный перезапуск Discord (Выход в\n"
            "     трее) сбрасывает ТОЛЬКО ваш локальный кеш, но не кеш\n"
            "     CDN, поэтому ненадёжно и лечит только у вас.\n\n"
            "КНОПКА:\n"
            "  Добавляет кликабельную ссылку под активностью.\n"
            "  Поля: Button Label (макс. 32 символа)\n"
            "        Button URL (макс. 512 симв., только http/https)\n"
            "  SC Checker автоматически добавит https:// если схема отсутствует.\n\n"
            "  ВАЖНО: Discord скрывает кнопку на ВАШЕМ СОБСТВЕННОМ профиле.\n"
            "  Только ДРУГИЕ пользователи могут видеть и нажимать её.\n"
            "  Попросите друга проверить ваш профиль.\n\n"
            "РЕШЕНИЕ ПРОБЛЕМ:\n"
            "  Статус 'Disconnected'    \u2014 Клиент Discord не запущен.\n"
            "  Пустая картинка          \u2014 large_image_key не совпадает\n"
            "                              с именем загруженного ассета.\n"
            "  Старая картинка висит    \u2014 Кеш Discord. Загрузите под НОВЫМ\n"
            "                              именем, см. раздел ИЗОБРАЖЕНИЯ выше.\n"
            "  Кнопка не видна вам     \u2014 Нормально! Другие её видят.\n"
            "  Кнопка не видна никому   \u2014 URL невалиден. Проверьте подсказку.\n"
            "  Таймер отсутствует       \u2014 show_elapsed выключен или mode=hidden.\n"
            "  Изменения не применились \u2014 Нажмите Сохранить в диалоге.\n"
        ),

        "doc_Graph": (
            "СТРАНИЦА ГРАФА\n\n"
            "Интерактивная топологическая карта, показывающая связи:\n"
            "  - Хост (центр, синий)\n"
            "  - Субдомены (голубой)\n"
            "  - Открытые порты (оранжевый)\n"
            "  - Критические пути (красный)\n\n"
            "УПРАВЛЕНИЕ:\n"
            "  Колесо мыши  — приближение/отдаление (0.2x - 5.0x)\n"
            "  ЛКМ + тянем  — панорамирование\n"
            "  Двойной клик — сброс вида\n"
            "  ПКМ          — сброс вида\n\n"
            "УРОВЕНЬ ЗУМА:\n"
            "  Отображается в правом верхнем углу (напр. 150%)\n\n"
            "ЛЕГЕНДА:\n"
            "  В левом нижнем углу\n\n"
            "Граф обновляется при каждом скане.\n"
            "Зум и панорама сбрасываются при новом скане.\n"
        ),
        "doc_Keyboard Shortcuts": (
            "ГОРЯЧИЕ КЛАВИШИ\n\n"
            "  Ctrl+Enter    Начать скан\n"
            "  Escape         Остановить скан\n"
            "  Ctrl+S         Экспорт в JSON\n"
            "  Ctrl+Shift+S   Экспорт в HTML\n"
            "  Ctrl+C         Копировать отчёт (на странице Отчёт)\n\n"
            "НАВИГАЦИЯ:\n"
            "  Нажимайте кнопки сайдбара для переключения страниц.\n"
            "  Активная страница подсвечивается синим.\n\n"
            "УПРАВЛЕНИЕ ГРАФОМ:\n"
            "  Колесо мыши    Зум\n"
            "  Перетаскивание Панорама\n"
            "  Двойной клик   Сброс\n"
        ),

        "doc_Proxy": (
            "НАСТРОЙКА ПРОКСИ\n\n"
            "Маршрутизация всего трафика сканирования через прокси-сервер\n"
            "для анонимности, тестирования по геолокации или обхода\n"
            "сетевых ограничений.\n\n"
            "ПОДДЕРЖИВАЕМЫЕ ТИПЫ ПРОКСИ:\n"
            "  - HTTP    (http://host:port)\n"
            "  - HTTPS   (https://host:port)\n"
            "  - SOCKS5  (socks5://host:port)\n\n"
            "АУТЕНТИФИКАЦИЯ:\n"
            "  - Поддержка имени пользователя и пароля\n"
            "  - Формат: type://user:pass@port\n"
            "  - Анонимные прокси: type://host:port\n\n"
            "КАК ИСПОЛЬЗОВАТЬ:\n"
            "  1. Перейдите на страницу Прокси в сайдбаре\n"
            "  2. Нажмите '+ Добавить прокси'\n"
            "  3. Выберите тип прокси (HTTP, HTTPS или SOCKS5)\n"
            "  4. Введите хост, порт и учётные данные (при необходимости)\n"
            "  5. Нажмите 'Тест соединения' для проверки\n"
            "  6. Нажмите 'Сохранить' для сохранения прокси\n"
            "  7. Включите галочку для активации прокси\n\n"
            "АКТИВНЫЙ ПРОКСИ:\n"
            "  - Одновременно может быть активен только один прокси\n"
            "  - Включение одного прокси отключает все остальные\n"
            "  - Активный прокси отображается в верхней части списка\n"
            "  - Весь трафик сканирования идёт через активный прокси\n\n"
            "ЧТО ИДЁТ ЧЕРЕЗ ПРОКСИ:\n"
            "  - HTTP/HTTPS запросы\n"
            "  - Брутфорс путей\n"
            "  - Сканирование портов (TCP-соединения)\n"
            "  - Запросы к CVE\n"
            "  - Геолокация IP\n"
            "  - Перечисление субдоменов\n"
            "  - Все остальные исходящие запросы\n\n"
            "ХРАНЕНИЕ:\n"
            "  Конфигурации прокси сохраняются в proxies.json\n"
            "  в директории скрипта, сохраняются между сессиями.\n"
        ),
        "doc_Terminal": (
            "КОНСОЛЬ / ТЕРМИНАЛ\n\n"
            "Встроенная консоль позволяет запускать команды не покидая приложение.\n"
            "Доступна на странице Console в сайдбаре.\n"
            "Поддерживает Tab-автодополнение, историю команд (Вверх/Вниз)\n"
            "и фильтрацию через pipe с grep.\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  СКАНИРОВАНИЕ\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  scan <цель>              Начать скан цели\n"
            "                           Принимает домен, IP или URL.\n"
            "                           Примеры:\n"
            "                             scan example.com\n"
            "                             scan 192.168.1.1\n"
            "                             scan https://example.com\n"
            "                             scan  (использует текущее поле)\n\n"
            "  scan-multi <ц1,ц2,...>   Скан нескольких целей последовательно\n"
            "                           Список целей через запятую.\n"
            "                           Пример: scan-multi a.com,b.com,c.com\n\n"
            "  stop                     Остановить текущий скан\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  РЕЗУЛЬТАТЫ\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  show [секция]            Показать результаты последнего скана\n"
            "                           Секция по умолчанию: stats\n\n"
            "  Доступные секции:\n\n"
            "    stats      Обзор: цель, IP, статус, риски, пути,\n"
            "               порты, субдомены, CVE, WAF, CMS, SSL\n"
            "    paths      Найденные пути со статусом HTTP и размером\n"
            "               (до 30, цветовые метки по статусу)\n"
            "    ports      Открытые TCP-порты с названиями сервисов\n"
            "    dns        DNS-записи (A, AAAA, MX, NS, TXT и др.)\n"
            "    headers    Security-заголовки (отсутствующие и имеющиеся)\n"
            "    cve        Найденные CVE с CVSS-оценками\n"
            "    waf        Обнаруженные WAF / файрволлы\n"
            "    subdomains Найденные субдомены\n"
            "    ssl        Срок действия TLS-сертификата, информация о шифре\n"
            "    csp        Анализ Content Security Policy\n"
            "    tech       Обнаруженные технологии и фреймворки\n\n"
            "  Примеры:\n"
            "    show stats\n"
            "    show paths\n"
            "    show cve\n\n"
            "  stats                    Показать полную статистику скана\n"
            "                           (то же, что show stats)\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  ЭКСПОРТ\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  export [json|html|txt]   Экспорт последнего отчёта\n"
            "                           Формат по умолчанию: json\n"
            "                           Сохраняется в: reports/report_<хост>.<формат>\n"
            "                           Примеры:\n"
            "                             export json\n"
            "                             export html\n"
            "                             export txt\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  ФИЛЬТРАЦИЯ\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  grep <паттерн>           Фильтр вывода последней команды\n"
            "                           по текстовому шаблону (без учёта регистра)\n"
            "                           Совпадения подсвечиваются жёлтым.\n\n"
            "  Pipe-оператор            Комбинирует любую команду с grep:\n"
            "                             show paths | grep 200\n"
            "                             show ports | grep 443\n"
            "                             show cve | grep critical\n"
            "                             stats | grep risk\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  СИСТЕМА\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  lang [en|ru]             Переключить язык интерфейса\n"
            "                           Без аргумента: переключает EN/RU\n\n"
            "  proxy <url>              Установить прокси для всех запросов\n"
            "                           Поддерживает HTTP, SOCKS4, SOCKS5.\n"
            "                           Очистить: proxy\n"
            "                           Примеры:\n"
            "                             proxy socks5://127.0.0.1:9050\n"
            "                             proxy http://10.0.0.1:8080\n"
            "                             proxy  (очистить прокси)\n\n"
            "  theme [имя]              Переключить тему интерфейса\n"
            "                           Без аргумента: показывает доступные темы.\n"
            "                           Доступные: neon, cyber, midnight,\n"
            "                                       forest, crimson, light\n\n"
            "  update                   Проверить GitHub на наличие обновлений\n"
            "                           Скачивает и проверяет SHA256-хеш.\n\n"
            "  version                  Показать текущую версию\n\n"
            "  clear                    Очистить вывод консоли\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  УТИЛИТЫ\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  history                  Показать историю команд (последние 50)\n"
            "                           Команды пронумерованы.\n\n"
            "  help                     Показать таблицу справки в консоли\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  ГОРЯЧИЕ КЛАВИШИ\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  Enter ............ Выполнить текущую команду\n"
            "  Вверх / Вниз .... Навигация по истории команд\n"
            "  Tab .............. Автодополнение команды или подпараметра\n"
            "  Ctrl+Enter ....... Начать скан (из любой вкладки)\n"
            "  Escape ........... Остановить запущенный скан\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  ЦВЕТОВАЯ МАРКИРОВКА\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  Синий ............ Эхо команды / информация\n"
            "  Зелёный .......... Успех / активное\n"
            "  Жёлтый .......... Предупреждение / команды\n"
            "  Красный .......... Ошибка / критическое\n"
            "  Голубой .......... Заголовки / ссылки\n"
            "  Фиолетовый ...... Технологии / плагины\n"
            "  Серый ............ Приглушённый / продолжение\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  СОВЕТЫ\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "  - Цель можно задать через поле Target на Дашборде\n"
            "  - Результаты всегда берутся из последнего завершённого скана\n"
            "  - Наберите часть команды и нажмите Tab для автодополнения\n"
            "  - Комбинируйте show + pipe для мощной фильтрации:\n"
            "      show paths | grep 404\n"
            "      show headers | grep Content-Security\n"
            "      show dns | grep MX\n"
        ),
        # ── Hardcoded UI strings (RU) ──
        "stop_btn": "Стоп",
        "log_title": "Живой лог",
        "log_clear": "Очистить",
        "console_title": "Консоль",
        "console_clear": "Очистить",
        "console_run": "Запуск",
        "console_placeholder": "Введите команду...",
        "save_settings": "Сохранить настройки",
        "settings_saved": "Настройки сканирования сохранены",
        "no_ai_data": "Нет данных AI",
        "risk_score_label": "Оценка рисков",
        "status_done": "Готово",
        "status_stopped": "Скан остановлен",
        "status_stopped_short": "Остановлен",
        "status_starting_batch": "Запуск пакета...",
        "status_initializing": "Инициализация...",
        "status_downloading": "Загрузка...",
        "status_checking": "Проверка...",
        "btn_retry": "Повтор",
        "report_no_data": "Нет данных",
        # Phase names
        "phase_subdomains": "Перечисление субдоменов",
        "phase_dns": "Разрешение DNS записей",
        "phase_headers": "Проверка заголовков безопасности",
        "phase_ssl": "Проверка SSL сертификата",
        "phase_paths": "Сканирование путей",
        "phase_ports": "Сканирование портов",
        "phase_sqli": "Тестирование SQL инъекций",
        "phase_xss": "Тестирование XSS",
        "phase_waf": "Обнаружение WAF",
        "phase_cve": "Проверка CVE",
        "phase_cms": "Определение CMS",
        # Dashboard stat labels
        "dash_status": "Статус",
        "dash_paths": "Пути",
        "dash_critical": "Критические",
        "dash_ports": "Порты",
        "dash_waf": "WAF",
        "dash_cves": "CVE",
        "dash_sub": "Суб",
        "dash_errors": "Ошибки",
        # Security page
        "sec_waf_fingerprint": "Отпечаток WAF",
        "sec_rate_cors": "Лимит запросов и CORS",
        "sec_exploit_verified": "Эксплойт проверен",
        # AI Settings dialog
        "ai_account_id": "Account ID",
        "ai_top_p": "Top P",
        "ai_nucleus": "Nucleus сэмплинг",
        "ai_freq_penalty": "Частот. штраф",
        "ai_reduce_repetition": "Снизить повторы",
        "ai_pres_penalty": "Pres штраф",
        "ai_encourage_topics": "Стимулировать новые темы",
        "ai_select_provider_first": "Сначала выберите провайдер",
        "ai_enter_key_first": "Сначала введите API ключ",
        "ai_fetching_models": "Получение моделей...",
        "ai_no_models_returned": "Модели не получены — проверьте API ключ",
        "ai_testing_connection": "Проверка соединения...",
        "ai_select_model_first": "Сначала выберите или получите модель",
        # Custom list dialogs
        "list_template": "Шаблон:",
        "list_quick_add": "Быстрое добавление:",
        "list_sort": "Сортировка",
        "list_dedup": "Убрать дубли",
        "list_export": "Экспорт",
        "list_entries": "записей",
        "list_from_scan": "Из скана",
        # Plugin dialog
        "plugin_no_plugins": "Плагины не найдены\n\nПоместите .py файлы в папку plugins/.",
        "plugin_dir_label": "Папка плагинов",
        # Email/Webhook dialogs
        "email_settings": "Настройки почты",
        "webhook_title": "Уведомления вебхуков",
        "webhook_no_configured": "Вебхуки не настроены.\nНажмите '+ Добавить' для начала.",
        "webhook_new": "Новый вебхук",
        "webhook_name": "Имя",
        "webhook_channel": "Канал",
        # Paths filter
        "paths_filter": "Фильтр",
        # Graph
        "graph_host": "Хост",
        "graph_no_data": "Данные не найдены",
        # Topology
        "topo_subdomains": "Субдомены",
        "topo_ports": "Порты",
        "topo_critical": "Критические",
        # Dialogs & messages
        "quit_title": "Выход",
        "quit_scan_confirm": "Сканирование запущено. Всё равно выйти?",
        "enter_target": "Введите цель",
        "invalid_target": "Неверная цель",
        "invalid_target_msg": "Некорректный домен, IP или URL",
        "batch_info": "Вставлено",
        "batch_targets": "целей",
        "batch_press_scan": "Нажмите SCAN для запуска",
        "error": "Ошибка",
        "import_error": "Ошибка импорта",
        "email_sent": "Отчёт отправлен!",
        "email_error": "Ошибка email",
        "export_saved": "Сохранено в",
        "scan_stopped": "Сканирование остановлено",
        "scan_stopped_user": "Сканирование остановлено пользователем",
        # Update dialog
        "update_checking": "Проверка...",
        "update_available": "ДОСТУПНО ОБНОВЛЕНИЕ",
        "update_install": "УСТАНОВИТЬ",
        "update_later": "ПОТОМ",
        "update_downloading": "Загрузка...",
        "update_retry": "Повторить",
        "update_up_to_date": "Актуальная версия ✓",
        "update_error": "Ошибка обновления",
        # Additional UI labels
        "cvss_scores": "Оценки CVSS",
        "dns_records_page": "DNS записи",
        "subdomains_page": "Субдомены",
        "discovered": "Обнаружено",
        "email_recon": "Email",
        "optional": "необязательно",
        "no_targets_found": "В файле цели не найдены",
        "plugins_label": "Плагины",
        "dsl_rules_saved": "DSL правила сохранены",
        "api_key": "API ключ",
        "cloudflare_only": "Только Cloudflare",
        "ai_disabled": "AI: выключен",
        "on_off": "Вкл/Выкл",
        "webhook_example": "напр. Мой Telegram",
        "tab_connection": "Подключение",
        "tab_presence": "Присутствие",
        "tab_images_timer": "Изображения и таймер",
        "connected": "Подключено",
        "export_title": "Экспорт",
        "batch_title": "Пакет",
        "email_title": "Email",
        # Console strings
        "console_version": "SC Checker Консоль",
        "console_help_hint": "Введите 'help' для списка команд.",
        "console_commands": "Команды:",
        "console_help_scan": "начать скан цели",
        "console_help_scanmulti": "скан нескольких целей (через запятую)",
        "console_help_stop": "остановить текущий скан",
        "console_help_export": "экспорт последнего отчёта",
        "console_help_show": "показать результаты",
        "console_help_stats": "показать статистику скана",
        "console_help_clear": "очистить консоль",
        "console_help_lang": "переключить язык",
        "console_help_proxy": "установить прокси",
        "console_help_update": "проверить обновления",
        "console_help_version": "показать версию",
        "console_no_target": "Цель не указана.",
        "console_starting_scan": "Запуск скана",
        "console_usage_scanmulti": "Использование: scan-multi host1,host2,host3",
        "console_starting_batch": "Запуск пакетного скана",
        "console_scan_stopped": "Скан остановлен.",
        "console_no_scan_running": "Скан не запущен.",
        "console_no_report_export": "Нет отчёта для экспорта. Сначала запустите скан.",
        "console_no_report": "Нет отчёта. Сначала запустите скан.",
        "console_exported": "Экспортировано в",
        "console_no_waf": "WAF не обнаружен.",
        "console_unknown_section": "Неизвестная секция",
        "console_use_sections": "Используйте: paths|ports|dns|headers|cve|waf",
        "console_stats_title": "=== Статистика скана ===",
        "console_target": "Цель",
        "console_ip": "IP",
        "console_status": "Статус",
        "console_risk": "Риск",
        "console_duration": "Длительность",
        "console_paths": "Пути",
        "console_ports": "Порты",
        "console_open": "открыто",
        "console_subdomains": "Субдомены",
        "console_cves": "CVE",
        "console_waf": "WAF",
        "console_none": "Нет",
        "console_unknown": "Неизвестно",
        "console_days": "дн.",
        "console_errors": "Ошибки",
        "console_lang_set": "Язык изменён на",
        "console_usage_lang": "Использование: lang [en|ru]",
        "console_proxy_set": "Прокси установлен:",
        "console_checking_updates": "Проверка обновлений...",
        "console_update_error": "Ошибка проверки обновлений:",
        "console_update_available": "Доступно обновление:",
        "console_no_update": "Нет обновлений. Текущая:",
        "console_type_help": "Введите 'help' для списка команд.",
        "console_unknown_command": "Неизвестная команда:",
        # Discord hints
        "discord_party_hint": "Показывает 'X из Y' в Discord при пакетном скане",
        "discord_countdown_hint": "Показывать таймер обратного отсчёта при скане",
        "discord_show_party": "Показывать прогресс пакета (3/10)",
        "discord_show_countdown": "Показывать таймер обратного отсчёта при скане",
        "discord_countdown_dur": "Длительность отсчёта",
        "discord_countdown_hint2": "Формат: секунды (300) или ММ:СС (05:00) — сброс каждую фазу",
        "discord_button2_label": "Метка кнопки 2",
        "discord_button2_url": "URL кнопки 2",
        "discord_button2_hint": "Discord допускает до 2 кнопок — необязательная вторая кнопка",
        "discord_button2_url_hint": "Необязательно — напр. https://github.com/your-repo",
        "discord_idle_hint": "Играет в игру",
        # Discord Profiles
        "discord_profiles_title": "Профили",
        "discord_active_profile": "Активный:",
        "discord_no_profile": "Нет профиля",
        "discord_no_profile_selected": "Профиль не выбран",
        "discord_profile_switching": "Переключение...",
        "discord_profile_switched": "Переключено на: {name}",
        "discord_profile_error": "Ошибка переключения профиля",
        "discord_switch_btn": "Переключить",
        "discord_create_profile_title": "Создать новый профиль",
        "discord_profile_name_label": "Имя профиля:",
        "discord_profile_name_hint": "напр. Работа, Игры, Кастомный",
        "discord_profile_exists": "Профиль уже существует",
        "discord_profile_created": "Профиль создан: {name}",
        "discord_create_btn": "Создать",
        "discord_save_profile_title": "Сохранить текущие настройки как профиль",
        "discord_profile_saved": "Профиль сохранен: {name}",
        "discord_save_profile_btn": "Сохранить как",
        "discord_delete_confirm_title": "Подтверждение удаления",
        "discord_delete_confirm_msg": "Удалить профиль '{name}'?",
        "discord_delete_warning": "Это действие нельзя отменить.",
        "discord_profile_deleted": "Профиль удален: {name}",
        "discord_delete_btn": "Удалить",
        "dialog_create": "Создать",
        "dialog_delete": "Удалить",
    },
}
