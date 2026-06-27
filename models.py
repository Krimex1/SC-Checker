from dataclasses import dataclass, field


@dataclass(slots=True)
class Report:
    generated_at: str = ""
    target: str = ""
    normalized_url: str = ""
    host: str = ""
    ip: str = ""
    scheme: str = ""
    port: int = 0
    status_code: int | None = None
    final_url: str = ""
    response_time_ms: int | None = None
    risk_score: int = 0
    risk_level: str = "unknown"
    headers: dict = field(default_factory=dict)
    missing_security_headers: list = field(default_factory=list)
    fingerprint_hints: list = field(default_factory=list)
    allowed_methods: list = field(default_factory=list)
    trace_enabled: bool = False
    robots_entries: list = field(default_factory=list)
    sitemap_entries: list = field(default_factory=list)
    tls_summary: dict = field(default_factory=dict)
    discovered_paths: list = field(default_factory=list)
    critical_paths: list = field(default_factory=list)
    anomaly_hints: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    port_banners: dict = field(default_factory=dict)
    cookie_issues: list = field(default_factory=list)
    cookies_found: list = field(default_factory=list)  # names of cookies actually seen (incl. from redirects/Set-Cookie)
    cors_issues: list = field(default_factory=list)
    hsts_enabled: bool = False
    http_to_https_redirect: bool = False
    ssl_expiry_days: int | None = None
    ssl_expiry_date: str = ""
    ssl_weak_cipher: bool = False
    dns_records: dict = field(default_factory=dict)
    version_hints: list = field(default_factory=list)
    rate_limit_headers: dict = field(default_factory=dict)
    clickjacking_protected: bool = False
    directory_listing: list = field(default_factory=list)
    mixed_content: bool = False
    xss_reflection: bool = False
    sql_errors: list = field(default_factory=list)
    detected_cms: list = field(default_factory=list)
    detected_frameworks: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    total_paths_scanned: int = 0
    scan_duration_ms: int = 0
    waf_detected: list = field(default_factory=list)
    cve_findings: list = field(default_factory=list)
    proxy_used: str = ""
    ssl_deep: dict = field(default_factory=dict)
    http_methods_full: list = field(default_factory=list)
    security_txt: str = ""
    permissions_policy: str = ""
    csp_analysis: str = ""
    expect_ct: str = ""
    referrer_policy: str = ""
    x_permitted_cross: str = ""
    ttfb_ms: int | None = None
    content_size: int = 0
    content_encoding: str = ""
    redirect_chain: list = field(default_factory=list)
    emails_found: list = field(default_factory=list)
    phones_found: list = field(default_factory=list)
    social_links: list = field(default_factory=list)
    meta_tags: list = field(default_factory=list)
    hidden_forms: list = field(default_factory=list)
    external_links: list = field(default_factory=list)
    js_libraries: list = field(default_factory=list)
    server_banner: str = ""
    ip_geo: dict = field(default_factory=dict)
    asn_info: dict = field(default_factory=dict)
    reverse_dns: str = ""
    host_header_inject: str = ""
    crlf_injection: list = field(default_factory=list)
    open_redirect: list = field(default_factory=list)
    dir_traversal: list = field(default_factory=list)
    backup_files: list = field(default_factory=list)
    source_leak: list = field(default_factory=list)
    admin_panels: list = field(default_factory=list)
    login_pages: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)
    mutated_payloads: list = field(default_factory=list)
    supply_chain: list = field(default_factory=list)
    graphql_schema: dict = field(default_factory=dict)
    graphql_vulns: list = field(default_factory=list)
    websocket_results: list = field(default_factory=list)
    session_issues: list = field(default_factory=list)
    chaos_findings: list = field(default_factory=list)
    dsl_results: list = field(default_factory=list)
    ai_findings: list = field(default_factory=list)
    jwt_tokens: list = field(default_factory=list)
    ssti_results: list = field(default_factory=list)
    zone_transfer: list = field(default_factory=list)
    subdomain_takeover: list = field(default_factory=list)
    email_security: dict = field(default_factory=dict)
    http_smuggling: list = field(default_factory=list)
    tech_stack_deep: list = field(default_factory=list)
    hidden_endpoints: list = field(default_factory=list)
    # New security
    waf_fingerprint: dict = field(default_factory=dict)
    rate_limit: dict = field(default_factory=dict)
    cors_deep: list = field(default_factory=list)
    cvss_scores: list = field(default_factory=list)
    exploit_verified: list = field(default_factory=list)
    # New recon
    js_analysis: dict = field(default_factory=dict)
    shodan: dict = field(default_factory=dict)
    ct_logs: list = field(default_factory=list)
    whois: dict = field(default_factory=dict)
    screenshots: list = field(default_factory=list)
    scan_errors: list = field(default_factory=list)
    # Server node detection
    server_node: bool = False
    no_http: bool = False
    alternative_http_ports: list = field(default_factory=list)
    # Plugin-contributed graph nodes
    plugin_graph_nodes: list = field(default_factory=list)
