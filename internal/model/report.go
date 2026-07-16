package model

type Report struct {
	GeneratedAt            string              `json:"generated_at"`
	Target                 string              `json:"target"`
	NormalizedURL          string              `json:"normalized_url"`
	Host                   string              `json:"host"`
	IP                     string              `json:"ip"`
	Scheme                 string              `json:"scheme"`
	Port                   int                 `json:"port"`
	StatusCode             int                 `json:"status_code"`
	FinalURL               string              `json:"final_url"`
	ResponseTimeMs         int                 `json:"response_time_ms"`
	RiskScore              int                 `json:"risk_score"`
	RiskLevel              string              `json:"risk_level"`
	Headers                map[string]string   `json:"headers"`
	MissingSecurityHeaders []string            `json:"missing_security_headers"`
	FingerprintHints       []string            `json:"fingerprint_hints"`
	AllowedMethods         []string            `json:"allowed_methods"`
	TraceEnabled           bool                `json:"trace_enabled"`
	RobotsEntries          []string            `json:"robots_entries"`
	SitemapEntries         []string            `json:"sitemap_entries"`
	TLSSummary             map[string]string   `json:"tls_summary"`
	DiscoveredPaths        []PathItem          `json:"discovered_paths"`
	CriticalPaths          []string            `json:"critical_paths"`
	AnomalyHints           []string            `json:"anomaly_hints"`
	OpenPorts              []int               `json:"open_ports"`
	PortBanners            map[string]string   `json:"port_banners"`
	CookieIssues           []string            `json:"cookie_issues"`
	CookiesFound           []string            `json:"cookies_found"`
	CORSIssues             []string            `json:"cors_issues"`
	HSTSEnabled            bool                `json:"hsts_enabled"`
	HTTPToHTTPSRedirect    bool                `json:"http_to_https_redirect"`
	SSLExpiryDays          int                 `json:"ssl_expiry_days"`
	SSLExpiryDate          string              `json:"ssl_expiry_date"`
	SSLWeakCipher          bool                `json:"ssl_weak_cipher"`
	DNSRecords             map[string][]string `json:"dns_records"`
	VersionHints           []VersionHint       `json:"version_hints"`
	RateLimitHeaders       map[string]string   `json:"rate_limit_headers"`
	ClickjackingProtected  bool                `json:"clickjacking_protected"`
	DirectoryListing       []string            `json:"directory_listing"`
	MixedContent           bool                `json:"mixed_content"`
	XSSReflection          bool                `json:"xss_reflection"`
	SQLErrors              []string            `json:"sql_errors"`
	DetectedCMS            []string            `json:"detected_cms"`
	DetectedFrameworks     []string            `json:"detected_frameworks"`
	Subdomains             []string            `json:"subdomains"`
	TotalPathsScanned      int                 `json:"total_paths_scanned"`
	ScanDurationMs         int                 `json:"scan_duration_ms"`
	WAFDetected            []string            `json:"waf_detected"`
	CVEFindings            []CVEFinding        `json:"cve_findings"`
	ProxyUsed              string              `json:"proxy_used"`
	SSLDeep                map[string]any      `json:"ssl_deep"`
	HTTPMethodsFull        []MethodResult      `json:"http_methods_full"`
	SecurityTxt            string              `json:"security_txt"`
	PermissionsPolicy      string              `json:"permissions_policy"`
	CSPAnalysis            string              `json:"csp_analysis"`
	ReferrerPolicy         string              `json:"referrer_policy"`
	TTFBMs                 int                 `json:"ttfb_ms"`
	ContentSize            int                 `json:"content_size"`
	ContentEncoding        string              `json:"content_encoding"`
	RedirectChain          []RedirectEntry     `json:"redirect_chain"`
	EmailsFound            []string            `json:"emails_found"`
	PhonesFound            []string            `json:"phones_found"`
	SocialLinks            []string            `json:"social_links"`
	MetaTags               []MetaTag           `json:"meta_tags"`
	HiddenForms            []HiddenForm        `json:"hidden_forms"`
	ExternalLinks          []string            `json:"external_links"`
	JSLibraries            []string            `json:"js_libraries"`
	ServerBanner           string              `json:"server_banner"`
	IPGeo                  map[string]any      `json:"ip_geo"`
	ASNInfo                map[string]any      `json:"asn_info"`
	ReverseDNS             string              `json:"reverse_dns"`
	HostHeaderInject       string              `json:"host_header_inject"`
	CRLFInjection          []string            `json:"crlf_injection"`
	OpenRedirect           []string            `json:"open_redirect"`
	DirTraversal           []string            `json:"dir_traversal"`
	BackupFiles            []string            `json:"backup_files"`
	SourceLeak             []string            `json:"source_leak"`
	AdminPanels            []string            `json:"admin_panels"`
	LoginPages             []string            `json:"login_pages"`
	APIEndpoints           []string            `json:"api_endpoints"`
	MutatedPayloads        []MutationResult    `json:"mutated_payloads"`
	SupplyChain            []SupplyItem        `json:"supply_chain"`
	GraphQLSchema          map[string]any      `json:"graphql_schema"`
	GraphQLVulns           []GraphQLVuln       `json:"graphql_vulns"`
	WebSocketResults       []WSTestResult      `json:"websocket_results"`
	SessionIssues          []string            `json:"session_issues"`
	ChaosFindings          []ChaosFinding      `json:"chaos_findings"`
	DSLResults             []DSLResult         `json:"dsl_results"`
	JWTTokens              []JWTToken          `json:"jwt_tokens"`
	SSTIResults            []SSTIFinding       `json:"ssti_results"`
	ZoneTransfer           []ZoneFinding       `json:"zone_transfer"`
	SubdomainTakeover      []TakeoverFinding   `json:"subdomain_takeover"`
	EmailSecurity          EmailSecurity       `json:"email_security"`
	HTTPSmuggling          []SmugglingResult   `json:"http_smuggling"`
	TechStackDeep          []TechItem          `json:"tech_stack_deep"`
	HiddenEndpoints        []EndpointItem      `json:"hidden_endpoints"`
	WAFFingerprint         WAFFingerprint      `json:"waf_fingerprint"`
	RateLimit              RateLimitInfo       `json:"rate_limit"`
	CORSDeep               []CORSDeepResult    `json:"cors_deep"`
	CVSSScores             []CVSSScore         `json:"cvss_scores"`
	ExploitVerified        []VerifiedExploit   `json:"exploit_verified"`
	JSAnalysis             JSAnalysisResult    `json:"js_analysis"`
	Shodan                 ShodanResult        `json:"shodan"`
	CTLogs                 []CTLogEntry        `json:"ct_logs"`
	Whois                  WhoisResult         `json:"whois"`
	Screenshots            []ScreenshotItem    `json:"screenshots"`
	ScanErrors             []string            `json:"scan_errors"`
	ServerNode             bool                `json:"server_node"`
	NoHTTP                 bool                `json:"no_http"`
	AlternativeHTTPPorts   []int               `json:"alternative_http_ports"`
	PluginGraphNodes       []any               `json:"plugin_graph_nodes"`
}

type PathItem struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Size   int    `json:"size"`
}

type VersionHint struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CVEFinding struct {
	Product          string  `json:"product"`
	Version          string  `json:"version"`
	CVE              string  `json:"cve"`
	Score            float64 `json:"score"`
	Severity         string  `json:"severity"`
	Desc             string  `json:"desc"`
	CWE              string  `json:"cwe"`
	CISAKnownExploited bool  `json:"cisa_known_exploited"`
	EPSS             float64 `json:"epss"`
	ExploitAvailable bool   `json:"exploit_available"`
	ExploitLinks     []string `json:"exploit_links,omitempty"`
}

type MethodResult struct {
	Method  string `json:"method"`
	Status  int    `json:"status"`
	Allowed bool   `json:"allowed"`
}

type RedirectEntry struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Final  bool   `json:"final,omitempty"`
}

type MetaTag struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type HiddenForm struct {
	Action       string `json:"action"`
	Method       string `json:"method"`
	HiddenInputs int    `json:"hidden_inputs"`
}

type MutationResult struct {
	Original string `json:"original"`
	Mutated  string `json:"mutated"`
	Status   int    `json:"status"`
	Len      int    `json:"len"`
	Verdict  string `json:"verdict"`
}

type SupplyItem struct {
	URL         string   `json:"url"`
	Issues      []string `json:"issues"`
	CDN         string   `json:"cdn,omitempty"`
	Status      int      `json:"status,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
}

type GraphQLVuln struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
	Detail   string `json:"detail"`
}

type WSTestResult struct {
	URL       string        `json:"url"`
	Connected bool          `json:"connected"`
	Tests     []WSTestEntry `json:"tests"`
}

type WSTestEntry struct {
	Type     string `json:"type"`
	Payload  string `json:"payload,omitempty"`
	Severity string `json:"severity"`
	Detail   string `json:"detail,omitempty"`
}

type ChaosFinding struct {
	Type     string `json:"type"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
	Preview  string `json:"preview,omitempty"`
}

type DSLResult struct {
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
	Condition string `json:"condition,omitempty"`
}

type JWTToken struct {
	Token          string            `json:"token"`
	Source         string            `json:"source"`
	Algorithm      string            `json:"algorithm"`
	Header         map[string]any    `json:"header"`
	PayloadPreview map[string]string `json:"payload_preview"`
	Issues         []string          `json:"issues"`
	Severity       string            `json:"severity"`
}

type SSTIFinding struct {
	Payload  string `json:"payload"`
	Engine   string `json:"engine"`
	Method   string `json:"method,omitempty"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type ZoneFinding struct {
	Server   string   `json:"server"`
	Severity string   `json:"severity"`
	Detail   string   `json:"detail"`
	Records  []string `json:"records"`
}

type TakeoverFinding struct {
	Subdomain string `json:"subdomain"`
	Service   string `json:"service"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
}

type EmailSecurity struct {
	SPF    string   `json:"spf"`
	DMARC  string   `json:"dmarc"`
	DKIM   string   `json:"dkim"`
	Issues []string `json:"issues"`
}

type SmugglingResult struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type TechItem struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

type EndpointItem struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Size     int    `json:"size"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type WAFFingerprint struct {
	Detected bool     `json:"detected"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Rules    []string `json:"rules"`
}

type RateLimitInfo struct {
	Detected  bool              `json:"detected"`
	Limit     int               `json:"limit"`
	Remaining int               `json:"remaining"`
	Reset     string            `json:"reset"`
	Headers   map[string]string `json:"headers"`
	Note      string            `json:"note,omitempty"`
}

type CORSDeepResult struct {
	Test       string `json:"test"`
	Vulnerable bool   `json:"vulnerable"`
	ACAO       string `json:"acao"`
	ACAC       string `json:"acac"`
	Detail     string `json:"detail"`
	Severity   string `json:"severity"`
}

type CVSSScore struct {
	Finding  string  `json:"finding"`
	Severity string  `json:"severity"`
	CVSS     float64 `json:"cvss"`
}

type VerifiedExploit struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Detail   string `json:"detail"`
}

type JSAnalysisResult struct {
	Scripts    []string   `json:"scripts"`
	Endpoints  []string   `json:"endpoints"`
	Secrets    []JSSecret `json:"secrets"`
	Libs       []string   `json:"libs"`
	SRIMissing int        `json:"sri_missing"`
}

type JSSecret struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

type ShodanResult struct {
	IP    string   `json:"ip"`
	Ports []int    `json:"ports"`
	OS    string   `json:"os"`
	Org   string   `json:"org"`
	Vulns []string `json:"vulns"`
}

type CTLogEntry struct {
	Name      string `json:"name"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
}

type WhoisResult struct {
	Registrar   string `json:"registrar"`
	Created     string `json:"created"`
	Expires     string `json:"expires"`
	NameServers string `json:"name_servers"`
	Raw         string `json:"raw"`
}

type ScreenshotItem struct {
	URL      string `json:"url,omitempty"`
	Path     string `json:"path,omitempty"`
	Filename string `json:"filename,omitempty"`
	Error    string `json:"error,omitempty"`
}
