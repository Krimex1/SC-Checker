package engine

import (
	"fmt"
	"net"
	"sc-checker-go/internal/config"
	"sc-checker-go/internal/model"
	"sc-checker-go/internal/plugin"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	client       *ConcurrentClient
	singleClient *HTTPClient
	proxy        string
	timeout      int
	verifySSL    bool
	customPaths  []string
	stopCh       chan struct{}
	mu           sync.Mutex
	LogFn        func(string)
	ProgressFn   func(float64)
	plugins      *plugin.Manager
}

func NewEngine(proxy string, timeout int, verifySSL bool, customPaths []string) (*Engine, error) {
	poolSize := config.MaxConcurrentRequests
	cc, err := NewConcurrentClient(proxy, timeout, poolSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client pool: %w", err)
	}

	single, _ := NewHTTPClient(proxy, timeout*2)

	return &Engine{
		client:       cc,
		singleClient: single,
		proxy:        proxy,
		timeout:      timeout,
		verifySSL:    verifySSL,
		customPaths:  customPaths,
		stopCh:       make(chan struct{}),
	}, nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	select {
	case <-e.stopCh:
	default:
		close(e.stopCh)
	}
}

func (e *Engine) Close() {
	e.client.Close()
	e.singleClient.Close()
}

func (e *Engine) SetPlugins(pm *plugin.Manager) {
	e.plugins = pm
	if agents := e.getCustomUserAgents(); len(agents) > 0 {
		e.client.SetUserAgents(agents)
		if e.singleClient != nil {
			e.singleClient.SetUserAgents(agents)
		}
	}
	e.client.SetHookFn(func(hook string, data map[string]any) {
		if e.plugins != nil {
			e.plugins.FireHookWithData(hook, nil, data)
		}
	})
	if e.singleClient != nil {
		e.singleClient.HookFn = func(hook string, data map[string]any) {
			if e.plugins != nil {
				e.plugins.FireHookWithData(hook, nil, data)
			}
		}
	}
}

func (e *Engine) log(msg string) {
	if e.LogFn != nil {
		e.LogFn(msg)
	}
}

func (e *Engine) progress(v float64) {
	if e.ProgressFn != nil {
		e.ProgressFn(v)
	}
}

func (e *Engine) Run(target string) (r *model.Report) {
	startTime := time.Now()

	defer func() {
		if rec := recover(); rec != nil {
			e.log(fmt.Sprintf("PANIC: %v", rec))
			if r == nil {
				r = &model.Report{Target: target, RiskLevel: "error"}
			}
			r.ScanErrors = append(r.ScanErrors, fmt.Sprintf("Internal error: %v", rec))
		}
	}()

	r = &model.Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Target:      target,
		ProxyUsed:   e.proxy,
	}

	if e.plugins != nil {
		e.plugins.FireHook("on_scan_start", r)
	}

	e.log(fmt.Sprintf("Normalizing %s...", target))
	var err error
	r.NormalizedURL, r.Scheme, r.Host, r.Port, err = NormalizeTarget(target)
	if err != nil {
		r.ScanErrors = append(r.ScanErrors, err.Error())
		return r
	}

	isIP := net.ParseIP(target) != nil

	e.log(fmt.Sprintf("Resolving %s...", r.Host))
	if !isIP {
		r.IP, err = ResolveIP(r.Host)
		if err != nil {
			r.IP = r.Host
		}
	} else {
		r.IP = target
	}

	if e.plugins != nil {
		e.plugins.FireHook("on_after_dns", r)
	}

	e.log("Checking connectivity...")
	port, scheme, connected := ProbeConnectivity(r.Host, r.Port, e.stopCh)
	if !connected {
		e.log("No TCP ports reachable — server node mode")
		r.NoHTTP = true
		r.ServerNode = true
	} else if port != r.Port || scheme != r.Scheme {
		r.Port = port
		r.Scheme = scheme
		r.NormalizedURL = BaseURL(scheme, r.Host, port)
		e.log(fmt.Sprintf("Connected on port %d (%s)", port, scheme))
	}

	if e.isStopped() {
		return r
	}

	if isIP || r.ServerNode {
		return e.runIPScan(r, startTime)
	}

	base := BaseURL(r.Scheme, r.Host, r.Port)
	e.log("Probing root...")

	resp, elapsed, err := e.singleClient.Get(r.NormalizedURL, nil)
	if err == nil && resp != nil {
		r.ResponseTimeMs = int(elapsed.Milliseconds())
		r.StatusCode = resp.StatusCode
		r.FinalURL = resp.Request.URL.String()
	}

	if resp == nil && !r.ServerNode {
		e.log("No HTTP response — trying alternative ports...")
		r.NoHTTP = true
		altFound := ProbeAltPorts(r.Host, e.stopCh)
		if len(altFound) > 0 {
			best := altFound[0]
			for _, a := range altFound {
				r.AlternativeHTTPPorts = append(r.AlternativeHTTPPorts, a.Port)
			}
			r.Port = best.Port
			r.Scheme = best.Scheme
			r.NormalizedURL = best.URL
			base = BaseURL(r.Scheme, r.Host, r.Port)
			resp, elapsed, err = e.singleClient.Get(r.NormalizedURL, nil)
			if err == nil && resp != nil {
				r.ResponseTimeMs = int(elapsed.Milliseconds())
				r.StatusCode = resp.StatusCode
				r.FinalURL = resp.Request.URL.String()
				r.ServerNode = false
			}
		} else {
			r.ServerNode = true
		}
	}

	if e.isStopped() {
		return r
	}

	r.Headers = CollectHeaders(resp)
	if e.plugins != nil {
		e.plugins.FireHook("on_after_headers", r)
	}
	e.progress(0.12)

	var body string
	if resp != nil {
		bodyBuf := make([]byte, 100000)
		n, _ := resp.Body.Read(bodyBuf)
		body = string(bodyBuf[:n])
	}

	e.log("Running security checks...")

	r.MissingSecurityHeaders = MissingHeaders(r.Headers)
	r.FingerprintHints = FingerprintTech(r.Headers)
	r.CookieIssues, r.CookiesFound = CheckCookies(resp)
	r.HSTSEnabled = CheckHSTS(r.Headers, resp, r.Host)
	r.ClickjackingProtected = CheckClickjacking(r.Headers)
	r.WAFDetected = DetectWAF(resp)
	cmsHints, detectedCMS, detectedFrameworks := DetectCMS(resp, body)
	r.DetectedCMS = detectedCMS
	r.DetectedFrameworks = detectedFrameworks
	for _, h := range cmsHints {
		r.VersionHints = append(r.VersionHints, model.VersionHint{Name: "hint", Version: h})
	}
	r.MixedContent = CheckMixedContent(resp)
	r.DirectoryListing = CheckDirectoryListing(body)

	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		r.AllowedMethods, r.TraceEnabled = ProbeMethods(r.NormalizedURL, e.singleClient)
	}()
	go func() { defer wg.Done(); r.CORSIssues = CheckCORS(r.NormalizedURL, e.singleClient) }()
	go func() { defer wg.Done(); r.HTTPToHTTPSRedirect = CheckHTTPToHTTPS(r.Host, r.Port, e.singleClient) }()
	go func() { defer wg.Done(); r.XSSReflection = CheckXSS(r.NormalizedURL, e.singleClient) }()
	go func() { defer wg.Done(); r.SQLErrors = CheckSQLErrors(r.NormalizedURL, e.singleClient) }()
	wg.Wait()

	e.progress(0.22)

	sslResult := SSLCheck(r.Host, r.Port, config.FastTimeout)
	if sslResult.Error == "" {
		r.SSLExpiryDays = sslResult.ExpiryDays
		r.SSLExpiryDate = sslResult.ExpiryDate
		r.SSLWeakCipher = sslResult.WeakCipher
		r.TLSSummary = map[string]string{
			"version": sslResult.Version,
			"cipher":  sslResult.Cipher,
		}
		r.SSLDeep = sslResult.Deep
	}
	if e.plugins != nil {
		e.plugins.FireHook("on_after_ssl", r)
	}

	versions := DetectVersions(resp, body)
	r.VersionHints = append(r.VersionHints, versions...)

	if e.isStopped() {
		return r
	}

	e.log("DNS & recon checks...")
	wg2 := sync.WaitGroup{}
	wg2.Add(5)
	go func() { defer wg2.Done(); r.DNSRecords = CheckDNSRecords(r.Host) }()
	go func() { defer wg2.Done(); r.Subdomains = CheckSubdomains(r.Host, e.getCustomSubdomains(), e.stopCh) }()
	go func() { defer wg2.Done(); r.ReverseDNS = ReverseDNS(r.IP) }()
	go func() { defer wg2.Done(); r.ZoneTransfer = ZoneTransfer(r.Host) }()
	go func() {
		defer wg2.Done()
		if respR, _, err := e.singleClient.Get(base+"/robots.txt", nil); err == nil && respR != nil && respR.StatusCode == 200 {
			buf := make([]byte, 8192)
			n, _ := respR.Body.Read(buf)
			for _, line := range strings.Split(string(buf[:n]), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") &&
					(strings.HasPrefix(line, "Allow:") || strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Sitemap:")) {
					r.RobotsEntries = append(r.RobotsEntries, line)
				}
			}
		}
		if respSM, _, smErr := e.singleClient.Get(base+"/sitemap.xml", nil); smErr == nil && respSM != nil && respSM.StatusCode == 200 {
			buf := make([]byte, 32768)
			n, _ := respSM.Body.Read(buf)
			for _, line := range strings.Split(string(buf[:n]), "\n") {
				if strings.Contains(strings.ToLower(line), "<loc>") {
					r.SitemapEntries = append(r.SitemapEntries, strings.TrimSpace(line))
				}
			}
		}
	}()
	wg2.Wait()

	e.progress(0.35)

	e.log("Port scan...")
	customPorts := e.getCustomPorts()
	r.OpenPorts = ScanPorts(r.IP, customPorts, e.stopCh)
	if e.plugins != nil {
		e.plugins.FireHook("on_after_ports", r)
	}
	e.progress(0.45)

	e.log("Path brute-force...")
	allPaths := collectPaths(e.customPaths, e.getCustomWordlist())
	r.DiscoveredPaths, r.CriticalPaths = ScanPaths(base, allPaths, e.client, e.stopCh)
	r.TotalPathsScanned = len(allPaths)
	e.progress(0.55)

	if e.plugins != nil {
		e.plugins.FireHook("on_after_paths", r)
	}

	emails, phones, social, external := ExtractRecon(body, r.Host)
	r.EmailsFound = emails
	r.PhonesFound = phones
	r.SocialLinks = social
	r.ExternalLinks = external
	r.JSLibraries = JSLibrariesDetect(body)
	e.progress(0.60)

	wg3 := sync.WaitGroup{}
	checks := []func(){
		func() { r.HostHeaderInject = CheckHostHeaderInjection(r.NormalizedURL, e.singleClient) },
		func() { r.CRLFInjection = CheckCRLF(r.NormalizedURL, e.singleClient) },
		func() { r.OpenRedirect = CheckOpenRedirect(r.NormalizedURL, e.singleClient) },
		func() { r.DirTraversal = CheckDirTraversal(r.NormalizedURL, e.singleClient) },
		func() { r.BackupFiles = CheckBackupFiles(r.NormalizedURL, e.singleClient) },
		func() { r.SourceLeak = CheckSourceLeak(r.NormalizedURL, e.singleClient) },
		func() { r.AdminPanels = CheckAdminPanels(r.NormalizedURL, e.singleClient) },
		func() { r.LoginPages = CheckLoginPages(r.NormalizedURL, e.singleClient) },
		func() { r.APIEndpoints = CheckAPIEndpoints(r.NormalizedURL, body, e.singleClient) },
		func() { r.SSTIResults = CheckSSTI(r.NormalizedURL, e.singleClient) },
		func() { r.MutatedPayloads = PayloadMutation(body, base, e.singleClient) },
		func() { r.ExploitVerified = VerifyExploits(r, e.singleClient) },
		func() { r.HTTPMethodsFull = httpMethodsFull(r.NormalizedURL, e.singleClient) },
	}
	wg3.Add(len(checks))
	for _, fn := range checks {
		go func(f func()) { defer wg3.Done(); safeDo(e, "inj-check", f) }(fn)
	}
	wg3.Wait()
	e.progress(0.72)

	r.SecurityTxt = checkSecurityTxt(base, e.singleClient)
	csp := r.Headers["Content-Security-Policy"]
	if csp == "" {
		csp = r.Headers["content-security-policy"]
	}
	r.CSPAnalysis = AnalyzeCSP(csp)
	r.PermissionsPolicy = r.Headers["Permissions-Policy"]
	if r.PermissionsPolicy == "" {
		r.PermissionsPolicy = r.Headers["permissions-policy"]
	}
	r.ReferrerPolicy = r.Headers["Referrer-Policy"]
	if r.ReferrerPolicy == "" {
		r.ReferrerPolicy = r.Headers["referrer-policy"]
	}

	r.TTFBMs, r.ContentSize, r.ContentEncoding = MeasurePerf(r.NormalizedURL, e.singleClient)
	r.RedirectChain = TraceRedirects(r.NormalizedURL, e.singleClient)

	r.ServerBanner = r.Headers["Server"]
	if r.ServerBanner == "" {
		r.ServerBanner = r.Headers["server"]
	}

	e.log("Advanced checks...")
	advChecks := []func(){
		func() { r.JWTTokens = JWTScan(r.Headers, body, e.singleClient) },
		func() { r.GraphQLSchema, r.GraphQLVulns = GraphQLScan(base, e.singleClient) },
		func() { r.SupplyChain = SupplyChainAnalyze(body, r.Host, e.singleClient) },
		func() { r.WebSocketResults = WebSocketAnalyze(base, body) },
		func() { r.HiddenEndpoints = HiddenEndpoints(base, body, e.singleClient) },
		func() { r.RateLimit = RateLimitDetect(r.NormalizedURL, e.singleClient) },
		func() { r.CORSDeep = CORSDeepTest(r.NormalizedURL, e.singleClient) },
		func() { r.WAFFingerprint = WAFFingerprintDeep(r, body) },
		func() { r.JSAnalysis = JSAnalysis(body, e.singleClient) },
		func() { r.HTTPSmuggling = HTTPSmugglingCheck(base, e.singleClient) },
		func() { r.SessionIssues = SessionManipulation(base, e.singleClient) },
		func() { r.TechStackDeep = TechStackDeep(r, e.singleClient) },
		func() { r.EmailSecurity = EmailSecurityCheck(r.Host) },
		func() { r.SubdomainTakeover = SubdomainTakeoverCheck(r.Subdomains, e.singleClient) },
		func() { r.ChaosFindings = ChaosScan(base, e.singleClient) },
		func() { r.CVEFindings = CVELookup(r.VersionHints) },
	}
	wg4 := sync.WaitGroup{}
	wg4.Add(len(advChecks))
	for _, fn := range advChecks {
		go func(f func()) { defer wg4.Done(); safeDo(e, "adv", f) }(fn)
	}
	wg4.Wait()
	e.progress(0.88)

	r.MetaTags = extractMetaTags(body)
	r.HiddenForms = extractForms(body)

	r.DSLResults = DSLv2Evaluate(r)
	r.CVSSScores = CVSSScoring(r)
	safeDo(e, "DSLv1", func() { r.DSLResults = append(r.DSLResults, DSLScan(r)...) })

	e.log("Recon...")
	wg5 := sync.WaitGroup{}
	wg5.Add(5)
	go func() { defer wg5.Done(); r.IPGeo = IPGeoLookup(r.IP) }()
	go func() { defer wg5.Done(); r.ASNInfo = ASNLookup(r.IP) }()
	go func() { defer wg5.Done(); r.Whois = WhoisLookup(r.IP) }()
	go func() { defer wg5.Done(); r.Shodan = ShodanLookup(r.IP) }()
	go func() { defer wg5.Done(); r.CTLogs = CertificateTransparency(r.Host) }()
	wg5.Wait()
	e.progress(0.95)

	if e.plugins != nil {
		e.plugins.FireHook("on_after_recon", r)
	}

	BuildAnomalyHints(r)
	r.RiskScore, r.RiskLevel = ScoreRisk(r)
	r.ScanDurationMs = int(time.Since(startTime).Milliseconds())

	if e.plugins != nil {
		for _, result := range e.plugins.FireHook("on_scan_complete", r) {
			r.PluginGraphNodes = append(r.PluginGraphNodes, result)
		}
	}

	e.progress(1.0)

	e.log(fmt.Sprintf("Scan complete in %dms — Risk: %s (%d/100)", r.ScanDurationMs, r.RiskLevel, r.RiskScore))
	return r
}

func (e *Engine) runIPScan(report *model.Report, startTime time.Time) (r *model.Report) {
	r = report
	defer func() {
		if rec := recover(); rec != nil {
			e.log(fmt.Sprintf("PANIC (IP): %v", rec))
			r.ScanErrors = append(r.ScanErrors, fmt.Sprintf("Internal error: %v", rec))
		}
	}()

	e.log(fmt.Sprintf("IP mode: %s", r.Host))

	r.ReverseDNS = ReverseDNS(r.IP)
	r.DNSRecords = CheckDNSRecords(r.Host)

	r.OpenPorts = ScanPorts(r.IP, nil, e.stopCh)
	r.PortBanners = make(map[string]string)
	for p, b := range GrabBanners(r.IP, r.OpenPorts, e.stopCh) {
		r.PortBanners[fmt.Sprintf("%d", p)] = b
	}

	if contains(r.OpenPorts, 443) {
		sslResult := SSLCheck(r.Host, 443, config.FastTimeout)
		if sslResult.Error == "" {
			r.Scheme = "https"
			r.Port = 443
			r.SSLExpiryDays = sslResult.ExpiryDays
			r.SSLExpiryDate = sslResult.ExpiryDate
			r.SSLWeakCipher = sslResult.WeakCipher
			r.TLSSummary = map[string]string{"version": sslResult.Version, "cipher": sslResult.Cipher}
			r.SSLDeep = sslResult.Deep
		}
	}

	r.RiskScore, r.RiskLevel = ScoreRisk(r)
	r.ScanDurationMs = int(time.Since(startTime).Milliseconds())
	e.log(fmt.Sprintf("IP scan complete in %dms", r.ScanDurationMs))
	return r
}

func (e *Engine) isStopped() bool {
	select {
	case <-e.stopCh:
		return true
	default:
		return false
	}
}

func collectPaths(custom []string, pluginWordlist []string) []string {
	all := make(map[string]bool)
	for _, p := range custom {
		all[p] = true
	}
	for _, p := range pluginWordlist {
		all[p] = true
	}
	for _, p := range GenericPaths {
		all[p] = true
	}
	for _, p := range WPPaths {
		all[p] = true
	}
	for _, p := range LaravelPaths {
		all[p] = true
	}
	for _, p := range DrupalPaths {
		all[p] = true
	}
	for _, p := range JoomlaPaths {
		all[p] = true
	}
	for _, p := range SpringPaths {
		all[p] = true
	}
	for _, p := range DjangoPaths {
		all[p] = true
	}
	for _, p := range NextJSPaths {
		all[p] = true
	}

	var result []string
	for p := range all {
		if p == "" {
			continue
		}
		result = append(result, p)
	}
	return result
}

func (e *Engine) getCustomPorts() []int {
	if e.plugins == nil {
		return nil
	}
	strPorts := e.plugins.GetCustomList("ports")
	var ports []int
	for _, s := range strPorts {
		s = strings.TrimSpace(s)
		var p int
		if n, _ := fmt.Sscanf(s, "%d", &p); n == 1 && p > 0 && p < 65536 {
			ports = append(ports, p)
		}
	}
	return ports
}

func (e *Engine) getCustomWordlist() []string {
	if e.plugins == nil {
		return nil
	}
	return e.plugins.GetCustomList("wordlist")
}

func (e *Engine) getCustomSubdomains() []string {
	if e.plugins == nil {
		return nil
	}
	return e.plugins.GetCustomList("subdomains")
}

func (e *Engine) getCustomHeaders() map[string]string {
	if e.plugins == nil {
		return nil
	}
	lines := e.plugins.GetCustomList("headers")
	h := make(map[string]string)
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return h
}

func (e *Engine) getCustomUserAgents() []string {
	if e.plugins == nil {
		return nil
	}
	return e.plugins.GetCustomList("useragents")
}

func (e *Engine) getCustomBlacklist() map[string]bool {
	if e.plugins == nil {
		return nil
	}
	blacklist := make(map[string]bool)
	for _, p := range e.plugins.GetCustomList("blacklist") {
		blacklist[strings.TrimSpace(p)] = true
	}
	return blacklist
}

func checkSecurityTxt(base string, client *HTTPClient) string {
	u := fmt.Sprintf("%s/.well-known/security.txt", base)
	resp, _, err := client.Get(u, nil)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		body := make([]byte, 2000)
		n, _ := resp.Body.Read(body)
		if n > 10 {
			return string(body[:n])
		}
	}

	u2 := fmt.Sprintf("%s/security.txt", base)
	resp2, _, _ := client.Get(u2, nil)
	if resp2 != nil && resp2.StatusCode == 200 {
		body := make([]byte, 2000)
		n, _ := resp2.Body.Read(body)
		if n > 10 {
			return string(body[:n])
		}
	}
	return "NOT FOUND"
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func safeDo(e *Engine, name string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			e.log(fmt.Sprintf("PANIC in %s: %v", name, rec))
		}
	}()
	fn()
}
