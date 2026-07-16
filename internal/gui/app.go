package gui

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sc-checker-go/internal/config"
	"sc-checker-go/internal/engine"
	"sc-checker-go/internal/export"
	"sc-checker-go/internal/model"
	"sc-checker-go/internal/notifier"
	"sc-checker-go/internal/plugin"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type App struct {
	app      fyne.App
	window   fyne.Window
	engine   *engine.Engine
	mu       sync.Mutex
	scanning atomic.Bool
	report   *model.Report

	targetEntry *widget.Entry
	scanBtn     *widget.Button
	stopBtn     *widget.Button
	statusLabel *widget.Label
	progressBar *widget.ProgressBar
	logText     *widget.Entry

	infoGrid     *widget.Label
	securityGrid *widget.Label
	anomalyGrid  *widget.Label
	injectGrid   *widget.Label
	advancedGrid *widget.Label
	reconGrid    *widget.Label
	dnsGrid      *widget.Label
	sslGrid      *widget.Label
	deepGrid     *widget.Label
	cveGrid      *widget.Label
	pluginGrid   *widget.Label

	pathsList  *widget.List
	portsList  *widget.List
	reportData *widget.Entry

	whDiscord    *widget.Entry
	whSlack      *widget.Entry
	whTelegram   *widget.Entry
	whPushover   *widget.Entry
	whCustom     *widget.Entry
	whCustomName *widget.Entry

	dslEditor   *widget.Entry
	pluginList  *widget.List
	pluginFiles []string
	currentFile string

	proxyEntry     *widget.Entry
	proxyEnabled   *widget.Check
	timeoutEntry   *widget.Entry
	verifySSLCheck *widget.Check

	customListSelect *widget.Select
	customListEditor *widget.Entry
	pluginManager    *plugin.Manager

	tabs    *container.AppTabs
	wrapper *fyne.Container
	paths   []model.PathItem
	ports   []int
}

func Run() {
	guiApp := app.NewWithID("sc-checker-go")
	guiApp.Settings().SetTheme(theme.DarkTheme())

	a := &App{
		app:   guiApp,
		paths: make([]model.PathItem, 0),
		ports: make([]int, 0),
	}
	a.buildUI()
	a.window = guiApp.NewWindow(fmt.Sprintf("SC Checker v%s", config.Version))
	a.window.SetContent(a.wrapper)
	a.window.Resize(fyne.NewSize(1200, 800))
	a.window.SetFixedSize(true)
	a.window.SetCloseIntercept(func() {
		if a.engine != nil {
			a.engine.Stop()
		}
		a.window.Close()
	})

	go a.checkForUpdates()
	go a.sizeWatcher()

	a.window.ShowAndRun()
}

func (a *App) buildUI() {
	a.targetEntry = widget.NewEntry()
	a.targetEntry.SetPlaceHolder("Enter target — example.com or 1.2.3.4")
	a.targetEntry.OnSubmitted = func(s string) { a.startScan() }

	a.scanBtn = widget.NewButtonWithIcon("Scan", theme.MediaPlayIcon(), a.startScan)
	a.scanBtn.Importance = widget.HighImportance
	a.stopBtn = widget.NewButtonWithIcon("Stop", theme.MediaStopIcon(), a.stopScan)
	a.stopBtn.Disable()

	a.statusLabel = widget.NewLabel("Ready")
	a.progressBar = widget.NewProgressBar()
	a.logText = widget.NewMultiLineEntry()
	a.logText.Disable()

	a.infoGrid = widget.NewLabel("")
	a.securityGrid = widget.NewLabel("")
	a.anomalyGrid = widget.NewLabel("")
	a.injectGrid = widget.NewLabel("")
	a.advancedGrid = widget.NewLabel("")
	a.reconGrid = widget.NewLabel("")
	a.dnsGrid = widget.NewLabel("")
	a.sslGrid = widget.NewLabel("")
	a.deepGrid = widget.NewLabel("")
	a.cveGrid = widget.NewLabel("")
	a.pluginGrid = widget.NewLabel("")

	a.pathsList = widget.NewList(
		func() int { a.mu.Lock(); defer a.mu.Unlock(); return len(a.paths) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			a.mu.Lock()
			if id < len(a.paths) {
				p := a.paths[id]
				obj.(*widget.Label).SetText(fmt.Sprintf("%-30s  %d  %d bytes", p.Path, p.Status, p.Size))
			}
			a.mu.Unlock()
		},
	)
	a.portsList = widget.NewList(
		func() int { a.mu.Lock(); defer a.mu.Unlock(); return len(a.ports) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			a.mu.Lock()
			if id < len(a.ports) {
				p := a.ports[id]
				svc := config.PortServices[p]
				obj.(*widget.Label).SetText(fmt.Sprintf("Port %d — %s", p, svc))
			}
			a.mu.Unlock()
		},
	)

	a.reportData = widget.NewMultiLineEntry()
	a.reportData.SetMinRowsVisible(15)

	a.refreshPluginList()
	a.pluginList = widget.NewList(
		func() int { return len(a.pluginFiles) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id < len(a.pluginFiles) {
				obj.(*widget.Label).SetText(a.pluginFiles[id])
			}
		},
	)
	a.pluginList.OnSelected = func(id widget.ListItemID) {
		if id < len(a.pluginFiles) {
			a.openPluginFile(a.pluginFiles[id])
		}
	}

	a.whDiscord = widget.NewEntry()
	a.whDiscord.SetPlaceHolder("https://discord.com/api/webhooks/...")
	a.whSlack = widget.NewEntry()
	a.whSlack.SetPlaceHolder("https://hooks.slack.com/services/...")
	a.whTelegram = widget.NewEntry()
	a.whTelegram.SetPlaceHolder("BOT_TOKEN|CHAT_ID")
	a.whPushover = widget.NewEntry()
	a.whPushover.SetPlaceHolder("APP_TOKEN|USER_KEY")
	a.whCustom = widget.NewEntry()
	a.whCustom.SetPlaceHolder("https://your-webhook.com/endpoint")
	a.whCustomName = widget.NewEntry()
	a.whCustomName.SetPlaceHolder("Webhook Name")

	a.proxyEntry = widget.NewEntry()
	a.proxyEntry.SetPlaceHolder("http://proxy:8080 or socks5://127.0.0.1:9050")
	a.proxyEnabled = widget.NewCheck("Enabled", nil)
	a.timeoutEntry = widget.NewEntry()
	a.timeoutEntry.SetPlaceHolder("15")
	a.verifySSLCheck = widget.NewCheck("Verify SSL", nil)

	a.dslEditor = widget.NewMultiLineEntry()
	a.dslEditor.SetMinRowsVisible(10)

	customListKeys := []string{"headers", "payloads", "ports", "subdomains", "useragents", "blacklist", "wordlist"}
	customListLabels := []string{"Custom Headers (key: value)", "SQLi/XSS Payloads", "Custom Ports", "Subdomain Wordlist", "User Agents", "Blacklist Paths", "Custom Wordlist"}
	a.customListSelect = widget.NewSelect(customListLabels, func(s string) {
		for i, label := range customListLabels {
			if label == s && i < len(customListKeys) {
				a.loadCustomList(customListKeys[i])
				break
			}
		}
	})
	a.customListEditor = widget.NewMultiLineEntry()
	a.customListEditor.SetMinRowsVisible(8)
	a.customListSelect.SetSelected(customListLabels[0])

	a.loadWebhookSettings()
	a.loadProxySettings()

	topBar := container.NewBorder(nil, nil,
		container.NewHBox(a.scanBtn, a.stopBtn, widget.NewSeparator(), a.statusLabel),
		nil, a.targetEntry)

	dashTabs := container.NewAppTabs(
		container.NewTabItem("Overview", container.NewVScroll(container.NewVBox(
			widget.NewLabelWithStyle("Target Info", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), a.infoGrid,
			widget.NewSeparator(),
			widget.NewLabelWithStyle("Anomalies", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), a.anomalyGrid,
		))),
		container.NewTabItem("Security", container.NewVScroll(a.securityGrid)),
		container.NewTabItem("Injections", container.NewVScroll(a.injectGrid)),
		container.NewTabItem("Advanced", container.NewVScroll(a.advancedGrid)),
		container.NewTabItem("DNS/Subs", container.NewVScroll(a.dnsGrid)),
		container.NewTabItem("SSL/TLS", container.NewVScroll(a.sslGrid)),
		container.NewTabItem("Recon", container.NewVScroll(a.reconGrid)),
		container.NewTabItem("Deep Scan", container.NewVScroll(a.deepGrid)),
		container.NewTabItem("CVEs", container.NewVScroll(a.cveGrid)),
		container.NewTabItem("Paths", a.pathsList),
		container.NewTabItem("Ports", a.portsList),
		container.NewTabItem("Plugins", container.NewVScroll(a.pluginGrid)),
	)
	dashTabs.SetTabLocation(container.TabLocationTop)

	a.tabs = container.NewAppTabs(
		container.NewTabItem("Dashboard", dashTabs),
		container.NewTabItem("Report", container.NewBorder(nil,
			container.NewHBox(
				widget.NewButtonWithIcon("JSON", theme.DocumentSaveIcon(), a.exportJSON),
				widget.NewButtonWithIcon("HTML", theme.MailSendIcon(), a.exportHTML),
				widget.NewButtonWithIcon("TXT", theme.FileTextIcon(), a.exportTXT),
			), nil, nil, a.reportData)),
		container.NewTabItem("Webhooks",
			container.NewScroll(container.NewVBox(
				widget.NewLabelWithStyle("Discord", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), a.whDiscord,
				widget.NewSeparator(),
				widget.NewLabelWithStyle("Slack", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), a.whSlack,
				widget.NewSeparator(),
				widget.NewLabelWithStyle("Telegram (token|chat_id)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), a.whTelegram,
				widget.NewSeparator(),
				widget.NewLabelWithStyle("Pushover (token|user_key)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), a.whPushover,
				widget.NewSeparator(),
				widget.NewLabelWithStyle("Custom", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), a.whCustomName, a.whCustom,
				widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), a.saveWebhookSettings),
			)),
		),
		container.NewTabItem("Proxy", container.NewScroll(container.NewVBox(
			widget.NewLabelWithStyle("Proxy Settings", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			a.proxyEnabled,
			widget.NewLabel("Proxy URL:"), a.proxyEntry,
			widget.NewLabel("Timeout (s):"), a.timeoutEntry,
			a.verifySSLCheck,
			widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), a.saveProxySettings),
			widget.NewButtonWithIcon("Rebuild Engine", theme.ViewRefreshIcon(), a.rebuildEngine),
			widget.NewButtonWithIcon("Test Connection", theme.ConfirmIcon(), a.testProxy),
		))),
		container.NewTabItem("Plugins & DSL",
			container.NewAppTabs(
				container.NewTabItem("Plugins & DSL",
					container.NewBorder(nil,
						container.NewHBox(
							widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), a.saveDSL),
							widget.NewButtonWithIcon("New", theme.ContentAddIcon(), a.newPlugin),
							widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), a.deletePlugin),
							widget.NewButtonWithIcon("Open Folder", theme.FolderOpenIcon(), a.openPluginsFolder),
						), nil, nil,
						container.NewHSplit(
							container.NewVScroll(a.pluginList),
							a.dslEditor,
						),
					),
				),
				container.NewTabItem("Custom Lists",
					container.NewBorder(nil,
						container.NewHBox(
							widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), a.saveCustomList),
						), nil, nil,
						container.NewVSplit(
							container.NewVBox(
								widget.NewLabel("Select List:"),
								a.customListSelect,
							),
							a.customListEditor,
						),
					),
				),
			),
		),
	)

	a.wrapper = container.NewBorder(topBar, a.progressBar, nil, nil, a.tabs)

	a.buildEngine()
}

func (a *App) buildEngine() {
	var err error
	a.engine, err = engine.NewEngine("", 5, false, nil)
	if err != nil || a.engine == nil {
		a.engine, err = engine.NewEngine("", 5, false, nil)
	}
	if a.engine != nil {
		a.engine.LogFn = func(msg string) {
			fyne.Do(func() {
				a.logText.SetText(a.logText.Text + msg + "\n")
				a.statusLabel.SetText(msg)
			})
		}
		a.engine.ProgressFn = func(v float64) {
			fyne.Do(func() {
				a.progressBar.SetValue(v)
			})
		}
		pm := plugin.NewManager("plugins")
		a.engine.SetPlugins(pm)
		a.pluginManager = pm
	}
}

func (a *App) startScan() {
	target := strings.TrimSpace(a.targetEntry.Text)
	if target == "" {
		dialog.ShowError(fmt.Errorf("enter a target"), a.window)
		return
	}
	if a.engine == nil {
		dialog.ShowError(fmt.Errorf("engine not initialized"), a.window)
		return
	}

	a.mu.Lock()
	a.scanning.Store(true)
	a.paths = nil
	a.ports = nil
	a.report = nil
	a.mu.Unlock()

	a.scanBtn.Disable()
	a.stopBtn.Enable()
	a.statusLabel.SetText("Scanning...")
	a.progressBar.SetValue(0)

	for _, g := range []*widget.Label{a.infoGrid, a.securityGrid, a.anomalyGrid, a.injectGrid, a.advancedGrid, a.reconGrid, a.dnsGrid, a.sslGrid, a.deepGrid, a.pluginGrid} {
		g.SetText("")
	}

	go func() {
		r := a.engine.Run(target)

		a.mu.Lock()
		a.report = r
		a.scanning.Store(false)
		if r == nil {
			a.mu.Unlock()
			fyne.DoAndWait(func() {
				a.scanBtn.Enable()
				a.stopBtn.Disable()
				a.statusLabel.SetText("Error — scan returned no results")
				a.progressBar.SetValue(0)
			})
			return
		}
		if r != nil {
			a.paths = r.DiscoveredPaths
			if a.paths == nil {
				a.paths = []model.PathItem{}
			}
			a.ports = r.OpenPorts
			if a.ports == nil {
				a.ports = []int{}
			}
		}
		a.mu.Unlock()

		fyne.DoAndWait(func() {
			a.scanBtn.Enable()
			a.stopBtn.Disable()
			a.statusLabel.SetText(fmt.Sprintf("Done — Risk: %s (%d/100)", r.RiskLevel, r.RiskScore))
			a.progressBar.SetValue(1)
			if r != nil {
				a.fillAll(r)
				go a.sendWebhooks(r)
			}
			a.pathsList.Refresh()
			a.portsList.Refresh()
			a.window.Resize(fyne.NewSize(1200, 800))
		})
	}()
}

func (a *App) sendWebhooks(r *model.Report) {
	defer func() { recover() }()
	cfg := notifier.Config{}
	if a.whDiscord.Text != "" {
		cfg.Discords = append(cfg.Discords, notifier.Webhook{Name: "Discord", URL: a.whDiscord.Text})
	}
	if a.whSlack.Text != "" {
		cfg.Slacks = append(cfg.Slacks, notifier.Webhook{Name: "Slack", URL: a.whSlack.Text})
	}
	if a.whTelegram.Text != "" {
		cfg.Telegrams = append(cfg.Telegrams, notifier.Webhook{Name: "Telegram", URL: a.whTelegram.Text})
	}
	if a.whPushover.Text != "" {
		cfg.Pushovers = append(cfg.Pushovers, notifier.Webhook{Name: "Pushover", URL: a.whPushover.Text})
	}
	if a.whCustom.Text != "" {
		cfg.Customs = append(cfg.Customs, notifier.Webhook{Name: a.whCustomName.Text, URL: a.whCustom.Text})
	}
	notifier.NotifyAll(r, cfg)
}

func (a *App) fillAll(r *model.Report) {
	a.fillDashboard(r)
	a.fillSecurity(r)
	a.fillInjections(r)
	a.fillAdvanced(r)
	a.fillDNS(r)
	a.fillSSL(r)
	a.fillRecon(r)
	a.fillDeep(r)
	a.fillCVEs(r)
	a.fillPlugins(r)
	a.fillReport(r)
}

func (a *App) fillDashboard(r *model.Report) {
	info := fmt.Sprintf("Target: %s\nIP: %s:%d  |  Status: %d  |  %dms\nRisk: %d/100 (%s)  |  Duration: %dms\nPaths: %d/%d  |  Critical: %d  |  Ports: %d  |  Subs: %d\nWAF: %s  |  CMS: %s  |  Framework: %s",
		r.Target, r.IP, r.Port, r.StatusCode, r.ResponseTimeMs,
		r.RiskScore, strings.ToUpper(r.RiskLevel), r.ScanDurationMs,
		safeLen(r.DiscoveredPaths), r.TotalPathsScanned, safeLen(r.CriticalPaths), safeLen(r.OpenPorts), safeLen(r.Subdomains),
		trunc(join(r.WAFDetected, "none"), 200), trunc(join(r.DetectedCMS, "none"), 200), trunc(join(r.DetectedFrameworks, "none"), 200))
	a.infoGrid.SetText(info)
	a.anomalyGrid.SetText(trunc(join(r.AnomalyHints, "None"), 500))
}

func (a *App) fillSecurity(r *model.Report) {
	sec := fmt.Sprintf("HSTS: %v  |  Clickjack: %v  |  HTTP→HTTPS: %v  |  SSL Weak: %v\n"+
		"CORS issues: %d  |  Cookie issues: %d  |  Mixed content: %v  |  TRACE: %v\n"+
		"SSL Expiry: %d days  |  Missing Headers: %s\n"+
		"Server: %s  |  CSP: %s  |  TTFB: %dms  |  Size: %d",
		r.HSTSEnabled, r.ClickjackingProtected, r.HTTPToHTTPSRedirect, r.SSLWeakCipher,
		safeLen(r.CORSIssues), safeLen(r.CookieIssues), r.MixedContent, r.TraceEnabled,
		r.SSLExpiryDays, join(r.MissingSecurityHeaders, "none"),
		r.ServerBanner, safeStr(r.CSPAnalysis), r.TTFBMs, r.ContentSize)
	if len(r.CookieIssues) > 0 {
		sec += "\n\nCookie Issues:\n" + strings.Join(r.CookieIssues, "\n")
	}
	if len(r.CORSIssues) > 0 {
		sec += "\n\nCORS Issues:\n" + strings.Join(r.CORSIssues, "\n")
	}
	if len(r.RedirectChain) > 0 {
		sec += "\n\nRedirect Chain:"
		for _, rc := range r.RedirectChain {
			sec += fmt.Sprintf("\n  %s → %d", rc.URL, rc.Status)
		}
	}
	a.securityGrid.SetText(sec)
}

func (a *App) fillInjections(r *model.Report) {
	inj := fmt.Sprintf("XSS Reflected: %v\nSQL Errors: %d\nSSTI Findings: %d\nCRLF Injection: %d\nOpen Redirect: %d\nDir Traversal: %d\nHost Header: %s",
		r.XSSReflection, safeLen(r.SQLErrors), safeLen(r.SSTIResults), safeLen(r.CRLFInjection),
		safeLen(r.OpenRedirect), safeLen(r.DirTraversal), safeStr(r.HostHeaderInject))
	if len(r.SSTIResults) > 0 {
		inj += "\n\nSSTI:"
		for _, s := range r.SSTIResults {
			inj += fmt.Sprintf("\n  [%s] %s — %s", s.Severity, s.Engine, s.Detail)
		}
	}
	a.injectGrid.SetText(inj)
}

func (a *App) fillAdvanced(r *model.Report) {
	adv := fmt.Sprintf("JWT: %d | GraphQL: %d | Supply Chain: %d | WebSocket: %d\n"+
		"HTTP Smuggling: %d | Session Issues: %d | Rate Limit: %v\n"+
		"Hidden EP: %d | API EP: %d | Admin: %d | Login: %d\n"+
		"Source Leaks: %d | Backup: %d | Chaos: %d\n"+
		"CVEs: %d | CVSS: %d | Exploit Verified: %d | DSL: %d",
		safeLen(r.JWTTokens), safeLen(r.GraphQLVulns), safeLen(r.SupplyChain), safeLen(r.WebSocketResults),
		safeLen(r.HTTPSmuggling), safeLen(r.SessionIssues), r.RateLimit.Detected,
		safeLen(r.HiddenEndpoints), safeLen(r.APIEndpoints), safeLen(r.AdminPanels), safeLen(r.LoginPages),
		safeLen(r.SourceLeak), safeLen(r.BackupFiles), safeLen(r.ChaosFindings),
		safeLen(r.CVEFindings), safeLen(r.CVSSScores), safeLen(r.ExploitVerified), safeLen(r.DSLResults))
	a.advancedGrid.SetText(adv)
}

func (a *App) fillDNS(r *model.Report) {
	dns := fmt.Sprintf("IP: %s  |  Reverse DNS: %s\n", r.IP, safeStr(r.ReverseDNS))
	for rt, entries := range r.DNSRecords {
		dns += fmt.Sprintf("\n%s:", rt)
		for _, e := range entries {
			dns += fmt.Sprintf("\n  %s", e)
		}
	}
	if len(r.Subdomains) > 0 {
		dns += fmt.Sprintf("\n\nSubdomains (%d):", len(r.Subdomains))
		for _, s := range r.Subdomains {
			dns += fmt.Sprintf("\n  %s", s)
		}
	}
	if len(r.RobotsEntries) > 0 {
		dns += "\n\nrobots.txt:"
		for _, e := range r.RobotsEntries {
			dns += fmt.Sprintf("\n  %s", e)
		}
	}
	a.dnsGrid.SetText(trunc(dns, 3000))
}

func (a *App) fillSSL(r *model.Report) {
	ssl := fmt.Sprintf("Version: %s\nCipher: %s\nExpiry: %s (%d days)\nSubject: %s\nIssuer: %s\nWeak: %v",
		safeStr(r.TLSSummary["version"]), safeStr(r.TLSSummary["cipher"]),
		safeStr(r.SSLExpiryDate), r.SSLExpiryDays,
		safeStr(r.SSLDeep["subject"]), safeStr(r.SSLDeep["issuer"]), r.SSLWeakCipher)
	if sans, ok := r.SSLDeep["san"].([]string); ok {
		if len(sans) > 5 {
			ssl += fmt.Sprintf("\n\nSAN: (%d entries)", len(sans))
			for _, s := range sans {
				ssl += "\n  • " + s
			}
		} else {
			ssl += "\n\nSAN: " + strings.Join(sans, ", ")
		}
	}
	a.sslGrid.SetText(ssl)
}

func (a *App) fillRecon(r *model.Report) {
	rec := fmt.Sprintf("Emails: %d | Phones: %d | Social: %d\nExternal: %d | JS Libs: %d | Forms: %d\nWHOIS: %s | Shodan: %d ports | CT Logs: %d",
		safeLen(r.EmailsFound), safeLen(r.PhonesFound), safeLen(r.SocialLinks),
		safeLen(r.ExternalLinks), safeLen(r.JSLibraries), safeLen(r.HiddenForms),
		trunc(safeStr(r.Whois.Registrar), 80), safeLen(r.Shodan.Ports), safeLen(r.CTLogs))
	if len(r.EmailsFound) > 0 {
		rec += "\n\nEmails: " + trunc(strings.Join(r.EmailsFound, ", "), 500)
	}
	a.reconGrid.SetText(rec)
}

func (a *App) fillDeep(r *model.Report) {
	deep := fmt.Sprintf("SSL: %s / %s | Expiry: %s (%dd) | Weak: %v\n\n",
		safeStr(r.TLSSummary["version"]), safeStr(r.TLSSummary["cipher"]), safeStr(r.SSLExpiryDate), r.SSLExpiryDays, r.SSLWeakCipher)
	deep += "HTTP Methods:\n"
	for _, m := range r.HTTPMethodsFull {
		deep += fmt.Sprintf("  %-8s → %d (allowed: %v)\n", m.Method, m.Status, m.Allowed)
	}
	deep += fmt.Sprintf("\nPerf: TTFB %dms | Size %d | Encoding %s\n", r.TTFBMs, r.ContentSize, safeStr(r.ContentEncoding))
	deep += fmt.Sprintf("CSP: %s\n", safeStr(r.CSPAnalysis))
	deep += fmt.Sprintf("Security.txt: %s\n", safeStr(r.SecurityTxt))
	if len(r.RedirectChain) > 0 {
		deep += "\nRedirects:"
		for _, rc := range r.RedirectChain {
			f := ""
			if rc.Final {
				f = " [FINAL]"
			}
			deep += fmt.Sprintf("\n  %s → %d%s", rc.URL, rc.Status, f)
		}
	}
	a.deepGrid.SetText(deep)
}

func (a *App) fillCVEs(r *model.Report) {
	if len(r.CVEFindings) == 0 {
		a.cveGrid.SetText("No CVE findings")
		return
	}

	var out strings.Builder
	out.WriteString(fmt.Sprintf("CVE Findings: %d\n\n", len(r.CVEFindings)))
	for _, c := range r.CVEFindings {
		sevMarker := ""
		switch c.Severity {
		case "CRITICAL":
			sevMarker = "[CRITICAL]"
		case "HIGH":
			sevMarker = "[HIGH]"
		case "MEDIUM":
			sevMarker = "[MED]"
		case "LOW":
			sevMarker = "[LOW]"
		default:
			sevMarker = "[NONE]"
		}

		kevMark := ""
		if c.CISAKnownExploited {
			kevMark = " [CISA KEV]"
		}
		epssStr := ""
		if c.EPSS > 0 {
			epssStr = fmt.Sprintf(" EPSS:%.1f%%", c.EPSS*100)
		}
		exploitMark := ""
		if c.ExploitAvailable {
			exploitMark = " [EXPLOIT]"
		}
		cweStr := ""
		if c.CWE != "" {
			cweStr = fmt.Sprintf(" %s", c.CWE)
		}

		out.WriteString(fmt.Sprintf("\n%s %s%s%s%s %s %s%s\n",
			sevMarker, c.CVE, kevMark, exploitMark, cweStr,
			c.Product, c.Version, epssStr))
		if c.Desc != "" {
			out.WriteString(fmt.Sprintf("  %s\n", c.Desc))
		}
		if c.CISAKnownExploited {
			out.WriteString(fmt.Sprintf("  CISA Known Exploited Vulnerability\n"))
			out.WriteString(fmt.Sprintf("  https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n"))
		}
		if c.ExploitAvailable {
			for _, link := range c.ExploitLinks {
				out.WriteString(fmt.Sprintf("  Exploit: %s\n", link))
			}
		}
	}
	a.cveGrid.SetText(out.String())
}

func (a *App) fillPlugins(r *model.Report) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("DSL Results: %d\n", safeLen(r.DSLResults)))
	if len(r.DSLResults) > 0 {
		for _, d := range r.DSLResults {
			out.WriteString(fmt.Sprintf("  [%s] %s — %s\n", strings.ToUpper(d.Severity), d.Rule, d.Detail))
		}
	}
	out.WriteString(fmt.Sprintf("\nPlugin Findings: %d\n", safeLen(r.PluginGraphNodes)))
	if len(r.PluginGraphNodes) > 0 {
		for _, fn := range r.PluginGraphNodes {
			if fm, ok := fn.(map[string]any); ok {
				out.WriteString(fmt.Sprintf("  [%v] %v — %v\n",
					fm["severity"], fm["plugin"], fm["message"]))
			} else {
				out.WriteString(fmt.Sprintf("  %v\n", fn))
			}
		}
	}
	if len(r.CVSSScores) > 0 {
		out.WriteString(fmt.Sprintf("\nCVSS Scores: %d\n", len(r.CVSSScores)))
		for _, c := range r.CVSSScores {
			out.WriteString(fmt.Sprintf("  %s — %.1f (%s)\n", c.Finding, c.CVSS, c.Severity))
		}
	}
	if len(r.ScanErrors) > 0 {
		out.WriteString(fmt.Sprintf("\nScan Errors: %d\n", len(r.ScanErrors)))
		for _, e := range r.ScanErrors {
			out.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}
	a.pluginGrid.SetText(out.String())
}

func (a *App) fillReport(r *model.Report) {
	data, _ := json.MarshalIndent(r, "", "  ")
	report := string(data)
	lines := strings.Split(report, "\n")
	var out strings.Builder
	for _, line := range lines {
		if len(line) > 500 {
			line = line[:500] + "..."
		}
		out.WriteString(line + "\n")
	}
	a.reportData.SetText(out.String())
}

func (a *App) exportJSON() {
	if a.report == nil {
		dialog.ShowError(fmt.Errorf("no scan data"), a.window)
		return
	}
	if a.pluginManager != nil {
		a.pluginManager.FireHook("on_export", a.report)
	}
	dlg := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
		if err != nil || w == nil {
			return
		}
		defer w.Close()
		data, _ := json.MarshalIndent(a.report, "", "  ")
		w.Write(data)
	}, a.window)
	dlg.SetFileName("report.json")
	dlg.Show()
}

func (a *App) exportHTML() {
	if a.report == nil {
		dialog.ShowError(fmt.Errorf("no scan data"), a.window)
		return
	}
	if a.pluginManager != nil {
		a.pluginManager.FireHook("on_export", a.report)
	}
	dlg := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
		if err != nil || w == nil {
			return
		}
		defer w.Close()
		w.Write([]byte(export.ToHTML(a.report)))
	}, a.window)
	dlg.SetFileName("report.html")
	dlg.Show()
}

func (a *App) exportTXT() {
	if a.report == nil {
		dialog.ShowError(fmt.Errorf("no scan data"), a.window)
		return
	}
	if a.pluginManager != nil {
		a.pluginManager.FireHook("on_export", a.report)
	}
	dlg := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
		if err != nil || w == nil {
			return
		}
		defer w.Close()
		w.Write([]byte(export.ToTXT(a.report)))
	}, a.window)
	dlg.SetFileName("report.txt")
	dlg.Show()
}

func (a *App) loadWebhookSettings() {
	defer func() { recover() }()
	data, err := os.ReadFile("webhooks.json")
	if err != nil {
		return
	}
	wh := notifier.LoadEncryptedWebhooksJSON(data)
	if wh == nil {
		return
	}
	a.whDiscord.SetText(wh["discord"])
	a.whSlack.SetText(wh["slack"])
	a.whTelegram.SetText(wh["telegram"])
	a.whPushover.SetText(wh["pushover"])
	a.whCustom.SetText(wh["custom"])
	a.whCustomName.SetText(wh["custom_name"])
}

func (a *App) saveWebhookSettings() {
	wh := map[string]string{
		"discord": a.whDiscord.Text, "slack": a.whSlack.Text,
		"telegram": a.whTelegram.Text, "pushover": a.whPushover.Text,
		"custom": a.whCustom.Text, "custom_name": a.whCustomName.Text,
	}
	encrypted, err := notifier.EncryptWebhooksJSON(wh)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Encryption failed: %v", err), a.window)
		return
	}
	data, _ := json.MarshalIndent(encrypted, "", "  ")
	os.WriteFile("webhooks.json", data, 0644)
	dialog.ShowInformation("Saved", "Webhooks saved (encrypted)", a.window)
}

func (a *App) loadProxySettings() {
	defer func() { recover() }()
	data, err := os.ReadFile("proxy_settings.json")
	if err != nil {
		return
	}
	var p struct {
		Proxy, Timeout string
		Enabled        bool
		VerifySSL      bool
	}
	if json.Unmarshal(data, &p) == nil {
		a.proxyEntry.SetText(p.Proxy)
		a.timeoutEntry.SetText(p.Timeout)
		a.proxyEnabled.SetChecked(p.Enabled)
		a.verifySSLCheck.SetChecked(p.VerifySSL)
	}
}

func (a *App) saveProxySettings() {
	p := struct {
		Proxy, Timeout string
		Enabled        bool
		VerifySSL      bool
	}{a.proxyEntry.Text, a.timeoutEntry.Text, a.proxyEnabled.Checked, a.verifySSLCheck.Checked}
	data, _ := json.MarshalIndent(p, "", "  ")
	os.WriteFile("proxy_settings.json", data, 0644)
	dialog.ShowInformation("Saved", "Proxy settings saved", a.window)
}

func (a *App) rebuildEngine() {
	a.mu.Lock()
	oldEng := a.engine
	proxy := ""
	if a.proxyEnabled.Checked {
		proxy = a.proxyEntry.Text
	}
	timeout := 5
	if t, err := strconv.Atoi(a.timeoutEntry.Text); err == nil && t > 0 {
		timeout = t
	}
	verifySSL := a.verifySSLCheck.Checked
	a.mu.Unlock()

	eng, err := engine.NewEngine(proxy, timeout, verifySSL, nil)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to rebuild engine: %v", err), a.window)
		return
	}
	eng.LogFn = func(msg string) {
		fyne.Do(func() {
			a.logText.SetText(a.logText.Text + msg + "\n")
			a.statusLabel.SetText(msg)
		})
	}

	a.mu.Lock()
	a.engine = eng
	if a.pluginManager != nil {
		eng.SetPlugins(a.pluginManager)
	}
	if oldEng != nil {
		oldEng.Close()
	}
	a.mu.Unlock()
	dialog.ShowInformation("Done", fmt.Sprintf("Engine rebuilt%s", map[bool]string{true: " with proxy " + proxy, false: ""}[proxy != ""]), a.window)
}

func (a *App) testProxy() {
	proxy := strings.TrimSpace(a.proxyEntry.Text)
	if proxy == "" {
		dialog.ShowError(fmt.Errorf("Enter proxy URL first"), a.window)
		return
	}

	a.statusLabel.SetText(fmt.Sprintf("Testing proxy: %s...", proxy))
	go func() {
		client, err := engine.NewHTTPClient(proxy, 10)
		if err != nil {
			fyne.Do(func() {
				dialog.ShowError(fmt.Errorf("Proxy init error: %v", err), a.window)
				a.statusLabel.SetText("Proxy test failed")
			})
			return
		}
		defer client.Close()

		resp, elapsed, err := client.Get("http://httpbin.org/ip", nil)
		if err != nil {
			fyne.Do(func() {
				dialog.ShowError(fmt.Errorf("Proxy connection failed: %v", err), a.window)
				a.statusLabel.SetText("Proxy test failed")
			})
			return
		}

		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		fyne.Do(func() {
			a.statusLabel.SetText(fmt.Sprintf("Proxy OK — %dms, status %d", elapsed.Milliseconds(), resp.StatusCode))
			dialog.ShowInformation("Proxy Test", fmt.Sprintf("Success!\n%dms\nStatus: %d\nResponse: %s",
				elapsed.Milliseconds(), resp.StatusCode, string(body[:n])), a.window)
		})
	}()
}

func (a *App) stopScan() {
	if a.engine != nil {
		a.engine.Stop()
	}
}

func (a *App) sizeWatcher() {
	for {
		time.Sleep(500 * time.Millisecond)
		fyne.Do(func() {
			s := a.window.Canvas().Size()
			if s.Width > 1200 || s.Height > 800 {
				a.window.Resize(fyne.NewSize(1200, 800))
			}
		})
	}
}

func (a *App) checkForUpdates() {
	avail, latest, changelog, downloadURL, sha256 := engine.CheckUpdate("Krimex1", "SC-Checker", config.Version)
	if !avail {
		return
	}

	fyne.Do(func() {
		msg := fmt.Sprintf("New version %s available!\n\n%s\n\nUpdate now?", latest, changelog)
		dlg := dialog.NewConfirm("Update Available", msg, func(ok bool) {
			if !ok {
				return
			}
			a.statusLabel.SetText(fmt.Sprintf("Downloading v%s...", latest))
			go func() {
				result, err := engine.SelfUpdate(downloadURL, sha256)
				fyne.Do(func() {
					if err != nil {
						dialog.ShowError(fmt.Errorf("%s: %v", result, err), a.window)
						a.statusLabel.SetText("Update failed")
					} else {
						dialog.ShowInformation("Update", result, a.window)
						a.window.Close()
					}
				})
			}()
		}, a.window)
		dlg.Show()
	})
}

func (a *App) refreshPluginList() {
	os.MkdirAll("plugins", 0755)
	entries, _ := os.ReadDir("plugins")
	a.pluginFiles = nil
	execExts := map[string]bool{".exe": true, ".bat": true, ".ps1": true, ".cmd": true}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if strings.HasSuffix(ext, ".json") || execExts[ext] {
			a.pluginFiles = append(a.pluginFiles, e.Name())
		}
	}
	a.pluginFiles = append(a.pluginFiles, "dsl_rules.json")
}

func (a *App) openPluginFile(name string) {
	a.currentFile = name
	ext := strings.ToLower(filepath.Ext(name))
	execExts := map[string]bool{".exe": true, ".bat": true, ".ps1": true, ".cmd": true}
	if execExts[ext] {
		a.dslEditor.SetText(fmt.Sprintf(
			"# Executable Plugin: %s\n"+
				"# This is an external process plugin.\n"+
				"# It receives JSON via stdin: {\"hook\": \"...\", \"target\": \"...\", \"report\": {...}}\n"+
				"# It outputs JSON array of findings on stdout:\n"+
				"#   [{\"severity\": \"high\", \"title\": \"...\", \"detail\": \"...\"}]\n"+
				"# Place the executable in the plugins/ folder and it will auto-detect.", name))
		return
	}
	path := name
	if name != "dsl_rules.json" {
		path = filepath.Join("plugins", name)
	}
	data, _ := os.ReadFile(path)
	a.dslEditor.SetText(string(data))
}

func (a *App) saveDSL() {
	if a.currentFile == "" {
		a.currentFile = "dsl_rules.json"
	}
	ext := strings.ToLower(filepath.Ext(a.currentFile))
	execExts := map[string]bool{".exe": true, ".bat": true, ".ps1": true, ".cmd": true}
	if execExts[ext] {
		dialog.ShowInformation("Info", "Executable plugins are saved as files directly. Just place them in the plugins/ folder.", a.window)
		return
	}
	path := a.currentFile
	if a.currentFile != "dsl_rules.json" {
		path = filepath.Join("plugins", a.currentFile)
	}
	if err := os.WriteFile(path, []byte(a.dslEditor.Text), 0644); err != nil {
		dialog.ShowError(fmt.Errorf("Failed: %v", err), a.window)
	} else {
		dialog.ShowInformation("Saved", a.currentFile+" saved", a.window)
	}
}

func (a *App) newPlugin() {
	name := "new_plugin.json"
	i := 1
	for fileExists(filepath.Join("plugins", name)) {
		name = fmt.Sprintf("new_plugin_%d.json", i)
		i++
	}
	template := `{
  "name": "My Plugin",
  "hooks": ["on_scan_complete"],
  "condition": "critical_paths_count > 0",
  "action": "append_finding",
  "severity": "HIGH",
  "message": "Found {critical_paths_count} critical paths"
}`
	os.WriteFile(filepath.Join("plugins", name), []byte(template), 0644)
	a.refreshPluginList()
	a.pluginList.Refresh()
	a.openPluginFile(name)
}

func (a *App) deletePlugin() {
	if a.currentFile == "" || a.currentFile == "dsl_rules.json" {
		return
	}
	os.Remove(filepath.Join("plugins", a.currentFile))
	a.currentFile = ""
	a.dslEditor.SetText("")
	a.refreshPluginList()
	a.pluginList.Refresh()
}

func (a *App) openPluginsFolder() {
	os.MkdirAll("plugins", 0755)
	exec.Command("explorer", "plugins").Start()
}

func (a *App) loadCustomList(key string) {
	if a.pluginManager == nil {
		a.pluginManager = plugin.NewManager("plugins")
	}
	lines := a.pluginManager.GetCustomList(plugin.CustomListKey(key))
	a.customListEditor.SetText(strings.Join(lines, "\n"))
}

func (a *App) saveCustomList() {
	if a.pluginManager == nil {
		a.pluginManager = plugin.NewManager("plugins")
	}

	customListKeys := []string{"headers", "payloads", "ports", "subdomains", "useragents", "blacklist", "wordlist"}
	customListLabels := []string{"Custom Headers (key: value)", "SQLi/XSS Payloads", "Custom Ports", "Subdomain Wordlist", "User Agents", "Blacklist Paths", "Custom Wordlist"}

	selectedLabel := a.customListSelect.Selected
	var selectedKey string
	for i, label := range customListLabels {
		if label == selectedLabel && i < len(customListKeys) {
			selectedKey = customListKeys[i]
			break
		}
	}
	if selectedKey == "" {
		return
	}

	lines := strings.Split(a.customListEditor.Text, "\n")
	var cleanLines []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			cleanLines = append(cleanLines, l)
		}
	}

	err := a.pluginManager.SaveCustomList(plugin.CustomListKey(selectedKey), cleanLines)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to save: %v", err), a.window)
	} else {
		dialog.ShowInformation("Saved", fmt.Sprintf("Custom list '%s' saved (%d items)", selectedKey, len(cleanLines)), a.window)
	}
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

func safeLen[T any](s []T) int {
	if s == nil {
		return 0
	}
	return len(s)
}
func join(s []string, def string) string {
	if len(s) == 0 {
		return def
	}
	return strings.Join(s, ", ")
}
func safeStr(v any) string {
	if v == nil {
		return "—"
	}
	s := fmt.Sprintf("%v", v)
	if len(s) > 2000 {
		s = s[:2000] + "..."
	}
	return s
}

func trunc(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

func setLabel(g *widget.Label, text string) {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if len(line) > 400 {
			line = line[:400] + "..."
		}
		lines[i] = line
	}
	g.SetText(strings.Join(lines, "\n"))
}
