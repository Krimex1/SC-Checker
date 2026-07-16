package engine

var GenericPaths = []string{
	"admin", "administrator", "admin.php", "login", "signin", "auth",
	"dashboard", "panel", "controlpanel", "cpanel", "webmail",
	"config.php", "configuration.php", "settings.php",
	".htaccess", ".htpasswd", "web.config",
	"phpinfo.php", "info.php", "test.php", "server-status",
	".env", ".env.bak", ".env.production", ".env.local",
	".git/config", ".git/HEAD", ".svn/entries",
	"backup.sql", "database.sql", "dump.sql", "db.sql",
	"robots.txt", "sitemap.xml",
	"readme.html", "README.md", "LICENSE", "CHANGELOG.txt",
	"composer.json", "package.json", "package-lock.json", "yarn.lock",
	".bash_history", ".ssh/", "id_rsa", "id_ed25519",
	"debug.log", "error.log", "access.log",
	"phpmyadmin/", "pma/", "adminer.php",
	"api/", "api/v1/", "api/v2/", "graphql", "graphql/",
	"swagger.json", "openapi.json", "swagger-ui.html",
	"_debug/", "debug/", "test/", "dev/", "staging/",
	"tmp/", "temp/", "backup/", "backups/", "old/",
	"uploads/", "upload/", "files/", "downloads/",
	"private/", "confidential/", "secret/", "secure/",
	"logs/", "log/", "errors/", "error/",
	"status", "health", "healthcheck", "metrics",
	".well-known/security.txt", ".well-known/openid-configuration",
	"crossdomain.xml", "clientaccesspolicy.xml",
}

var WPPaths = []string{
	"wp-admin", "wp-login.php", "wp-config.php.bak",
	"wp-content/debug.log", "wp-includes/",
	"wp-cron.php", "xmlrpc.php", "wp-json/wp/v2/users/",
	"feed/", "wp-content/plugins/",
	"wp-content/themes/", "wp-content/uploads/",
	"wp-admin/admin-ajax.php", "wp-admin/install.php",
	"wp-content/upgrade/", "wp-includes/rss.php",
}

var LaravelPaths = []string{
	"artisan", "_profiler/", "storage/logs/laravel.log",
	"bootstrap/cache/", "storage/framework/views/",
	"storage/app/", ".env.example", "vendor/",
}

var DrupalPaths = []string{
	"core/CHANGELOG.txt", "sites/default/settings.php",
	"sites/default/files/", "user/login", "node/1",
	"core/install.php", "modules/", "themes/",
}

var JoomlaPaths = []string{
	"administrator/", "configuration.php",
	"tmp/", "cache/", "logs/",
	"language/en-GB/en-GB.xml", "components/",
}

var SpringPaths = []string{
	"actuator", "actuator/health", "actuator/env",
	"actuator/heapdump", "swagger-ui.html",
	"actuator/beans", "actuator/mappings", "actuator/metrics",
	"actuator/configprops", "actuator/loggers",
}

var DjangoPaths = []string{
	"admin/", "api/", "__debug__/",
	"static/", "media/", "accounts/login/",
}

var NextJSPaths = []string{
	"_next/", "api/auth/", "api/graphql",
	"_next/static/", "api/health",
}

var NodeJSPaths = []string{
	"node_modules/", "package.json", ".npmrc",
	".eslintrc", ".babelrc",
}

var ASPNetPaths = []string{
	"elmah.axd", "trace.axd", "WebResource.axd",
	"Telerik.Web.UI.WebResource.axd",
}

var SubdomainWordlist = []string{
	"www", "mail", "ftp", "webmail", "smtp", "ns1", "ns2",
	"vpn", "remote", "api", "dev", "staging", "test",
	"demo", "beta", "admin", "panel", "dashboard", "app",
	"cdn", "static", "media", "db", "redis", "git",
	"jenkins", "ci", "monitor", "grafana", "backup", "blog",
	"docs", "shop", "status", "sso", "auth", "login",
	"m", "mobile", "wap", "origin", "edge",
	"api-staging", "api-dev", "internal", "corp", "intranet",
	"partners", "portal", "gateway", "proxy", "ws",
	"crm", "erp", "billing", "payments", "store",
	"help", "support", "kb", "wiki", "community",
	"news", "events", "calendar", "jobs", "careers",
	"assets", "images", "img", "css", "js",
	"svn", "cvs", "hg", "bamboo", "jira", "confluence",
	"kibana", "elastic", "search", "elk", "nagios",
	"prometheus", "alertmanager", "zabbix", "graylog",
	"sandbox", "review", "uat", "qa", "preprod",
	"loadbalancer", "lb", "fe", "be", "bastion",
}

var CriticalPaths = map[string]string{
	".env":                        ".env",
	".env.bak":                    ".env.bak",
	".env.production":             ".env.production",
	".env.local":                  ".env.local",
	".git/config":                 ".git/config",
	".git/HEAD":                   ".git/HEAD",
	"backup.sql":                  "backup.sql",
	"database.sql":                "database.sql",
	"dump.sql":                    "dump.sql",
	"phpmyadmin":                  "phpmyadmin",
	"adminer.php":                 "adminer.php",
	"config.php":                  "config.php",
	".htpasswd":                   ".htpasswd",
	"id_rsa":                      "id_rsa",
	"id_ed25519":                   "id_ed25519",
	".bash_history":               ".bash_history",
	"storage/logs/laravel.log":    "storage/logs/laravel.log",
	"sites/default/settings.php":  "sites/default/settings.php",
	"actuator/env":                "actuator/env",
	"actuator/heapdump":           "actuator/heapdump",
}

var CriticalContentRules = map[string][]string{
	"id_rsa":          {"BEGIN", "PRIVATE KEY", "ssh-rsa", "-----BEGIN"},
	"id_ed25519":      {"BEGIN", "PRIVATE KEY", "ssh-ed25519", "-----BEGIN"},
	".env":            {"=", "APP_", "DB_", "SECRET", "KEY=", "PASSWORD"},
	".env.bak":        {"=", "APP_", "DB_", "SECRET", "KEY=", "PASSWORD"},
	".env.production": {"=", "APP_", "DB_", "SECRET", "KEY=", "PASSWORD"},
	".env.local":      {"=", "APP_", "DB_", "SECRET", "KEY=", "PASSWORD"},
	".git/config":     {"[core]", "repositoryformatversion", "[remote"},
	".git/HEAD":       {"ref:", "refs/heads"},
	"backup.sql":      {"CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL", "-- phpMyAdmin"},
	"database.sql":    {"CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL"},
	"dump.sql":        {"CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL"},
	".htpasswd":       {":"},
	".bash_history":   {"cd ", "ls ", "sudo ", "ssh ", "export "},
	"config.php":      {"<?php", "$db", "$database", "DB_HOST", "define("},
	"sites/default/settings.php": {"<?php", "$databases", "$settings", "drupal"},
	"storage/logs/laravel.log":   {"stack trace", "Stack trace", "Laravel", "ERROR"},
	"actuator/env":    {"{", "spring", "server.port", "environment"},
	"actuator/heapdump": {"JAVA PROFILE"},
	"phpmyadmin":      {"phpMyAdmin", "pma_username", "login_form"},
	"adminer.php":     {"Adminer", "login", "username"},
}

var CMSSignatures = map[string][]string{
	"WordPress":  {`wp-content/`, `content="WordPress`, `wp-json`, `wp-includes/`},
	"Joomla":     {`joomla`, `content="Joomla`, `com_content`},
	"Drupal":     {`drupal`, `content="Drupal`, `drupalSettings`},
	"Laravel":    {`laravel_session`, `XSRF-TOKEN`, `laravel`},
	"Django":     {`csrfmiddlewaretoken`, `__debug__`, `django`},
	"Spring":     {`Whitelabel Error Page`, `actuator`, `spring`},
	"Express":    {`X-Powered-By: Express`, `express`},
	"Next.js":    {`__next`, `__NEXT_DATA__`},
	"Nuxt.js":    {`__nuxt`, `__NUXT__`},
	"Angular":    {`ng-version`, `_nghost`, `app-root`},
	"ASP.NET":    {`__VIEWSTATE`, `__EVENTVALIDATION`, `asp.net`},
	"Ghost":      {`content="Ghost`, `ghost`},
	"Shopify":    {`cdn\.shopify\.com`, `shopify`},
	"Magento":    {`mage/`, `magento`, `Magento`},
	"Ruby on Rails": {`rails`, `_method`, `utf8`},
	"Flask":      {`flask`, `werkzeug`},
	"Symfony":    {`symfony`, `_fragment`},
	"React":      {`react`, `data-reactroot`, `__NEXT_DATA__`},
	"Vue.js":     {`vue`, `data-v-`},
}

var WAFFingerprints = map[string]struct {
	Headers []string
	Body    []string
}{
	"Cloudflare":  {Headers: []string{"cf-ray", "cf-cache-status", "__cfduid"}, Body: []string{"cloudflare", "cf-browser-verification", "jschl-answer"}},
	"AWS WAF":     {Headers: []string{"x-amzn-requestid", "x-amzn-waf", "x-amz-cf-id"}, Body: []string{"awswaf", "aws-waf", "x-amzn-errortype"}},
	"ModSecurity": {Body: []string{"mod_security", "modsecurity", "this error was generated by mod_security"}},
	"Imperva":     {Headers: []string{"x-iinfo", "x-cdn"}, Body: []string{"imperva", "incapsula", "visid_incap_"}},
	"Akamai":      {Headers: []string{"x-akamai-transformed", "x-akamai", "akamai-origin-hop"}, Body: []string{"akamai", "reference number"}},
	"Sucuri":      {Headers: []string{"x-sucuri-id", "x-sucuri-cache"}, Body: []string{"sucuri", "access denied - sucuri"}},
	"Wordfence":   {Body: []string{"wordfence", "wf-csrf-token", "generated by wordfence"}},
	"Barracuda":   {Body: []string{"barracuda", "barra_counter_session"}},
	"F5 BIG-IP":   {Headers: []string{"x-cnection", "x-wa-info"}, Body: []string{"bigip", "tscookieid", "f5 BIG-IP", "ASM"}},
	"FortiWeb":    {Body: []string{"fortiweb"}},
	"DenyAll":     {Body: []string{"denyall", "incap_ses", "session_timeout"}},
	"Radware":     {Headers: []string{"x-radware"}, Body: []string{"radware"}},
	"Citrix":      {Headers: []string{"x-citrix", "ns_gx"}, Body: []string{"citrix", "ns-gateway"}},
	"Kona":        {Headers: []string{"x-akamai"}, Body: []string{"kona performance", "x-akamai-transformed"}},
}

var VersionPatterns = map[string]string{
	`nginx/([\d.]+)`:          "Nginx",
	`nginx\/([\d.]+)`:         "Nginx",
	`Apache/([\d.]+)`:         "Apache",
	`Apache\/([\d.]+)`:        "Apache",
	`PHP/([\d.]+)`:            "PHP",
	`PHP\/([\d.]+)`:           "PHP",
	`IIS/([\d.]+)`:            "IIS",
	`IIS\/([\d.]+)`:           "IIS",
	`LiteSpeed/([\d.]+)`:      "LiteSpeed",
	`OpenResty/([\d.]+)`:      "OpenResty",
	`Caddy`:                   "Caddy",
	`Varnish/([\d.]+)`:        "Varnish",
	`WordPress\s+([\d.]+)`:    "WordPress",
	`wordpress\/([\d.]+)`:     "WordPress",
	`Drupal\s+([\d.]+)`:       "Drupal",
	`Joomla!\s+([\d.]+)`:      "Joomla",
	`jQuery\s+([\d.]+)`:       "jQuery",
	`jquery[@-]?([\d.]+)`:     "jQuery",
	`React/([\d.]+)`:          "React",
	`react[@-]?([\d.]+)`:      "React",
	`Vue\.js\s+([\d.]+)`:      "Vue.js",
	`vue[@-]?([\d.]+)`:        "Vue.js",
	`Angular[\s/]?([\d.]+)`:   "Angular",
	`Bootstrap\s+([\d.]+)`:    "Bootstrap",
	`bootstrap[@-]?([\d.]+)`:  "Bootstrap",
	`Node\.js/([\d.]+)`:       "Node.js",
	`Express[\s/]?([\d.]+)`:   "Express",
	`Python/([\d.]+)`:         "Python",
	`Ruby/([\d.]+)`:           "Ruby",
	`Rails\s+([\d.]+)`:        "Rails",
	`curl/([\d.]+)`:           "cURL",
	`Wget/([\d.]+)`:           "Wget",
	`Tomcat/([\d.]+)`:         "Tomcat",
	`Jetty/([\d.]+)`:          "Jetty",
	`Undertow/([\d.]+)`:       "Undertow",
	`MySQL/([\d.]+)`:          "MySQL",
	`MariaDB/([\d.]+)`:        "MariaDB",
	`PostgreSQL/([\d.]+)`:     "PostgreSQL",
}

var SensitiveCookiePatterns = []string{
	"session", "sid", "sess", "auth", "login", "user", "token",
	"csrf", "xsrf", "jwt", "bearer", "api_key", "secret",
	"password", "credential", "access", "refresh", "id_token",
	"phpsessid", "jsessionid", "asp.net_sessionid", "laravel_session",
	"csrftoken", "xsrf-token",
}

var TrackingDomains = map[string]bool{
	"google-analytics.com": true, "googletagmanager.com": true,
	"analytics.google.com": true, "doubleclick.net": true,
	"googleadservices.com": true, "facebook.com/tr": true,
	"connect.facebook.net": true, "hotjar.com": true,
	"mouseflow.com": true, "crazyegg.com": true,
	"fullstory.com": true, "optimizely.com": true,
	"bootstrapcdn.com": true, "cloudflare.com/cdn-cgi": true,
	"cdn.jsdelivr.net": true, "unpkg.com": true,
	"ajax.googleapis.com": true, "fonts.googleapis.com": true,
	"fonts.gstatic.com": true, "maxcdn.bootstrapcdn.com": true,
	"code.jquery.com": true, "stackpath.bootstrapcdn.com": true,
	"use.fontawesome.com": true, "kit.fontawesome.com": true,
	"polyfill.io": true, "cdnjs.cloudflare.com": true,
	"maps.googleapis.com": true, "api.mapbox.com": true,
	"pixel.wp.com": true, "stats.wp.com": true,
	"bat.bing.com": true, "clarity.ms": true,
	"linkedin.com/px": true, "snap.licdn.com": true,
	"pinterest.com": true, "redditstatic.com": true,
	"quantserve.com": true, "scorecardresearch.com": true,
	"outbrain.com": true, "taboola.com": true,
	"criteo.com": true, "adnxs.com": true,
	"rubiconproject.com": true, "openx.net": true,
}

var HSTSPreloadList = []string{
	"google.com", "gmail.com", "youtube.com", "github.com", "facebook.com",
	"twitter.com", "x.com", "instagram.com", "linkedin.com", "microsoft.com",
	"apple.com", "amazon.com", "wikipedia.org", "reddit.com", "netflix.com",
	"spotify.com", "discord.com", "slack.com", "zoom.us", "paypal.com",
	"dropbox.com", "stackoverflow.com", "medium.com", "gitlab.com",
	"docker.com", "npmjs.com", "pypi.org", "cloudflare.com",
	"bing.com", "outlook.com", "office.com", "live.com", "onedrive.com",
	"mozilla.org", "torproject.org", "eff.org", "letsencrypt.org",
	"digitalocean.com", "heroku.com", "vercel.com", "netlify.app",
	"pages.dev", "workers.dev", "firebaseapp.com", "ngrok.io",
	"bitbucket.org", "gitea.com", "sourceforge.net", "launchpad.net",
	"kernel.org", "python.org", "ruby-lang.org", "golang.org",
	"rust-lang.org", "nodejs.org", "deno.land", "devdocs.io",
	"stripe.com", "squareup.com", "shopify.com", "adyen.com",
	"cloudfront.net", "fastly.net", "akamai.net", "edgekey.net",
	"atlassian.com", "slack-edge.com", "twilio.com", "sendgrid.com",
	"mailgun.com", "postmarkapp.com", "dnsimple.com", "namecheap.com",
	"godaddy.com", "hover.com", "gandi.net", "ovh.com",
	"linode.com", "vultr.com", "alibabacloud.com", "oraclecloud.com",
	"salesforce.com", "sap.com", "oracle.com", "ibm.com",
	"dell.com", "hp.com", "lenovo.com", "intel.com", "amd.com",
	"nvidia.com", "arm.com", "qualcomm.com", "broadcom.com",
	"ubuntu.com", "debian.org", "fedoraproject.org", "archlinux.org",
	"freebsd.org", "openbsd.org", "netbsd.org", "dragonflybsd.org",
}
