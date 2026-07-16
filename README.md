# SC Checker Go

[![GitHub release (latest)](https://img.shields.io/github/v/release/Krimex1/SC-Checker?display_name=tag&sort=semver)](https://github.com/Krimex1/SC-Checker/releases/latest)
[![GitHub all releases](https://img.shields.io/github/downloads/Krimex1/SC-Checker/total)](https://github.com/Krimex1/SC-Checker/releases)
[![License: MIT](https://img.shields.io/github/license/Krimex1/SC-Checker)](./LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/Krimex1/SC-Checker)](./go.mod)
[![GitHub stars](https://img.shields.io/github/stars/Krimex1/SC-Checker)](https://github.com/Krimex1/SC-Checker/stargazers)

Comprehensive web security scanner written in Go. Performs automated reconnaissance, vulnerability assessment, and security analysis of web applications and servers through a native cross-platform GUI.

> **Status:** v2.0.0 — released. Pre-built binaries and full user documentation are attached to the [GitHub Releases](https://github.com/Krimex1/SC-Checker/releases) page.

---

## Features

- **Reconnaissance** — DNS records, subdomains (80+ wordlist), WHOIS, Shodan, Certificate Transparency, IP geolocation, ASN
- **Security headers** — HSTS, CSP, clickjacking, CORS (wildcard + origin reflection + credentials), cookie audit, mixed content, security.txt
- **SSL/TLS analysis** — certificate expiry, weak ciphers (RC4/DES/3DES/NULL/EXPORT/MD5), weak protocols (≤TLS 1.1), SAN extraction, deep SSL info
- **Injection testing** — SQL errors, XSS reflection, SSTI, CRLF, Host Header, directory traversal, open redirect
- **Port scanning** — 34 common ports + custom, banner grabbing, service detection (FTP/SSH/MySQL/Redis/...)
- **Path brute-force** — 8 framework wordlists (WordPress, Laravel, Drupal, Joomla, Spring, Django, Next.js, Node.js) + custom wordlist
- **Advanced checks** — JWT, GraphQL, WebSocket, HTTP Smuggling, Supply Chain, Email Security (SPF/DMARC/DKIM)
- **WAF detection (14 signatures)** — Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai, Sucuri, Wordfence, ...
- **CMS / framework detection (19 signatures)** — WordPress, Joomla, Laravel, Django, Spring, Next.js, ...
- **Version fingerprinting (37 patterns)** — Nginx, Apache, PHP, IIS, Node.js, Express, Python, ...
- **Mutation engine** — payload variants against SQL/XSS endpoints with verdict classification
- **DSL rules engine** — custom rule language with AST-based parser and safety validation
- **Plugin system** — JSON + external executable plugins, 9 lifecycle hooks
- **Custom lists** — headers, payloads, ports, subdomains, user-agents, blacklist, wordlist
- **Webhook notifications** — Discord, Slack, Telegram, Pushover, custom (with SSRF protection)
- **Encrypted secrets** — AES-256-GCM for webhook URLs and plugin API keys
- **Proxy support** — HTTP/HTTPS proxy with per-host verification
- **Auto-update** — GitHub-based with SHA256 binary verification
- **Multi-format reports** — JSON, HTML, TXT export

---

## Quick Start

### Download a pre-built binary

Grab `sc-checker.exe` from the [latest release](https://github.com/Krimex1/SC-Checker/releases/latest), double-click, and you're up.

#### Verifying your download

Each release ships a sidecar checksum file (`sc-checker.exe.sha256`). The built-in auto-updater uses it; you can verify a manual download the same way:

```cmd
certutil -hashfile sc-checker.exe SHA256
type sc-checker.exe.sha256
```

The two hashes must match. If they do not, do not run the binary — re-download or open an issue.

### Build from source

Requirements: Go 1.22+, a C compiler (MinGW on Windows / gcc on Linux), Git.

**Windows** (with [MSYS2](https://www.msys2.org/) or MinGW `gcc` on PATH):
```cmd
git clone https://github.com/Krimex1/SC-Checker.git
cd SC-Checker
build.bat
sc-checker.exe
```

**Linux / macOS**:
```bash
git clone https://github.com/Krimex1/SC-Checker.git
cd SC-Checker
CGO_ENABLED=1 go build -ldflags="-s -w" -trimpath -buildvcs=false -o sc-checker ./cmd/sc-checker
./sc-checker
```

The `build.bat` script on Windows applies the same optimization flags automatically and reports the resulting binary size.

---

## Usage

1. Launch `sc-checker.exe`
2. Enter a target — `example.com` or `1.2.3.4`
3. Click **Scan** and watch real-time progress
4. Switch between result tabs to explore findings
5. Export via the **Report** tab as JSON / HTML / TXT

Optional configuration tabs:

- **Webhooks** — Discord / Slack / Telegram / Pushover / custom
- **Proxy** — HTTP/HTTPS proxy with verification toggle
- **Plugins & DSL** — manage plugin files, edit DSL rules, configure custom lists

---

## Configuration

SC Checker stores user-specific files in the working directory. **None of these are committed to the repo** (see `.gitignore`):

| File | Purpose |
|---|---|
| `webhooks.json` | Webhook URLs (AES-256-GCM encrypted) |
| `proxy_settings.json` | Proxy configuration |
| `plugins/.secret.key` | 256-bit encryption key (auto-generated, 0600 perms) |
| `plugins/*.json` | User plugin files |
| `plugins/custom/*.txt` | User-customizable wordlists |

Example configs and a starter plugin live in [`examples/`](./examples/).

### Custom lists

Drop files into `plugins/custom/`:

| File | Format |
|---|---|
| `headers.txt` | `Header: value` (one per line) |
| `payloads.txt` | SQLi / XSS payloads (one per line) |
| `ports.txt` | Custom port numbers (one per line) |
| `subdomains.txt` | Subdomain prefixes (one per line) |
| `useragents.txt` | User-Agent strings (rotated per request) |
| `blacklist.txt` | Paths to skip during path brute-force |
| `wordlist.txt` | Custom path wordlist |

Lines starting with `#` are treated as comments. Empty lines are ignored.

### DSL rules

Edit `dsl_rules.json` (copy from `examples/dsl_rules.json`) to add custom rules. The DSL supports `IF/THEN/ELSE/END`, `FOR/IN`, `ASSERT`, `CAPTURE`, `REQUEST`, and standard comparisons (`==`, `!=`, `>`, `<`, `contains`) with `AND`/`OR`/`NOT`.

See [`docs/index.html`](./docs/index.html) → **DSL Rules Engine** for the full grammar and field whitelist.

### Plugins

Plugins are JSON files in the `plugins/` directory. Minimal example:

```json
{
  "name": "Critical Path Alert",
  "version": "1.0.0",
  "author": "you",
  "hooks": ["on_scan_complete"],
  "condition": "critical_paths_count > 0",
  "action": "append_finding",
  "severity": "CRITICAL",
  "message": "Found {critical_paths_count} critical paths on {target}"
}
```

Full plugin reference: [`docs/index.html`](./docs/index.html) → **Plugins**.

---

## Documentation

Full user and developer documentation lives in [`docs/index.html`](./docs/index.html). Open it in a browser for a searchable, dark-themed reference covering every feature, hook, DSL field, and config option.

---

## Security

- **Use only against systems you own or have explicit permission to test.** Unauthorized scanning may be illegal in your jurisdiction.
- The scanner sends traffic that may trigger WAF / IDS / SIEM alerts on the target.
- All encrypted secrets use a local AES-256-GCM key (`plugins/.secret.key`, auto-generated with `0600` permissions). **Never commit this file** — it is already excluded via `.gitignore`.
- Auto-update verifies release SHA256 against GitHub release assets; the update is refused on mismatch.

---

## Project Structure

```
sc-checker-go/
├── cmd/sc-checker/         # main entry point
├── internal/
│   ├── config/             # constants, port/services tables
│   ├── engine/             # scan engine, client pool, wordlists, dsl, scoring
│   ├── export/             # HTML / JSON / TXT report rendering
│   ├── gui/                # fyne GUI: tabs, dashboard, settings panels
│   ├── model/              # report struct
│   ├── notifier/           # webhook dispatch + AES-256-GCM crypto
│   └── plugin/             # plugin loader + DSL helpers
├── docs/                   # generated user/developer documentation
├── examples/               # sample DSL rules and plugin JSON
├── plugins/                # user plugins (gitignored contents)
├── build.bat               # Windows release build with size flags
├── go.mod
└── LICENSE
```

---

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](./CONTRIBUTING.md) for guidelines.

When opening an issue, please include:
- SC Checker version (`Help` → `About`, or the build commit)
- Target URL (anonymized if sensitive)
- Reproduction steps
- Relevant log lines from the scan tab

---

## License

[MIT](./LICENSE) © 2024-2026 Krimex1
