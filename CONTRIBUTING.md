# Contributing to SC Checker Go

Thanks for taking an interest in SC Checker Go! Contributions of all sizes are welcome — bug reports, fixes, new features, new wordlists, new plugin examples, and documentation improvements.

## Code of conduct

Be respectful. This is a security tool; contributions must stay within the scope of **defensive security research and authorized testing**. Do not submit code that:
- Targets, weaponizes, or facilitates attacks against systems you do not own or have explicit permission to test
- Adds covert exfiltration or data-leak capabilities
- Bypasses authentication or authorization in malicious ways

## Reporting security issues

**Please do not open a public GitHub issue for security vulnerabilities.** Email the maintainer directly (see the repository's `SECURITY.md` if present, or the contact link on the GitHub profile). Expect a private disclosure process.

## Reporting a bug

Open a GitHub issue and include:
- SC Checker version (see `internal/config/config.go` → `Version`)
- Operating system and Go version (`go version`)
- Steps to reproduce
- Expected vs. actual behavior
- Relevant log output (the in-app log tab, or stdout when running from a terminal)
- Target URL — anonymize if it is sensitive (use `example.com` or a redacted form)

## Suggesting a feature

Open a GitHub issue with the `enhancement` label. Describe the use case first, then the proposed API/UX. Features that have a clear security-scanning use case are prioritized.

## Submitting a pull request

1. Fork the repo and create a feature branch: `git checkout -b feat/short-description`
2. Make your changes. Keep the diff focused — one feature or fix per PR.
3. Format: `gofmt -w .` (or `gofmt -s -w .` for simplification). The repo uses the standard Go style.
4. Make sure the code compiles: `go build ./...`
5. Run `go vet ./...` and fix any warnings you introduced.
6. Update `CHANGELOG.md` under an "Unreleased" section.
7. If you changed the user-facing behavior, update `docs/index.html` accordingly.
8. Open the PR with a clear description of what and why. Reference the related issue if any.

## Adding wordlists or signatures

Wordlists, fingerprint signatures, and plugin examples are great first contributions. They live in:

- `internal/engine/wordlists.go` — path wordlists, subdomain wordlists, payload sets
- `internal/engine/advanced.go` — tech fingerprint patterns
- `internal/engine/dsl.go` / `internal/engine/dslv2.go` — DSL grammar
- `examples/plugins/` — JSON plugin examples
- `examples/dsl_rules.json` — example DSL rules

When adding a wordlist, sort entries alphabetically and de-duplicate. Keep line counts reasonable (no megabytes of generated content — link to the upstream source in a comment).

## Coding conventions

- Standard Go style. `gofmt` and `go vet` are non-negotiable.
- Errors are returned, not panicked. The GUI layer may `dialog.ShowError(...)`.
- Keep package boundaries clean: `internal/engine` should not import `internal/gui` or `fyne`.
- Concurrency: prefer `chan` + `sync.WaitGroup` over shared mutable state. The existing `ConcurrentClient` pool is a good model.
- Logging: use the `Engine.LogFn` / `Engine.ProgressFn` callbacks. Don't `fmt.Println` from the engine — the GUI owns the log widget.

## Release process

1. Bump `Version` in `internal/config/config.go`
2. Move the `Unreleased` section of `CHANGELOG.md` to a dated versioned section
3. Commit, tag (`git tag vX.Y.Z`), push — `git push origin main --tags`
4. Build the release binary:
   - Windows: `build.bat` → produces `sc-checker.exe` (~26 MB)
   - Linux / macOS: `GOOS=linux GOARCH=amd64 ./build.sh` → produces `sc-checker` and `sc-checker.sha256`
5. Create a GitHub release for the tag, copy the relevant `CHANGELOG.md` section into the body, and upload:
   - The binary itself (e.g. `sc-checker.exe` or `sc-checker`)
   - The matching `.sha256` sidecar (e.g. `sc-checker.exe.sha256`) — **required** for the in-app auto-updater to verify the upgrade; without it the update is applied without integrity check
6. Mark the release as "Latest" so the in-app updater sees it

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
