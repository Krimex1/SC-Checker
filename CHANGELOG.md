# Changelog

All notable changes to SC Checker Go are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] — 2026-07-12

### Removed
- **AI Chat tab** and all AI provider integrations (9 LLM providers — OpenAI, Gemini, Anthropic, OpenRouter, Groq, Mistral, DeepSeek, Cloudflare, Pollinations)
- `internal/engine/ai.go` (AI provider map, `AIAnalyze`, `AIAnalyzeWithMessage`, `FetchModels`, per-provider HTTP callers)
- `AIFindings` field from report model
- AI settings persistence (`ai_settings.json`) and the corresponding load/save/encrypt code paths
- AI-related documentation from `docs/index.html`

### Changed
- `internal/gui/app.go` — removed `AI Chat` tab, AI widget fields, and `loadAISettings` / `saveAISettings` / `fetchModels` / `aiSend` / `detectLanguage` functions
- `internal/engine/engine.go` — removed `aiSettings` field, `SetAI` method, and the post-recon `AIAnalyze` invocation
- Release build pipeline: `build.bat` applies `-ldflags="-s -w" -trimpath -buildvcs=false` for ~43% smaller binary (45 MB → 25.5 MB)

### Security
- `plugins/.secret.key` excluded from version control via `.gitignore` (was previously untracked)

### Documentation
- New `README.md` with feature overview, build instructions, and configuration reference
- New `LICENSE` (MIT)
- New `CONTRIBUTING.md`
- New `.gitignore` covering build artifacts, scan outputs, runtime config, and the encryption key
- New `examples/` directory with starter DSL rules and a sample plugin

---

## Earlier versions

Pre-2.0.0 release history is not tracked in this file. See [Git commit history](https://github.com/Krimex1/SC-Checker/commits) for the complete timeline.
