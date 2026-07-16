# Examples

Starter configuration files. Copy any of these into the project root to enable them.

| File | What it does |
|---|---|
| [`dsl_rules.json`](./dsl_rules.json) | Sample DSL rules: assert risk score on critical paths / open ports / weak ciphers, plus a `FOR` loop over open ports and a `CAPTURE` over subdomains |
| [`plugins/critical_path_alert.json`](./plugins/critical_path_alert.json) | Sample JSON plugin: emits a CRITICAL finding on `on_scan_complete` if any critical path was discovered |

None of these are loaded automatically — they live in `examples/` so they ship with the repo without affecting the user's own configuration.

To enable:

```bash
cp examples/dsl_rules.json ./dsl_rules.json
cp examples/plugins/critical_path_alert.json ./plugins/
```

Then restart SC Checker.
