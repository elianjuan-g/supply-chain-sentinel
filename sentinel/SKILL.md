---
name: sentinel-edition
description: >
  Bumblebee Sentinel Edition — fork supply-chain scanner milik Homelab
  Elian. 10 tool NDJSON/script di atas bumblebee: baseline diff, refresh
  katalog OSV, audit MCP, notifier notification webhook, postinstall hunter, SBOM
  CycloneDX, deteksi typosquat, secret-scan opt-in, reachability audit,
  inventaris Windows native. Nol token, runtime lokal di PC.
  Use when: "sentinel", "cek keamanan package", "audit supply chain",
  "ada package baru", atau tiap pagi via cron 07:00.
version: 3.0
license: Apache-2.0 (upstream © Perplexity AI — atribusi dipertahankan)
metadata:
  owner: Ciel
  status: draft
  reviewed_at: 2026-10-16
  upstream: https://github.com/perplexityai/bumblebee
  rule_of_three: 0/3 (belum terbukti)
---

# Sentinel Edition — Household Skill (DRAFT)

Fork homelab dari bumblebee v0.1.2. Inti upstream tidak diubah;
fitur Sentinel = lapisan script di atas output NDJSON (rebase murah).

## 10 Tool (`~/.local/bin/`, state `~/.hermes/sentinel/`)

| Tool | Fungsi | Kebisingan |
|---|---|---|
| sentinel-diff | baseline diff package (baru/hilang) | diam bila tak ada perubahan |
| sentinel-refresh | refresh katalog OSV (atomic swap + last-good) | mingguan |
| sentinel-mcp-audit | audit server MCP vs allowlist (hanya nama!) | diam bila nol server |
| sentinel-notify | kirim temuan ke notification webhook, dedup hash | diam bila bersih |
| sentinel-postinstall | hunter script postinstall mencurigakan | skor 0–10 |
| sentinel-sbom | SBOM CycloneDX 1.5 | `sbom-latest.json` |
| sentinel-typosquat | Damerau-Levenshtein vs paket populer | jarak 1=tinggi, 2=sedang |
| sentinel-secretscan | pindai pola secret (**opt-in**: `SENTINEL_SECRETSCAN=1`) | tak pernah pancarkan nilai |
| sentinel-reachability | package terpasang vs terpakai (AST, tanpa eksekusi) | INFORMASI saja |
| sentinel-winnative | inventaris Windows via interop WSL | read-only |

## Operasi

```bash
# harian 07:00 (cron PC) — pipeline diam-bila-bersih
~/.local/bin/sentinel-daily
# mingguan Minggu 04:00
~/.local/bin/sentinel-refresh
# manual
~/.local/bin/sentinel-diff && ~/.local/bin/sentinel-mcp-audit && ~/.local/bin/sentinel-notify
SENTINEL_SECRETSCAN=1 ~/.local/bin/sentinel-secretscan  # opt-in
```

## Batas jujur

- Berjalan di PC operator (WSL), bukan dari cloud.
- Notifier butuh notification webhook hidup; DRY_RUN=1 untuk uji.
- secretscan melewati `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`, test/spec.
- reachability = informasi, JANGAN uninstall berdasar laporannya saja.
- Status DRAFT: butuh 3 eksekusi nyata terpisah yang hasilnya dipakai
  (Rule of Three) + verdict operator sebelum promosi ke ACTIVE.
