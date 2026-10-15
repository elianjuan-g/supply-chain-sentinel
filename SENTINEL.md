# Bumblebee — Sentinel Edition (fork rumah tangga)

Fork dari [perplexityai/bumblebee](https://github.com/perplexityai/bumblebee)
v0.1.2 (upstream commit `c1e83c0`), branch `sentinel`.

**Lisensi:** Apache-2.0 (dipertahankan dari upstream).
**Atribusi:** kode inti © Perplexity AI — lihat `LICENSE`. Fork ini menambahkan
lapisan dan fitur milik Rumah Tangga Elian tanpa menghapus kredit pembuat asli.

## Arah

1. **Jangan fork inti lebih dari perlu** — fitur non-invasif (diff, notifikasi,
   SBOM, refresh intel) dibangun sebagai tool terpisah di atas output NDJSON
   bumblebee, agar rebase ke upstream tetap murah (lihat `BLUEPRINT.md`).
2. **Sentuh Go hanya untuk** parser/matcher ecosystem baru (prioritas: Windows
   native) dan detector baru (postinstall-hunter, typosquat).
3. **Nol token saat jalan** — semua komponen berjalan lokal di PC.

## Struktur

- `sentinel/` — lapisan Sentinel (script + tool pendamping, di luar binary inti)
  - `sentinel-diff.sh` — baseline diff: hanya lapor package baru/hilang/berubah (diam bila tak ada perubahan)
  - `sentinel-refresh.sh` — refresh katalog paparan: sparse-clone ossf/malicious-packages → osvcatalog → validasi → swap atomik (fail-safe)
  - `sentinel-mcp-audit.sh` — audit server MCP vs allowlist; PRIVASI: hanya nama server, tidak pernah sentuh nilai env/credential
  - `sentinel-notify.sh` — kirim temuan ke Meja Bar (sender CIEL, pola fw-watch); dedup via hash; diam bila tak ada temuan; DRY_RUN=1 untuk uji
- `BLUEPRINT.md` — peta arsitektur + hasil diverge→converge + premortem

## Operasi yang disarankan (cron di PC — BELUM dipasang, menunggu persetujuan jadwal)

```cron
# diff + audit + notifikasi: tiap pagi 07:00
0 7 * * * ~/.local/bin/sentinel-diff && ~/.local/bin/sentinel-mcp-audit && ~/.local/bin/sentinel-notify
# refresh katalog intel: tiap Minggu 04:00
0 4 * * 0 ~/.local/bin/sentinel-refresh
```

State: `~/.hermes/sentinel/` (baseline, katalog, allowlist, log).
Katalog live: `~/.hermes/sentinel/catalog/` → pakai `bumblebee scan --exposure-catalog ~/.hermes/sentinel/catalog/`.

## Status

- Fase 1 (fondasi): SELESAI 2026-10-15 — Go 1.27.2 di PC, `go build` + `go test ./...`
  hijau (24 paket), `sentinel-diff.sh` terverifikasi 3 skenario di PC.
- Fase 2 (lapisan Sentinel): SELESAI 2026-10-15 —
  - `sentinel-diff`: baseline diff 90 records, diam bila bersih ✓
  - `sentinel-refresh`: 16 katalog (osv-malicious + 15 kurasi), 71MB, swap atomik fail-safe ✓
  - `sentinel-mcp-audit`: 0 server MCP di PC, allowlist siap ✓
  - `sentinel-notify`: DRY_RUN terverifikasi, dedup hash, pola posting = fw-watch ✓
  - Exposure scan end-to-end (`--exposure-catalog` + `--findings-only`): PC BERSIH, nol temuan ✓
  - Semua terpasang di `~/.local/bin/sentinel-*`
- Fase 3 (overpower): berjalan — 3a `sentinel-postinstall` SELESAI 2026-10-15
  (skor heuristik isi hook; teruji: KRITIS 10 / mencurigakan 3 / jinak diam;
  vs PC asli: temuan 0). Berikutnya per BLUEPRINT.md: typosquat, SBOM,
  secret-scan, reachability, Windows native, ide liar.
