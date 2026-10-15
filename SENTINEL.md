# Bumblebee — Sentinel Edition (fork homelab)

Fork dari [perplexityai/bumblebee](https://github.com/perplexityai/bumblebee)
v0.1.2 (upstream commit `c1e83c0`), branch `sentinel`.

**Lisensi:** Apache-2.0 (dipertahankan dari upstream).
**Atribusi:** kode inti © Perplexity AI — lihat `LICENSE`. Fork ini menambahkan
lapisan dan fitur milik homelab tanpa menghapus kredit pembuat asli.

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
  - `sentinel-notify.sh` — kirim temuan ke notification webhook (sender CIEL, pola fw-watch); dedup via hash; diam bila tak ada temuan; DRY_RUN=1 untuk uji
- `BLUEPRINT.md` — peta arsitektur + hasil diverge→converge + premortem

## Operasi (cron di PC — TERPASANG 2026-10-16 atas "Gass" operator)

```cron
# diff + audit + notifikasi: tiap pagi 07:00 (diam bila bersih)
0 7 * * * $HOME/.local/bin/sentinel-daily
# refresh katalog intel: tiap Minggu 04:00
0 4 * * 0 $HOME/.local/bin/sentinel-refresh >>$HOME/.hermes/sentinel/cron-refresh.log 2>&1
```

`sentinel-daily` = diff + mcp-audit + postinstall + typosquat → notify.
secretscan SENGAJA tidak di-cron (tetap opt-in `SENTINEL_SECRETSCAN=1`).
Log: `~/.hermes/sentinel/cron-daily.log` (rotasi 200 baris).

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
  vs PC asli: temuan 0). 3b `sentinel-sbom` SELESAI 2026-10-15 (CycloneDX 1.5,
  90 komponen/90 purl).
- Fase 3c SELESAI 2026-10-16 (perintah Tuan "Lanjutkan sentinel"):
  - `sentinel-typosquat`: jarak Damerau-Levenshtein vs kurasi populer npm/pypi
    (jarak 1 = TINGGI, jarak 2 = SEDANG bila nama >=6 char); allowlist
    `tomli` (false positive legit vs `toml`, ditemukan di data asli).
    Teruji fixture 3/3 tertangkap; vs PC asli: bersih.
  - `sentinel-secretscan`: OPT-IN (`SENTINEL_SECRETSCAN=1`), desain privasi
    mengikat — TIDAK PERNAH memancarkan nilai (hanya file:baris + tipe);
    cakupan terbatas (~/src ~/workspace, tanpa ~/.ssh/~/.aws, tanpa test/*);
    pola: aws-key, private-key, github-token, generic. Teruji fixture 2/2
    tanpa bocor nilai; vs PC asli: bersih (di luar fixture test).
  - `sentinel-reachability`: audit terpasang-vs-dipakai (ast import pypi +
    package.json deps npm); paket OS-managed (global_package_root) diabaikan
    jujur; status INFORMASI — tidak di-wire ke notify. Vs PC: 90 paket sistem
    diabaikan, 0 user-space.
  - `sentinel-winnative`: inventaris Windows asli via interop WSL
    (keputusan: tanpa dep Go baru; powershell.exe/reg/schtasks + timeout).
    Hasil PC: 115 program, 91 modul PS, 424 scheduled task, 20 startup
    (winget terlewat/timeout — tercatat).
  - `sentinel-notify`: di-wire untuk typosquat + secretscan (DRY_RUN
    terverifikasi; pesan secret aman by construction).
  - Semua terpasang di `~/.local/bin/sentinel-*` (total 10 tool).
