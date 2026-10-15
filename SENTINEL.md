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
  - `sentinel-diff.sh` — baseline diff: hanya lapor package baru/hilang/berubah
- `BLUEPRINT.md` — peta arsitektur + hasil diverge→converge + premortem

## Status

- Fase 1 (fondasi): SELESAI 2026-10-15 — Go 1.27.2 di PC, `go build` + `go test ./...`
  hijau (24 paket), `sentinel-diff.sh` terverifikasi 3 skenario di PC.
- Fase 2 (lapisan Sentinel): berjalan — diff ✓, berikutnya: refresh intel,
  notifier Meja Bar, audit MCP.
- Fase 3 (overpower): sesuai urutan build di `BLUEPRINT.md`.
