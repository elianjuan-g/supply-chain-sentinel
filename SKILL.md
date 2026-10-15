---
name: bumblebee
description: >
  Supply-chain security scanner — pemindai read-only untuk inventaris
  package/ekstensi di endpoint developer (npm, PyPI, Go, RubyGems, Composer,
  ekstensi editor/browser, MCP configs). Menjawab: "apakah mesin ini kena
  package yang terkompromi?" dari advisory. Output NDJSON terstruktur.
  Use when: "supply chain", "package terkompromi", "cek dependency",
  "advisory", atau setelah ada kabar paket npm/PyPI dibajak.
version: 1.0
license: Apache-2.0
metadata:
  owner: Ciel
  status: draft
  reviewed_at: 2026-10-15
  upstream: https://github.com/perplexityai/bumblebee
  local_path: upstream-bumblebee/
---

# Bumblebee — Supply-Chain Scanner (upstream)

Repo upstream utuh di `upstream-bumblebee/` (clone depth-1, 2026-10-15).
Binary Go tunggal, nol dependensi non-stdlib. Read-only: tidak mengeksekusi
package manager, tidak membaca source file.

## Cara pakai

```bash
# build (butuh Go 1.25+)
go build -o bumblebee ./cmd/bumblebee
bumblebee selftest

# inventaris baseline
bumblebee scan --profile baseline > inventory.ndjson

# cek paparan terhadap advisory tertentu
bumblebee scan --profile deep --root "$HOME" \
  --exposure-catalog ./catalog.json --findings-only
```

Katalog paparan contoh: `upstream-bumblebee/threat_intel/`.

## Batas jujur

- Butuh Go 1.25+ untuk build — VM Ciel belum tentu punya; PC WSL bisa dipasang.
- Berjalan di mesin target (PC Tuanku), bukan dari cloud VM.
- Hanya mencocokkan (ecosystem, name, version) terhadap katalog — bukan
  pendeteksi malware generik.

## Kombinasi kreatif

- **Bumblebee × Strix**: Bumblebee jaga rantai pasok (dependency bersih?),
  Strix jaga aplikasi (ada celah?). Dua lapis pertahanan rumah tangga.
- **Bumblebee × fw-watch**: tiap ada advisory besar (mis. npm dibajak),
  jalankan deep scan di PC, hasilnya masuk Meja Bar bila ada temuan.
- Dijadwalkan: cron mingguan `baseline` di PC sebagai "pos jaga" supply chain.
