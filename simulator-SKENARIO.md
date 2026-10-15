# Self-Attack Simulator — Daftar Skenario (DOKUMEN SAJA, BELUM DIEKSEKUSI)

> Gate G2: tiap skenario butuh stempel MyLord satu per satu SEBELUM eksekusi.
> Gate G1: eksekusi HANYA di sandbox tanpa jaringan + tanpa akses file rumah tangga.
> Gate G3: tiap skenario wajib rollback + verifikasi kebersihan (hash sebelum/sesudah).
> Gate G4: TIDAK PERNAH menyentuh package/direktori produksi — hanya fixture.

## Skenario yang diusulkan

### S-01: Typosquat install di sandbox
- **Aksi:** record fixture `lodahs@9.9.9` (npm) di scan sandbox;
  `sentinel-typosquat` harus flag TINGGI (jarak 1 dari `lodash`).
- **Hasil uji 2026-10-16:** PASS — `[typosquat jarak=1 TINGGI] lodahs mirip 'lodash'`.
- **Risiko:** rendah (fixture lokal, tanpa publish).

### S-02: Postinstall mencurigakan di sandbox
- **Aksi:** package fixture dengan skrip `postinstall` berpola `curl|bash`;
  hunter membaca ISI hook (read-only, tidak dieksekusi) dan harus memflag
  (skor ≥3 = dilaporkan).
- **Hasil uji 2026-10-16:** PASS — terflag `[mencurigakan skor=4]`
  (rule curl|bash=3 + curl=1). Ekspektasi awal "≥7" dikoreksi: ambang lapor
  yang benar adalah ≥3.
- **Risiko:** rendah (hook hanya dibaca, tidak dijalankan).
- **Verifikasi:** sandbox dihapus total setelahnya.

### S-03: Secret-scan terhadap fixture bocor
- **Aksi:** file fixture berisi pola `AKIA...` palsu + `db_password` di sandbox;
  `SENTINEL_SECRETSCAN=1 sentinel-secretscan` harus menangkap keduanya tanpa
  memancarkan nilainya.
- **Hasil uji 2026-10-16:** PASS parsial → temuan nyata: pola `db_password`
  LOLOS karena `\b` ketat. Diperbaiki: `(?:^|[^a-zA-Z0-9])` — kini keduanya
  tertangkap, nilai tetap tidak bocor.
- **Risiko:** rendah (pola palsu, terlabel fixture).

### S-04: (DITAHAN) Simulasi serangan jaringan / privilege escalation
- **Status:** TIDAK diusulkan untuk dieksekusi. Melebihi batas aman rumah tangga.

## Rekomendasi Ciel

Mulai dari S-01 (risiko terendah, nilai validasi tinggi). S-02 setelah S-01
bersih. S-03 bisa jalan kapan saja (read-only). S-04 jangan pernah.
