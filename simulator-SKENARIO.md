# Self-Attack Simulator — Daftar Skenario (DOKUMEN SAJA, BELUM DIEKSEKUSI)

> Gate G2: tiap skenario butuh stempel MyLord satu per satu SEBELUM eksekusi.
> Gate G1: eksekusi HANYA di sandbox tanpa jaringan + tanpa akses file rumah tangga.
> Gate G3: tiap skenario wajib rollback + verifikasi kebersihan (hash sebelum/sesudah).
> Gate G4: TIDAK PERNAH menyentuh package/direktori produksi — hanya fixture.

## Skenario yang diusulkan

### S-01: Typosquat install di sandbox
- **Aksi:** buat package npm lokal bernama `lodahs` (fixture), install di
  direktori sandbox kosong, jalankan `sentinel-typosquat` → harus flag TINGGI.
- **Risiko:** rendah (fixture lokal, tanpa publish).
- **Verifikasi:** sandbox dihapus total setelahnya; hash direktori kerja kembali.

### S-02: Postinstall mencurigakan di sandbox
- **Aksi:** package fixture dengan skrip `postinstall` yang mencoba menulis ke
  `/tmp/sim-probe` (jinak, tanpa jaringan); jalankan install di sandbox;
  `sentinel-postinstall` harus memberi skor ≥7.
- **Risiko:** sedang (kode berjalan walau jinak).
- **Verifikasi:** `/tmp/sim-probe` tidak boleh ada di luar sandbox; sandbox dihapus.

### S-03: Secret-scan terhadap fixture bocor
- **Aksi:** tulis file fixture berisi pola `AKIA...` palsu di sandbox;
  `SENTINEL_SECRETSCAN=1 sentinel-secretscan` harus menangkap tanpa
  memancarkan nilainya.
- **Risiko:** rendah (pola palsu, terlabel fixture).
- **Verifikasi:** tidak ada nilai secret di output/log.

### S-04: (DITAHAN) Simulasi serangan jaringan / privilege escalation
- **Status:** TIDAK diusulkan untuk dieksekusi. Melebihi batas aman rumah tangga.

## Rekomendasi Ciel

Mulai dari S-01 (risiko terendah, nilai validasi tinggi). S-02 setelah S-01
bersih. S-03 bisa jalan kapan saja (read-only). S-04 jangan pernah.
