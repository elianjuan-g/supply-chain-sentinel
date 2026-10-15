# Gate Desain — Ide Liar Sentinel (EKSPERIMENTAL)

> Disusun: 2026-10-16. Prinsip: premortem dulu, aksi kemudian.
> **Update 2026-10-16 (atas "Gass" MyLord):** canary DEPLOYED (lihat bawah).
> Simulator masih DOKUMEN — tiap skenario butuh stempel satu per satu.

## 1. Canary Honeypot

**Ide:** umpan palsu (file kredensial dummy, package name menarik) yang dipasang di
lokasi terpantau; bila ada yang menyentuhnya → alert.

**Risiko:**
- False positive: MyLord/alat rumah tangga sendiri bisa menyentuh umpan.
- Umpan kredensial dummy bisa membingungkan (dianggap kredensial asli).
- Bila umpan berupa package di registry publik → melanggar (tidak boleh).

**Gate yang diusulkan (semua HARUS dipenuhi sebelum eksekusi):**
1. G1: Umpan HANYA file lokal di direktori khusus `~/.hermes/sentinel/canary/`
   — TIDAK PERNAH di-publish ke registry mana pun.
2. G2: Isi umpan jelas berlabel `SENTINEL-CANARY-DO-NOT-USE` (bukan kredensial
   yang terlihat asli).
3. G3: Allowlist: sentuhan oleh proses rumah tangga (backup, sync) tidak alert.
4. G4: MyLord menyetujui lokasi + nama umpan secara eksplisit.

## 2. Self-Attack Simulator

**Ide:** simulasi serangan terhadap diri sendiri (mis. install package typosquat
di sandbox, jalankan postinstall mencurigakan di jail) untuk menguji deteksi.

**Risiko:**
- Esekusi kode berbahaya — walau "simulasi", tetap kode berbahaya.
- Sandbox jebol → insiden nyata.
- False negative memberi rasa aman palsu.

**Gate yang diusulkan (semua HARUS dipenuhi sebelum eksekusi):**
1. G1: HANYA di dalam container/jail tanpa akses jaringan + tanpa akses file
   rumah tangga (mount read-only kecuali direktori kerja simulasi).
2. G2: Daftar skenario simulasi ditulis dulu, disetujui MyLord satu per satu.
3. G3: Setiap simulasi WAJIB ada prosedur rollback + verifikasi kebersihan
   setelahnya (hash direktori sebelum/sesudah).
4. G4: TIDAK PERNAH menyentuh package/direktori produksi — hanya fixture.

## Rekomendasi Ciel

Bangun G1–G4 sebagai **dokumen + fixture non-eksekusi dulu** (aman, 0 risiko).
Eksekusi simulasi hanya setelah MyLord men-stempel tiap gate. Canary lebih
aman dari simulator — bila harus pilih satu, mulai dari canary.

## Status Deploy Canary (2026-10-16, atas "Gass" MyLord)

- Lokasi: `/home/elian/.hermes/sentinel/canary/` (G1: lokal saja, tak dipublish)
- 3 file umpan, semua berlabel `SENTINEL-CANARY-DO-NOT-USE` (G2):
  `AWS_CREDENTIALS.CANARY.txt`, `.env.CANARY`, `id_rsa.CANARY`
- Check: `/home/elian/.local/bin/sentinel-canary-check` (manifest mtime+size;
  `--init` sekali, diam bila tak tersentuh; teruji: sentuhan terdeteksi)
- Terhubung ke `sentinel-daily` (cek tiap 07:00)
- G3: sentuhan oleh proses rumah tangga (backup/sync) akan dilaporkan —
  allowlist menyusul bila ada false positive.
