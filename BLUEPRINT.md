# BLUEPRINT — Bumblebee Sentinel Edition (Fork)

> Analisis statis dari source `~/workspace/bumblebee-fork/` (branch `sentinel`,
> identik upstream v0.1.2, Apache-2.0). **Read-only**: tidak ada file source
> yang diubah untuk blueprint ini. Toolchain Go belum tersedia, jadi semua
> klaim di bawah berasal dari pembacaan kode, bukan dari `go build`/`go test`.

## 1. Ringkasan eksekutif

Bumblebee adalah *read-only inventory collector*: ia berjalan di filesystem,
membaca **metadata** (lockfile, manifest, config — bukan isi source code),
lalu mencocokkan daftar package dengan katalog paparan (exposure catalog).
Arsitekturnya sangat rapi untuk dievolusi: tiap ecosystem punya parser
sendiri dengan pola seragam, output-nya NDJSON ber-skema versi, dan
record punya identitas stabil (StableID = sha256 konten) yang membuat
**diff antar run menjadi trivial**.

Keputusan arsitektur terpenting blueprint ini: **jangan fork inti scanner —
bangun DI ATAS output NDJSON-nya** untuk semua fitur non-invasif (diff,
notifikasi, SBOM, refresh intel). Sentuh inti Go hanya untuk hal yang
benar-benar butuh parser/matcher baru (Windows, typosquat, secret scan).
Ini menjaga kita tetap bisa rebase dari upstream tanpa konflik neraka.

---

## 2. Peta arsitektur (aliran data)

```
cmd/bumblebee/main.go          CLI: scan|roots|selftest|version, flags, sink (stdout/file/http)
        │
        ▼
cmd/bumblebee/roots.go         resolveRoots(): profil baseline/project/deep → daftar Root{Path, Kind}
                               (switch runtime.GOOS: HANYA darwin & linux — TIDAK ADA windows)
        │
        ▼
internal/scanner.Run()         orkestrator: worker pool (concurrency), job queue
        │
        ├─▶ internal/walk.Walk()   walker: excludes, proteksi symlink-loop (inode), tidak follow symlink dir
        │        │                  dispatch per basename via predikat Is*() tiap ecosystem
        │        ▼
        │   job{kind, path, ...} ──▶ internal/ecosystem/<nama>/*.Scan*()
        │                              Pola seragam: Scanner{MaxFileSize, Emit, Diag}
        │                              + predikat Is*(base/path) + readBounded()
        │                              Emit(model.Record) per temuan
        ▼
internal/normalize             NPM: lowercase · PyPI: PEP 503 · default: lowercase+trim
        │
        ▼
internal/model                 Record / Finding / ScanSummary / Diagnostic (NDJSON, schema 0.2.0)
                               StableID(): sha256(record_type + field-field kunci) → dedup & diff
                               FindingType saat ini HANYA: "package_exposure"
        │
        ├─▶ internal/exposure  Catalog.Load(file|dir) → index (ecosystem\x00normalized_name)
        │                      MatchAll(): exact (ecosystem, name, version) atau any-version ["*"]
        │                      → model.Finding per match
        │
        └─▶ internal/output.Emitter  dedup via StableID → NDJSON ke sink (stdout/file/HTTP POST)
                                     Diag() → stderr (bukan ke sink records)

Jalur pendukung (offline, bukan bagian binary):
  tools/osvcatalog ──▶ internal/osv: unduh data OSV (ossf/malicious-packages) → konversi
                       record MAL-* menjadi exposure-catalog JSON. Scanner TIDAK PERNAH
                       kontak osv.dev saat scan.
  threat_intel/*.json: katalog kurasi manual (shai-hulud, glassworm, …)
```

### Inventarisasi paket kunci

| Paket | Peran | Ukuran | Catatan untuk fork |
|---|---|---|---|
| `cmd/bumblebee` (main, roots, sink, selftest, version) | CLI + resolusi root + sink | ±1330 baris | `roots.go`: titik masuk dukungan Windows (tambah `case "windows"`) |
| `internal/scanner` | Orkestrator walk→parse→emit→match | ±470 baris | Dispatch table `switch j.kind` — tambah kind baru = tambah parser |
| `internal/walk` | Walker aman (excludes, anti-loop) | ±230 baris | `DefaultExcludes` sentris macOS/Linux; butuh varian Windows |
| `internal/ecosystem/*` (13 paket) | Parser per ecosystem | 150–600 baris/paket | Pola seragam → parser baru tinggal meniru (contoh terbaik: `npm`, `mcp`) |
| `internal/model` | Skema NDJSON 0.2.0 + StableID | ±330 baris | `FindingType*` const = extension point tipe temuan baru |
| `internal/exposure` | Exact-match katalog | ±330 baris | Matcher fuzzy/typosquat = modul baru, jangan ubah yang exact |
| `internal/osv` + `tools/osvcatalog` | Konverter OSV→katalog (offline) | ±470 baris | Fondasi auto-refresh; tinggal bungkus download+swap atomik |
| `internal/output` (+httpsink) | Emitter dedup + sink HTTP | ±200 baris | Pola sink bisa ditiru untuk notifier notification webhook |
| `internal/endpoint` | Identitas host | kecil | Sudah cukup |
| `internal/normalize` | Normalisasi nama | kecil | Tambah normalisasi per ecosystem baru bila perlu |

Fakta penting dari pembacaan kode:
- `Record.HasLifecycleScripts` + `Record.LifecycleScripts` **sudah diisi** parser npm
  (scriptKeys memfilter preinstall/install/postinstall/prepare/…). Postinstall-hunter
  praktis tinggal fungsi skoring — datanya sudah mengalir.
- Parser MCP **sengaja membuang** nilai `env` (privasi). Audit MCP yang aman harus
  mempertahankan prinsip ini: deteksi pola, jangan pernah emit nilai secret.
- Walker **melewatkan** `.env`/`.envrc` dan direktori kredensial (`.ssh`, `.aws`, …).
  Secret scanner = pembalikan prinsip desain yang disengaja → wajib profil opt-in terpisah.
- Tidak ada satu pun `case "windows"` di `roots.go`; `walk/dirkey_unix.go` vs
  `dirkey_other.go` (fallback). Dukungan Windows = fitur baru, bukan porting.

---

## 3. Extension point berperingkat (mudah → sulit)

### MUDAH — tanpa menyentuh inti scanner
1. **Post-processor NDJSON** (binary/script terpisah): `sentinel diff` (bandingkan
   StableID antar run → delta saja), ekspor SBOM CycloneDX, notifier notification webhook.
   Tidak ada perubahan Go inti; bisa Python/Go kecil.
2. **Tipe Finding baru** (`internal/model`): tambah konstanta
   `FindingTypePostinstallRisk`, `FindingTypeTyposquatSuspect`,
   `FindingTypeSecretExposure`, … + skema `docs/schema/`. Situs emit sudah ada
   di `scanner.Run` (loop `Catalog.MatchAll`).
3. **Parser ecosystem baru** (file-based): tiru pola `Scanner{MaxFileSize, Emit, Diag}`
   + predikat `Is*()` + daftarkan `case` di dispatch `scanner.go` + root di `roots.go`.
   Contoh: PowerShell `*.psd1`, Scheduled Tasks XML, Startup folder, Chocolatey `.nuspec`.

### SEDANG — menyentuh inti secara terkendali
4. **Matcher exposure baru**: modul fuzzy (typosquat: edit-distance vs daftar
   package populer per ecosystem) yang hidup berdampingan dengan exact-matcher —
   jangan ubah `exposure.MatchAll` yang sudah teruji.
5. **Perluasan parser MCP**: deteksi server *baru* vs baseline, flag `npx -y`/selector
   `@latest` tak terpin, heuristik nama key `env` yang mirip secret (nama saja,
   bukan nilai).
6. **Kasus Windows di `roots.go`** + `DefaultExcludes` varian Windows
   (`AppData`, `Program Files`, …). Perhatikan: path Windows butuh penanganan
   separator di predikat `Is*` (beberapa sudah sadar Windows, mis. `looksLikePackageSpec`).

### SULIT — keputusan desain / dependensi
7. **Pembacaan konten source** (secret scan, reachability): melanggar invarian
   "tidak membaca source file" yang disengaja. Wajib: profil opt-in terpisah
   (`--profile deep` saja), `max-duration` ketat, dan finding yang **tidak pernah**
   membawa nilai secret (hanya nama pola + file:baris).
8. **Sumber berbasis registry Windows** (WinGet/Uninstall, Run keys): stdlib Go
   **tidak bisa** membaca registry → pilihan: (a) dependensi `golang.org/x/sys`
   (merusak kemurnian zero-dependency), atau (b) eksekusi `reg.exe` read-only
   (merusak prinsip "tidak mengeksekusi apa pun"). Butuh keputusan desain eksplisit
   sebelum dikerjakan — dahulukan sumber file-based (butir 3) yang bebas dilema ini.

---

## 4. Creation Synthesis (formal)

### 4a. Kontradiksi TRIZ inti

> **Jika** KEDALAMAN inspeksi membaik (byte konten pengguna yang dibaca per run naik
> dari ~5 MB metadata menjadi >500 MB source + registry, dan kelas temuan naik dari
> 1 menjadi ≥4), **maka** KECEPATAN memburuk (durasi scan baseline naik dari hitungan
> detik menjadi hitungan menit) **dan** JAMINAN PRIVASI memburuk (dari "tidak pernah
> menyentuh source/kredensial" menjadi "membaca semua source").

Resolusi TRIZ yang dipakai: **Segmentasi** (scan dalam vs dangkal jadi profil
terpisah, bukan satu mode), **Aksi Pendahulu** (intel dihitung offline via osvcatalog —
pola yang sudah ada, tinggal otomatisasi), **Sebaliknya** (jangan scanner yang
membaca lebih banyak — tapi *receiver* yang berlangganan delta), **Murah/berumur
pendek** (deep scan dibatasi `max-duration` ketat).

### 4b. SCAMPER atas pipeline Bumblebee

| Huruf | Pemicu → Aplikasi singkat |
|---|---|
| **S**ubstitute | Ganti exact-match exposure dengan fuzzy-match untuk typosquat; ganti katalog JSON statis dengan feed OSV yang di-refresh otomatis. |
| **C**ombine | Gabungkan inventory package + audit MCP + secret-scan menjadi satu "posture record" per host; gabungkan `osvcatalog refresh` sebagai pre-scan hook. |
| **A**dapt | Adaptasi penanganan `env`-block parser MCP (buang nilai, simpan sinyal) menjadi credential-hygiene auditor: flag *keberadaan* key mirip-secret tanpa pernah mengutip nilainya. |
| **M**odify/Magnify | Besarkan capture lifecycle-script yang sudah ada (npm) menjadi postinstall-risk scorer lintas ecosystem. |
| **P**ut to other use | Pakai ulang NDJSON untuk hal lain: ekspor SBOM CycloneDX, baseline diff, alert notification webhook — semua tanpa menyentuh binary. |
| **E**liminate | Eliminasi full-scan berulang: emit hanya delta via StableID (incremental), full scan hanya mingguan. |
| **R**everse | Balik arah aliran: bukan scanner push ke sink, tapi receiver pull delta; balik arah matching: selain katalog→host, juga host→baseline-terakhir (drift detection). |

### 4c. DIVERGE — 12 opsi power-up (penilaian ditunda)

1. **Secret-scan engine** — scan regex+entropi atas source file, finding `secret_exposure` berisi nama pola + file:baris (nilai secret tidak pernah di-emit).
2. **Ecosystem Windows native (file-based)** — modul PowerShell (`*.psd1`), Scheduled Tasks XML, folder Startup, Chocolatey `.nuspec`, + `case "windows"` di roots & excludes.
3. **Postinstall-hook hunter** — skor konten `LifecycleScripts` (pipa curl|bash, blob base64, URL outbound) → finding `postinstall_risk`.
4. **Deteksi typosquatting** — edit-distance vs daftar package populer per ecosystem → finding `typosquat_suspect` (mode findings-only).
5. **Reachability analyzer** — parse import JS/TS/Python/Go di project root; tandai package terinstall-tapi-tak-dipakai; tekan noise exposure untuk yang tak dipakai.
6. **Intel auto-refresh** (`sentinel refresh`) — unduh ossf/malicious-packages → jalankan osvcatalog → swap atomik katalog, simpan N versi terakhir.
7. **Baseline diff** (`sentinel diff`) — bandingkan NDJSON antar run via StableID; emit hanya record/finding baru/berubah/hilang.
8. **notification webhook notifier** — finding → pesan bridge/notification webhook, dedup via StableID, tier notifikasi (kritis vs info).
9. **Eksportir SBOM CycloneDX** — NDJSON → CycloneDX 1.5 JSON (post-processor).
10. **MCP posture auditor** — server baru vs baseline, flag `npx -y`/selector `@latest`, heuristik nama key env mirip-secret (nama saja).
11. **[LIAR] Canary honeypot** — tanam package/file canary (token `.npmrc` palsu, entri MCP server canary) yang tidak pernah disentuh tool legit; bila terbaca/terekfiltrasi → alert. Lapisan deception.
12. **[LIAR] Self-attack simulator** — Sentinel berkala menjatuhkan fixture "package jahat" palsu ke sandbox tree lalu menjalankan pipeline penuh untuk *membuktikan* deteksi masih bekerja — red-team vs blue-team dalam satu binary, continuous proof-of-detection.

### 4d. CONVERGE — skor 1–5 (feasibility, impact, cost↓=skor↑, risk↓=skor↑)

| # | Opsi | Feas | Impact | Cost | Risk | Total |
|---|---|---|---|---|---|---|
| 7 | Baseline diff | 5 | 4 | 5 | 5 | **19** ✅ pemenang |
| 3 | Postinstall-hook hunter | 5 | 4 | 5 | 4 | 18 |
| 6 | Intel auto-refresh | 5 | 4 | 5 | 4 | 18 |
| 8 | notification webhook notifier | 5 | 4 | 5 | 4 | 18 |
| 9 | SBOM CycloneDX exporter | 5 | 3 | 5 | 5 | 18 |
| 10 | MCP posture auditor | 4 | 5 | 4 | 4 | 17 |
| 2 | Windows native (file-based) | 4 | 5 | 3 | 4 | 16 |
| 4 | Typosquat detector | 4 | 3 | 4 | 3 | 14 |
| 12 | [LIAR] Self-attack simulator | 4 | 3 | 3 | 4 | 14 |
| 1 | Secret-scan engine | 3 | 5 | 2 | 2 | 12 |
| 5 | Reachability analyzer | 2 | 3 | 2 | 3 | 10 |
| 11 | [LIAR] Canary honeypot | 3 | 2 | 3 | 2 | 10 |

**Pemenang: #7 Baseline diff (19).** Alasan: satu-satunya opsi yang *mengalikan* nilai
semua opsi lain (tanpa diff, setiap detektor = noise); trivial dibangun di atas
StableID yang sudah content-addressed; risiko nol; dan ia membuka jalan bagi
alerting yang waras.

**Satu kalimat penolakan tiap opsi yang kalah:**
- #3: kalah selisih 1 poin — tetap prioritas kedua karena datanya sudah mengalir.
- #6: kalah selisih 1 poin — prasyarat agar katalog tidak basi; dikerjakan segera setelah diff.
- #8: butuh #7 dulu agar tidak membanjiri notification webhook; tanpa dedup ia adalah spam generator.
- #9: nilai keamanan langsung kecil — artefak bukti yang bagus, bukan detektor.
- #10: dampak tertinggi untuk homelab ini, tapi butuh definisi "baseline MCP" dulu (#7).
- #2: dampak besar (target deploy = PC Windows) namun butuh keputusan registry (butir 8) untuk versi penuhnya.
- #4: serangan nyata tapi jarang; risiko false-positive pada nama yang mirip secara sah.
- #12: secara filosofis kuat (proof-of-detection) tapi praktisnya adalah test harness — mewah untuk sekarang.
- #1: dampak terbesar kedua, namun menabrak invarian privasi desain dan butuh profil opt-in + tuning FP yang panjang.
- #5: parsing import multi-bahasa yang akurat adalah proyek tersendiri; nilai/usaha terburuk.
- #11: menyenangkan tapi nilai deteksi marjinal dan berisiko membingungkan tool legit (self-inflicted FP).

---

## 5. Premortem — andaikan fork gagal total dalam 3 bulan

| # | Penyebab kegagalan paling mungkin | Mitigasi |
|---|---|---|
| 1 | **Drift & beban maintenance**: upstream merilis schema v0.3/breaking change; rebase menumpuk konflik; fork membusuk. | Jaga fork inti tetap minimal — fitur baru sebagai paket/binary terpisah yang mengonsumsi NDJSON; rebase terjadwal tiap tag upstream; ekstensi skema hanya aditif. |
| 2 | **Kelelahan noise**: secret-scan/typosquat membanjiri notification webhook dengan FP → operator mute → sistem jadi hiasan. | Diff dulu (#7), detektor berisik belakangan; tier severity; allowlist FP; ambang "alert hanya untuk delta kritis". |
| 3 | **Ledakan performa**: secret-scan + reachability mengubah scan detik menjadi menit/jam → cron tumpang tindih, PC meraung, operator mematikan. | Fitur berat hanya di profil `deep` opt-in; `max-duration` ketat sebagai default; benchmark di PC riil sebelum diaktifkan default. |
| 4 | **Insiden privasi**: bug di secret scanner meng-emit nilai secret mentah ke diagnostic/notification webhook → kepercayaan hancur. | Finding tidak pernah membawa nilai secret (nama pola + file:baris saja); fixture berisi secret palsu di test; anggap jalur diagnostic sebagai tidak tepercaya. |
| 5 | **Jebakan dependensi Windows**: pilih `x/sys` (rusak kemurnian zero-dep) atau `reg.exe` (rusak prinsip no-exec) tanpa keputusan → setengah jalan, rapuh. | Keputusan desain eksplisit tertulis dulu; dahulukan sumber file-based (psd1, Tasks XML, startup folder, nuspec) yang bebas dilema; registry = modul opsional bermarkah jelas. |

---

## 6. Urutan build Fase 3 yang direkomendasikan

1. `sentinel diff` — post-processor NDJSON via StableID (fondasi segalanya).
2. `sentinel refresh` — bungkus download OSV + osvcatalog + swap atomik + cron mingguan.
3. Postinstall-hook hunter — tipe finding baru di atas `LifecycleScripts` yang sudah ada.
4. notification webhook notifier — di atas #1, dedup + tier.
5. MCP posture auditor — butuh #1 untuk definisi "server baru".
6. Ecosystem Windows file-based + `case "windows"` di roots/excludes.
7. Typosquat detector (mode findings-only).
8. Eksportir SBOM CycloneDX.
9. Secret-scan engine — profil opt-in, finding ter-redaksi (ditunda: risiko privasi).
10. Reachability analyzer (ditunda: sulit, nilai/usaha rendah).
11. Ide liar (#11 canary, #12 self-attack sim) — eksperimental, default mati.
12. Sumber registry Windows — hanya setelah keputusan dependensi eksplisit.

Aturan main selama build: tiap fitur baru wajib mengikuti pola fixture-test
seperti `selftest.go`; perubahan skema bersifat aditif; file `LICENSE`
Apache-2.0 + atribusi upstream dipertahankan.

---

## 7. Yang tidak saya ketahui (jujur)

- Belum menjalankan `go build`/`go test` — tidak ada toolchain Go di VM maupun PC
  saat analisis; semua klaim extension point berasal dari pembacaan statis.
- Belum verifikasi seberapa besar overlap GitHub Advisory (GHSA) vs set MAL- di
  OSV — klaim "OSV saja cukup" masih hipotesis, perlu dicek sebelum #6 final.
- Belum mengukur durasi scan riil di PC operator (baseline di WSL) — angka
  "hitungan detik" berasal dari klaim desain upstream, bukan pengukuran.
- Bentuk fisik WinGet di disk (apakah cukup dari file tanpa registry) belum
  diteliti — butir #2 fase file-based menghindari ini, tapi WinGet penuh mungkin
  tetap butuh registry.
- `walk/dirkey_other.go` belum dibaca baris-per-baris — diasumsikan fallback
  non-Unix; proteksi symlink-loop di Windows perlu verifikasi saat implementasi.
