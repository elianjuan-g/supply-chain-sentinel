#!/usr/bin/env bash
# sentinel-secretscan — Pemindai secret di file proyek (Fase 3).
#
# DESAIN PRIVASI (ditulis SEBELUM implementasi, mengikat — jangan dilonggarkan
# tanpa persetujuan eksplisit Tuan):
#   1. OPT-IN PENUH: hanya berjalan bila SENTINEL_SECRETSCAN=1. Tanpa itu,
#      script mencetak "nonaktif (opt-in)" lalu exit 0. Default = tidak
#      memindai apa pun. (Ini SENGAJA membalik desain privasi upstream
#      Bumblebee yang menolak secret scanning — di sini pemilik mesin
#      yang memutuskan.)
#   2. TIDAK PERNAH memancarkan nilai secret: laporan hanya berisi
#      <file>:<baris> + JENIS pola. Tidak ada potongan nilai, tidak ada
#      prefix, tidak ada hash nilai. Aturan ini berlaku juga untuk output
#      notifier (sentinel-notify hanya membaca file laporan ini).
#   3. CAKUPAN TERBATAS: root default $HOME/src $HOME/workspace
#      (ditambah $SENTINEL_SCAN_ROOTS bila di-set). TIDAK menyentuh:
#      ~/.ssh ~/.aws ~/.gnupg ~/.config ~/.cache, profil browser,
#      dan file credential store apa pun. Direktori node_modules/.git/
#      .cache/__pycache__/dist/build/test/tests selalu dilewati, begitu pula
#      file *test*/*spec* (fixture kredensial palsu di test = noise, bukan
#      kebocoran; ini praktik standar gitleaks/trufflehog).
#   4. File >1MB dilewati; file biner (NUL byte) dilewati.
#   5. Pola kecil & terdokumentasi di bawah — ini HEURISTIK pola, bukan
#      bukti kebocoran. False positive mungkin (contoh: string contoh di
#      dokumentasi). Setiap temuan wajib ditinjau manusia.
#
# Pola yang dipindai:
#   aws-key:      AKIA[0-9A-Z]{16}
#   private-key:  -----BEGIN [RSA |EC |OPENSSH |DSA ]?PRIVATE KEY-----
#   github-token: ghp_|gho_|ghu_|ghs_|ghr_ + >=36 char alnum
#   generic:      (password|passwd|secret|api[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]
#   (nilai di kanan pola generic TIDAK PERNAH dicatat — hanya lokasi + tipe)
#
# Kontrak:
#   - stdout: "nonaktif (opt-in)" bila SENTINEL_SECRETSCAN!=1; temuan bila ada;
#     diam bila bersih dan opt-in aktif
#   - $STATE/secretscan-latest.txt: laporan terakhir ("temuan: N" + baris [secret <tipe>] file:baris)
#   - exit 0 selalu (kecuali dependensi hilang)
set -euo pipefail

STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
OUT="$STATE/secretscan-latest.txt"
mkdir -p "$STATE"

if [ "${SENTINEL_SECRETSCAN:-0}" != "1" ]; then
  echo "nonaktif (opt-in): set SENTINEL_SECRETSCAN=1 untuk memindai"
  printf '=== Sentinel secret-scanner %s ===\nstatus: nonaktif (opt-in)\ntemuan: 0\n' \
    "$(date '+%Y-%m-%d %H:%M %Z')" > "$OUT"
  exit 0
fi

# Root default: hanya direktori proyek; yang tidak ada dilewati diam-diam.
ROOTS="${SENTINEL_SCAN_ROOTS:-$HOME/src $HOME/workspace $HOME/hermes-hub-r2}"
EXIST=""
for d in $ROOTS; do
  [ -d "$d" ] && EXIST="$EXIST $d"
done
if [ -z "${EXIST//[[:space:]]/}" ]; then
  echo "sentinel-secretscan: tidak ada root proyek yang ada — diam" >&2
  printf '=== Sentinel secret-scanner %s ===\nstatus: root kosong\ntemuan: 0\n' \
    "$(date '+%Y-%m-%d %H:%M %Z')" > "$OUT"
  exit 0
fi

# Kumpulkan file kandidat: teks, <=1MB, bukan biner, bukan direktori terlarang.
LIST="$STATE/secretscan-files.txt"
: > "$LIST"
for d in $EXIST; do
  find "$d" \
    \( -path "*/node_modules/*" -o -path "*/.git/*" -o -path "*/.cache/*" \
       -o -path "*/__pycache__/*" -o -path "*/dist/*" -o -path "*/build/*" \
       -o -path "*/test/*" -o -path "*/tests/*" \) -prune \
    -o -type f -size -1024k ! -name "*test*" ! -name "*spec*" -print 2>/dev/null >> "$LIST" || true
done

python3 - "$LIST" > "$STATE/secretscan-findings.txt" <<'EOF' || true
import re, sys

PATTERNS = [
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("generic", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]

def is_binary(path):
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except Exception:
        return True

findings = []
with open(sys.argv[1]) as f:
    files = [l.strip() for l in f if l.strip()]

for path in files:
    if is_binary(path):
        continue
    try:
        fh = open(path, "r", encoding="utf-8", errors="strict")
    except Exception:
        continue
    with fh:
        for n, line in enumerate(fh, 1):
            for tname, rx in PATTERNS:
                if rx.search(line):
                    # SENGAJA: hanya tipe + lokasi. Nilai TIDAK PERNAH dicatat.
                    findings.append((tname, path, n))
                    break  # satu baris = satu temuan (tipe pertama yang cocok)
            if len(findings) >= 200:
                break
    if len(findings) >= 200:
        break

for tname, path, n in findings:
    print(f"[secret {tname}] {path}:{n}")
print(f"TOTAL:{len(findings)}")
if len(findings) >= 200:
    print("CATATAN: dibatasi 200 temuan pertama")
EOF

TOTAL=$(grep -E "^TOTAL:" "$STATE/secretscan-findings.txt" | cut -d: -f2 || true)
grep -v -E "^(TOTAL|CATATAN):" "$STATE/secretscan-findings.txt" > "$STATE/secretscan-body.txt" || true
{
  echo "=== Sentinel secret-scanner $(date '+%Y-%m-%d %H:%M %Z') ==="
  echo "catatan: OPT-IN aktif; nilai secret TIDAK PERNAH dicatat — hanya lokasi + tipe pola"
  echo "temuan: ${TOTAL:-0}"
  [ "${TOTAL:-0}" -gt 0 ] 2>/dev/null && cat "$STATE/secretscan-body.txt"
  grep -E "^CATATAN:" "$STATE/secretscan-findings.txt" || true
} > "$OUT"

if [ "${TOTAL:-0}" -gt 0 ] 2>/dev/null; then
  cat "$STATE/secretscan-body.txt"
fi
exit 0
