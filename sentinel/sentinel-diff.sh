#!/usr/bin/env bash
# sentinel-diff — Baseline diff untuk Bumblebee Sentinel Edition.
#
# Menjalankan `bumblebee scan --profile baseline`, membandingkan record_id
# dengan baseline sebelumnya, dan HANYA melaporkan yang baru/hilang/berubah.
# Diam (exit 0 tanpa output) bila tidak ada perubahan — sesuai pola "diam bila
# normal" rumah tangga.
#
# Output contract:
#   - $STATE/scan-previous.ndjson : baseline acuan run berikutnya
#   - $STATE/diff-latest.txt      : ringkasan diff terakhir (selalu ditulis)
#   - stdout                      : ringkasan, HANYA bila ada perubahan
#   - exit 0                       : selalu (kecuali scan gagal total)
#
# Env override: BUMBLEBEE_BIN, SENTINEL_STATE
set -euo pipefail

BIN="${BUMBLEBEE_BIN:-$HOME/.local/bin/bumblebee}"
STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
mkdir -p "$STATE"

CUR="$STATE/scan-current.ndjson"
PREV="$STATE/scan-previous.ndjson"
DIFF="$STATE/diff-latest.txt"
TS="$(date '+%Y-%m-%d %H:%M %Z')"

[ -x "$BIN" ] || { echo "sentinel-diff: binary tidak ditemukan: $BIN" >&2; exit 1; }

"$BIN" scan --profile baseline > "$CUR" 2>/dev/null

extract_ids() {
  # kunci dedup = record_id (StableID kanonis) pada package records.
  # NB: pola grep mengasumsikan JSON kompak ala Go (tanpa spasi).
  # Bila format berubah, hasil 0 akan memicu error keras di bawah (fail-closed).
  # Kurung kurawal WAJIB: tanpa itu, `||` mengikat lebih longgar dari `|`
  # sehingga `true | python3 | sort` tidak jalan saat grep sukses.
  { grep '"record_type":"package"' "$1" 2>/dev/null || true; } | python3 -c "
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        print(json.loads(line).get('record_id', ''))
    except Exception:
        pass
" | sort -u
}

extract_ids "$CUR" > "$STATE/ids-current.txt"
TOTAL=$(wc -l < "$STATE/ids-current.txt" | tr -d ' ')

if [ "$TOTAL" -eq 0 ]; then
  echo "sentinel-diff: ERROR: scan menghasilkan 0 package records — format output kemungkinan berubah, investigasi manual diperlukan" >&2
  exit 1
fi

if [ ! -f "$PREV" ]; then
  mv "$CUR" "$PREV"
  cp "$STATE/ids-current.txt" "$STATE/ids-previous.txt"
  {
    echo "=== Sentinel diff $TS ==="
    echo "baseline awal tersimpan: $TOTAL package records"
  } > "$DIFF"
  cat "$DIFF"
  exit 0
fi

extract_ids "$PREV" > "$STATE/ids-previous.txt"
NEW_IDS="$STATE/ids-new.txt"
GONE_IDS="$STATE/ids-gone.txt"
comm -13 "$STATE/ids-previous.txt" "$STATE/ids-current.txt" > "$NEW_IDS" || true
comm -23 "$STATE/ids-previous.txt" "$STATE/ids-current.txt" > "$GONE_IDS" || true
N_NEW=$(wc -l < "$NEW_IDS" | tr -d ' ')
N_GONE=$(wc -l < "$GONE_IDS" | tr -d ' ')

describe_id() {
  # $1 = record_id, $2 = ndjson file
  grep -m1 -F "\"record_id\":\"$1\"" "$2" 2>/dev/null | python3 -c "
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    raise SystemExit
r = json.loads(raw)
print('[' + str(r.get('ecosystem', '?')) + '] ' + str(r.get('package_name', '?')) + ' ' + str(r.get('version', '?')) + (' :: ' + r['project_path'] if r.get('project_path') else ''))
"
}

{
  echo "=== Sentinel diff $TS ==="
  echo "baru: $N_NEW | hilang: $N_GONE | total kini: $TOTAL"
  if [ "$N_NEW" -gt 0 ]; then
    echo "--- BARU ---"
    while IFS= read -r id; do
      [ -n "$id" ] && describe_id "$id" "$CUR"
    done < "$NEW_IDS"
  fi
  if [ "$N_GONE" -gt 0 ]; then
    echo "--- HILANG ---"
    while IFS= read -r id; do
      [ -n "$id" ] && describe_id "$id" "$PREV"
    done < "$GONE_IDS"
  fi
} > "$DIFF"

# rotasi: current menjadi baseline acuan berikutnya
mv "$CUR" "$PREV"
cp "$STATE/ids-current.txt" "$STATE/ids-previous.txt"

if [ "$N_NEW" -gt 0 ] || [ "$N_GONE" -gt 0 ]; then
  cat "$DIFF"
fi
exit 0
