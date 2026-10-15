#!/usr/bin/env bash
# sentinel-refresh — Refresh katalog paparan (exposure catalog) Sentinel.
#
# Alur: shallow+sparse clone ossf/malicious-packages -> build osvcatalog ->
# generate katalog MAL-* -> gabung katalog kurasi bawaan fork -> validasi ->
# swap atomik. Katalog live TIDAK diganti bila validasi gagal (fail-safe).
#
# Kontrak:
#   - $STATE/catalog/      : direktori katalog live (untuk --exposure-catalog)
#   - $STATE/catalog.prev/ : katalog sebelumnya (fallback manual)
#   - $STATE/refresh.log   : riwayat refresh
#   - exit 0 + ringkasan singkat bila sukses; exit 1 + pesan bila gagal
set -euo pipefail

SRC="${SENTINEL_SRC:-$HOME/src/bumblebee-fork}"
STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
REPO_URL="https://github.com/ossf/malicious-packages"
MP_DIR="$STATE/malicious-packages"
CAT_NEW="$STATE/catalog.new"
CAT_LIVE="$STATE/catalog"
LOG="$STATE/refresh.log"

mkdir -p "$STATE"
export PATH="$HOME/.local/go/bin:$PATH"

# 1. build osvcatalog bila belum ada
OSVCATALOG="$STATE/bin/osvcatalog"
if [ ! -x "$OSVCATALOG" ]; then
  [ -d "$SRC/tools/osvcatalog" ] || { echo "sentinel-refresh: ERROR: source fork tidak ada: $SRC" >&2; exit 1; }
  mkdir -p "$STATE/bin"
  ( cd "$SRC" && go build -o "$OSVCATALOG" ./tools/osvcatalog ) || { echo "sentinel-refresh: ERROR: build osvcatalog gagal" >&2; exit 1; }
fi

# 2. sparse shallow clone (hanya butuh osv/malicious/)
if [ -d "$MP_DIR/.git" ]; then
  BRANCH="$(git -C "$MP_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
  if ! git -C "$MP_DIR" fetch --depth 1 -q origin "$BRANCH" 2>/dev/null \
    || ! git -C "$MP_DIR" reset -q --hard FETCH_HEAD 2>/dev/null; then
    echo "sentinel-refresh: WARN: update gagal, clone ulang" >&2
    rm -rf "$MP_DIR"
    git clone --depth 1 --filter=blob:none --sparse -q "$REPO_URL" "$MP_DIR"
    git -C "$MP_DIR" sparse-checkout set osv/malicious
  fi
else
  rm -rf "$MP_DIR"
  git clone --depth 1 --filter=blob:none --sparse -q "$REPO_URL" "$MP_DIR" \
    || { echo "sentinel-refresh: ERROR: clone gagal" >&2; exit 1; }
  git -C "$MP_DIR" sparse-checkout set osv/malicious
fi
OSV_SRC="$MP_DIR/osv/malicious"
[ -d "$OSV_SRC" ] || { echo "sentinel-refresh: ERROR: path tak ada: $OSV_SRC" >&2; exit 1; }

# 3. generate katalog
rm -rf "$CAT_NEW"; mkdir -p "$CAT_NEW"
STAMP="$(date -u '+%Y-%m-%dT%H:%MZ')"
"$OSVCATALOG" -o "$CAT_NEW/osv-malicious.json" --source "$REPO_URL@$STAMP" "$OSV_SRC" 2>/dev/null \
  || { echo "sentinel-refresh: ERROR: osvcatalog gagal" >&2; exit 1; }
# katalog kurasi bawaan fork (kampanye besar: shai-hulud, glassworm, dsb.)
if [ -d "$SRC/threat_intel" ]; then
  cp "$SRC"/threat_intel/*.json "$CAT_NEW/" 2>/dev/null || true
fi

# 4. validasi sebelum swap (fail-safe)
python3 - "$CAT_NEW" <<'EOF'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1])
files = sorted(d.glob("*.json"))
assert files, "tidak ada file katalog"
for f in files:
    json.loads(f.read_text())  # raise bila rusak
main = d / "osv-malicious.json"
assert main.exists() and main.stat().st_size > 1000, "osv-malicious.json kosong/rusak"
print(f"valid: {len(files)} katalog")
EOF

# 5. swap atomik
[ -d "$CAT_LIVE" ] && rm -rf "$STATE/catalog.prev" && mv "$CAT_LIVE" "$STATE/catalog.prev"
mv "$CAT_NEW" "$CAT_LIVE"
N=$(ls "$CAT_LIVE"/*.json 2>/dev/null | wc -l | tr -d ' ')
echo "$(date '+%Y-%m-%d %H:%M %Z') refresh OK: $N katalog ($(du -sh "$CAT_LIVE" | cut -f1)))" | tee -a "$LOG"
