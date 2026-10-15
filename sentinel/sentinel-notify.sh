#!/usr/bin/env bash
# sentinel-notify — Kirim temuan Sentinel ke Meja Bar, hanya bila ada yang baru.
#
# Membaca diff-latest.txt + mcp-latest.txt, menyusun SATU pesan ringkas,
# dedup via hash (tidak repost temuan yang sama), diam total bila tak ada temuan.
# Pesan SENGAJA tanpa timestamp agar stabil untuk dedup.
# Pola posting mengikuti fw-watch.py: sender CIEL, token via ?k= .
#
# Kontrak:
#   - stdout : "posted OK" bila terkirim, "DRY_RUN: ..." bila DRY_RUN=1, diam bila tak ada temuan
#   - $STATE/last-notified.hash : hash pesan terakhir yang terkirim (hanya ditulis saat sukses)
#   - exit 0 selalu; kegagalan post dicatat ke stderr dan dicoba lagi di run berikut
set -euo pipefail

STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
MEJA_API="${MEJA_API:-http://100.87.176.12:8788/api/post}"
TOKEN_F="/home/elian/.hermes/meja-bar-app/token.txt"
HASH_F="$STATE/last-notified.hash"

MSG=""

# --- temuan diff package ---
DIFF_F="$STATE/diff-latest.txt"
if [ -f "$DIFF_F" ] && grep -qE "baru: [1-9]|hilang: [1-9]" "$DIFF_F" 2>/dev/null; then
  SUM=$(grep -E "^(baru|===)" "$DIFF_F" | head -2 | tr '\n' ' ' | sed 's/  */ /g')
  DETAIL=$(awk '/--- BARU ---/{f=1;next} /--- HILANG ---/{f=0} f' "$DIFF_F" | head -8)
  MSG="🛡️ [Sentinel] Perubahan package: $SUM"
  if [ -n "$DETAIL" ]; then
    MSG="$MSG"$'\n'"$DETAIL"
  fi
  NGONE=$(grep -oE "hilang: [0-9]+" "$DIFF_F" 2>/dev/null | awk '{print $2}' || true)
  if [ "${NGONE:-0}" -gt 0 ] 2>/dev/null; then
    MSG="$MSG"$'\n'"(ada package yang hilang — cek $DIFF_F)"
  fi
fi

# --- temuan MCP ---
MCP_F="$STATE/mcp-latest.txt"
if [ -f "$MCP_F" ]; then
  N=$(grep -oE "unknown: [0-9]+" "$MCP_F" 2>/dev/null | awk '{print $2}' || true)
  if [ "${N:-0}" -gt 0 ] 2>/dev/null; then
    MLIST=$(grep -v -E "^(===|terdeteksi|unknown:|---)" "$MCP_F" | head -8)
    MSG="$MSG"$'\n'"⚠️ Server MCP tak dikenal ($N):"$'\n'"$MLIST"
  fi
fi

# --- temuan postinstall-hunter ---
PI_F="$STATE/postinstall-latest.txt"
if [ -f "$PI_F" ]; then
  P=$(grep -oE "temuan: [0-9]+" "$PI_F" 2>/dev/null | awk '{print $2}' || true)
  if [ "${P:-0}" -gt 0 ] 2>/dev/null; then
    PLIST=$(grep -E "^\[(KRITIS|mencurigakan)" "$PI_F" | head -8)
    MSG="$MSG"$'\n'"🔍 Install-hook mencurigakan ($P):"$'\n'"$PLIST"
  fi
fi

# buang baris kosong di tepi
MSG="$(printf '%s' "$MSG" | sed -e '/./,$!d' -e :a -e '/^\n*$/{$d;N;ba' -e '}')"
if [ -z "${MSG//[[:space:]]/}" ]; then
  exit 0 # diam: tak ada temuan
fi

# batasi panjang (Meja Bar bukan log)
if [ "${#MSG}" -gt 1500 ]; then
  MSG="${MSG:0:1500}"$'\n'"…(dipotong; detail di $STATE)"
fi

# dedup: jangan repost temuan yang sama
HASH="$(printf '%s' "$MSG" | sha256sum | cut -d' ' -f1)"
if [ -f "$HASH_F" ] && [ "$(cat "$HASH_F")" = "$HASH" ]; then
  exit 0
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "DRY_RUN — pesan yang akan dikirim:"
  printf '%s\n' "$MSG"
  exit 0
fi

[ -f "$TOKEN_F" ] || { echo "sentinel-notify: ERROR: token Meja Bar tak ada" >&2; exit 1; }
TOKEN="$(cat "$TOKEN_F" | tr -d '[:space:]')"
if python3 - "$MEJA_API" "$TOKEN" "$MSG" <<'EOF'; then
import json, sys, urllib.request
api, token, msg = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.dumps({"sender": "CIEL", "text": msg}).encode()
req = urllib.request.Request(api + "?k=" + token, data=data,
                             headers={"Content-Type": "application/json"})
urllib.request.urlopen(req, timeout=10).read()
EOF
  printf '%s' "$HASH" > "$HASH_F"
  echo "posted OK"
else
  echo "sentinel-notify: WARN: post gagal, dicoba lagi di run berikut" >&2
  exit 0
fi
