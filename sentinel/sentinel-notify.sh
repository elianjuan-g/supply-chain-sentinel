#!/usr/bin/env bash
# sentinel-notify — Kirim temuan Sentinel ke webhook, hanya bila ada yang baru.
#
# Membaca diff-latest.txt + mcp-latest.txt + postinstall-latest.txt +
# typosquat-latest.txt + secretscan-latest.txt, menyusun SATU pesan ringkas,
# dedup via hash (tidak repost temuan yang sama), diam total bila tak ada temuan.
# Pesan SENGAJA tanpa timestamp agar stabil untuk dedup.
# Pola posting: sender CIEL, token via ?k= (kompatibel webhook ala webhook).
#
# Kontrak:
#   - stdout : "posted OK" bila terkirim, "DRY_RUN: ..." bila DRY_RUN=1, diam bila tak ada temuan
#   - $STATE/last-notified.hash : hash pesan terakhir yang terkirim (hanya ditulis saat sukses)
#   - exit 0 selalu; kegagalan post dicatat ke stderr dan dicoba lagi di run berikut
set -euo pipefail

STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
MEJA_API="${MEJA_API:-http://localhost:8788/api/post}"  # override via env untuk webhook sendiri
TOKEN_F="${SENTINEL_TOKEN_FILE:-$HOME/.sentinel/notify-token.txt}"
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

# --- temuan typosquat ---
TQ_F="$STATE/typosquat-latest.txt"
if [ -f "$TQ_F" ]; then
  T=$(grep -oE "temuan: [0-9]+" "$TQ_F" 2>/dev/null | awk '{print $2}' || true)
  if [ "${T:-0}" -gt 0 ] 2>/dev/null; then
    TLIST=$(grep -E "^\[typosquat" "$TQ_F" | head -8)
    MSG="$MSG"$'\n'"⌨️ Kemiripan typosquat ($T):"$'\n'"$TLIST"
  fi
fi

# --- temuan secret-scan ---
# AMAN by construction: secretscan-latest.txt TIDAK PERNAH berisi nilai secret
# (hanya file:baris + tipe pola, sesuai desain privasi) — aman untuk webhook.
SS_F="$STATE/secretscan-latest.txt"
if [ -f "$SS_F" ]; then
  S=$(grep -oE "temuan: [0-9]+" "$SS_F" 2>/dev/null | awk '{print $2}' || true)
  if [ "${S:-0}" -gt 0 ] 2>/dev/null; then
    SLIST=$(grep -E "^\[secret" "$SS_F" | head -8)
    MSG="$MSG"$'\n'"🔑 Indikasi secret di file ($S) — nilai tidak ditampilkan:"$'\n'"$SLIST"
  fi
fi

# buang baris kosong di tepi
MSG="$(printf '%s' "$MSG" | sed -e '/./,$!d' -e :a -e '/^\n*$/{$d;N;ba' -e '}')"
if [ -z "${MSG//[[:space:]]/}" ]; then
  exit 0 # diam: tak ada temuan
fi

# batasi panjang (webhook bukan log)
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

[ -f "$TOKEN_F" ] || { echo "sentinel-notify: ERROR: token webhook tak ada" >&2; exit 1; }
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
