#!/usr/bin/env bash
# sentinel-mcp-audit — Audit server MCP di PC.
#
# PRIVASI (keras): hanya NAMA server yang dibaca dan dilaporkan. Nilai env /
# credential TIDAK PERNAH dibaca, disimpan, atau dipancarkan — bumblebee
# sendiri membuangnya saat parsing, dan kita tidak mengembalikannya.
#
# Kontrak:
#   - $STATE/mcp-allowlist.txt : server yang sudah disetujui MyLord (satu nama per baris)
#   - $STATE/mcp-latest.txt    : hasil audit terakhir ("unknown: N" + daftar)
#   - stdout : daftar server tak dikenal, HANYA bila ada; diam bila bersih
#   - exit 0 selalu (kecuali scan gagal total)
set -euo pipefail

BIN="${BUMBLEBEE_BIN:-$HOME/.local/bin/bumblebee}"
STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
ALLOW="$STATE/mcp-allowlist.txt"
OUT="$STATE/mcp-latest.txt"
mkdir -p "$STATE"; touch "$ALLOW"

[ -x "$BIN" ] || { echo "sentinel-mcp-audit: ERROR: binary tak ada: $BIN" >&2; exit 1; }

SCAN="$STATE/mcp-scan.ndjson"
"$BIN" scan --profile baseline > "$SCAN" 2>/dev/null

python3 - "$SCAN" > "$STATE/mcp-found.txt" <<'EOF' || true
import json, sys
seen = {}
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("record_type") == "package" and r.get("ecosystem") == "mcp":
            name = r.get("package_name") or ""
            if name:
                seen[name] = r.get("server_name") or ""
for n in sorted(seen):
    alias = seen[n]
    print(n if not alias or alias == n else f"{n} (alias: {alias})")
EOF

python3 - "$STATE/mcp-found.txt" "$ALLOW" > "$STATE/mcp-unknown.txt" <<'EOF' || true
import sys
found = [l.rstrip("\n") for l in open(sys.argv[1]) if l.strip()]
allow = {l.strip() for l in open(sys.argv[2]) if l.strip()}
for f in found:
    name = f.split(" (alias:")[0]
    if name not in allow:
        print(f)
EOF

N_FOUND=$(wc -l < "$STATE/mcp-found.txt" | tr -d ' ')
N=$(wc -l < "$STATE/mcp-unknown.txt" | tr -d ' ')
{
  echo "=== Sentinel mcp-audit $(date '+%Y-%m-%d %H:%M %Z') ==="
  echo "terdeteksi: $N_FOUND | unknown: $N"
  if [ "$N" -gt 0 ]; then
    echo "--- SERVER TAK DIKENAL (cek allowlist: $ALLOW) ---"
    cat "$STATE/mcp-unknown.txt"
  fi
} > "$OUT"

if [ "$N" -gt 0 ]; then
  cat "$STATE/mcp-unknown.txt"
fi
exit 0
