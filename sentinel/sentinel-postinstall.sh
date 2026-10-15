#!/usr/bin/env bash
# sentinel-postinstall — Pemburu install-hook mencurigakan (Fase 3, item pertama).
#
# Vektor serangan supply-chain #1: script npm yang berjalan OTOMATIS saat
# install (preinstall/install/postinstall). Bumblebee mencatat hook APA yang
# ada (has_lifecycle_scripts); script ini membaca ISI hook dari package.json
# asal (terverifikasi namanya cocok) dan memberi skor indikator.
#
# Skor indikator (pada isi command hook):
#   +3  eksekusi kode dinamis: eval(, new Function(
#   +3  download-and-exec: curl|wget ... | sh|bash ; powershell -enc
#   +3  obfuskasi: String.fromCharCode, \xNN / \uNNNN
#   +2  base64 decode / atob(
#   +2  sentuh credential: ~/.ssh, ~/.aws, id_rsa, .npmrc
#   +2  network dalam node -e (http.get/https.get/fetch()
#   +1  curl/wget polos (umum di install legit -> kecil)
# Pola jinak (skor 0): node-gyp, prebuild-install, husky, patch-package
# Threshold lapor: >=3 "mencurigakan", >=6 "KRITIS".
#
# Batas jujur: ini heuristik pola, bukan deteksi malware generik. Serangan
# baru tanpa pola di atas tidak tertangkap.
#
# Kontrak:
#   - sumber data: $STATE/scan-previous.ndjson (dari sentinel-diff) bila ada,
#     bila tidak: scan baseline sendiri
#   - stdout: temuan, HANYA bila ada; diam bila bersih
#   - $STATE/postinstall-latest.txt: laporan terakhir
#   - exit 0 selalu (kecuali dependensi hilang)
set -euo pipefail

BIN="${BUMBLEBEE_BIN:-$HOME/.local/bin/bumblebee}"
STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
OUT="$STATE/postinstall-latest.txt"
mkdir -p "$STATE"

[ -x "$BIN" ] || { echo "sentinel-postinstall: ERROR: binary tak ada: $BIN" >&2; exit 1; }

SCAN="$STATE/scan-previous.ndjson"
if [ ! -s "$SCAN" ]; then
  SCAN="$STATE/postinstall-scan.ndjson"
  "$BIN" scan --profile baseline > "$SCAN" 2>/dev/null
fi

python3 - "$SCAN" > "$STATE/postinstall-findings.txt" <<'EOF' || true
import json, sys, re, os

HOOKS = ("preinstall", "install", "postinstall")
BENIGN = re.compile(r"node-gyp|prebuild-install|husky|patch-package", re.I)
RULES = [
    (3, re.compile(r"\beval\s*\(|new\s+Function\s*\(")),
    (3, re.compile(r"(curl|wget)[^\n|]*\|\s*(sh|bash)")),
    (3, re.compile(r"powershell[^\n]*-e(nc|ncodedCommand)?\b", re.I)),
    (3, re.compile(r"String\.fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}")),
    (2, re.compile(r"base64\s+(-d|--decode)")),
    (2, re.compile(r"atob\s*\(")),
    (2, re.compile(r"~/\.ssh|~/\.aws|id_rsa|\.npmrc")),
    (2, re.compile(r"node\s+-e\s+[\"'][^\"']*(https?\.get|fetch\()")),
    (1, re.compile(r"\b(curl|wget)\b")),
]

def read_hooks(pkg_json_path, expect_name):
    """Ambil {hook: command}; {} bila file tak ada / nama tak cocok (anti salah atribusi)."""
    try:
        with open(pkg_json_path) as f:
            pj = json.load(f)
        got = (pj.get("name") or "").lower()
        if got != (expect_name or "").lower():
            return {}
        scripts = pj.get("scripts") or {}
        return {h: scripts[h] for h in HOOKS if scripts.get(h)}
    except Exception:
        return {}

def score(cmd):
    if BENIGN.search(cmd):
        return 0, []
    total, hits = 0, []
    for pts, rx in RULES:
        if rx.search(cmd):
            total += pts
            hits.append(rx.pattern[:36])
    return total, hits

findings = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("record_type") != "package" or r.get("ecosystem") != "npm":
            continue
        if not r.get("has_lifecycle_scripts"):
            continue
        # hanya dari node_modules (source_file = package.json paket itu sendiri);
        # record lockfile dilewati jujur (isi hook tak tersedia lokal)
        if r.get("source_type") != "npm-node_modules":
            continue
        pj_path = r.get("source_file") or ""
        if not pj_path.endswith("package.json") or not os.path.isfile(pj_path):
            continue
        hooks = read_hooks(pj_path, r.get("package_name"))
        for hook, cmd in hooks.items():
            s, hits = score(cmd)
            if s >= 3:
                findings.append((s, r.get("package_name"), r.get("version"),
                                 hook, cmd[:220], pj_path, hits))

findings.sort(key=lambda x: -x[0])
for s, pkg, ver, hook, cmd, path, hits in findings:
    level = "KRITIS" if s >= 6 else "mencurigakan"
    print(f"[{level} skor={s}] {pkg}@{ver} :: {hook}")
    print(f"  cmd: {cmd}")
    print(f"  pola: {'; '.join(hits)}")
print(f"TOTAL:{len(findings)}")
EOF

TOTAL=$(grep -E "^TOTAL:" "$STATE/postinstall-findings.txt" | cut -d: -f2)
grep -v -E "^TOTAL:" "$STATE/postinstall-findings.txt" > "$STATE/postinstall-body.txt" || true
{
  echo "=== Sentinel postinstall-hunter $(date '+%Y-%m-%d %H:%M %Z') ==="
  echo "temuan: $TOTAL"
  [ "${TOTAL:-0}" -gt 0 ] 2>/dev/null && cat "$STATE/postinstall-body.txt"
} > "$OUT"

if [ "${TOTAL:-0}" -gt 0 ] 2>/dev/null; then
  cat "$STATE/postinstall-body.txt"
fi
exit 0
