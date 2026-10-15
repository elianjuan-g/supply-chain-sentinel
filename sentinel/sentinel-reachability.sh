#!/usr/bin/env bash
# sentinel-reachability — Audit "terpasang vs dipakai" (Fase 3).
#
# Pertanyaan: paket mana yang terpasang di PC tapi (kemungkinan) tidak dipakai
# oleh proyek mana pun? Tujuannya HIGIENE (ruang disk, permukaan serangan),
# bukan keamanan langsung.
#
# Metode (konservatif, dua ekosistem):
#   pypi: parse import (ast, tanpa eksekusi) dari semua *.py di root proyek ->
#         himpunan modul top-level ter-import; dinormalisasi (lowercase,
#         '-'/'_' disamakan) lalu dicocokkan ke nama package terpasang.
#   npm:  kumpulkan dependencies+devDependencies+peerDependencies dari semua
#         package.json di root proyek; cocokkan ke package node_modules
#         terpasang (nama persis).
#
# Root proyek default: $HOME/src $HOME/workspace $HOME/hermes-hub-r2
# (+$SENTINEL_SCAN_ROOTS). node_modules/.git dilewati.
#
# BATAS JUJUR (baca sebelum bertindak):
#   - import dinamis (importlib, __import__), plugin, entry-point console,
#     dan CLI tool yang dipakai langsung -> false "tak terpakai".
#   - package yang HANYA dipakai sebagai dependency transitif juga
#     dilaporkan tak terpakai (benar secara langsung, tapi menghapusnya
#     tetap aman karena transitif).
#   - JANGAN uninstall berdasarkan laporan ini saja. Ini daftar periksa,
#     bukan vonis.
#
# Status temuan: INFORMASI, bukan alert -> SENGAJA tidak di-wire ke
# sentinel-notify (prinsip: notifikasi hanya untuk temuan keamanan).
#
# Kontrak:
#   - stdout: ringkasan selalu (ini audit, bukan hunter); detail di file
#   - $STATE/reachability-latest.txt: laporan terakhir
#   - exit 0 selalu (kecuali dependensi hilang)
set -euo pipefail

BIN="${BUMBLEBEE_BIN:-$HOME/.local/bin/bumblebee}"
STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
OUT="$STATE/reachability-latest.txt"
mkdir -p "$STATE"

[ -x "$BIN" ] || { echo "sentinel-reachability: ERROR: binary tak ada: $BIN" >&2; exit 1; }

SCAN="$STATE/scan-previous.ndjson"
if [ ! -s "$SCAN" ]; then
  SCAN="$STATE/reachability-scan.ndjson"
  "$BIN" scan --profile baseline > "$SCAN" 2>/dev/null
fi

ROOTS="${SENTINEL_SCAN_ROOTS:-$HOME/src $HOME/workspace $HOME/hermes-hub-r2}"

python3 - "$SCAN" $ROOTS > "$STATE/reachability-report.txt" <<'EOF' || true
import ast, json, os, sys

scan_path = sys.argv[1]
roots = [d for d in sys.argv[2:] if os.path.isdir(d)]

SKIP_DIRS = {"node_modules", ".git", ".cache", "__pycache__", "dist", "build", ".venv", "venv"}

def walk_py(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)

def walk_json(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn == "package.json":
                yield os.path.join(dirpath, fn)

def norm_py(name):
    return name.lower().replace("-", "_")

# --- kumpulkan sinyal pemakaian ---
used_py_mods = set()
for root in roots:
    for fp in walk_py(root):
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                tree = ast.parse(f.read())
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    used_py_mods.add(norm_py((a.name or "").split(".")[0]))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    used_py_mods.add(norm_py(node.module.split(".")[0]))

used_npm_deps = set()
for root in roots:
    for fp in walk_json(root):
        try:
            with open(fp, encoding="utf-8", errors="ignore") as f:
                pj = json.load(f)
        except Exception:
            continue
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = pj.get(section) or {}
            if isinstance(deps, dict):
                used_npm_deps.update(deps.keys())

# --- bandingkan dengan yang terpasang ---
# Paket OS-managed (root_kind global_*) dikelompokkan terpisah: mereka milik
# sistem operasi, bukan proyek pengguna — melaporkannya sebagai "tak terpakai"
# adalah noise yang menyesatkan. Hanya paket user-space yang dianalisis.
installed = []
with open(scan_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("record_type") == "package" and r.get("ecosystem") in ("pypi", "npm"):
            installed.append(r)

system_pkgs = [r for r in installed if (r.get("root_kind") or "").startswith("global_")]
user_pkgs = [r for r in installed if not (r.get("root_kind") or "").startswith("global_")]

unused_py, unused_npm = [], []
for r in user_pkgs:
    name, eco, ver = r.get("package_name") or "", r.get("ecosystem"), r.get("version") or ""
    if eco == "pypi":
        if norm_py(name) not in used_py_mods:
            unused_py.append((name, ver))
    elif eco == "npm":
        if name not in used_npm_deps:
            unused_npm.append((name, ver))

print(f"ROOT_DIPINDAI:{len(roots)}")
print(f"PAKET_SISTEM_OS_MANAGED:{len(system_pkgs)} (diabaikan dari analisis)")
print(f"PAKET_USER_SPACE:{len(user_pkgs)}")
print(f"PY_TERIMPORT:{len(used_py_mods)} NPM_DEP:{len(used_npm_deps)}")
print(f"PY_MUNGKIN_TAK_TERPAKAI:{len(unused_py)}")
for n, v in sorted(unused_py)[:60]:
    print(f"  - {n}@{v}")
if len(unused_py) > 60:
    print(f"  ... +{len(unused_py) - 60} lainnya")
print(f"NPM_MUNGKIN_TAK_TERPAKAI:{len(unused_npm)}")
for n, v in sorted(unused_npm)[:60]:
    print(f"  - {n}@{v}")
if len(unused_npm) > 60:
    print(f"  ... +{len(unused_npm) - 60} lainnya")
EOF

{
  echo "=== Sentinel reachability-audit $(date '+%Y-%m-%d %H:%M %Z') ==="
  echo "INFORMASI (bukan alert): daftar periksa higiene — JANGAN uninstall hanya dari laporan ini."
  cat "$STATE/reachability-report.txt"
} > "$OUT"

cat "$STATE/reachability-report.txt"
exit 0
