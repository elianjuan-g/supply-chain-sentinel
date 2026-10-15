#!/usr/bin/env bash
# sentinel-typosquat — Detektor typosquat pada package terpasang (Fase 3).
#
# Vektor serangan supply-chain: paket bernama MIRIP paket populer
# (lodahs vs lodash, requets vs requests) untuk menjebak salah ketik
# atau salah ingat nama saat install.
#
# Metode: jarak Damerau-Levenshtein terbatas (mendukung transposisi huruf)
# antara nama paket terpasang vs daftar kurasi paket populer per ekosistem.
#   jarak 1        -> TINGGI  (hampir pasti typosquat / salah ketik)
#   jarak 2        -> SEDANG, hanya bila panjang nama >= 6 (anti noise)
#   nama ADA di daftar populer -> bukan temuan (jarak 0 dilewati)
#   ekosistem selain npm/pypi -> dilewati jujur (daftar kurasi belum ada)
#
# Daftar populer: kurasi statis di dalam script — offline, deterministik,
# tanpa download. Daftar ini BUKAN kebenaran absolut.
#
# Batas jujur: hanya mendeteksi kemiripan dengan daftar kurasi. Typosquat
# dari paket populer yang tidak masuk daftar tidak tertangkap. Temuan
# adalah "mencurigakan", bukan vonis jahat.
#
# Kontrak:
#   - sumber data: $STATE/scan-previous.ndjson (dari sentinel-diff) bila ada,
#     bila tidak: scan baseline sendiri
#   - stdout: temuan, HANYA bila ada; diam bila bersih
#   - $STATE/typosquat-latest.txt: laporan terakhir ("temuan: N" + baris [typosquat ...])
#   - exit 0 selalu (kecuali dependensi hilang)
set -euo pipefail

BIN="${BUMBLEBEE_BIN:-$HOME/.local/bin/bumblebee}"
STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
OUT="$STATE/typosquat-latest.txt"
mkdir -p "$STATE"

[ -x "$BIN" ] || { echo "sentinel-typosquat: ERROR: binary tak ada: $BIN" >&2; exit 1; }

SCAN="$STATE/scan-previous.ndjson"
if [ ! -s "$SCAN" ]; then
  SCAN="$STATE/typosquat-scan.ndjson"
  "$BIN" scan --profile baseline > "$SCAN" 2>/dev/null
fi

python3 - "$SCAN" > "$STATE/typosquat-findings.txt" <<'EOF' || true
import json, sys

# Kurasi paket populer — target typosquat paling umum. Statis & offline.
POPULAR = {
    "npm": """lodash express react react-dom vue axios webpack babel typescript eslint
jest mocha chalk commander debug glob mkdirp rimraf semver yargs inquirer moment dayjs
uuid nanoid dotenv cors helmet morgan mongoose redis ioredis socket.io ws node-fetch
cheerio puppeteer next vite rollup prettier husky nodemon async rxjs tslib core-js
jquery bootstrap tailwindcss underscore backbone d3 three gsap moment request
body-parser cookie-parser multer passport jsonwebtoken bcryptjs validator classnames
prop-types redux mobx styled-components emotion antd element-ui vuetify""".split(),
    "pypi": """requests numpy pandas scipy matplotlib tensorflow torch keras
scikit-learn django flask fastapi sqlalchemy celery redis boto3 botocore pillow
opencv-python lxml beautifulsoup4 scrapy selenium pytest mock coverage black flake8
pylint mypy ipython jupyter notebook click typer rich tqdm pyyaml toml jsonschema
cryptography paramiko fabric ansible awscli click six dateutil pytz urllib3 certifi
chardet idna setuptools wheel pip virtualenv gunicorn uvicorn httpx aiohttp
django-rest-framework celery pytest-django factory-boy faker python-dotenv""".split(),
}
POPULAR = {k: {w.lower() for w in v} for k, v in POPULAR.items()}

# Paket legit yang KEBETULAN dekat dengan nama populer (false positive
# yang sudah diketahui). Dikurasi manual; bertambah bila temuan baru
# terbukti legit. Contoh: tomli adalah parser TOML populer (backport
# tomllib), bukan typosquat dari toml.
ALLOWLIST = {"tomli"}


def damerau_osa(a, b):
    """Optimal string alignment (Damerau-Levenshtein terbatas) — cukup untuk typosquat."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 2:
        return 3
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


findings = []
seen = set()
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("record_type") != "package":
            continue
        eco = (r.get("ecosystem") or "").lower()
        popular = POPULAR.get(eco)
        if not popular:
            continue
        name = (r.get("package_name") or "")
        lname = name.lower()
        if not lname or lname in popular or lname in seen or lname in ALLOWLIST:
            continue
        seen.add(lname)
        best, bestd = None, 3
        for p in popular:
            if abs(len(lname) - len(p)) > 2:
                continue
            dd = damerau_osa(lname, p)
            if dd < bestd:
                best, bestd = p, dd
                if dd == 1:
                    break
        if bestd == 1:
            findings.append(("TINGGI", name, r.get("version"), eco, best, bestd))
        elif bestd == 2 and len(lname) >= 6:
            findings.append(("SEDANG", name, r.get("version"), eco, best, bestd))

for lvl, name, ver, eco, pop, dist in sorted(findings):
    print(f"[typosquat jarak={dist} {lvl}] {name}@{ver} ({eco}) mirip '{pop}'")
print(f"TOTAL:{len(findings)}")
EOF

TOTAL=$(grep -E "^TOTAL:" "$STATE/typosquat-findings.txt" | cut -d: -f2 || true)
grep -v -E "^TOTAL:" "$STATE/typosquat-findings.txt" > "$STATE/typosquat-body.txt" || true
{
  echo "=== Sentinel typosquat-detector $(date '+%Y-%m-%d %H:%M %Z') ==="
  echo "temuan: ${TOTAL:-0}"
  [ "${TOTAL:-0}" -gt 0 ] 2>/dev/null && cat "$STATE/typosquat-body.txt"
} > "$OUT"

if [ "${TOTAL:-0}" -gt 0 ] 2>/dev/null; then
  cat "$STATE/typosquat-body.txt"
fi
exit 0
