#!/usr/bin/env bash
# sentinel-sbom — Ekspor SBOM CycloneDX dari inventory Bumblebee.
#
# Mengubah package records NDJSON menjadi Software Bill of Materials
# standar CycloneDX 1.5 — cocok dengan budaya "integritas-bukti": daftar
# resmi dan terverifikasi atas semua komponen di PC.
#
# Kontrak:
#   - sumber data: $STATE/scan-previous.ndjson (dari sentinel-diff) bila ada,
#     bila tidak: scan baseline sendiri
#   - output: $STATE/sbom-latest.json (CycloneDX 1.5, tervalidasi JSON)
#   - stdout: ringkasan singkat (N komponen, N dengan purl)
#   - exit 0; exit 1 bila validasi gagal (fail-closed)
set -euo pipefail

BIN="${BUMBLEBEE_BIN:-$HOME/.local/bin/bumblebee}"
STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
OUT="$STATE/sbom-latest.json"
mkdir -p "$STATE"

[ -x "$BIN" ] || { echo "sentinel-sbom: ERROR: binary tak ada: $BIN" >&2; exit 1; }

SCAN="$STATE/scan-previous.ndjson"
if [ ! -s "$SCAN" ]; then
  SCAN="$STATE/sbom-scan.ndjson"
  "$BIN" scan --profile baseline > "$SCAN" 2>/dev/null
fi

python3 - "$SCAN" "$OUT" <<'EOF'
import json, sys, datetime

scan_path, out_path = sys.argv[1], sys.argv[2]

def purl(eco, name, ver):
    """Package URL per ekosistem; None bila tak ada padanan baku."""
    if not name:
        return None
    v = f"@{ver}" if ver else ""
    table = {
        "npm": f"pkg:npm/{name}{v}",
        "pypi": f"pkg:pypi/{name}{v}",
        "go": f"pkg:golang/{name}{v}",
        "rubygems": f"pkg:gem/{name}{v}",
        "packagist": f"pkg:composer/{name}{v}",
    }
    return table.get(eco)

components, seen = [], set()
with open(scan_path) as f:
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
        rid = r.get("record_id") or ""
        if not rid or rid in seen:
            continue
        seen.add(rid)
        eco, name, ver = r.get("ecosystem", "?"), r.get("package_name", "?"), r.get("version", "")
        comp = {
            "type": "library",
            "bom-ref": rid,
            "name": name,
            "version": ver,
            "properties": [
                {"name": "sentinel:ecosystem", "value": eco},
                {"name": "sentinel:source_type", "value": r.get("source_type", "")},
            ],
        }
        p = purl(eco, name, ver)
        if p:
            comp["purl"] = p
        # buang property kosong agar SBOM bersih
        comp["properties"] = [pr for pr in comp["properties"] if pr["value"]]
        components.append(comp)

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": [{"name": "sentinel-sbom", "version": "1.0"}],
        "component": {"type": "application", "name": "sentinel-inventory"},
    },
    "components": sorted(components, key=lambda c: (c["name"], c["version"])),
}

with open(out_path, "w") as f:
    json.dump(bom, f, indent=1)
    f.write("\n")

# validasi fail-closed: JSON valid + struktur inti benar
chk = json.load(open(out_path))
assert chk["bomFormat"] == "CycloneDX" and isinstance(chk["components"], list)
n_purl = sum(1 for c in chk["components"] if "purl" in c)
print(f"SBOM OK: {len(chk['components'])} komponen ({n_purl} dengan purl) -> {out_path}")
EOF
