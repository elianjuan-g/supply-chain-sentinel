#!/usr/bin/env bash
# sentinel-winnative — Inventaris sisi Windows asli (Fase 3).
#
# Bumblebee (dan Sentinel) berjalan di WSL — buta terhadap sisi Windows:
# program WinGet, modul PowerShell, scheduled task, dan startup Windows
# tidak tercatat di inventory Linux. Script ini menutup celah itu.
#
# KEPUTUSAN DEPENDENSI (dicatat eksplisit): TANPA dependensi Go baru (x/sys)
# dan tanpa package manager baru. Kolektor memakai interop WSL yang sudah
# ada — powershell.exe / reg.exe / schtasks.exe — masing-masing dibungkus
# `timeout`. Murni read-only: tidak install, tidak mengubah registry.
#
# Kolektor:
#   1. winget list                        (timeout 120 — paling lambat)
#   2. program terpasang (registry Uninstall 64-bit + 32-bit/Wow6432Node)
#   3. modul PowerShell (Get-Module -ListAvailable)
#   4. scheduled tasks (schtasks /query /fo csv)
#   5. startup (registry HKCU/HKLM ...\Run)
#   6. chocolatey local (bila choco ada)
# Tiap kolektor yang gagal -> tercatat "terlewat (alasan)", bukan fatal.
# Output mentah disimpan di $STATE/winnative/ untuk diff masa depan.
#
# Batas jujur: ini INVENTARIS, bukan penilaian. "Terpasang" != "jahat".
# Scheduled task asing tetap butuh tinjauan manusia.
#
# Kontrak:
#   - stdout: ringkasan selalu (ini inventaris, bukan hunter)
#   - $STATE/winnative-latest.txt: ringkasan; $STATE/winnative/*.txt: mentah
#   - exit 0 selalu (kecuali interop WSL tak ada sama sekali)
set -euo pipefail

STATE="${SENTINEL_STATE:-$HOME/.hermes/sentinel}"
RAW="$STATE/winnative"
OUT="$STATE/winnative-latest.txt"
mkdir -p "$RAW"

# Lokasi binary Windows: PATH dulu, lalu fallback path absolut (interop WSL di
# mesin ini tidak menyuntikkan PATH Windows, tapi .exe-nya bisa dieksekusi
# langsung). Variabel dipakai langsung agar tembus ke `timeout`.
win_bin() { # $1=nama.exe -> cetak path yang bisa dieksekusi, atau kosong
  local n="$1" p
  if command -v "$n" >/dev/null 2>&1; then printf '%s' "$n"; return 0; fi
  for p in "/mnt/c/Windows/System32/$n" \
           "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/$n" \
           "/mnt/c/ProgramData/chocolatey/bin/$n"; do
    if [ -x "$p" ]; then printf '%s' "$p"; return 0; fi
  done
  return 1
}

PS_BIN="$(win_bin powershell.exe || true)"
if [ -z "$PS_BIN" ]; then
  echo "sentinel-winnative: interop WSL->Windows tak tersedia — dilewati" >&2
  printf '=== Sentinel windows-native %s ===\nstatus: interop tak tersedia\n' \
    "$(date '+%Y-%m-%d %H:%M %Z')" > "$OUT"
  exit 0
fi
SCHTASKS_BIN="$(win_bin schtasks.exe || true)"
CHOCO_BIN="$(win_bin choco.exe || true)"

PS="$PS_BIN -NoProfile -NonInteractive -Command"

# --- 1. winget ---
timeout 120 $PS "winget list | Out-String" > "$RAW/winget.txt" 2>/dev/null || \
  echo "TERLEWAT: winget (timeout/tak ada)" > "$RAW/winget.txt"

# --- 2. program terpasang (registry) ---
timeout 60 $PS "
\$p=@(); foreach (\$k in 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*') {
  \$p += Get-ItemProperty \$k -ErrorAction SilentlyContinue |
    Where-Object { \$_.DisplayName } |
    ForEach-Object { \"\$(\$_.DisplayName) || \$(\$_.DisplayVersion)\" }
}; \$p | Sort-Object -Unique" > "$RAW/programs.txt" 2>/dev/null || \
  echo "TERLEWAT: registry Uninstall" > "$RAW/programs.txt"

# --- 3. modul PowerShell ---
timeout 60 $PS "
Get-Module -ListAvailable | Select-Object Name,Version -Unique |
  ForEach-Object { \"\$(\$_.Name) || \$(\$_.Version)\" } | Sort-Object -Unique" \
  > "$RAW/psmodules.txt" 2>/dev/null || \
  echo "TERLEWAT: Get-Module" > "$RAW/psmodules.txt"

# --- 4. scheduled tasks ---
if [ -n "$SCHTASKS_BIN" ]; then
  timeout 60 "$SCHTASKS_BIN" /query /fo csv > "$RAW/schedtasks.csv" 2>/dev/null || \
    echo "TERLEWAT: schtasks" > "$RAW/schedtasks.csv"
else
  echo "TERLEWAT: schtasks.exe tak ditemukan" > "$RAW/schedtasks.csv"
fi

# --- 5. startup (Run keys) ---
timeout 60 $PS "
foreach (\$k in 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run') {
  (Get-Item \$k -ErrorAction SilentlyContinue).Property | ForEach-Object { \"\$_\" }
}" > "$RAW/startup.txt" 2>/dev/null || \
  echo "TERLEWAT: Run keys" > "$RAW/startup.txt"

# --- 6. chocolatey (bila ada) ---
if [ -n "$CHOCO_BIN" ]; then
  timeout 60 "$CHOCO_BIN" list --local-only > "$RAW/choco.txt" 2>/dev/null || \
    echo "TERLEWAT: choco list" > "$RAW/choco.txt"
else
  echo "TIDAK_ADA: chocolatey tidak terpasang" > "$RAW/choco.txt"
fi

# --- ringkasan ---
count_lines() { # $1=file, $2=pola baris valid
  grep -v -E "^(TERLEWAT|TIDAK_ADA)" "$1" 2>/dev/null | grep -cE "$2" || true
}
{
  echo "=== Sentinel windows-native $(date '+%Y-%m-%d %H:%M %Z') ==="
  echo "winget: $(count_lines "$RAW/winget.txt" '.') baris"
  echo "program: $(count_lines "$RAW/programs.txt" '\\|\\|') entri"
  echo "modul-powershell: $(count_lines "$RAW/psmodules.txt" '\\|\\|') entri"
  echo "scheduled-task: $(($(count_lines "$RAW/schedtasks.csv" '^"') - 1)) entri"
  echo "startup: $(count_lines "$RAW/startup.txt" '.') entri"
  echo "choco: $(count_lines "$RAW/choco.txt" '.') baris"
  echo "mentah: $RAW/"
} > "$OUT"

cat "$OUT"
exit 0
