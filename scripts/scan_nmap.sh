#!/usr/bin/env bash
set -euo pipefail

# Run nmap with sane defaults and store output/command.
# Usage: ./scripts/scan_nmap.sh <target> <env_name> <outdir>
# - Tries TCP SYN scan (-sS) with version detection (-sV) on common ports.
# - If -sS fails (e.g., due to lack of privileges), falls back to -sT.
# - Outputs XML to <outdir>/<target>.<env_name>.xml
# - Saves the exact command used to <outdir>/<target>.<env_name>.cmd.txt

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <target> <env_name> <outdir>" >&2
  exit 1
fi

TARGET="$1"
ENV_NAME="$2"
OUTDIR="$3"

mkdir -p "$OUTDIR"

OUT_XML="$OUTDIR/${TARGET}.${ENV_NAME}.xml"
CMD_FILE="$OUTDIR/${TARGET}.${ENV_NAME}.cmd.txt"

# Build commands (common ports are nmap defaults when no -p is provided)
CMD_SYN=(nmap -sS -sV -oX "$OUT_XML" "$TARGET")
CMD_TCP=(nmap -sT -sV -oX "$OUT_XML" "$TARGET")

# Try SYN scan first; if it fails, fall back to TCP connect scan.
set +e
"${CMD_SYN[@]}"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
  USED_CMD=("${CMD_SYN[@]}")
else
  set +e
  "${CMD_TCP[@]}"
  rc2=$?
  set -e
  if [[ $rc2 -ne 0 ]]; then
    echo "nmap failed with both -sS and -sT scans (exit codes: $rc, $rc2)." >&2
    exit 1
  fi
  USED_CMD=("${CMD_TCP[@]}")
fi

# Record and print the exact command used
USED_CMD_STR=$(printf '%q ' "${USED_CMD[@]}")
echo "$USED_CMD_STR" | sed 's/[[:space:]]$//' | tee "$CMD_FILE"

echo "Saved XML output to: $OUT_XML"
