#!/usr/bin/env bash
# Append a phase marker to a timeline csv: host clock (same as the pcap), phase, note.
#
#   capture/phase.sh <timeline.csv> <phase> [note]
#
# Phases used by the run scripts: idle, load, generate, generate-long, kill, pause, cut,
# heal, resume, background, done. analysis/classify.py --timeline labels findings with them.
set -euo pipefail
f=$1; phase=$2; note=${3:-}
mkdir -p "$(dirname "$f")"
[ -s "$f" ] || echo "# t,phase,note" > "$f"
printf '%s,%s,%s\n' "$(LC_ALL=C date +%s.%N)" "$phase" "$note" >> "$f"
