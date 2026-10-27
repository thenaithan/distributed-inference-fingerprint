#!/usr/bin/env bash
# The false-positive set: background/run.sh's generators on a podman network with no
# inference cluster on it, captured like a real run. The bridge exists only while a
# container is attached, so an idle anchor holds it up for the capture to start on.
#
#   capture/run_background.sh [network] [duration_seconds]      default llama-net, 600
#
# Needs: tcpdump on the host; the generator images are pulled on first use.
set -euo pipefail
cd "$(dirname "$0")/.."
NET=${1:-llama-net}; DUR=${2:-600}
stamp=$(LC_ALL=C date +%Y%m%d-%H%M%S)
dir=captures/background; pcap=$dir/$stamp.pcap; tl=$dir/$stamp.timeline.csv
mkdir -p "$dir"
mark() { capture/phase.sh "$tl" "$@"; }

podman network exists "$NET" || podman network create "$NET" >/dev/null
podman rm -f anchor >/dev/null 2>&1 || true
podman run -d --rm --name anchor --network "$NET" docker.io/library/alpine:3.20 sleep infinity >/dev/null
capture/capture.sh start "$NET" "$pcap"
sleep 5
mark background "background/run.sh $NET $DUR: download, stream, ping, mdns, iperf halfway"
background/run.sh "$NET" "$DUR"
mark done ""
capture/capture.sh stop
podman rm -f anchor >/dev/null 2>&1 || true
echo "wrote $pcap"; echo "analyse: python3 -m analysis.classify $pcap --timeline $tl"
