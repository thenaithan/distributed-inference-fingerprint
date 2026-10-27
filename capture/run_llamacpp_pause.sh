#!/usr/bin/env bash
# The hang case alone: load, then pause rpc-1 0.5 s into a request, hold, resume. A short
# capture (about 2 minutes) that supplies the wake-up the full run of 2026-10-27 lost when a
# Ctrl-C stopped tcpdump before the resume.
#
#   capture/run_llamacpp_pause.sh [hold_seconds]     default 60
#
# Needs: the llamacpp-rpc image built (see llamacpp/Containerfile), tcpdump on the host.
set -euo pipefail
cd "$(dirname "$0")/.."
HOLD=${1:-60}
stamp=$(LC_ALL=C date +%Y%m%d-%H%M%S)
dir=captures/llamacpp; pcap=$dir/$stamp.pcap; tl=$dir/$stamp.timeline.csv; rq=$dir/$stamp.requests.jsonl
mkdir -p "$dir"
mark() { capture/phase.sh "$tl" "$@"; }

llamacpp/cluster.sh down >/dev/null 2>&1 || true
llamacpp/cluster.sh up 2
until curl -sf http://localhost:8080/health >/dev/null; do sleep 1; done
capture/capture.sh start llama-net "$pcap"
sleep 5
mark load "cluster.sh main: the main host reconnects to both rpc hosts and uploads the slices"
llamacpp/cluster.sh main >/dev/null
until curl -sf http://localhost:8080/health >/dev/null; do sleep 1; done
mark warm "one 30-token request so the pause request is not the first"
python3 capture/requests.py --base http://localhost:8080 --n 1 --max-tokens 30 --out "$rq"
mark pause "pause rpc-1 0.5 s into a 300-token request; client gives up after 20 s without a token"
( sleep 0.5; llamacpp/cluster.sh pause 1 >/dev/null ) &
python3 capture/requests.py --base http://localhost:8080 --n 1 --max-tokens 300 --out "$rq" --timeout 20 || true
mark hold "rpc-1 stays paused for $HOLD s with the request abandoned"
sleep "$HOLD"
mark resume "cluster.sh resume 1: what the main host does with the late reply"
llamacpp/cluster.sh resume 1 >/dev/null
sleep 20
mark probe "one 30-token request after the resume: does the cluster still answer?"
python3 capture/requests.py --base http://localhost:8080 --n 1 --max-tokens 30 --out "$rq" --timeout 20 || true
sleep 5
mark done ""
capture/capture.sh stop
llamacpp/cluster.sh down >/dev/null
echo "wrote $pcap"; echo "analyse: python3 -m analysis.classify $pcap --timeline $tl"
