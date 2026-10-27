#!/usr/bin/env bash
# One llama.cpp RPC capture: load, idle, generation, long prefill, node loss. Everything on
# the llama-net bridge goes to captures/llamacpp/<stamp>.pcap with a timeline beside it.
#
#   capture/run_llamacpp.sh [idle_seconds]      default 600
#
# Needs: the llamacpp-rpc image built (see llamacpp/Containerfile), tcpdump on the host.
set -euo pipefail
cd "$(dirname "$0")/.."
IDLE=${1:-600}
stamp=$(date +%Y%m%d-%H%M%S); dir=captures/llamacpp; pcap=$dir/$stamp.pcap; tl=$dir/$stamp.timeline.csv; rq=$dir/$stamp.requests.jsonl
mkdir -p "$dir"
mark() { capture/phase.sh "$tl" "$@"; }

llamacpp/cluster.sh down >/dev/null 2>&1 || true
podman network exists llama-net || podman network create llama-net >/dev/null
capture/capture.sh start llama-net "$pcap"
mark load "cluster.sh up 2: rpc hosts then main; weights move now"
llamacpp/cluster.sh up 2
until curl -sf http://localhost:8080/health >/dev/null; do sleep 1; done
mark idle "model loaded, no requests for $IDLE s"
sleep "$IDLE"
mark generate "20 x 30 tokens, 33-token prompt"
python3 capture/requests.py --base http://localhost:8080 --n 20 --max-tokens 30 --out "$rq"
mark generate-long "5 x 30 tokens, ~2048-token prompt"
python3 capture/requests.py --base http://localhost:8080 --n 5 --max-tokens 30 --prompt-tokens 2048 --out "$rq"
mark kill "killproc rpc-0 during a request"
( sleep 2; llamacpp/cluster.sh killproc 0 >/dev/null ) &
python3 capture/requests.py --base http://localhost:8080 --n 1 --max-tokens 60 --out "$rq" --timeout 120 || true
sleep 20
mark recover "cluster.sh up 2 again"
llamacpp/cluster.sh up 2
until curl -sf http://localhost:8080/health >/dev/null; do sleep 1; done
mark pause "pause rpc-1 during a request (never detected: 120 s harness timeout)"
( sleep 2; llamacpp/cluster.sh pause 1 >/dev/null ) &
python3 capture/requests.py --base http://localhost:8080 --n 1 --max-tokens 60 --out "$rq" --timeout 120 || true
mark resume ""
llamacpp/cluster.sh resume 1 >/dev/null
sleep 10
mark done ""
capture/capture.sh stop
llamacpp/cluster.sh down >/dev/null
echo "wrote $pcap"; echo "analyse: python3 -m analysis.classify $pcap --timeline $tl"
