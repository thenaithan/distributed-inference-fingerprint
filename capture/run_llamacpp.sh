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
stamp=$(LC_ALL=C date +%Y%m%d-%H%M%S)     # LC_ALL=C: a Thai locale prints the Buddhist year
dir=captures/llamacpp; pcap=$dir/$stamp.pcap; tl=$dir/$stamp.timeline.csv; rq=$dir/$stamp.requests.jsonl
mkdir -p "$dir"
mark() { capture/phase.sh "$tl" "$@"; }

# the bridge exists only while a container is attached, so: cluster up, capture, then
# restart the main host alone so the HELLO and the weight upload happen on the capture
llamacpp/cluster.sh down >/dev/null 2>&1 || true
llamacpp/cluster.sh up 2
until curl -sf http://localhost:8080/health >/dev/null; do sleep 1; done
capture/capture.sh start llama-net "$pcap"
sleep 5
mark load "cluster.sh main: the main host reconnects to both rpc hosts and uploads the slices"
llamacpp/cluster.sh main >/dev/null
until curl -sf http://localhost:8080/health >/dev/null; do sleep 1; done
mark idle "model loaded, no requests for $IDLE s"
sleep "$IDLE"
mark generate "20 x 30 tokens, 33-token prompt"
python3 capture/requests.py --base http://localhost:8080 --n 20 --max-tokens 30 --out "$rq"
mark generate-long "5 x 30 tokens, ~2048-token prompt"
python3 capture/requests.py --base http://localhost:8080 --n 5 --max-tokens 30 --prompt-tokens 2048 --out "$rq"
mark kill "killproc rpc-0 0.5 s into a 300-token request"
( sleep 0.5; llamacpp/cluster.sh killproc 0 >/dev/null ) &
python3 capture/requests.py --base http://localhost:8080 --n 1 --max-tokens 300 --out "$rq" --timeout 120 || true
sleep 20
# the first cluster's logs before cluster.sh up replaces its containers (the kill phase)
for c in main $(podman ps -a --format '{{.Names}}' | grep '^rpc-' || true); do podman logs "$c" > "$dir/$stamp.$c.1.log" 2>&1 || true; done
mark recover "cluster.sh up 2 again"
llamacpp/cluster.sh up 2
until curl -sf http://localhost:8080/health >/dev/null; do sleep 1; done
mark pause "pause rpc-1 0.5 s into a 300-token request (never detected: 120 s harness timeout)"
( sleep 0.5; llamacpp/cluster.sh pause 1 >/dev/null ) &
python3 capture/requests.py --base http://localhost:8080 --n 1 --max-tokens 300 --out "$rq" --timeout 120 || true
mark resume ""
llamacpp/cluster.sh resume 1 >/dev/null
sleep 10
mark done ""
capture/capture.sh stop
# container logs next to the pcap before the containers go: llama-server's per-request
# timings (the server-side rate for prediction 7) and its prompt-cache lines live there
for c in main $(podman ps -a --format '{{.Names}}' | grep '^rpc-' || true); do podman logs "$c" > "$dir/$stamp.$c.log" 2>&1 || true; done
llamacpp/cluster.sh down >/dev/null
echo "wrote $pcap"; echo "analyse: python3 -m analysis.classify $pcap --timeline $tl"
