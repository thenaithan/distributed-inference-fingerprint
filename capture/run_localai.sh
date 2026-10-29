#!/usr/bin/env bash
# One LocalAI P2P capture: discovery, idle, load, generation, long prefill, node loss.
# Everything on the localai-net bridge goes to captures/localai/<stamp>.pcap with a
# timeline beside it.
#
#   capture/run_localai.sh [idle_seconds]          default 600
#   DHT=1 capture/run_localai.sh 300               prediction 12: DHT and bootstrap on
#   LOOPBACK=1 capture/run_localai.sh              also tcpdump -i lo inside main and workers
#
# Needs: localai/cluster.sh (v4.12.1, model and backend in their volumes after the first
# `up`), tcpdump on the host. Phases differ from run_llamacpp.sh where LocalAI differs:
# the idle phase comes before the load (LocalAI loads the model on the first request, so
# idle here is the overlay alone: ledger, mDNS, discovery), and recovery needs a request to
# load the model again.
set -euo pipefail
cd "$(dirname "$0")/.."
IDLE=${1:-600}
N=2; NET=localai-net; API=http://localhost:${LOCALAI_API_PORT:-8080}; MODEL=Qwen3-0.6B-Q8_0.gguf
stamp=$(LC_ALL=C date +%Y%m%d-%H%M%S)     # LC_ALL=C: a Thai locale prints the Buddhist year
dir=captures/localai; pcap=$dir/$stamp.pcap; tl=$dir/$stamp.timeline.csv
rq=$dir/$stamp.requests.jsonl; p2p=$dir/$stamp.p2p.jsonl; lopids=$dir/$stamp.lo.pids
mkdir -p "$dir"
mark() { capture/phase.sh "$tl" "$@"; }
req() { python3 capture/requests.py --base "$API" --model "$MODEL" --out "$rq" "$@"; }
save_logs() { for c in main $(podman ps -a --format '{{.Names}}' | grep '^worker-' || true); do
                podman logs "$c" > "$dir/$stamp.$c$1.log" 2>&1 || true; done; }

# LOOPBACK=1: the plaintext llama.cpp RPC on each container's lo (ground truth for the
# encrypted bridge flows, STUDY.md). The host's tcpdump in the container's network
# namespace; the image has none. One pcap per container and cluster start (suffix $1).
lo_start() {
  [ "${LOOPBACK:-0}" = 1 ] || return 0
  for c in main $(podman ps --format '{{.Names}}' | grep '^worker-' || true); do
    pid=$(podman inspect -f '{{.State.Pid}}' "$c")
    setsid podman unshare nsenter --net="/proc/$pid/ns/net" tcpdump -i lo -s 0 -n -U -B 524288 \
      -w "$dir/$stamp.$c$1.lo.pcap" >/dev/null 2>"$dir/$stamp.$c$1.lo.pcap.log" &
    echo $! >> "$lopids"
  done
}
lo_stop() {
  [ -f "$lopids" ] || return 0
  while read -r pid; do pkill -INT -P "$pid" 2>/dev/null || true; kill -INT "$pid" 2>/dev/null || true; done < "$lopids"
  sleep 1; rm -f "$lopids"
  # size and hash next to each pcap, as capture.sh does for the bridge (STYLE §4)
  for f in "$dir/$stamp".*.lo.pcap; do
    [ -f "$f" ] || continue
    printf '%s  %s  %s bytes\n' "$(sha256sum "$f" | cut -d" " -f1)" "$(basename "$f")" "$(stat -c %s "$f")" > "$f.sha256"
  done
}
fail() { mark failed "$1"; echo "$1" >&2; save_logs ""; lo_stop; capture/capture.sh stop
         localai/cluster.sh down >/dev/null; podman rm -f anchor >/dev/null 2>&1 || true; exit 1; }

localai/cluster.sh down >/dev/null 2>&1 || true
podman network exists "$NET" || podman network create "$NET" >/dev/null
# the bridge exists only while a container is attached; the anchor holds it up so the
# capture runs before the main node starts (mDNS, the first libp2p handshakes)
podman rm -f anchor >/dev/null 2>&1 || true
podman run -d --rm --name anchor --network "$NET" docker.io/library/alpine:3.20 sleep infinity >/dev/null
capture/capture.sh start "$NET" "$pcap"
sleep 3

mark start "cluster.sh up $N (DHT=${DHT:-0}): mDNS, libp2p handshakes, token, ledger"
localai/cluster.sh up "$N"
localai/cluster.sh tunnels "$N" || fail "fewer than $N tunnels"
lo_start ""
# /api/p2p every 5 s for the whole run: the workers' LastSeen, for node-loss detection times
( while :; do printf '{"t":%s,"p2p":%s}\n' "$(date +%s.%N)" "$(curl -s -m 4 "$API/api/p2p" || echo null)" >> "$p2p"; sleep 5; done ) &
sampler=$!
trap 'kill $sampler 2>/dev/null || true' EXIT

mark idle "workers attached, model not loaded, no requests for $IDLE s"
sleep "$IDLE"
mark load "first request (10 tokens): the model loads through the tunnels"
req --n 1 --max-tokens 10 --timeout 600
mark generate "20 x 30 tokens, 33-token prompt"
req --n 20 --max-tokens 30
mark generate-long "5 x 30 tokens, ~2048-token prompt"
req --n 5 --max-tokens 30 --prompt-tokens 2048
mark kill "killproc worker-0 0.5 s into a 300-token request"
( sleep 0.5; localai/cluster.sh killproc 0 >/dev/null ) &
req --n 1 --max-tokens 300 --timeout 120 || true
sleep 60     # past the 40 s offline window: the main node drops the dead worker's tunnel
save_logs ".1"

mark recover "cluster.sh up $N again (new token), then one request to load the model"
localai/cluster.sh up "$N"
localai/cluster.sh tunnels "$N" || fail "fewer than $N tunnels after recover"
lo_start ".2"
req --n 1 --max-tokens 10 --timeout 600
mark pause "pause worker-1 0.5 s into a 300-token request (client gives up after 120 s without a token)"
( sleep 0.5; localai/cluster.sh pause 1 >/dev/null ) &
req --n 1 --max-tokens 300 --timeout 120 || true
mark resume "cluster.sh resume 1, then one 30-token request: does the cluster still answer?"
localai/cluster.sh resume 1 >/dev/null
sleep 10
req --n 1 --max-tokens 30 --timeout 120 || true
mark done ""

kill "$sampler" 2>/dev/null || true
podman stats --no-stream main $(podman ps --format '{{.Names}}' | grep '^worker-' || true) > "$dir/$stamp.stats.txt" 2>&1 || true
lo_stop
capture/capture.sh stop
# container logs next to the pcap before the containers go (the first cluster's are .1)
save_logs ".2"
localai/cluster.sh down >/dev/null
podman rm -f anchor >/dev/null 2>&1 || true
echo "wrote $pcap"; echo "analyse: python3 -m analysis.classify $pcap --timeline $tl"
