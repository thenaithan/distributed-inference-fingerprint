#!/usr/bin/env bash
# One LocalAI load attempt under capture: discovery, the lazy model load through the P2P
# tunnels, and whatever happens to it (at v3.0.0 the worker being uploaded to was dropped
# after 40 s, FINDINGS-wire §3). Not the full run; that is run_localai.sh once a load completes.
#
#   capture/run_localai_load.sh [load_timeout_s]               default 600
#   NO_LIMITS=1 capture/run_localai_load.sh                    libp2p resource manager off
#   P2P_LISTEN=/ip4/0.0.0.0/tcp/0 capture/run_localai_load.sh  TCP-only overlay
#
# Writes next to the pcap: the timeline, the request log, /api/p2p sampled every 5 s
# (<stamp>.p2p.jsonl: the workers' LastSeen during the load), podman stats at the end
# (NET IO = bytes each worker received) and podman logs of every container.
set -euo pipefail
cd "$(dirname "$0")/.."
LOAD_TIMEOUT=${1:-600}
N=2; NET=localai-net; API=http://localhost:${LOCALAI_API_PORT:-8080}
stamp=$(LC_ALL=C date +%Y%m%d-%H%M%S); dir=captures/localai
pcap=$dir/$stamp.pcap; tl=$dir/$stamp.timeline.csv; rq=$dir/$stamp.requests.jsonl; p2p=$dir/$stamp.p2p.jsonl
mkdir -p "$dir"
mark() { capture/phase.sh "$tl" "$@"; }
# the main node prints the swarm token (its pre-shared secret) at start; kept out of the logs
redact() { sed -E 's/^b3RwOg[A-Za-z0-9+\/=]*$/<redacted: the swarm token>/; s/export TOKEN="[^"]*"/export TOKEN="<redacted>"/'; }

localai/cluster.sh down >/dev/null 2>&1 || true
podman network exists "$NET" || podman network create "$NET" >/dev/null
# the bridge exists only while a container is attached; the anchor holds it up so the
# capture runs before the main node starts (mDNS, the first libp2p handshakes)
podman rm -f anchor >/dev/null 2>&1 || true
podman run -d --rm --name anchor --network "$NET" docker.io/library/alpine:3.20 sleep infinity >/dev/null
capture/capture.sh start "$NET" "$pcap"
sleep 3
mark start "cluster.sh up $N (P2P_LISTEN=${P2P_LISTEN:-default})"
localai/cluster.sh up "$N"
# the model loads on the first request, so wait until the main node has a tunnel to every
# worker; a request before that loads the whole model on the main node alone
if ! localai/cluster.sh tunnels "$N"; then
  mark failed "fewer than $N tunnels after the wait"
  for c in main $(podman ps -a --format '{{.Names}}' | grep '^worker-' || true); do podman logs "$c" 2>&1 | redact > "$dir/$stamp.$c.log" || true; done
  capture/capture.sh stop; localai/cluster.sh down >/dev/null; podman rm -f anchor >/dev/null 2>&1 || true
  echo "no load attempted; logs in $dir/$stamp.*.log"; exit 1
fi
sleep 15
mark load "first request: the model loads through the tunnels (timeout $LOAD_TIMEOUT s)"
( while :; do printf '{"t":%s,"p2p":%s}\n' "$(date +%s.%N)" "$(curl -s "$API/api/p2p" || echo null)" >> "$p2p"; sleep 5; done ) &
sampler=$!
python3 capture/requests.py --base "$API" --model Qwen3-0.6B-Q8_0.gguf --n 1 --max-tokens 10 \
  --timeout "$LOAD_TIMEOUT" --out "$rq" || true
kill "$sampler" 2>/dev/null || true
mark done ""
podman stats --no-stream main $(podman ps --format '{{.Names}}' | grep '^worker-' || true) > "$dir/$stamp.stats.txt" 2>&1 || true
capture/capture.sh stop
for c in main $(podman ps -a --format '{{.Names}}' | grep '^worker-' || true); do podman logs "$c" 2>&1 | redact > "$dir/$stamp.$c.log" || true; done
localai/cluster.sh down >/dev/null
podman rm -f anchor >/dev/null 2>&1 || true
cat "$dir/$stamp.stats.txt"
echo "wrote $pcap"; echo "analyse: python3 -m analysis.classify $pcap --timeline $tl"
