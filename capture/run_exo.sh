#!/usr/bin/env bash
# One exo capture: cluster start (discovery, election), placement (load + warmup), idle,
# generation, long prefill, worker loss. Capture on the exo-net bridge.
#
#   capture/run_exo.sh [idle_seconds]      default 600
#
# Needs: the exo-node image (exo/Containerfile), tcpdump, and the Experiment 3 harness for
# placement: set RECOVERY to the distributed-inference-recovery checkout (its exo/trial.py
# places the model over 3 nodes and runs one request; --mode none).
set -euo pipefail
cd "$(dirname "$0")/.."
IDLE=${1:-600}
RECOVERY=${RECOVERY:-../distributed-inference-recovery}
MODEL=mlx-community/Qwen3-0.6B-8bit
stamp=$(LC_ALL=C date +%Y%m%d-%H%M%S); dir=captures/exo; pcap=$dir/$stamp.pcap; tl=$dir/$stamp.timeline.csv; rq=$dir/$stamp.requests.jsonl
mkdir -p "$dir"
mark() { capture/phase.sh "$tl" "$@"; }

exo/cluster.sh down >/dev/null 2>&1 || true
podman network exists exo-net || podman network create --ipv6 exo-net >/dev/null
# the bridge exists only while a container is attached; an idle anchor holds it up so the
# capture is running before the first exo node starts (beacons, zenoh links, election)
podman rm -f anchor >/dev/null 2>&1 || true
podman run -d --rm --name anchor --network exo-net docker.io/library/alpine:3.20 sleep infinity >/dev/null
capture/capture.sh start exo-net "$pcap"
sleep 3
mark start "cluster.sh up 3: discovery beacons, zenoh links, election"
exo/cluster.sh up 3
sleep 30
mark place "place_instance over 3 nodes: load, warmup (50 tokens), one request"
python3 "$RECOVERY/exo/trial.py" --nodes 3 --mode none --out "$dir/$stamp.place.jsonl"
mark idle "instance ready, no requests for $IDLE s"
sleep "$IDLE"
mark generate "20 x 30 tokens, 33-token prompt (2.4 s/token: ~25 min)"
python3 capture/requests.py --base http://localhost:52415 --model "$MODEL" --n 20 --max-tokens 30 --gap 10 --out "$rq"
# one long request (the plan cut this phase to one); its prefill runs ~90 min at 2.6 s/token
# with no token to show for it, so the no-token deadline must outlast it
mark generate-long "1 x 30 tokens, ~2048-token prompt (prefill ~90 min at 2.6 s/token)"
python3 capture/requests.py --base http://localhost:52415 --model "$MODEL" --n 1 --max-tokens 30 --prompt-tokens 2048 --timeout 10800 --out "$rq"
mark kill "kill worker node 1 during a request; exo detects at 15 s, re-places (~275 s)"
python3 "$RECOVERY/exo/trial.py" --nodes 3 --fail-worker --mode kill --out "$dir/$stamp.kill.jsonl" || true
mark done ""
capture/capture.sh stop
exo/cluster.sh down >/dev/null
podman rm -f anchor >/dev/null 2>&1 || true
echo "wrote $pcap"; echo "analyse: python3 -m analysis.classify $pcap --timeline $tl"
