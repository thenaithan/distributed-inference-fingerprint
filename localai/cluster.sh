#!/usr/bin/env bash
# LocalAI in P2P worker mode on a podman network: one main node (`local-ai run --p2p`) and
# N workers (`local-ai worker p2p-llama-cpp-rpc`) sharing the token the main node mints.
# This is llama.cpp's rpc-server reached over libp2p streams (FINDINGS-wire.md §3).
#
#   localai/cluster.sh up [N]      main node, then N workers (default 2) with its token
#   localai/cluster.sh down
#   localai/cluster.sh logs <name> main | worker-0 | ...
#   localai/cluster.sh token       print the token the main node is using
#
# Not yet run (plumbing check pending). Known unknowns, to settle on the first run:
#   - whether mDNS discovery works across containers on one podman bridge (LocalAI's docs
#     recommend --net host); if not, set LOCALAI_P2P_LISTEN_MADDRS / bootstrap maddrs to the
#     main node's container address;
#   - the image's llama-cpp backend must be present for the worker (`llama-cpp-rpc-server`),
#     else the worker auto-installs it from the gallery (needs internet inside the container);
#   - the model: a GGUF the main node loads with the rpc workers attached; the docs say the
#     weights are split by worker memory.
# DHT is off by default here (LOCALAI_P2P_DISABLE_DHT=true) so nothing leaves the LAN;
# set DHT=1 for the prediction-12 run.
set -euo pipefail
NET=localai-net; IMG=${LOCALAI_IMAGE:-docker.io/localai/localai:latest-cpu}; VOL=localai-models
MODEL=${LOCALAI_MODEL:-huggingface://ggml-org/Qwen3-0.6B-GGUF/Qwen3-0.6B-Q8_0.gguf}
API_PORT=${LOCALAI_API_PORT:-8080}
DHT=${DHT:-0}
cmd=${1:-}; arg=${2:-}

ensure() { podman network exists "$NET" 2>/dev/null || podman network create "$NET" >/dev/null
           podman volume exists "$VOL" 2>/dev/null || podman volume create "$VOL" >/dev/null; }
dht_env() { [ "$DHT" = 1 ] && echo "-e LOCALAI_P2P_DISABLE_DHT=false" || echo "-e LOCALAI_P2P_DISABLE_DHT=true"; }
token() { curl -sf "http://localhost:$API_PORT/p2p/token"; }

case "$cmd" in
  up)
    n=${arg:-2}; ensure
    podman rm -f main >/dev/null 2>&1 || true
    # shellcheck disable=SC2046
    # the model goes in through LOCALAI_MODELS: the positional form (`local-ai run <uri>`)
    # exists in the pinned source but not in every image build ("unexpected argument")
    podman run -d --name main --network "$NET" -v "$VOL:/models" -p "$API_PORT:8080" \
      -e LOCALAI_P2P=true $(dht_env) -e LOCALAI_P2P_LOGLEVEL=debug -e LOCALAI_MODELS="$MODEL" "$IMG" \
      local-ai run --p2p >/dev/null
    echo "image $(podman image inspect "$IMG" --format '{{.Digest}}')"
    echo "started main; waiting for its token"
    for _ in $(seq 60); do t=$(token || true); [ -n "$t" ] && break; sleep 2; done
    [ -n "${t:-}" ] || { echo "no token from main (podman logs main)"; exit 1; }
    for i in $(seq 0 $((n-1))); do
      podman rm -f "worker-$i" >/dev/null 2>&1 || true
      # shellcheck disable=SC2046
      podman run -d --name "worker-$i" --network "$NET" -v "$VOL:/models" \
        -e TOKEN="$t" $(dht_env) -e LOCALAI_P2P_LOGLEVEL=debug "$IMG" \
        local-ai worker p2p-llama-cpp-rpc >/dev/null
      echo "started worker-$i"
    done
    echo "token: $t"; echo "API on http://localhost:$API_PORT; workers appear under /p2p (or the Swarm page)" ;;
  token) token; echo ;;
  down)  for c in main $(podman ps -a --format '{{.Names}}' | grep '^worker-' || true); do podman rm -f "$c" >/dev/null 2>&1 || true; done; echo removed ;;
  logs)  podman logs -f "$arg" ;;
  *) sed -n 2,10p "$0" ;;
esac
