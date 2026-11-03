#!/usr/bin/env bash
# LocalAI in P2P worker mode on a podman network: one main node (`local-ai run --p2p`) and
# N workers (`local-ai p2p-worker p2p-llama-cpp-rpc`) sharing the token the main node mints.
# This is llama.cpp's rpc-server reached over libp2p streams (FINDINGS-wire.md §3).
#
#   localai/cluster.sh up [N]      main node, then N workers (default 2) with its token
#   localai/cluster.sh down
#   localai/cluster.sh logs <name> main | worker-0 | ...
#   localai/cluster.sh token       print the token the main node is using
#   localai/cluster.sh backend     reinstall the llama-cpp backend into its volume
#   localai/cluster.sh tunnels [N]  wait until main has a tunnel to N workers (fails after 180 s)
#   localai/cluster.sh killproc|pause|resume <i>   node loss on worker-<i>
#
# Settled on v3.0.0 and still true at v4.12.1 (FINDINGS-wire §3): mDNS discovery works on one podman bridge; the model is
# loaded on the first request, not at start; the `model` field is the file name
# (Qwen3-0.6B-Q8_0.gguf). Environment knobs: DHT, P2P_LISTEN, LIB_LOG, NO_LIMITS (below).
# DHT is off by default here (LOCALAI_P2P_DISABLE_DHT=true) so nothing leaves the LAN;
# set DHT=1 for the prediction-12 run.
set -euo pipefail
NET=localai-net; VOL=localai-models; BVOL=localai-backends
# LocalAI v4.12.1 (2026-10-23, git ec92740; the CPU image is the unsuffixed tag since v3:
# `latest-cpu` stopped at v3.0.0 on 2025-06-19), pinned by digest; the wire findings were
# read at 35224b8 (master, 2026-10-27)
IMG=${LOCALAI_IMAGE:-docker.io/localai/localai@sha256:c8556c4f7b6dd9b76e915d515ab5cfe5a765d8ea8fd3f0cf563f9c690b48a7f4}
# v4 images carry no backends; every node installs llama-cpp from the gallery on first use
# (quay.io, a moving `latest-` tag). Installed once here instead, from the release tag, into
# a volume all nodes share, so no node leaves the LAN for it during a capture.
BACKEND=${LOCALAI_BACKEND:-quay.io/go-skynet/local-ai-backends:v4.12.1-cpu-llama-cpp}
MODEL=${LOCALAI_MODEL:-huggingface://ggml-org/Qwen3-0.6B-GGUF/Qwen3-0.6B-Q8_0.gguf}
API_PORT=${LOCALAI_API_PORT:-8080}
DHT=${DHT:-0}
# P2P_LISTEN: LOCALAI_P2P_LISTEN_MADDRS on all nodes, e.g. /ip4/0.0.0.0/tcp/0 for TCP only
# (unset: libp2p's default TCP + QUIC + WebTransport + WebRTC; the tunnels then pick QUIC).
# LIB_LOG: go-libp2p's own log level (LocalAI defaults it to fatal, which hides quic-go).
# NO_LIMITS=1: go-libp2p's resource manager off. LocalAI reads LOCALAI_P2P_ENABLE_LIMITS
# inverted (p2p.go:382 `!= "true"` into Limit.Enable), so limits are on by default and
# "ENABLE_LIMITS=true" is what turns them off (mudler/LocalAI#13031).
P2P_LISTEN=${P2P_LISTEN:-}; LIB_LOG=${LIB_LOG:-info}; NO_LIMITS=${NO_LIMITS:-0}
cmd=${1:-}; arg=${2:-}

ensure() { podman network exists "$NET" 2>/dev/null || podman network create "$NET" >/dev/null
           podman volume exists "$VOL" 2>/dev/null || podman volume create "$VOL" >/dev/null
           podman volume exists "$BVOL" 2>/dev/null || podman volume create "$BVOL" >/dev/null
           [ -d "$(podman volume inspect "$BVOL" --format '{{.Mountpoint}}')/llama-cpp" ] || install_backend; }
# named llama-cpp: the worker looks the backend up by that name (worker_llamacpp.go:38)
install_backend() { echo "installing $BACKEND into $BVOL"
  podman run --rm -v "$BVOL:/backends" "$IMG" backends install "$BACKEND" llama-cpp; }
dht_env() { [ "$DHT" = 1 ] && echo "-e LOCALAI_P2P_DISABLE_DHT=false" || echo "-e LOCALAI_P2P_DISABLE_DHT=true"
            echo "-e LOCALAI_P2P_LIB_LOGLEVEL=$LIB_LOG"
            [ -z "$P2P_LISTEN" ] || echo "-e LOCALAI_P2P_LISTEN_MADDRS=$P2P_LISTEN"
            [ "$NO_LIMITS" != 1 ] || echo "-e LOCALAI_P2P_ENABLE_LIMITS=true"; }
token() { curl -sf "http://localhost:$API_PORT/api/p2p/token"; }

case "$cmd" in
  up)
    n=${arg:-2}; ensure
    podman rm -f main >/dev/null 2>&1 || true
    # LOCALAI_MODELS only until the model is in the volume: on every start v4's importer
    # asks Hugging Face about the URI again even when the file is there. Its config, written
    # by the importer, is loaded from /models without it.
    models_env="-e LOCALAI_MODELS=$MODEL"
    [ -f "$(podman volume inspect "$VOL" --format '{{.Mountpoint}}')/$(basename "$MODEL").yaml" ] && models_env=""
    # shellcheck disable=SC2046,SC2086
    # LOCALAI_VRAM_WARM_LIMIT=0: v4 otherwise "warms" size estimates for 300 gallery models
    # after start, ~2 GB from Hugging Face over 5.5 min (estimate_warm.go; 2026-10-29 run).
    # the image's entrypoint already execs ./local-ai, so the command starts at the
    # subcommand (`run`, `worker`); a leading `local-ai` becomes a stray argument and the
    # parser rejects whatever comes last. The model goes in through LOCALAI_MODELS.
    podman run -d --name main --network "$NET" -v "$VOL:/models" -v "$BVOL:/backends" -p "$API_PORT:8080" \
      -e LOCALAI_P2P=true $(dht_env) -e LOCALAI_P2P_LOGLEVEL=debug -e LOCALAI_LOG_LEVEL=debug $models_env \
      -e LOCALAI_VRAM_WARM_LIMIT=0 "$IMG" \
      run --p2p >/dev/null
    echo "image $(podman image inspect "$IMG" --format '{{.Digest}}')"
    echo "started main; waiting for its token"
    # v4 preloads LOCALAI_MODELS before the HTTP server binds: the first start downloads
    # the 767 MB model into the volume first
    for _ in $(seq 300); do t=$(token || true); [ -n "$t" ] && break; sleep 2; done
    [ -n "${t:-}" ] || { echo "no token from main (podman logs main)"; exit 1; }
    for i in $(seq 0 $((n-1))); do
      podman rm -f "worker-$i" >/dev/null 2>&1 || true
      # shellcheck disable=SC2046
      # v4: the P2P llama.cpp worker is `p2p-worker p2p-llama-cpp-rpc` (core/cli/cli.go:21);
      # `worker` is now the generic distributed worker and rejects it with kong's usage
      # exit 80. LocalAI's docs and main's start-up hint (run.go:550) still print the v3 form
      # (mudler/LocalAI#13032).
      podman run -d --name "worker-$i" --network "$NET" -v "$BVOL:/backends" \
        -e TOKEN="$t" $(dht_env) -e LOCALAI_LOG_LEVEL=debug -e LOCALAI_P2P_LOGLEVEL=debug "$IMG" \
        p2p-worker p2p-llama-cpp-rpc >/dev/null
      echo "started worker-$i"
    done
    echo "token: $t"; echo "API on http://localhost:$API_PORT; workers appear under /api/p2p (JSON) or /p2p (the Swarm page)" ;;
  backend) podman volume rm -f "$BVOL" >/dev/null 2>&1 || true; ensure ;;
  token) token; echo ;;
  # wait until the main node has a tunnel to <N> workers (default 2): a request before that
  # loads the whole model on the main node alone. Counted from the last "setting
  # LLAMACPP_GRPC_SERVERS" line (v3 and v4 format it differently). Fails after 180 s or as
  # soon as a worker has exited, instead of waiting forever.
  tunnels)
    n=${arg:-2}
    for _ in $(seq 90); do
      got=$(podman logs main 2>&1 | grep 'setting LLAMACPP_GRPC_SERVERS' | tail -1 | grep -o '127\.0\.0\.1:[0-9]*' | wc -l || true)
      [ "$got" -ge "$n" ] && { echo "$got tunnels"; exit 0; }
      dead=$(podman ps -a --filter name='^worker-' --filter status=exited --format '{{.Names}} {{.Status}}')
      [ -z "$dead" ] || { echo "worker exited: $dead" >&2; exit 1; }
      sleep 2
    done
    echo "fewer than $n tunnels after 180 s" >&2; exit 1 ;;
  # node loss, as llamacpp/cluster.sh: <arg> is the worker number. killproc kills the
  # container's init (local-ai, which takes its llama-cpp-rpc-server child with it) from the
  # host; the kernel ignores SIGKILL sent to a PID namespace's init from inside it
  killproc) date +%s.%N; kill -9 "$(podman inspect -f '{{.State.Pid}}' "worker-$arg")" ;;
  pause)    date +%s.%N; podman pause "worker-$arg" >/dev/null ;;
  resume)   date +%s.%N; podman unpause "worker-$arg" >/dev/null ;;
  down)  for c in main $(podman ps -a --format '{{.Names}}' | grep '^worker-' || true); do podman rm -f "$c" >/dev/null 2>&1 || true; done; echo removed ;;
  logs)  podman logs -f "$arg" ;;
  *) sed -n 2,10p "$0" ;;
esac
