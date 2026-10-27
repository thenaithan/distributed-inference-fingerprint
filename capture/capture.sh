#!/usr/bin/env bash
# Passive capture on a rootless Podman network's bridge (vantage V1 in STUDY.md).
#
#   capture/capture.sh start <network> <out.pcap>     tcpdump on the network's bridge, in the background
#   capture/capture.sh stop                            stop it
#   capture/capture.sh iface <network>                 print the bridge interface name
#
# Rootless Podman puts the bridge in a per-user network namespace, so tcpdump runs inside
# it with `podman unshare --rootless-netns`. In that namespace the user is root and has
# CAP_NET_RAW; no sudo. The pcap is written in classic pcap format (-w, not pcapng) with
# full packets (-s 0). Timestamps are the host clock, the same clock capture/phase.sh uses.
set -euo pipefail
cmd=${1:-}; net=${2:-}; out=${3:-}
PIDFILE=${CAPTURE_PIDFILE:-/tmp/capture.pid}

iface() { podman network inspect "$1" --format '{{.NetworkInterface}}'; }

case "$cmd" in
  iface) iface "$net" ;;
  start)
    [ -n "$net" ] && [ -n "$out" ] || { echo "usage: capture.sh start <network> <out.pcap>" >&2; exit 2; }
    podman network exists "$net" || { echo "network $net does not exist; start the cluster first" >&2; exit 1; }
    ifc=$(iface "$net")
    mkdir -p "$(dirname "$out")"
    # -U: write each packet as it arrives, so a kill loses nothing; -n: no name lookups
    podman unshare --rootless-netns tcpdump -i "$ifc" -s 0 -n -U -w "$out" >/dev/null 2>"$out.log" &
    echo $! > "$PIDFILE"
    sleep 1
    kill -0 "$(cat "$PIDFILE")" 2>/dev/null || { echo "tcpdump did not start:"; cat "$out.log"; exit 1; }
    echo "capturing $ifc ($net) -> $out  (pid $(cat "$PIDFILE"))" ;;
  stop)
    [ -f "$PIDFILE" ] || { echo "no capture running"; exit 0; }
    pid=$(cat "$PIDFILE")
    # the pid is the `podman unshare` wrapper; tcpdump is its child. INT lets tcpdump flush.
    pkill -INT -P "$pid" 2>/dev/null || true
    kill -INT "$pid" 2>/dev/null || true
    sleep 1
    rm -f "$PIDFILE"; echo stopped ;;
  *) sed -n 2,13p "$0" ;;
esac
