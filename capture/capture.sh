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
    # the bridge exists only while a container is attached to the network
    podman unshare --rootless-netns ip link show "$ifc" >/dev/null 2>&1 || {
      echo "bridge $ifc is not up: no container is attached to $net yet (start the cluster first)" >&2; exit 1; }
    mkdir -p "$(dirname "$out")"
    # -U: write each packet as it arrives, so a kill loses nothing; -n: no name lookups;
    # -B 524288: a 512 MiB kernel buffer, because a slice upload runs at several Gbit/s on
    # the bridge and the default 2 MiB buffer dropped 7% of packets (20% of bytes) in the
    # first capture
    setsid podman unshare --rootless-netns tcpdump -i "$ifc" -s 0 -n -U -B 524288 -w "$out" >/dev/null 2>"$out.log" &
    echo $! > "$PIDFILE"; echo "$out" > "$PIDFILE.out"
    sleep 1
    kill -0 "$(cat "$PIDFILE")" 2>/dev/null || { echo "tcpdump did not start:"; cat "$out.log"; exit 1; }
    echo "capturing $ifc ($net) -> $out  (pid $(cat "$PIDFILE"))" ;;
  stop)
    [ -f "$PIDFILE" ] || { echo "no capture running"; exit 0; }
    pid=$(cat "$PIDFILE")
    # the pid is the `podman unshare` wrapper (its own session, via setsid, so a Ctrl-C on a
    # run script does not take the capture down); tcpdump is its child. INT lets tcpdump flush.
    pkill -INT -P "$pid" 2>/dev/null || true
    kill -INT "$pid" 2>/dev/null || true
    sleep 1
    rm -f "$PIDFILE"
    # STYLE §4: the pcap is not committed; its size and hash go next to it so a regenerated
    # capture can be told from the original
    out=$(cat "$PIDFILE.out" 2>/dev/null || true)
    if [ -n "$out" ] && [ -f "$out" ]; then
      printf '%s  %s  %s bytes\n' "$(sha256sum "$out" | cut -d" " -f1)" "$(basename "$out")" "$(stat -c %s "$out")" > "$out.sha256"
      cat "$out.sha256"
    fi
    rm -f "$PIDFILE.out"; echo stopped ;;
  *) sed -n 2,13p "$0" ;;
esac
