#!/usr/bin/env bash
# Background traffic on a podman network, for the false-positive set (STUDY.md). Each
# generator is a pair of containers on the given network; they run for DURATION seconds
# while capture/capture.sh records the bridge.
#
#   background/run.sh <network> [duration_seconds]       default 600
#
# Generators (all from the docker.io/library images, pulled on first use):
#   download   nginx serving a 300 MB file, curl fetching it on a loop       (bulk, like a model load)
#   stream     ffmpeg pushing a test pattern as MPEG-TS over UDP at a fixed rate (steady, like decode)
#   ssh-ish    two alpine containers exchanging a 64-byte UDP ping every 2 s   (heartbeat-like)
#   mdns       an avahi container announcing a fake service                   (multicast beacon)
#   iperf      iperf3 for 30 s in the middle                                  (saturating flow)
set -euo pipefail
NET=${1:?network}; DUR=${2:-600}
A=docker.io/library/alpine:3.20
run() { podman run -d --rm --network "$NET" "$@" >/dev/null; }

run --name bg-nginx docker.io/library/nginx:alpine sh -c 'head -c 300000000 /dev/urandom > /usr/share/nginx/html/big; nginx -g "daemon off;"'
sleep 3
run --name bg-curl $A sh -c "apk add -q curl; while true; do curl -s -o /dev/null http://bg-nginx/big; sleep 30; done"
run --name bg-stream-rx $A sh -c "apk add -q socat; socat -u UDP-RECV:5004 /dev/null"
run --name bg-stream-tx docker.io/linuxserver/ffmpeg:latest -re -f lavfi -i testsrc=size=640x480:rate=25 -c:v libx264 -b:v 2M -f mpegts udp://bg-stream-rx:5004?pkt_size=1316
run --name bg-ping-b $A sh -c "apk add -q socat; socat -u UDP-RECV:9000 /dev/null"
run --name bg-ping-a $A sh -c "apk add -q socat; while true; do head -c 64 /dev/zero | socat -u - UDP-SENDTO:bg-ping-b:9000; sleep 2; done"
run --name bg-mdns $A sh -c "apk add -q avahi dbus; mkdir -p /run/dbus; dbus-daemon --system; avahi-daemon --no-drop-root --no-chroot -D; avahi-publish -s printer _ipp._tcp 631 pdl=application/pdf"
run --name bg-iperf-s $A sh -c "apk add -q iperf3; iperf3 -s"
sleep $((DUR / 2))
podman run --rm --network "$NET" --name bg-iperf-c $A sh -c "apk add -q iperf3; iperf3 -c bg-iperf-s -t 30" >/dev/null || true
sleep $((DUR / 2 - 30))
for c in bg-curl bg-nginx bg-stream-tx bg-stream-rx bg-ping-a bg-ping-b bg-mdns bg-iperf-s; do podman rm -f "$c" >/dev/null 2>&1 || true; done
echo done
