# Experiment 4: fingerprinting shard-to-shard traffic

## The question

The essay asked whether shard-to-shard traffic can be fingerprinted against background
noise, and what decentralised coordination looks like on the wire. Experiments 1 to 3
took the operator's and the defender's side of a swarm that is already known to exist.
This experiment is the defender's first step: **from a packet capture alone, with no access
to any node, how quickly and how reliably can a distributed-inference swarm be recognised,
which stack it is, and what it is doing; and what does encryption take away?**

Two readers again. The operator wants to know what the swarm gives away and what a
configuration change could hide. The defender wants the smallest capture (seconds, bytes,
vantage point) that gives a confident call, and a false-positive rate against ordinary
traffic.

## Scope

Measure and classify, with rules that can be read. No machine-learned detector beyond a
baseline for comparison; no modification of any stack to hide it (evasion is the operator's
problem and a different experiment); cooperative systems only, as shipped. The stacks are
the ones from Experiment 3 that put traffic on a wire, plus the one the essay named:

| stack | why | what it tests |
|---|---|---|
| exo bc412e2 | the consumer-device swarm of the essay's scenario | custom beacon, plaintext control plane, separate data ring |
| llama.cpp RPC 74bca39 | the CPU stack most likely on real consumer hardware | plaintext, fixed port, silent when idle |
| LocalAI 35224b8, worker mode | llama.cpp RPC inside an encrypted libp2p overlay; the essay names LocalAI and libp2p | what survives encryption: timing and overlay handshake only |

vLLM is left out: with PP=2 on one host its ranks share memory and nothing reaches the
wire; multi-node vLLM runs over a datacenter fabric a defender's LAN or home-router vantage
does not see. Petals is left out for the same reason as in Experiment 3 (no commits since
September 2024) and because LocalAI covers libp2p.

## Vantage points

- **V1, on the LAN.** A passive tap on the segment the nodes share: sees multicast
  discovery, every unicast flow between nodes, and the API traffic. In rootless Podman that
  is the network's bridge inside the rootless network namespace (`capture/capture.sh`).
  Everything is captured here.
- **V2, at the egress of one home.** Sees only what one device sends off its LAN. For a
  swarm inside one LAN: nothing. For the Frontier Red Team scenario, boxes in different
  homes, each box's coordination and shard traffic is its egress. Not captured separately:
  each per-peer flow in the V1 capture is what one home router would see, so V2 is read off
  the V1 capture by restricting to one node's flows.
- **V3, on a node.** Process and socket listings; trivial and out of scope.

## What is captured

Per stack, on V1, with `tcpdump` writing pcap plus a timeline file of what the harness did
and when (same clock as the capture):

| phase | duration | what should be on the wire (FINDINGS-wire.md) |
|---|---|---|
| idle, cluster up, model loaded, no requests | 10 min | exo: 1 s beacon, 1 s info, 5 s heartbeat, 10 s `GET /node_id`; llama.cpp: nothing; LocalAI: 10/20/60 s ledger |
| load | one model load | llama.cpp and LocalAI: bulk upload the size of the slice; exo: nothing on the wire (weights on disk per node) |
| generation | 20 requests, 30 tokens each, 33-token prompt; 5 requests with a 2048-token prompt | per-token bursts at the decode rate; prefill bursts proportional to prompt |
| node loss | the Experiment 3 kill, pause, cut on one node, once each | detection and re-placement as seen from outside |

Background traffic, captured on the same bridge with the swarm down and separately with
it up (mixed):

| generator | why |
|---|---|
| HTTP file download (nginx container → curl) | bulk transfer, like a model load |
| HTTP video stream (ffmpeg → HTTP → ffplay/curl) | steady rate, fixed-size packets, like decode |
| SSH session with periodic keepalive, and `ping` | small periodic packets, like heartbeats |
| mDNS/avahi, SSDP from a container | multicast beacons, like discovery |
| iperf3 | saturating flow |
| a syncthing pair, if time allows | libp2p-like encrypted peer traffic with periodic announces |

Public home-network captures would be a better negative set; none is bundled by default,
and `analysis/` accepts any pcap so one can be added later with its source cited.

## Predictions, written before any capture

Numbered so §8 of the results can score them, as in Experiment 3.

1. **exo is identified by its first beacon.** Within 1 s of capture, a 20-byte UDP datagram
   to `[ff12::e0a1:de89]:52413` with payload starting `45 58 4F 00` appears from every node.
   No other process on a LAN sends to that group. One datagram is enough; the rule has no
   false positives on the background set.
2. **exo's node count is readable from the beacon sources within 2 s**, and the master is
   identifiable within 10 s as the node whose 52414 flows carry the `global_events` replies
   (or, failing that, as the hub of the `GET /node_id` bursts).
3. **exo's control plane shows at least three periodicities when idle**: 1 s (beacon and
   info), 5 s (election heartbeat), 10 s (`GET /node_id`), plus one near 2.5 s from zenoh
   keepalives. Autocorrelation of per-second byte counts on the 52414 flows shows the 1 s
   and 5 s peaks within 60 s of capture.
4. **exo generation appears as a new pair of TCP flows on ports in 49153–65535 between
   ring neighbours**, silent until a request, then bursts of about 2 KiB per hop at the
   decode rate (0.4 Hz on this CPU), and one JSON message of a few hundred bytes per token
   on 52414. Prefill of a 2048-token prompt is a single burst of about 4 MiB per hop.
5. **llama.cpp is identified by one TCP segment**: the 33-byte HELLO on port 50052. If the
   capture starts after the connection, every request frame still starts with a command
   byte 0x00–0x16 and an 8-byte little-endian length, and tensor names (`blk.N.attn_q.weight`
   style) are readable in the load phase. The rule has no false positives on the background
   set.
6. **llama.cpp is invisible when idle.** Between the load and the first request, and between
   requests, the 50052 flows carry zero payload bytes for the whole 10-minute idle phase.
7. **llama.cpp generation is a star with a heavy return leg.** Per token: the main host sends
   about 4 KiB plus small inputs to the first host and receives about 4 KiB; sends about
   4 KiB to the second and receives about 600 KB (logits, n_vocab 151 936 × 4 B). The RPC
   hosts never exchange a packet. The per-token byte count is constant within 5% across
   tokens of one request. The decode rate is readable from the burst interval to within 10%
   of the server's reported timing.
8. **llama.cpp's load phase moves the slice size** to each host: about 320 MB each for the
   two-host Qwen3-0.6B Q8_0 split, in SET_TENSOR frames; with `-c` on a second start, under
   1 MB.
9. **LocalAI shows the libp2p handshake and nothing after.** `/multistream/1.0.0` and
   `/noise` (or a TLS ClientHello with ALPN `libp2p` and no SNI) at connection start; no
   readable RPC bytes anywhere in the LAN capture. The loopback capture inside the
   containers shows the §2 llama.cpp signatures unchanged.
10. **LocalAI's timing signature equals llama.cpp's plus overhead.** The per-token burst
    structure of prediction 7 is visible in the encrypted flows with sizes larger by a
    roughly constant overlay overhead (Noise and yamux framing, under 10% on the 600 KB leg,
    more on the 4 KiB legs). The decode rate is still readable from the burst interval.
11. **LocalAI's idle periodicities are 10 s, 20 s and 60 s** in the encrypted flows between
    nodes, visible in autocorrelation within 2 minutes of capture; plus mDNS queries and
    answers on 224.0.0.251:5353 carrying a 43-character random label and `/p2p/` TXT records.
12. **LocalAI leaves the LAN by default**: with no bootstrap list the node contacts public
    DHT bootstrap addresses within 60 s of starting, mostly on port 4001; with
    `LOCALAI_P2P_DISABLE_DHT=true` it does not. exo and llama.cpp send nothing off the LAN
    after the model is on disk.
13. **Encryption does not hide generation.** A rule using only packet sizes and timing (no
    payload) flags generation in all three stacks within 10 tokens, and separates it from
    the video stream and the download in the background set, because neither of those has
    the alternating request/response structure with a fixed large return leg.
14. **Node loss is visible from outside.** exo: the beacon from the lost node stops at
    once, and 15 s later a burst on 52414 (instance deleted, re-placement) followed by
    silence on the old ring ports and new ring flows on new ports; llama.cpp: a TCP RST (kill)
    or nothing at all (pause, cut), matching Experiment 3's detection times.
15. **The static rules fail only one way**: a port change. Changing `--discovery-port`,
    the zenoh port, or `-p` on rpc-server defeats the port part of each rule but not the
    byte signatures (exo magic, llama.cpp HELLO and frame structure), which need a source
    patch to remove.

Predictions 1, 5 and 9 are the ones that decide the experiment's headline: how much
capture is enough. 7, 10 and 13 decide what encryption costs the defender. 12 is the one
that matters for the home-router vantage.

## Method

Same host as Experiment 3 (i5-14600K, rootless Podman, EndeavourOS). The exo and llama.cpp
clusters are the Experiment 3 harnesses (`cluster.sh` from distributed-inference-recovery,
vendored here unchanged). LocalAI gets its own `Containerfile` and `cluster.sh`: one main
node and two workers in `worker p2p-llama-cpp-rpc` mode sharing a token, DHT disabled for
the main runs and enabled once for prediction 12.

Capture: `capture/capture.sh <net> <out.pcap>` runs `tcpdump -i <bridge> -s 0 -w` inside
the rootless network namespace (`podman unshare --rootless-netns`), and
`capture/phase.sh` appends `t,phase,note` lines to a timeline file with the host clock so
pcap timestamps and phases line up. For LocalAI the containers also run `tcpdump -i lo`
inside (ground truth for the encrypted flows).

Analysis (`analysis/`): `flows.py` turns a pcap into a flow table (5-tuple, start, end,
packets, bytes each way, payload-size histogram, inter-arrival series) and a per-second
byte series per flow; `signatures.py` holds the static rules (exo beacon, llama.cpp
HELLO and frame grammar, libp2p multistream/ALPN, mDNS label shape); `rhythm.py` finds
periodicities (autocorrelation of per-second counts) and generation bursts (runs of
alternating request/response with stable sizes); `classify.py` applies the rules to any
pcap and reports, per flow and per host: stack, role, phase, confidence, and the capture
time at which the call became possible. `evaluate.py` runs it over the swarm captures and
the background captures and reports detection latency, true-positive and false-positive
counts per rule.

Reported, per stack: time-to-detect from capture start for each rule; what the rule needs
(bytes, packets, seconds); node count and role recovery; decode rate recovered vs. reported;
what survives encryption; false positives on the background set; what leaves the LAN.

## Out of scope

Evasion (changing the stacks to hide); WAN conditions (`tc netem`, NAT traversal in
anger); vLLM and Petals; machine-learned classifiers beyond a baseline; training traffic
(the essay's "heavier, bursty" case); attributing traffic to a model or a shard count
beyond what sizes give away.

## Reading

- The essay's detection question: naithanweigh.com/writing/asymmetric-persistence/
- Experiment 3's source readings, reused here: distributed-inference-recovery,
  `FINDINGS-source.md`.
- zenoh transport (keepalive, lease, link framing): zenoh 1.x docs on `transport/link/tx`
  and `lease`; the fork's defaults are assumed equal to upstream.
- libp2p specs: multistream-select, Noise handshake, TLS ALPN `libp2p`, mDNS discovery
  (`_p2p._udp.local` by default; LocalAI overrides the label), Kademlia DHT and the IPFS
  bootstrap list.
- Traffic-analysis background: website fingerprinting on encrypted flows (packet-size and
  timing features) is the nearest literature; the per-token cadence here is a far stronger
  signal than anything those papers work with.
