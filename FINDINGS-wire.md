# What each stack puts on the wire, read from source

Read before any capture, at the commits below. Citations are file:line in the checked-out
tree; constants are the defaults in code. Anything not confirmed from this source is
marked **[inferred]**.

- exo: `exo-explore/exo` at `bc412e2` (the Experiment 3 commit); Python under `src/exo`,
  networking in Rust under `rust/networking`. zenoh is a fork (`evanev7/zenoh`, branch
  `exo`, `Cargo.toml:51,63-85`) whose source was not read.
- llama.cpp: `ggml-org/llama.cpp` at `74bca39` (the Experiment 3 commit); RPC backend in
  `ggml/src/ggml-rpc/ggml-rpc.cpp`, sockets in `ggml/src/ggml-rpc/transport.cpp`.
- LocalAI: `mudler/LocalAI` at `35224b8` (2026-10-27); P2P in `core/p2p`, worker in
  `core/cli/worker`. edgevpn v0.34.0 and go-libp2p v0.48.0 (`go.mod:34,40`) were not
  readable from the sandbox; their behaviour is **[inferred]** from library defaults.

The short version: **exo and llama.cpp RPC are plaintext with fixed ports and fixed byte
signatures; LocalAI is llama.cpp RPC carried over an encrypted libp2p overlay, so its
signatures are the overlay's handshake and its timing, not its content.** None of the
three hides its periodicity.

| | exo | llama.cpp RPC | LocalAI P2P (worker mode) |
|---|---|---|---|
| discovery | own UDP beacon, IPv6 multicast `ff12::e0a1:de89` port 52413, 1 Hz | none (static `--rpc host:port` list) | mDNS 224.0.0.251:5353 with a per-network random label; Kademlia DHT on by default |
| control transport | zenoh, TCP 52414, plaintext JSON | the RPC connection itself | libp2p streams (Noise/TLS, yamux), random ports |
| data transport | MLX ring, TCP on random ports 49153–65535, neighbours only | TCP 50052, plaintext, star through the main host | the same RPC, inside the overlay |
| encryption | none | none | all but the handshake |
| idle periodicity | 1 s beacon, 1 s node info, 5 s election heartbeat, ~10 s `GET /node_id`, ~2.5 s zenoh keepalive [inferred] | none: silent when idle | 10 s ledger sync, 20 s worker announce, 60 s service announce, 10 s discovery |
| leaves the LAN | Hugging Face downloads only | nothing | DHT bootstrap (public IPFS nodes unless disabled) [inferred], AutoNAT/relay, gallery hosts |

## 1. exo (bc412e2)

### Discovery: a custom beacon, not zenoh scouting
- Multicast group `ff12::e0a1:de89` (`rust/networking/src/discovery.rs:19`), UDP port 52413
  (`--discovery-port`, `src/exo/main.py:538-544`), socket bound to `[::]:52413` and joined on
  every interface with a non-loopback IPv6 address (`discovery.rs:75,85-99`).
- Datagrams are packed little-endian structs with a 4-byte header: magic `"EXO"`
  (`45 58 4F`) and a kind byte (`discovery.rs:20,462-465`).
  - **Hello**, kind `00`, 20 bytes: header, 8-byte random nonce, 8-byte namespace
    (`discovery.rs:469-472`). Sent to the group on each interface every **1 s**
    (`discovery.rs:138,282-293`).
  - **WhatsUp**, kind `01`, 30 bytes: header, echoed nonce, 16-byte zenoh id, zenoh port as
    u16 LE (`discovery.rs:480-484`). **Unicast** back to the Hello's source
    (`discovery.rs:230-240`).
  - Any other size is dropped (`discovery.rs:205,248`).
- The namespace bytes are the first 8 of `blake3(namespace)` (`lib.rs:61-65`); the default
  namespace is the exo version string (`main.py:411-416`), so all nodes of one release
  carry the same 8 bytes at offset 12.
- After a WhatsUp, the node with the larger zid dials the other over TCP (`lib.rs:84-104`).
  There is no peer list; `--bootstrap-peers` refuses to start (`main.py:373-374`).

### Control plane: zenoh 1.9 fork, plaintext
- Router mode, listening on `tcp/[::]:52414` (`rust/networking/src/lib.rs:30-31`,
  default from `main.py:531-537`). Only a `tcp/` endpoint is configured: **no TLS**.
- zenoh's own multicast scouting is **off** (`lib.rs:32-33`); gossip multihop is on
  (`lib.rs:34`); adminspace on (`lib.rs:35`); a memory storage on `storage/mem1/**` with
  `replication.interval: 2` (`lib.rs:40-50`), which **[inferred]** may send digests every 2 s.
- Lease and keepalive are not set by exo; a comment states the lease is 10 s
  (`discovery.rs:32`); **[inferred]** zenoh sends 4 keepalives per lease, so one every
  ~2.5 s. Experiment 3 measured the lease path at 13.2 s (10 s lease plus a 3 s election).
- Key expressions: `topics/<name>` (`swarm.rs:168,185`) with names `global_events`,
  `local_events`, `state_snapshots`, `commands`, `election_messages`, `download_commands`
  (`src/exo/routing/topics.py:44-56`); liveliness tokens `live/<zid>` (`swarm.rs:106-114`).
- Payloads are UTF-8 JSON from pydantic `model_dump_json` (`topics.py:37-41`). Election
  messages are sent at zenoh priority InteractiveHigh, the rest at Data (`swarm.rs:167-175`).

### Idle traffic
| message | interval | cite |
|---|---|---|
| discovery Hello, 20 B UDP multicast | 1 s per interface | `discovery.rs:138` |
| `NodeGatheredInfo` JSON on `local_events` (psutil memory on Linux) | 1 s | `src/exo/utils/info_gatherer/info_gatherer.py:447,452` |
| other monitors | 10 s, 30 s, 60 s | `info_gatherer.py:448-456` |
| election heartbeat (`ElectionMessage`, `heartbeat: true`) | 5 s | `src/exo/shared/election.py:23,186-194` |
| HTTP `GET /node_id` to every interface IP of every peer, port 52415, 3 tries | ~10 s | `src/exo/utils/info_gatherer/net_profile.py:26-29`, `src/exo/worker/main.py:569-612` |
| zenoh keepalive and liveliness | ~2.5 s [inferred] | |

`NODE_SILENCE_TIMEOUT` 15 s checked every 1 s (`src/exo/master/main.py:91,93`);
`MASTER_SILENCE_TIMEOUT` 30 s, election timeout 3 s (`election.py:20,27`).

### Data plane: MLX ring on random ports
- `mx.distributed.init(backend="ring")` (`src/exo/worker/engines/mlx/utils_mlx.py:106-120`).
  Each rank listens on `0.0.0.0:<port>` and connects only to its left and right
  neighbours; non-neighbours get the placeholder `198.51.100.1:0`
  (`src/exo/master/placement_utils.py:382-426`). The port is random in 49153–65535
  (`src/exo/utils/ports.py:4-6`), chosen once per instance (`placement.py:399`).
  **[inferred]** plain TCP.
- Per token: each stage's last layer sends its output to rank `(r+1) % s`, the next stage
  receives it (`auto_parallel.py:137,175-177`); during decode there is also an
  `all_gather` of that output across the group (`auto_parallel.py:188-191`).
  **[inferred]** per hop, `batch × 1 × hidden × dtype` bytes, so 2 KiB for Qwen3-0.6B
  (hidden 1024, bf16); prefill sends `seq_len × hidden`.
- Every runner also opens a msgpack TCP server on a random port when ready
  (`src/exo/worker/runner/runner.py:157-159,289`; `src/exo/worker/disaggregated/server.py`).
- Generated tokens go back over zenoh as `ChunkGenerated` JSON events with `text`,
  `token_id`, `logprob` (`runner.py:394`, `src/exo/shared/types/chunks.py:23-31`): one
  plaintext JSON message per token on the control plane.
- Clients: HTTP and SSE on `0.0.0.0:52415`, IPv4 only (`src/exo/api/listening_socket.py`,
  `api/main.py:729,991,1034`). The dashboard is on the same port.

### Outbound
No telemetry found. Model downloads go to `https://huggingface.co` or `$HF_ENDPOINT`
(`src/exo/download/huggingface_utils.py:62`); the download coordinator rescans every 60 s
(`download/coordinator.py:49`); `--offline` / `EXO_OFFLINE` disables it (`main.py:496-501`).

### Distinctive on the wire
- 20-byte UDP datagrams to `[ff12::e0a1:de89]:52413` once a second per node, payload
  starting `45 58 4F 00`, constant bytes at offset 12; 30-byte unicast replies starting
  `45 58 4F 01`.
- TCP 52414 over IPv6 with `topics/local_events`, `live/`, `"heartbeat":true`,
  `"token_id"`, `"text"` in plaintext. **[inferred]** key expressions may be declared once
  and then replaced by numeric ids.
- A 1 Hz JSON flow per node, a 5 s heartbeat, a 10 s burst of `GET /node_id` on 52415.
- High-port TCP between ring neighbours, silent when idle, fixed-size bursts during
  generation; plus one JSON event per generated token on 52414.

## 2. llama.cpp RPC (74bca39)

### Transport
- IPv4 TCP only: `socket(AF_INET, SOCK_STREAM)` (`transport.cpp:730,758`); `-H` must be a
  dotted address (`transport.cpp:738`); the client resolves names with `gethostbyname`
  (`transport.cpp:769`).
- Default port 50052, default host 127.0.0.1 (`tools/rpc/rpc-server.cpp:95-96`); binding
  elsewhere prints a "not secure" warning (`rpc-server.cpp:224-232`).
- No TLS, no authentication; the only negotiation is a 24-byte RDMA capability exchange
  that falls back to TCP (`transport.cpp:593-654`). `TCP_NODELAY` on both ends
  (`transport.cpp:703-708,721,762`). No keepalive, no timeout (`transport.cpp:575-590`).
- Listen backlog 1, one client at a time (`transport.cpp:750`; `ggml-rpc.cpp:2817-2825`).
  One TCP connection per endpoint, shared through a dispatcher (`ggml-rpc.cpp:708-724`).

### Framing
- Request: `cmd (1 B) | size (8 B, native LE) | payload` (`ggml-rpc.cpp:372-386`);
  response: `size (8 B) | payload` (`:388-405,323-331`). Packed structs (`:34`).
- Command bytes (`:57-83`; HELLO pinned at 14 by a static_assert, `:85`): 0 ALLOC_BUFFER,
  1 GET_ALIGNMENT, 2 GET_MAX_SIZE, 3 BUFFER_GET_BASE, 4 FREE_BUFFER, 5 BUFFER_CLEAR,
  6 SET_TENSOR, 7 SET_TENSOR_HASH, 8 GET_TENSOR, 9 COPY_TENSOR, 10 GRAPH_COMPUTE,
  11 GET_DEVICE_MEMORY, 12 INIT_TENSOR, 13 GET_ALLOC_SIZE, 14 HELLO, 15 DEVICE_COUNT,
  16 GRAPH_RECOMPUTE, 17 MEMSET_TENSOR, 18 SET_TENSOR_2D, 19 GET_TENSOR_2D, 20 COMM_INIT,
  21 COMM_ALLREDUCE, 22 COMM_FREE.
- Protocol version 8.0.1 (`ggml-rpc.h:9-11`; the README's "v3.0.0" is stale).
- **HELLO**: the client's first segment is 33 bytes,
  `0E | 18 00 00 00 00 00 00 00 | 24 × 00` (`ggml-rpc.cpp:124-126,423-429`); the server
  answers 36 bytes, `1C 00 00 00 00 00 00 00 | 08 00 01 00 | 24 × 00` (`:128-134,1455-1457,
  2463-2467`). The server rejects any other first byte or size (`:2438-2456`).
- `rpc_tensor` is 296 bytes and carries the tensor name as zero-padded ASCII
  (`:36-52,793-796`). SET_TENSOR frames are 314 B + data (`:828-838`); GET_TENSOR request
  321 B, response 8 B + data (`:214-218`); SET_TENSOR_HASH 321 B with a 9 B response;
  GRAPH_RECOMPUTE 21 B (`:238-241`); GRAPH_COMPUTE 20 + 8·n_nodes + 296·n_tensors
  (`:1219-1222`).
- No response for SET_TENSOR, SET_TENSOR_2D, GRAPH_COMPUTE, GRAPH_RECOMPUTE, INIT_TENSOR,
  FREE_BUFFER, BUFFER_CLEAR, MEMSET_TENSOR, COMM_ALLREDUCE, COMM_FREE (`:2570-2737`).

### Load
HELLO, DEVICE_COUNT, GET_ALIGNMENT, GET_MAX_SIZE, GET_DEVICE_MEMORY, ALLOC_BUFFER,
BUFFER_GET_BASE, then one whole-tensor SET_TENSOR per weight (`src/llama-model-loader.cpp:
1744,1816`; RPC reports `host_buffer=false`, `ggml-rpc.cpp:2865`). Bytes uploaded ≈ the
on-disk size of the host's layer slice plus ~330 B of framing per tensor. With `-c`,
tensors over 10 MiB are first offered by a 64-bit FNV-1a hash (`:118,313-321,844-869`)
and skipped on a hit; the cache is on disk (`:1742-1751`; `rpc-server.cpp:243`).

### Per token
- The dispatcher sends commands in order; commands without a response are fire-and-forget
  (`:660-697,1173,1252,1266`); at most one response outstanding per connection. The rhythm
  is a pipelined batch ending in a request-response, not strict ping-pong.
- Graph reuse sends a 21-byte GRAPH_RECOMPUTE (`src/llama-context.cpp:1538`;
  `ggml-rpc.cpp:1246-1252`); a rebuilt graph is re-sent in full (**[inferred]** tens to
  hundreds of KB).
- **Star topology** with a layer split: copies between two RPC servers go through the main
  host (`:937-939`; `ggml-backend.cpp:640-647,1854-1861`). **[inferred]** per token the main
  host sends host A `inp_embd` (n_embd × n_tokens × 4 B, F32) plus positions and the KQ mask,
  then the graph command; gets the boundary activation back (n_embd × n_tokens × 4 B);
  sends it to host B with B's inputs; gets the logits back (n_vocab × 4 × n_outputs B).
  For Qwen3-0.6B: 4 KiB per activation hop, and ~600 KB of logits per decode token from
  the last host (n_vocab 151 936).
- Exception: `--split-mode tensor` with exactly two RPC backends opens a direct link between
  the servers on rank 0's port + 1000 carrying unframed allreduce tensors
  (`:2993-3044,2236-2276`); `GGML_RPC_NO_COMM` disables it. Not used here.

### Other
No model download in rpc-server (no libcommon, `rpc-server.cpp:27`). RDMA env vars
`GGML_RPC_NO_RDMA`, `GGML_RDMA_DEV`, `GGML_RDMA_GID` (`transport.cpp:215-216,596`).

### Distinctive on the wire
- Long-lived plaintext TCP on 50052 with no TLS ClientHello; first client segment exactly
  33 bytes starting `0E 18 00 00 00 00 00 00 00`, reply 36 bytes starting
  `1C 00 … 08 00 01 00`.
- Every request starts with a byte in 0x00–0x16 followed by an 8-byte LE length, most of
  them the fixed small values above; tensor names in readable ASCII inside 296-byte records.
- Load: a bulk upload the size of the model slice in frames with ~314-byte headers.
- Decode: bursts at the token rate of nearly constant size, with a ~600 KB logits return
  from the last host on every token, and an asymmetric star: the main host talks to each
  RPC host in turn, the RPC hosts never to each other.
- Idle: nothing at all. A connected but idle cluster is invisible on the wire.

## 3. LocalAI P2P, worker mode (35224b8)

### What it is
llama.cpp's rpc-server, bound to localhost, reached through libp2p streams. The worker
runs `llama-cpp-rpc-server` (`core/cli/worker/worker_llamacpp.go:26,58-61`; it is
ggml-rpc-server copied at `backend/cpp/llama-cpp/Makefile:164-165`) with
`--host 127.0.0.1 --port <free port>` (`worker_p2p.go:45-50,88`) and registers
`127.0.0.1:<port>` as a service (`core/p2p/p2p.go:329`). The main node listens on
`127.0.0.1:<free port>` per worker (`p2p.go:279-288`), opens a libp2p stream to the worker
for each accepted connection and copies bytes both ways (`p2p.go:104-127`); those local
addresses go into `LLAMACPP_GRPC_SERVERS` (`core/application/p2p.go:104-115`,
`core/cli/run.go:395-398`; `backend/cpp/llama-cpp/grpc-server.cpp:1340-1343`). Not a VPN
tunnel interface: one libp2p stream per RPC connection.

### Libraries and settings
- go-libp2p v0.48.0, edgevpn v0.34.0, kad-dht v0.40.0, pubsub v0.16.0, zeroconf (mDNS)
  v2.2.0, flynn/noise, yamux v5, quic-go v0.59 (`go.mod:34,40,338,417,456,458,464,512`).
- DHT on unless `LOCALAI_P2P_DISABLE_DHT=true`; mDNS always on; discovery interval 10 s;
  HolePunch and AutoRelay on; NAT service and NAT map on (`core/p2p/p2p.go:381,403-437`).
- Listen addresses from `LOCALAI_P2P_LISTEN_MADDRS` (`p2p.go:387-390`), default the libp2p
  `0.0.0.0` multiaddrs (`docs/content/features/distributed_inferencing.md:145`):
  **[inferred]** random ports for TCP, QUIC-v1, WebTransport and WebRTC-direct.
- Bootstrap peers only from `LOCALAI_P2P_BOOTSTRAP_PEERS_MADDRS` (`p2p.go:392-395`); none
  hard-coded in LocalAI. **[inferred]** edgevpn falls back to the public IPFS bootstrap
  nodes when the list is empty, so a default install beacons to the internet.
- Security and muxing **[inferred]** go-libp2p defaults: Noise and TLS 1.3, yamux.
- The token (`p2p.go:31-63`) is base64 of: room name, rendezvous string and mDNS label (each
  a random 43-character string, `:43-45`), an OTP DHT key (rotation 360 s, `run.go:117`), an
  OTP crypto key (9000 s, `run.go:118`), max message size 20 MB. A long-lived pre-shared
  secret, not one-time; peer identity is not in it.
- Possible bug: `LOCALAI_P2P_ENABLE_LIMITS` is read inverted into `Limit.Enable`
  (`p2p.go:382,407`).

### Idle traffic (intervals from LocalAI code)
Ledger sync and announce 10 s (`p2p.go:415-416`); users announce `{PeerID, Timestamp}` 10 s
(`:75-86`); worker `NodeData` announce 20 s (`:345-357`); service registration 60 s
(`:329`); `services.Alive(30s, 900s, 15m)` (`:444`); mDNS/DHT discovery 10 s (`:429`); a
node is "online" if seen within 40 s (`core/schema/localai.go:200-203`). The ledger carries
hostnames and model names, **[inferred]** encrypted twice (transport security and the OTP
crypto key). **[inferred]** library defaults add identify, ping and gossipsub's 1 s heartbeat.

### Federated mode
`local-ai federated` listens in plaintext HTTP on `:8080` (`core/cli/federated.go:12`) and
forwards each client connection over one libp2p stream to a chosen instance
(`federated_server.go:59-96`); every node holds the full model. Not a sharded swarm; out of
scope here beyond noting the difference.

### Leaves the LAN
DHT and bootstrap (unless disabled), AutoNAT, relay and hole punching with public peers
**[inferred]**, UPnP/NAT-PMP to the router **[inferred]**; gallery hosts `index.localai.io`,
GitHub and quay.io mirrors (`core/config/runtime_settings_startup.go:20-21`); model
download hosts. No phone-home telemetry found in the P2P path.

### Distinctive on the wire
- mDNS on 224.0.0.251:5353 with a random 43-character service label; **[inferred]** TXT
  `dnsaddr=/ip4/…/p2p/12D3Koo…` records in plaintext, revealing peer ids and ports.
- TCP handshake in plaintext multistream-select: `/multistream/1.0.0\n` then `/noise` or
  `/tls/1.0.0`; everything after is encrypted, including stream protocol ids. TLS
  ClientHello with ALPN `libp2p` and no SNI; QUIC Initials show the same ALPN.
- Random high ports; SSDP to 239.255.255.250:1900 if UPnP is on; DHT traffic to public
  addresses, usually port 4001.
- 10 s, 20 s and 60 s ledger bursts.
- Hidden by encryption: the RPC commands, tensor names and sizes, hostnames, model names.
  What remains is sizes and timing: a weight-upload burst at load, then the per-token
  cadence, with overlay framing added.
- Ground truth for a capture: the plaintext RPC runs over loopback on both ends (worker:
  edgevpn to `127.0.0.1:port`; main node: grpc-server to the local proxy port). Capturing
  `lo` inside each container gives the decrypted stream next to the encrypted LAN capture.
- Plaintext comparison: manual mode (`worker llama-cpp-rpc` with
  `LLAMACPP_GRPC_SERVERS=host:port`, docs `:93-99`) is llama.cpp RPC with no overlay, i.e.
  §2.

## 4. What this means before any capture

1. **Static signatures suffice for exo and llama.cpp, from one packet.** A single exo
   Hello (20 bytes, fixed magic, fixed group and port, once a second) identifies a node; a
   single llama.cpp HELLO (33 fixed bytes on a fixed port) identifies a connection. Neither
   stack has a configuration that hides these short of patching the source.
2. **LocalAI removes content signatures and keeps the overlay's.** The multistream and
   ALPN strings, the mDNS TXT records and the DHT contacts identify libp2p, not LocalAI;
   the same signatures belong to IPFS, Petals (hivemind's p2pd) and anything else on
   libp2p. Telling LocalAI from IPFS needs timing, not bytes.
3. **Periodicity survives encryption.** exo's 1 s and 5 s, LocalAI's 10 s, 20 s and 60 s
   are set in code and independent of load. llama.cpp has none: an idle RPC cluster is
   silent, and is visible only while loading or generating.
4. **Generation has a size-and-rhythm signature in all three**: a burst per token at the
   decode rate, nearly constant in size, with a fixed asymmetry (exo: ring neighbours plus a
   JSON event per token on the control plane; llama.cpp: a star, ~600 KB of logits back from
   the last host per token; LocalAI: the same inside the overlay). Prefill is one larger
   burst proportional to prompt length. Load is a bulk upload the size of the slice.
5. **The vantage point decides what is visible.** On the LAN everything above is visible.
   At the egress router of a single home, a swarm inside that home is invisible, and a swarm
   spanning homes shows each box's share: for exo, zenoh plus ring traffic to a few peers;
   for llama.cpp, one plaintext 50052 flow; for LocalAI, libp2p flows plus DHT chatter to
   public addresses that an ordinary home also produces if it runs IPFS or a libp2p app.
6. **What a defender cannot get from the wire** without the content: which model, how many
   shards, and (for LocalAI) which stack. exo and llama.cpp leak the model's hidden size and
   vocabulary through tensor sizes; LocalAI leaks them only as sizes plus overlay overhead.
