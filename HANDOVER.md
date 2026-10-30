# Handover: Experiment 4 state on 2026-10-29

For whoever picks this up next, human or model. Everything below is verifiable from the
branch; nothing here is in the README yet.

## 1. Where the work lives

- Branch `exp4-localai`, built on `exp4-exo`, which is where all results are. `main` is the
  signed history up to the first exo run; fast-forward it when the LocalAI side is settled.
- Captures are committed as timeline + request log + `.pcap.sha256` + `classify.py --json`
  report next to each other under `captures/<stack>/<stamp>.*`. The pcaps are not committed
  (`.gitignore`); which ones are still on the host's disk is listed in §3.
- The machine that captures is the user's Arch host (rootless podman, tcpdump). The agent
  pod cannot run containers, tcpdump or `git push`; it sees the checkout as a bind mount and
  runs the analysis and commits. So: the user runs `capture/run_*.sh`, the agent classifies
  what lands and commits, the user signs (`git rebase -f -S main`) and pushes.
- Node logs for exo are under `exo/logs/`, LocalAI's under `localai/logs/` (both untracked,
  not ignored; decide). llama.cpp runs
  save `podman logs` of each container next to the pcap (`<stamp>.main.log` etc.).

## 2. Done

### llama.cpp RPC (three captures, two pcaps left)
- `25691027-122003` (Buddhist-era stamp; 60 s idle; pcap on disk, 1.7 GB): 7% packet /
  20% byte kernel drops with tcpdump's default buffer. Fixed since (`-B 524288`, and
  `flows.py` counts bytes from TCP sequence numbers so drops do not corrupt totals).
- `20261027-150104` (600 s idle, kill 0.5 s into a 300-token request, pause; pcap deleted):
  the headline run. Its report is on the old rule set and cannot be regenerated. A 20-minute
  rerun of `capture/run_llamacpp.sh` would replace it and also save the container logs.
- `20261027-163215` (pause-only, with the resume; pcap on disk, 0.7 GB).

Findings, all from the reports and the ad-hoc checks in the session:
- HELLO is 33 bytes but three TCP segments (1 + 8 + 24); every RPC message is a 1-byte
  command, 8-byte length, body triplet of sends. Byte rule matches at the first connection
  (3.9 s after the main host starts); 15 short connections per rpc host precede the long one.
- Idle is silent: zero packets on the RPC flows for the full 600 s.
- Per token: main → rpc-0 ~16 KB (7 SET_TENSOR + graph + GET_TENSOR), back 8 + 4096 B;
  main → rpc-1 7170 B, back 8 + 607,744 B (n_vocab × 4). Decode rate from direction-change
  exchanges matches the request log within 3%. Slice uploads 252 MB and 385 MB (sum = the
  whole Q8_0 file; the main host, weighted 0, keeps nothing).
- Prompt switches move KV state: with distinct prompts every request begins with rpc → main
  transfers (4.5 + 3.9 MB for a 63-token context, 65 + 56 MB for ~1750 tokens). Consistent
  with llama-server's prompt cache; not yet confirmed from a main-host log (the next full run
  saves it; grep "cache").
- Node loss: kill while idle → one FIN from the dead host, no reaction; kill mid-request →
  RST from the dead host at +0.04 s, main host FINs the other leg at +3.4 s, HTTP stream
  ends at +3.5 s. Pause → nothing at all for 53 min; on resume one logits-sized reply.
- llama-server keeps a stalled HTTP stream alive with a ~25 s send, so a client timeout
  must count tokens, not bytes (`requests.py` does now). With `-hf`, each main-host start
  opens two TLS connections to CloudFront (leaves the LAN). API traffic on 8080 never
  crosses the bridge (rootlessport on loopback).

### Background set (false positives)
- `20261028-081447` is the clean one (all generators incl. the mDNS beacon, no drops):
  no stack rule matched, no generation-like flow, mDNS classed as ordinary. Keep.
- `20261028-074554` (no mDNS generator) and `20261027-163430` (55 GB, 81% drops,
  unthrottled generators) are superseded; their reports stay, pcaps mostly deleted.
- Generators now run at LAN rates (`background/run.sh`), the mDNS generator is
  `background/mdns.py` (avahi never started under podman), teardown tolerates a missing
  container, `capture/run_background.sh` holds the bridge up with an anchor.

### exo (two captures, pcaps on disk, 168 MB and 95 MB)
- `20261028-083159`: start, placement, 600 s idle, kill. Generation phase failed: exo's
  runner supervisor kills a runner with no token for 90 s, and the 40-token prompt prefilled
  slower than that at 2.6 s/token. Every request was cancelled and the instance rebuilt.
- `20261028-125140`: short prompt (~20 tokens), 20/20 requests, 2.46 s/token, 71 s to first
  token; long prefill cancelled by the watchdog as expected; kill at token 5 detected in
  15.2 s, re-placed in 175 s.
- Findings: beacon at 6.6 s (3.6 s after the nodes start), zenoh at the same instant,
  node_id probes at 16.7 s and about one per second per pair (the findings file said ~10 s);
  1 s beacon period scores 1.0; ring decode exchanges 2.4 s apart, 4104 B forward /
  2048 B back, flagged generation-like per phase; nodes open 50–60 connections each to
  Hugging Face's CDN at placement. Open question for the collaborator: is the 90 s
  no-progress watchdog a constant in exo's runner supervisor that a run could raise?

### Analysis (collaborator's branch, merged)
- Per-phase exchange judgement, host-pair periodicity (socket-per-beat heartbeats),
  cumulative sequence accounting, generation rule needs data both ways and one
  activation-sized leg. Four reports regenerated on it; the two with deleted pcaps are not.

## 3. Pcaps still on the host (for reruns of the analysis)
`captures/llamacpp/25691027-122003.pcap`, `captures/llamacpp/20261027-163215.pcap`,
`captures/background/20261028-074554.pcap`, `captures/background/20261028-081447.pcap`,
`captures/exo/20261028-083159.pcap`, `captures/exo/20261028-125140.pcap`,
`captures/localai/20261029-142814.pcap` (v4 load attempt, 663 MB),
`captures/localai/20261029-144115.pcap` (full run, 4.3 GB) and its six `*.lo.pcap` (6.8 GB),
`captures/localai/20261029-151923.pcap` (DHT run, 4.4 GB).

## 4. LocalAI

**Version: everything in items 1–7 and "Where it fails now" is v3.0.0, which was a
mistake.** `latest-cpu` looked current but has not moved since 2025-06-19 (v3.0.0); LocalAI
stopped publishing `-cpu` tags and the CPU image is the unsuffixed `latest` / `vX.Y.Z`. The
current release is v4.12.1 (2026-10-23, git ec92740), and the wire findings (master
35224b8, 2026-10-27) describe v4, not v3. `cluster.sh` is now pinned to v4.12.1 (see
"Moved to v4.12.1" below); nothing of LocalAI was captured on v3, so nothing is lost.

`localai/cluster.sh` starts. What is known to work, in order (on v3.0.0):
1. Image `localai/localai:latest-cpu` pulled 2026-10-28 = v3.0.0 (git f9b968e), then pinned
   by digest; replaced by v4.12.1, see above.
2. The image's entrypoint execs `./local-ai` itself, so container commands start at the
   subcommand (`run --p2p`, `worker p2p-llama-cpp-rpc`). A leading `local-ai` made the
   model URI a stray argument (the first failure).
3. The model is passed as `LOCALAI_MODELS=huggingface://ggml-org/Qwen3-0.6B-GGUF/Qwen3-0.6B-Q8_0.gguf`;
   it downloads into the `localai-models` volume (767 MB) and is served under the file
   name `Qwen3-0.6B-Q8_0.gguf`. That file name is the `model` field in requests, not
   `Qwen3-0.6B` (that was a wrong suggestion; it made LocalAI look for a file by that name).
4. Token endpoint is `/api/p2p/token`, nodes at `/api/p2p`. Workers are discovered over
   the bridge (mDNS works), each runs `llama-cpp-rpc-server` ("RPC server v2.0.0") on a
   random local port exposed through a libp2p tunnel; the main node sets
   `LLAMACPP_GRPC_SERVERS=127.0.0.1:<tunnel>,127.0.0.1:<tunnel>`.
5. The worker's libp2p host listens on TCP, QUIC, WebTransport and WebRTC-direct at once,
   so overlay traffic may be QUIC/UDP rather than the TCP the findings assumed.

6. Model loading is lazy: nothing loads until the first request. `up` returns before the
   workers are in the ledger (discovery every 10 s), so a request sent straight after `up`
   finds `LLAMACPP_GRPC_SERVERS` empty and the backend loads the whole model on the main
   node. That is what the first "working" completion on 2026-10-29 was: worker NET IO
   745 kB each, main 5.9 GB resident, no `Accepted client connection` on the workers.
   It does settle one question from the previous handover: the image's llama.cpp backend
   (build 5700, 8d947136) loads and serves this model on this CPU. The failure is in the
   P2P/RPC path, not the backend.
7. With the workers in the ledger first (`up 2`, `sleep 60`, then the request), the RPC path
   is taken: `using device RPC[127.0.0.1:35987]` and `RPC[127.0.0.1:37935]`,
   `offloaded 29/29 layers to GPU` (llama.cpp calls every non-CPU device "GPU"; both are
   CPU rpc-servers, `create_backend: using CPU backend`, backend memory = host RAM; the
   image is CPU-only), buffers `CPU_Mapped` 157.65 MiB on main (token embeddings) +
   239.19 MiB on worker-1 + 364.95 MiB on worker-0 = the 761.8 MiB file. Offload to the
   RPC devices comes from LocalAI's default `gpu_layers`; at 0 the workers get nothing.
   With workers attached the backend's `system_info` reports `CPU : SSE3 SSSE3 BMI2` (no
   AVX/AVX2), against AVX2 on the main-only run: LocalAI picks a different llama.cpp build
   for the RPC case. Worth a sentence in the README; it does not explain the failure.

Where it fails now (logs of that run in `localai/logs/`, untracked, 05:10–05:39 UTC):
the weight upload starts with worker-1 (the first RPC device), and worker-1's 20 s
`NodeData` announce stops at that moment: its last `LastSeen` in the ledger is 05:10:06 and
never moves again, while its edgevpn healthcheck keeps arriving (last 05:39:21), so the
node and its connection are alive. About 40 s later the main node's `ensureService`
(`core/p2p/p2p.go` at v3.0.0: offline if not seen in 40 s, then cancel the tunnel) logs
`Node 3e0dfe9278ae-cUiMiCEmsC is offline, deleting` and `accept tcp 127.0.0.1:35987: use
of closed network connection`. The upload dies at ~52 MB of 239 MiB (worker-1 NET IO),
worker-0 has had ~6 MB, `LLAMACPP_GRPC_SERVERS` shrinks to the one worker, and the
llama.cpp RPC client waits on the dead connection forever: the HTTP request hangs with no
error. The upload was also slow, ~1.5 MB/s on a local bridge in the 35 s before the cut, so
a full load would take minutes, far past the 40 s offline window.

Not known: why the announce stops when the upload starts (the worker logged at info level,
the cause is somewhere in edgevpn's ledger), and whether the Go runtime fatal error of the
earlier attempts is the same failure seen differently. `localai/cluster.sh` now starts the
workers with `LOCALAI_LOG_LEVEL=debug` so the next run has the worker's side.

Checked against v3.0.0 after the collaborator's reply:
- Limits are **off** by default at v3.0.0: `noLimits := os.Getenv("LOCALAI_P2P_ENABLE_LIMITS") == "true"`
  (`core/p2p/p2p.go:387`) into `Limit.Enable` (`:412`), so unset means disabled; the
  worker logs say `go-libp2p resource manager protection disabled` and `connmanager
  disabled`. Setting the variable to `true` would turn them on. Not the cause.
- The tunnels were already **QUIC**: `Redirecting 127.0.0.1:35987 to
  /ip4/10.89.4.17/udp/42507/quic-v1` (and the same for the other worker). So TCP/yamux
  head-of-line blocking is not what happened; the contrasting run is TCP-only
  (`P2P_LISTEN=/ip4/0.0.0.0/tcp/0`). For prediction 9 this also means no plaintext
  `/multistream/1.0.0` on the tunnel flows, and `libp2p_alpn` in `signatures.py` looks for a
  TLS ClientHello in plaintext, which a QUIC Initial is not (its ALPN is under the Initial
  keys): the rule needs a QUIC Initial decoder or the prediction fails on QUIC.
- The 40 s window is `NodeData.IsOnline` in `core/p2p/node.go:21-25` at v3.0.0 (moved to
  `core/schema/localai.go` on master), hard-coded; confirmed.
- go-libp2p logs at `fatal` unless `LOCALAI_P2P_LIB_LOGLEVEL` is set, which hides quic-go's
  own warnings (a UDP receive buffer too small for QUIC would also explain ~1.5 MB/s).
  `cluster.sh` now sets it to `info` (`LIB_LOG=` to change).

### Moved to v4.12.1 (read from the v4.12.1 source)
- Pin: `docker.io/localai/localai@sha256:c8556c4f7b6dd9b76e915d515ab5cfe5a765d8ea8fd3f0cf563f9c690b48a7f4`.
- **The worker command moved**: `p2p-worker p2p-llama-cpp-rpc` (`core/cli/cli.go:21`);
  `worker` is now the generic distributed worker, and `worker p2p-llama-cpp-rpc` exits 80
  (kong v1.15.0's usage-error code) at once. LocalAI's docs
  (`distributed_inferencing.md:122`) and main's start-up hint (`run.go:550`) still print
  the v3 form. The first v4 run (2026-10-29 13:06 local) died on this: both workers exited
  80, the load script waited forever (it now gives up after 3 min or on a dead worker).
- **v4 contacts Hugging Face for ~5.5 min after every start**: a gallery "estimate
  warm-up" for 300 models, ~2 GB on that run (`core/gallery/estimate_warm.go`), plus
  `index.localai.io` and `raw.githubusercontent.com`; and the importer re-queries
  Hugging Face for a `huggingface://` model on each start even when the file is present.
  `cluster.sh` sets `LOCALAI_VRAM_WARM_LIMIT=0` and passes `LOCALAI_MODELS` only while the
  model's config is not in the volume. Both are prediction 12 material: a default v4
  install leaves the LAN at every start, DHT or not.
- Same as v3: `run --p2p`, `TOKEN`, `LOCALAI_MODELS`,
  `LOCALAI_P2P_*`, `/api/p2p` and `/api/p2p/token`, the 40 s window (now
  `core/schema/localai.go:199-203`), the 20 s worker announce (`p2p.go:347`).
- **Limits are on by default in v4** (the collaborator was reading master):
  `noLimits := os.Getenv("LOCALAI_P2P_ENABLE_LIMITS") != "true"` (`p2p.go:382`) into
  `Limit.Enable` (`:407`). So the collaborator's experiment applies: `NO_LIMITS=1` in
  `cluster.sh` sets `LOCALAI_P2P_ENABLE_LIMITS=true`, which turns them off.
- **No backends in the image.** v4 ships `local-ai` alone (`VOLUME /backends`); each node
  installs `llama-cpp` from the gallery on first use, `cpu-llama-cpp` =
  `quay.io/go-skynet/local-ai-backends:latest-cpu-llama-cpp`, a moving tag and an internet
  download inside the capture. `cluster.sh` installs it once instead, from the release tag
  `v4.12.1-cpu-llama-cpp` (manifest `sha256:c788fad0…`, the same as `latest-` today),
  into a `localai-backends` volume mounted on every node, named `llama-cpp` because the
  worker looks it up by that name (`core/cli/worker/worker_llamacpp.go:38`).
  `cluster.sh backend` reinstalls it.
- Model path: v4's base path is the working directory `/`, so models land in `/models`, the
  volume. On v3 they went to `/build/models` inside the container, which is why every v3
  start downloaded the 767 MB again (main NET IO 824 MB). v4 preloads `LOCALAI_MODELS`
  before the HTTP server binds, so the first start takes a while; `up` waits up to 600 s.
- The `setting LLAMACPP_GRPC_SERVERS` log line is formatted differently in v4 (`xlog`
  key-value); `run_localai_load.sh` counts the tunnel addresses on the last such line.

### First v4.12.1 run: the load works (`captures/localai/20261029-142814`, 34 s)
`capture/run_localai_load.sh` with v4 defaults (limits on, QUIC). Report in `.report.json`;
pcap 663 MB on the host.
- Tunnels to both workers 10 s after `up`; no model import, no warm-up traffic.
- Load: main sent 652.3 MB, worker-0 received 259.1 MB and worker-1 393.5 MB (NET IO), in
  about 1.5 s; the embeddings stay on main as on v3. On v3 the same upload ran at ~1.5 MB/s
  and lost a worker after 40 s. This llama.cpp build (RPC server v8.0.0) does not log
  buffer sizes at default verbosity, so the split is read from NET IO.
- Generation: 40-token prompt in 281 ms, 10 tokens at 33.9 tokens/s (llama.cpp timings in
  main's log). `requests.py` recorded 0 tokens: v4 streams thinking as `delta.reasoning`,
  which it did not count (fixed).
- The backend runs `llama-cpp-grpc` (run.sh picks it when `LLAMACPP_GRPC_SERVERS` is set),
  with `system_info` SSE3/SSSE3 only, no AVX: as on v3, the RPC build is not the AVX2 one.
- Classifier: no libp2p rule matched. The tunnels are QUIC (`Redirecting ... /udp/.../quic-v1`),
  so no plaintext multistream and no plaintext ClientHello: **prediction 9 fails for LocalAI
  on its default transport** unless `signatures.py` decodes QUIC Initials (ALPN `libp2p`
  sits under the Initial keys, which are derivable from the DCID). mDNS was classed
  ordinary at first; that was the classifier's fault (see the full runs below), the
  records do carry `dnsaddr=.../p2p/...`.
- Load signature without payload: each worker flow, thousands of exchanges ~0.1 ms apart,
  46.8 KB out / 38 B back.
- **The workers talk to each other** (QUIC flow worker-0 <-> worker-1, ~50 KB each way,
  presumably ledger gossip); llama.cpp's RPC hosts never exchange a packet.
- Off the LAN even with DHT off: one TLS flow to Cloudflare, SNI `index.localai.io` (the
  gallery index; read from the full run's ClientHello), probably the start-up backend
  upgrade check (`upgrade_checker.go`, at start and every 6 h; auto-upgrade is off by
  default, so the pinned backend does not change).

### The full runs: `20261029-144115` (LOOPBACK=1, DHT off) and `20261029-151923` (DHT=1, idle 300 s)
Both ran every phase to `done`; 0 packets dropped on the bridge (399 k and 714 k packets,
4.3 GB and 4.4 GB) and on every loopback capture. Reports in `.report.json`, and for main's
loopback of the first run `.main.lo.report.json`. The two runs agree on everything below
except the DHT.

| phase | 144115 | 151923 |
|---|---|---|
| load (first request, model to both workers) | 8 tok, TTFT 4.5 s | 8 tok, TTFT 4.0 s |
| generate 20 x 30 | 20/20, TTFT 0.33 s, 32.7 tok/s | 20/20, 0.33 s, 33.1 tok/s |
| generate-long 5 x ~2048 | 5/5, TTFT 13.4 s, 9.9 tok/s | 5/5, 13.6 s, 9.7 tok/s |
| kill worker-0 at 0.5 s | 0 tok, stream closed at 33.5 s, **no error** | 2 tok, closed at 33.6 s, no error |
| recover (new cluster, reload) | 8 tok, TTFT 4.7 s | 8 tok, TTFT 4.0 s |
| pause worker-1 at 0.5 s | 12 tok, closed at 35.1 s, no error | 14 tok, closed at 30.9 s, no error |
| resume, one probe | 28 tok, TTFT 4.9 s (reload) | 28 tok, TTFT 4.2 s (reload) |

**Node loss (both runs, kill and pause alike).** The llama.cpp RPC client sees the tunnel
close 30 s after the loss (`recv returned 0 (peer closed?)`, then `ggml-rpc.cpp:682: Remote
RPC server crashed`, the backend process aborts), main logs `Stream ended with error ...
EOF`, and the HTTP client gets a stream that simply ends, with no error: a truncated answer
that looks complete. 30 s in all four cases (kill 07:55:31 -> 07:56:01, pause 07:57:32 ->
07:58:06, kill 08:28:40 -> 08:29:10, pause 08:30:40 -> 08:31:10), not the 40 s ledger
window: the `Node is offline, deleting` line comes before or after it (07:55:55, 07:58:10,
08:29:24, 08:31:14). 30 s is quic-go's default idle timeout; not checked in the source.
The next request restarts the backend with the remaining workers in
`LLAMACPP_GRPC_SERVERS` and uploads the whole model again (~650 MB to the one worker left,
4–5 s TTFT). The paused worker came back after resume in the DHT run (fresh `LastSeen` 15 s
after `resume`, too late for the probe, which loaded on one worker); in the first run it
had not reappeared by `done`, 21 s after resume. `/api/p2p` keeps listing a dead node with
a stale `LastSeen` until the cluster goes down.

**On the wire (bridge, from `144115`):**
- Prediction 9, half: no readable RPC anywhere on the bridge, while the loopback capture
  on main shows the llama.cpp signatures unchanged (`llama_hello` on every tunnel
  connection at load, `llama_tensor_names` at +0.1 s). The other half, a plaintext libp2p
  handshake, fails on QUIC: no libp2p rule matches any tunnel flow. A QUIC Initial
  decoder (ALPN `libp2p` under keys derivable from the DCID) is still the fix.
- Prediction 11: mDNS **is** libp2p's: `dnsaddr=/ip4/.../p2p/12D3KooW...` TXT records and a
  random label, every 23.3 s (cv 0.05) from each node. `mdns_libp2p` fires at 4.1 s and
  tags main and both workers as libp2p. It had missed because the classifier kept only a
  flow's first 64 payload bytes and the TXT record is at byte 183 after a 67-byte query;
  fixed (`flows.py` markers over the first 256 packets). The same limit had kept
  `llama_tensor_names` from ever firing (names at byte 528 on loopback); the two llama.cpp
  reports with pcaps on disk are regenerated and now show it during load. The encrypted
  overlay itself is not 10/20/60 s periodic: ~1 exchange/s of 115 B / ~1.6 KB per
  main-worker pair in idle (0.3–0.5 MB per direction in 600 s), strongest period 6.1 s at
  0.2. Worker `LastSeen` refreshes every 20–30 s.
- Prediction 10 holds by hand: in a 30-token request worker-0 sends one burst per token,
  median 621 KB (logits 151 936 x 4 B = 608 KB, +2% overlay), median interval 29.6 ms =
  33.8 tok/s against 33.7 tok/s at the client. Worker-0 carries the output layer: 800 KB
  per generated token back to main over the generate phase, worker-1 166 KB.
- Prediction 13 not yet: the classifier's generation rule did not fire on LocalAI. Its
  exchanges are packet-scale on QUIC (46.8 KB one way, a 38-byte ACK back), which fails the
  rule's 256-byte minimum leg; it needs the burst grouping above (5 ms gap) on UDP.
- Load: 392 MB to worker-0, 258 MB to worker-1 (main->worker flows), ~1.5 s.
- Workers talk to each other only for the overlay: ~0.6 MB each way over the whole run,
  115-byte exchanges, nothing during load or generation; tensors go through main (a star,
  as llama.cpp).
- Node loss from outside: the dead or paused node goes silent at once, main keeps sending
  a few small QUIC probes a second for 30 s, then nothing (kill: 2 ICMP packets); on
  resume a burst of ~36 packets. The reload that follows is a ~650 MB one-way burst.
- Off the LAN with DHT off: TLS to `index.localai.io` (Cloudflare 172.67.174.186 /
  104.21.80.62) from main at 10.7 s and again from the second main at recover, ~57 KB.

**Prediction 12 (`151923`, DHT=1) holds:** main opens TCP to 104.131.131.82:4001 (an IPFS
bootstrap node) 1.1 s after start; over the 728 s run the three nodes of each cluster
(main and both workers, all of them) talk to 2,649 public addresses, 131 MB (59 MB up,
72 MB down, ~180 KB/s), mostly UDP and TCP 4001; 942 distinct public hosts during the
300 s idle, 122–645 in each later phase. With DHT off the only off-LAN traffic is `index.localai.io`.
The classifier on this run: `mdns_libp2p` at 5.0 s and **`libp2p_multistream` at 5.0 s on
2,240 TCP flows, every one to a public peer** (`multistream-select then /tls` or `/noise`):
with DHT on, prediction 9's plaintext handshake is there, just not on the LAN tunnels,
which stay QUIC. 17 flows were flagged `generation_like`, all of them UDP 4001 to DHT
peers in idle (exchanges every ~5 s, ~2.7 KB / 1.5 KB), none on the LAN: the generation
rule's false positives for prediction 13. Two classifier fixes came out of this run: the
periodicity autocorrelation took hours on its 12 k flows (now 5 s, same scores), and TCP
sequence accounting counted libp2p's redials from one port as 2.7 TB "dropped" (a new
sequence space at each SYN now; the exo reports had the same artefact, 630 GB and 228 GB,
and are regenerated).

### The full run script: `capture/run_localai.sh`
On the pattern of `run_llamacpp.sh`: anchor container first, then `start` (cluster up,
`cluster.sh tunnels` waits for both tunnels), `idle` (600 s, workers attached, model not
loaded: the overlay alone, for prediction 11), `load` (first 10-token request), `generate`
(20 x 30), `generate-long` (5 x ~2048-token prompt), `kill` (`cluster.sh killproc 0` 0.5 s
into a 300-token request, then 60 s, past the 40 s offline window), `recover` (`up` again,
one request to reload), `pause` (worker-1, 0.5 s into a 300-token request, 120 s client
timeout), `resume` + one probe request. `/api/p2p` sampled every 5 s for the whole run
(`<stamp>.p2p.jsonl`: worker `LastSeen`, for detection times). Logs of the first cluster
are `<stamp>.<container>.1.log`, of the second `.2.log`.
- `DHT=1 capture/run_localai.sh 300`: prediction 12.
- `LOOPBACK=1`: also `tcpdump -i lo` in main's and each worker's network namespace (the
  host's tcpdump via `podman unshare nsenter`; the image has none), one
  `<stamp>.<container>[.2].lo.pcap` per cluster start, hashed at the end. Works: ~6.8 GB
  for the six loopback pcaps of one run, so check disk space first.
- `cluster.sh` gained `tunnels [N]`, `killproc|pause|resume <i>`.

Next:
1. Analysis: a QUIC Initial decoder (prediction 9), the 30 s detection against quic-go's
   idle timeout in the source; keep the generation rule off the DHT's exchanges with
   public peers (33 flows: every 5 s of ~3.0 KB / 1.4 KB, every 10 s of ~1.5 KB / 6.9 KB).
   Done 2026-10-30: the generation rule on QUIC. UDP datagrams under 64 B are left out of
   every exchange grouping, and a turn starting under 2 ms after the previous one is
   folded into it (LocalAI opens each request with ~26 round trips 0.4 ms apart, 351 B
   out and 146 KB back). Both tunnels are flagged in `generate` on both runs: 7067 B /
   621 122 B and 16 111 B / 4194 B every 30.0 ms.
2. Optional: `NO_LIMITS=1` and `P2P_LISTEN=/ip4/0.0.0.0/tcp/0` runs (TCP would give
   prediction 9 its plaintext multistream handshake, and shows whether the 30 s is QUIC's).
3. A longer resume wait in `run_localai.sh` (the paused worker needs >21 s to rejoin).

## 5. Harness changes made this week, all merged
`capture.sh`: 512 MiB buffer, setsid (survives Ctrl-C), size and SHA-256 at stop.
`requests.py`: timeout counts from the last token; varied prompts; `--prompt`; keeps
llama-server's timings. `run_llamacpp.sh`: load captured by restarting the main host; kill
and pause 0.5 s into a 300-token request; container logs saved. `run_llamacpp_pause.sh`: the
hang case alone, with resume and a probe. `run_exo.sh`: anchor container, short prompt, one
long request. `run_background.sh`: anchor + throttled generators + status print.
`llamacpp/cluster.sh`: 1 s stop grace. `localai/cluster.sh`: as in §4: v4.12.1, backend
volume, workers at debug log level, `P2P_LISTEN`, `LIB_LOG`, `NO_LIMITS`.
`run_localai_load.sh`: one captured LocalAI load attempt. `run_localai.sh`: the full LocalAI
run (§4). `requests.py`: counts LocalAI v4's `delta.reasoning`. `analysis/flows.py`: byte
markers over a flow's first 256 packets, for `mdns_libp2p` and `llama_tensor_names`. TCP
sequence accounting restarts at each SYN. `analysis/rhythm.py`: periodicity in occupied
bins (same scores, 5 s instead of hours on a DHT capture).

## 6. Still open
- README: intro and conclusion unwritten; the numbers above are the material.
- Rerun `run_llamacpp.sh 600` to replace the headline report (old rules, no logs).
- Confirm the KV-state transfers against a llama-server log.
- exo: the 90 s watchdog constant; whether a long-prefill result is obtainable at all.
- Analysis: the `periodicity per host pair` rule is new and untested on exo's probe storm;
  the exo generate-phase detector also flagged one flow in idle on the second run
  (unexplained, probably the placement request's tail).
