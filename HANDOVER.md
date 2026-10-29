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
- Node logs for exo are under `exo/logs/` (untracked, not ignored; decide). llama.cpp runs
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
`captures/exo/20261028-083159.pcap`, `captures/exo/20261028-125140.pcap`.

## 4. LocalAI: where it stopped

`localai/cluster.sh` now starts. What is known to work, in order:
1. Image `localai/localai:latest-cpu` pulled 2026-10-28 = v3.0.0 (git f9b968e), pinned by
   digest in the script. The wire findings were read at master 35224b8; the P2P paths
   checked are the same at both, but the README must state v3.0.0.
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

Where it fails: with the workers up and the right model name, the main node's llama.cpp
backend connects to both workers (the worker logs five accepted connections, the device
probes), then dies with a Go runtime fatal error (register dump in the debug log) before
sending any model data. LocalAI then tries every other backend and returns 500.

Not yet done, and the next step: the same request with no workers (`localai/cluster.sh up 0`,
model name `Qwen3-0.6B-Q8_0.gguf`). If it answers, the crash is specific to the RPC path
and the backend's own stderr with the workers up is the thing to read:

    podman logs main 2>&1 | grep 'GRPC(Qwen3' | grep -i -E 'llama|ggml|rpc|device|load|error|fatal|signal|panic' | grep -v '/root/go\|fp=0x' | head -60

If it also fails, the image's backend cannot load this model on this CPU at all (no AVX-512
here; the "fallback" variant failed the same way), and the options are a different image
tag, LocalAI's `--backends` gallery install of a newer llama-cpp backend, or a model YAML
in the volume that sets `backend: llama-cpp` and `gpu_layers` explicitly. If none of those
works in a bounded effort, the honest outcome for the study is: LocalAI's P2P worker mode
at v3.0.0 did not run on this host; the discovery and overlay handshake (beacon, token,
mDNS, tunnels) were captured up to the point of model load. That is most of prediction 9
and 11 anyway; predictions 10, 12 and 13's LocalAI rows would be reported as not run.

There is no `capture/run_localai.sh` yet. When the cluster serves a completion, write it on
the pattern of `capture/run_llamacpp.sh` (DHT off, then a second run with `DHT=1` for
prediction 12), and save `podman logs` of main and workers next to the pcap.

## 5. Harness changes made this week, all merged
`capture.sh`: 512 MiB buffer, setsid (survives Ctrl-C), size and SHA-256 at stop.
`requests.py`: timeout counts from the last token; varied prompts; `--prompt`; keeps
llama-server's timings. `run_llamacpp.sh`: load captured by restarting the main host; kill
and pause 0.5 s into a 300-token request; container logs saved. `run_llamacpp_pause.sh`: the
hang case alone, with resume and a probe. `run_exo.sh`: anchor container, short prompt, one
long request. `run_background.sh`: anchor + throttled generators + status print.
`llamacpp/cluster.sh`: 1 s stop grace. `localai/cluster.sh`: as in §4.

## 6. Still open
- README: intro and conclusion unwritten; the numbers above are the material.
- Rerun `run_llamacpp.sh 600` to replace the headline report (old rules, no logs).
- Confirm the KV-state transfers against a llama-server log.
- exo: the 90 s watchdog constant; whether a long-prefill result is obtainable at all.
- Analysis: the `periodicity per host pair` rule is new and untested on exo's probe storm;
  the exo generate-phase detector also flagged one flow in idle on the second run
  (unexplained, probably the placement request's tail).
