# distributed-inference-fingerprint

Experiment 4 of the distributed-inference resilience work: **what a swarm looks like on
the wire, and how little capture a defender needs to recognise it.** Three stacks, read
from source first (`FINDINGS-wire.md`), predictions written before any capture
(`STUDY.md`), then packet captures of exo, llama.cpp RPC and LocalAI's P2P mode on a
rootless Podman bridge, with ordinary traffic captured the same way as the negative set.

Earlier experiments: the model and the cut experiment in
[distributed-inference-resilience](https://github.com/thenaithan/distributed-inference-resilience),
the measured recovery cost in
[distributed-inference-recovery](https://github.com/thenaithan/distributed-inference-recovery).

## Contents

- `FINDINGS-wire.md`: discovery, transport, framing, periodicity and data-plane sizes of
  each stack, with file:line. Start here.
- `STUDY.md`: the question, vantage points, what is captured, fifteen numbered predictions,
  method, out of scope.
- `capture/`: `capture.sh` (tcpdump on a rootless Podman network's bridge), `phase.sh`
  (timeline markers on the same clock), `requests.py` (streaming requests to any
  OpenAI-compatible endpoint), `run_llamacpp.sh` and `run_exo.sh` (one full scenario each:
  load, idle, generation, long prefill, node loss).
- `exo/`, `llamacpp/`: the Experiment 3 cluster scripts and images, unchanged.
  `localai/cluster.sh`: main node plus P2P workers (not yet run).
- `background/run.sh`: the ordinary-traffic generators for the false-positive set.
- `analysis/`: standard-library only. `pcap.py` (reader), `flows.py` (flow table),
  `signatures.py` (byte and port rules per stack), `rhythm.py` (periodicities and
  generation bursts: the rules that need no payload), `classify.py` (apply everything to a
  capture and report what could be said, and when).
- `tests/synthetic.py`: a synthetic pcap with the predicted shapes, to exercise the
  analysis without a cluster. It is not evidence.

## Quick start

```
# analysis needs nothing beyond Python 3.10+
python3 -m tests.synthetic /tmp/syn.pcap && python3 -m analysis.classify /tmp/syn.pcap

# a capture (host with the Experiment 3 images built, tcpdump installed)
capture/run_llamacpp.sh 600                 # ~25 min; writes captures/llamacpp/<stamp>.pcap + timeline
RECOVERY=../distributed-inference-recovery capture/run_exo.sh 600   # hours on CPU: exo decodes at 2.4 s/token
python3 -m analysis.classify captures/llamacpp/<stamp>.pcap --timeline captures/llamacpp/<stamp>.timeline.csv

# background, on the same bridge with the swarm down, then again with it up
capture/capture.sh start llama-net captures/background/<stamp>.pcap
background/run.sh llama-net 600
capture/capture.sh stop
```

Captures are large (the llama.cpp generation phase alone is ~600 KB per token); they are
not committed. What is committed is the per-capture report from `classify.py --json` and
the timelines.

## Status

- [x] wire protocols read from source (exo bc412e2, llama.cpp 74bca39, LocalAI 35224b8)
- [x] predictions written (STUDY.md)
- [x] capture harness and analysis written; analysis checked on a synthetic capture only
- [ ] plumbing: `capture.sh` inside the rootless network namespace; LocalAI cluster
- [ ] captures: llama.cpp, exo, LocalAI (DHT off, then on), background
- [ ] results and the predictions scored
