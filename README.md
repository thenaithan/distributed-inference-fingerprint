# distributed-inference-fingerprint

<!-- INTRO (Nat): the question (the essay's "can shard-to-shard traffic be fingerprinted
against background noise"), where it came from, the two readers, scope (measure and
classify with readable rules; no evasion; vLLM dropped, LocalAI added, see STUDY.md), the
one-sentence outcome once there is one, who did what, where the numbers come from
(analysis/classify.py from the committed reports and timelines). -->

Experiment 4 of the distributed-inference resilience work: what a swarm looks like on the
wire, and how little capture a defender needs to recognise it. Three stacks, read from
source first ([FINDINGS-wire.md](FINDINGS-wire.md)), fifteen predictions written before
any capture ([STUDY.md](STUDY.md)), then packet captures of exo, llama.cpp RPC and
LocalAI's P2P mode on a rootless Podman bridge, with ordinary traffic captured the same
way as the negative set. Earlier experiments: the model and the cut experiment in
[distributed-inference-resilience](https://github.com/thenaithan/distributed-inference-resilience),
the measured recovery cost in
[distributed-inference-recovery](https://github.com/thenaithan/distributed-inference-recovery).

## 1. What is measured

<!-- to be written from the captures: setup, vantage, phases; see STUDY.md until then -->

## 2. Static signatures

<!-- time-to-detect per rule per stack; false positives on the background set -->

## 3. Timing and size

<!-- periodicities when idle; generation bursts; what encryption leaves (LocalAI) -->

## 4. What leaves the LAN

## 5. Predictions against measurements

<!-- STUDY.md predictions 1 to 15 scored -->

## 6. Limitations

## Conclusion

<!-- CONCLUSION (Nat) -->

## Repository

- `FINDINGS-wire.md`: discovery, transport, framing, periodicity and data-plane sizes of
  each stack, read from source with file:line. Start here.
- `STYLE.md`: the series' style, copied in unchanged.
- `STUDY.md`: the question, vantage points, what is captured, the fifteen numbered
  predictions, method, out of scope.
- `capture/`: `capture.sh` (tcpdump on a rootless Podman network's bridge), `phase.sh`
  (timeline markers on the same clock as the pcap), `requests.py` (streaming requests to
  any OpenAI-compatible endpoint), `run_llamacpp.sh` and `run_exo.sh` (one full scenario
  each: load, idle, generation, long prefill, node loss).
- `exo/`, `llamacpp/`: the Experiment 3 `Containerfile` and `cluster.sh`, unchanged.
  `localai/cluster.sh`: main node plus P2P workers (not yet run; its unknowns are listed
  at the top of the file).
- `background/run.sh`: the ordinary-traffic generators for the false-positive set.
- `analysis/`: standard library only. `pcap.py` (reader), `flows.py` (flow table),
  `signatures.py` (byte and port rules per stack), `rhythm.py` (periodicities and
  generation bursts: the rules that need no payload), `classify.py` (apply everything to a
  capture and report what could be said, and when).
- `tests/synthetic.py`: a synthetic pcap with the predicted shapes, to exercise the
  analysis without a cluster. It is not evidence.
- `captures/`: per capture, the timeline, the request log and the `classify.py --json`
  report are committed; the pcaps are not (`.gitignore`).

### Reproducing

Analysis needs Python 3.10 or later and nothing else:

```
python3 -m tests.synthetic /tmp/syn.pcap && python3 -m analysis.classify /tmp/syn.pcap
```

Captures need the host from Experiment 3 (i5-14600K, rootless Podman, the `exo-node`
and `llamacpp-rpc` images built from `exo/Containerfile` and `llamacpp/Containerfile`)
and `tcpdump` installed:

```
capture/run_llamacpp.sh 600                 # ~25 min; writes captures/llamacpp/<stamp>.pcap + timeline + requests
RECOVERY=../distributed-inference-recovery capture/run_exo.sh 600    # hours on CPU: exo decodes at 2.4 s/token
python3 -m analysis.classify captures/llamacpp/<stamp>.pcap --timeline captures/llamacpp/<stamp>.timeline.csv --json captures/llamacpp/<stamp>.report.json

# background, on the same bridge with the swarm down, then once more with it up
capture/capture.sh start llama-net captures/background/<stamp>.pcap
background/run.sh llama-net 600
capture/capture.sh stop
```

### Status

- [x] wire protocols read from source (exo bc412e2, llama.cpp 74bca39, LocalAI 35224b8)
- [x] predictions written (STUDY.md)
- [x] capture harness and analysis written; the analysis is checked on a synthetic capture only
- [ ] plumbing: `capture.sh` inside the rootless network namespace; `localai/cluster.sh`
- [ ] captures: llama.cpp, exo, LocalAI (DHT off, then on), background
- [ ] results, figures, the predictions scored

## Acknowledgement

The source reading, the capture harness and the analysis were developed together with
Claude (Anthropic). The questions, the framing, the captures and the conclusions are
Naithan Weigh's.
