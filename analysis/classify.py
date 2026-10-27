"""Apply the rules to a capture and report what a defender could say, and when.

    python3 -m analysis.classify capture.pcap [--timeline phases.csv] [--json out.json]

For every flow with a match: the rule, what it needed, and the capture time (seconds from
the first packet) at which the match became possible. Then per host: the stack(s) seen,
and per flow with enough traffic: periodicities and burst structure (the rules that need
no payload). The timeline, if given, labels each finding with the harness phase it fell in.
"""

from __future__ import annotations

import argparse
import csv
import json
from typing import Dict, List, Optional

from . import pcap, rhythm, signatures
from .flows import Flow, build, hosts


def load_timeline(path: Optional[str]) -> List[tuple]:
    if not path:
        return []
    rows = []
    with open(path) as fh:
        for r in csv.reader(fh):
            if len(r) >= 2 and r[0] and not r[0].startswith("#"):
                try:
                    rows.append((float(r[0]), r[1], r[2] if len(r) > 2 else ""))
                except ValueError:
                    pass
    return sorted(rows)


def phase_at(timeline: List[tuple], t: float) -> str:
    cur = ""
    for t0, ph, _ in timeline:
        if t0 <= t:
            cur = ph
        else:
            break
    return cur


def analyse(path: str, timeline: Optional[str] = None, min_packets: int = 20) -> dict:
    stats = pcap.Stats()
    flows = build(path, stats=stats)
    if not flows:
        return {"error": "no IP packets", "packets": stats.packets}
    t0 = min(f.t_first for f in flows.values())
    tl = load_timeline(timeline)
    sha = None
    try:
        with open(path + ".sha256") as fh:
            sha = fh.read().split()[0]
    except OSError:
        pass
    out = {"capture": path, "sha256": sha, "packets": stats.packets, "skipped": stats.skipped,
           "t0": t0, "duration": max(f.t_last for f in flows.values()) - t0,
           "hosts": hosts(flows), "flows": len(flows), "matches": [], "rhythm": [], "by_host": {}}
    first_by_rule: Dict[str, float] = {}
    for f in flows.values():
        for m in signatures.match_all(f):
            rel = m.t - t0
            out["matches"].append({"flow": f.endpoints(), "rule": m.rule, "stack": m.stack, "what": m.what,
                                   "needs": m.needs, "strength": m.strength, "t": round(rel, 3),
                                   "phase": phase_at(tl, m.t)})
            first_by_rule[m.rule] = min(first_by_rule.get(m.rule, rel), rel)
            if m.stack != "background":
                for h in (f.a[0], f.b[0]):
                    out["by_host"].setdefault(h, set()).add(m.stack)
        if f.packets >= min_packets and (f.series_ab or f.series_ba):
            per = rhythm.periodicities(f)
            b = rhythm.bursts(f)
            if per or (b and b.n >= 3):
                out["rhythm"].append({
                    "flow": f.endpoints(), "packets": f.packets, "duration": round(f.duration, 1),
                    "payload_ab": f.payload_ab, "payload_ba": f.payload_ba,
                    "periods": per,
                    "bursts": None if not b else {
                        "n": b.n, "period_s": round(b.period_s, 3), "period_cv": round(b.period_cv, 2),
                        "req_bytes": round(b.req_bytes), "resp_bytes": round(b.resp_bytes),
                        "req_cv": round(b.req_cv, 2), "resp_cv": round(b.resp_cv, 2),
                        "generation_like": b.looks_like_generation(),
                        "t": round(b.t_start - t0, 1), "phase": phase_at(tl, b.t_start)}})
    out["by_host"] = {h: sorted(s) for h, s in out["by_host"].items()}
    out["first_match_s"] = {r: round(t, 3) for r, t in sorted(first_by_rule.items(), key=lambda x: x[1])}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--timeline", help="csv of t,phase,note written by capture/phase.sh")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--min-packets", type=int, default=20)
    args = ap.parse_args()
    r = analyse(args.pcap, args.timeline, args.min_packets)
    if "error" in r:
        print(r); return
    print(f"{r['capture']}: {r['packets']} packets ({r['skipped']} non-IP skipped), {r['flows']} flows, "
          f"{r['duration']:.1f} s, hosts: {', '.join(r['hosts'])}")
    print("\nfirst match per rule (s from capture start):")
    for rule, t in r["first_match_s"].items():
        print(f"  {t:8.3f}  {rule}")
    print("\nstack per host (from byte or port signatures):")
    for h, s in r["by_host"].items():
        print(f"  {h:<40} {', '.join(s)}")
    print("\nmatches:")
    seen = set()
    for m in r["matches"]:
        k = (m["flow"], m["rule"])
        if k in seen:
            continue
        seen.add(k)
        print(f"  {m['t']:8.3f}  {m['strength']:<4} {m['rule']:<18} {m['what']:<48} needs {m['needs']:<16} {m['flow']}  {m['phase']}")
    print("\ntiming (no payload needed):")
    for x in r["rhythm"]:
        b = x["bursts"]
        per = " ".join(f"{p}s({s})" for p, s in x["periods"]) or "-"
        bs = ("-" if not b else f"{b['n']} bursts every {b['period_s']} s (cv {b['period_cv']}), "
              f"{b['req_bytes']} B -> / {b['resp_bytes']} B <- (cv {b['req_cv']}/{b['resp_cv']})"
              + ("  GENERATION-LIKE" if b["generation_like"] else "") + f"  at {b['t']} s {b['phase']}")
        print(f"  {x['flow']}\n      {x['packets']} pkts, {x['duration']} s, {x['payload_ab']}/{x['payload_ba']} B; periods: {per}\n      {bs}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(r, fh, indent=1)


if __name__ == "__main__":
    main()
