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
        out.setdefault("flow_table", []).append({
            "flow": f.endpoints(), "t": round(f.t_first - t0, 3), "duration": round(f.duration, 1),
            "packets": f.packets, "bytes_ab": f.bytes_ab, "bytes_ba": f.bytes_ba,
            "payload_ab": f.payload_ab, "payload_ba": f.payload_ba,
            "expected_ab": f.expected_ab, "expected_ba": f.expected_ba, "dropped": f.dropped,
            "fin": None if f.fin_at is None else round(f.fin_at - t0, 3),
            "rst": None if f.rst_at is None else round(f.rst_at - t0, 3),
            "phase": phase_at(tl, f.t_first)})
        if f.packets >= min_packets and (f.series_ab or f.series_ba):
            per = rhythm.periodicities(f)
            # exchanges are judged per harness phase: a flow that carries a load, short
            # requests, long prefills and a hang in turn has no single exchange shape
            entry = {"flow": f.endpoints(), "packets": f.packets, "duration": round(f.duration, 1),
                     "payload_ab": f.payload_ab, "payload_ba": f.payload_ba, "periods": per, "scales": []}
            for ph, pf in rhythm.by_phase(f, tl):
                scales = rhythm.burst_scales(pf)
                tb = rhythm.turns(pf)
                if tb and not any(abs(b.period_s - tb.period_s) / max(tb.period_s, 1e-9) < 0.2 for b in scales):
                    scales.insert(0, tb)
                    scales.sort(key=lambda b: b.period_s)
                for b in scales:
                    entry["scales"].append({
                        "phase": ph, "n": b.n, "period_s": round(b.period_s, 4), "period_cv": round(b.period_cv, 2),
                        "req_bytes": round(b.req_bytes), "resp_bytes": round(b.resp_bytes),
                        "req_cv": round(b.req_cv, 2), "resp_cv": round(b.resp_cv, 2),
                        "generation_like": b.looks_like_generation(), "t": round(b.t_start - t0, 1)})
            if per or entry["scales"]:
                out["rhythm"].append(entry)
    out["by_host"] = {h: sorted(s) for h, s in out["by_host"].items()}
    # periodicity per host pair, across all its flows: a heartbeat that opens a socket per
    # beat is hundreds of one-packet flows and invisible per flow (background set, 2026-10-28)
    out["pair_periods"] = []
    for (proto, h1, h2), (times, nflows) in rhythm.pair_series(flows).items():
        per = rhythm.periodicities_of(times)
        if per and nflows > 1:
            out["pair_periods"].append({"pair": f"{proto} {h1} <-> {h2}", "flows": nflows,
                                        "packets": len(times), "periods": per})
    out["dropped_bytes"] = sum(f["dropped"] for f in out.get("flow_table", []))
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
    if r.get("dropped_bytes"):
        print(f"  capture dropped {r['dropped_bytes']} payload bytes (by TCP sequence accounting); "
              f"byte figures below use expected_* where it matters")
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
        per = " ".join(f"{p}s({s})" for p, s in x["periods"]) or "-"
        print(f"  {x['flow']}\n      {x['packets']} pkts, {x['duration']} s, {x['payload_ab']}/{x['payload_ba']} B; periods: {per}")
        for b in x["scales"]:
            print(f"      [{b['phase'] or '-'}] {b['n']} exchanges every {b['period_s']} s (cv {b['period_cv']}), "
                  f"{b['req_bytes']} B -> / {b['resp_bytes']} B <- (cv {b['req_cv']}/{b['resp_cv']})"
                  + ("  GENERATION-LIKE" if b["generation_like"] else "") + f"  from {b['t']} s")
    if r.get("pair_periods"):
        print("\nperiodicity per host pair, across flows:")
        for x in r["pair_periods"]:
            print(f"  {x['pair']:<50} {x['flows']} flows, {x['packets']} pkts: "
                  + " ".join(f"{p}s({s})" for p, s in x["periods"]))
    ext = [f for f in r.get("flow_table", []) if not any(h in f["flow"] for h in ("10.", "192.168.", "fe80:", "ff02:", "fd", "172."))]
    if ext:
        print("\nflows with an endpoint outside private/link-local ranges (what left the LAN):")
        for f in ext:
            print(f"  {f['t']:8.3f}  {f['flow']:<55} {f['packets']} pkts, {f['bytes_ab']}/{f['bytes_ba']} B  {f['phase']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(r, fh, indent=1)


if __name__ == "__main__":
    main()
