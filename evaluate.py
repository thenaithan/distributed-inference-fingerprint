"""The README's tables, from the committed reports (captures/<stack>/<stamp>.report.json)
and timelines. No pcap needed.

    python3 evaluate.py            # prints every table
    python3 evaluate.py --json out.json

Tables: time to first match per rule per capture (§2); generation-like exchanges per
stack and phase (§3); periodicities per stack in idle (§3); false positives on the
background set (§2, §3); flows that left private address ranges (§4), with a total per
capture and the generation-like ones among them; connections and bytes per LAN host pair
(§2, §3); the client's decode rate per phase (§3); capture quality (packets, drops).
"""

from __future__ import annotations

import argparse
import csv
import glob
import ipaddress
import json
import os
import statistics as st
from collections import defaultdict


def timeline(path):
    rows = []
    if os.path.exists(path):
        with open(path) as fh:
            for row in csv.reader(fh):
                if row and not row[0].startswith("#") and len(row) >= 2:
                    try:
                        rows.append((float(row[0]), row[1]))
                    except ValueError:
                        pass
    return sorted(rows)


def reports():
    out = []
    for path in sorted(glob.glob("captures/*/*.report.json")):
        stack = path.split(os.sep)[1]
        stamp = os.path.basename(path).replace(".report.json", "")
        with open(path) as fh:
            r = json.load(fh)
        base = os.path.join(os.path.dirname(path), stamp.split(".")[0])
        out.append((stack, stamp, r, timeline(base + ".timeline.csv")))
    return out


def is_private(host: str) -> bool:
    h = host.strip("[]")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return True
    return ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_loopback or ip.is_unspecified


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def endpoints(flow: str):
    proto, rest = flow.split(" ", 1)
    a, b = rest.split(" <-> ")
    return proto, a.rsplit(":", 1)[0], b.rsplit(":", 1)[0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    args = ap.parse_args()
    reps = reports()
    out = {}

    print("## capture quality")
    print("| stack | capture | packets | flows | duration s | dropped bytes |")
    print("|---|---|---:|---:|---:|---:|")
    out["quality"] = []
    for stack, stamp, r, tl in reps:
        row = dict(stack=stack, capture=stamp, packets=r["packets"], flows=r["flows"],
                   duration=round(r["duration"]), dropped=r.get("dropped_bytes", 0))
        out["quality"].append(row)
        print(f"| {stack} | {stamp} | {row['packets']} | {row['flows']} | {row['duration']} | {row['dropped']} |")

    print("\n## time to first match, seconds from the start of the capture")
    print("| stack | capture | rule | first match s | phase | flows matched |")
    print("|---|---|---|---:|---|---:|")
    out["first_match"] = []
    for stack, stamp, r, tl in reps:
        t0 = r["t0"]
        nflows = defaultdict(set)
        for m in r.get("matches", []):
            nflows[m["rule"]].add(m["flow"])
        for rule, t in sorted(r.get("first_match_s", {}).items(), key=lambda x: x[1]):
            ph = ""
            for tt, p in tl:
                if tt - t0 <= t:
                    ph = p
            out["first_match"].append(dict(stack=stack, capture=stamp, rule=rule, t=t, phase=ph, flows=len(nflows[rule])))
            print(f"| {stack} | {stamp} | {rule} | {t:.2f} | {ph} | {len(nflows[rule])} |")

    print("\n## generation-like exchanges (token scale), one row per flow and phase")
    print("| stack | capture | phase | flow | exchanges | period ms | bytes in | bytes out |")
    print("|---|---|---|---|---:|---:|---:|---:|")
    out["generation"] = []
    for stack, stamp, r, tl in reps:
        for x in r.get("rhythm", []):
            for b in x.get("scales", []):
                if b.get("generation_like") and b["period_s"] < 5:
                    row = dict(stack=stack, capture=stamp, phase=b.get("phase", ""), flow=x["flow"].split(" ", 1)[1],
                               n=b["n"], period_ms=round(1000 * b["period_s"], 1), bytes_in=b["req_bytes"], bytes_out=b["resp_bytes"])
                    out["generation"].append(row)
                    print(f"| {stack} | {stamp} | {row['phase']} | {row['flow']} | {row['n']} | {row['period_ms']} | {row['bytes_in']} | {row['bytes_out']} |")

    print("\n## periodicities per host pair (across flows), top two per pair, pairs with >= 10 flows")
    print("| stack | capture | pair | flows | periods s (score) |")
    print("|---|---|---|---:|---|")
    out["periods"] = []
    for stack, stamp, r, tl in reps:
        for p in r.get("pair_periods", []):
            if p["flows"] >= 10:
                per = " ".join(f"{a} ({b})" for a, b in p["periods"][:2])
                out["periods"].append(dict(stack=stack, capture=stamp, pair=p["pair"], flows=p["flows"], periods=p["periods"][:2]))
                print(f"| {stack} | {stamp} | {p['pair']} | {p['flows']} | {per} |")

    print("\n## flows with an endpoint outside private, link-local, multicast and loopback ranges (what left the LAN)")
    print("| stack | capture | phase | remote hosts | flows | bytes up | bytes down |")
    print("|---|---|---|---:|---:|---:|---:|")
    out["off_lan"] = []
    for stack, stamp, r, tl in reps:
        agg = defaultdict(lambda: [set(), 0, 0, 0])
        for f in r.get("flow_table", []):
            proto, a, b = endpoints(f["flow"])
            pa, pb = is_private(a), is_private(b)
            if pa and pb:
                continue
            remote = b if pa else a
            up, down = (f["bytes_ab"], f["bytes_ba"]) if pa else (f["bytes_ba"], f["bytes_ab"])
            g = agg[f.get("phase", "")]
            g[0].add(remote); g[1] += 1; g[2] += up; g[3] += down
        for ph, (hosts, n, up, down) in sorted(agg.items()):
            out["off_lan"].append(dict(stack=stack, capture=stamp, phase=ph, hosts=len(hosts), flows=n, up=up, down=down))
            print(f"| {stack} | {stamp} | {ph} | {len(hosts)} | {n} | {up} | {down} |")
        if len(agg) > 1:                      # the whole capture: distinct hosts across phases
            allh = set().union(*(g[0] for g in agg.values()))
            n, up, down = (sum(g[i] for g in agg.values()) for i in (1, 2, 3))
            out["off_lan"].append(dict(stack=stack, capture=stamp, phase="all", hosts=len(allh), flows=n, up=up, down=down))
            print(f"| {stack} | {stamp} | all | {len(allh)} | {n} | {up} | {down} |")

    print("\n## generation-like phase-flows with an endpoint off the LAN (false positives: no decode leaves the LAN here)")
    print("| stack | capture | phase-flows | flows | period s, median per band (count) |")
    print("|---|---|---:|---:|---|")
    out["off_lan_generation"] = []
    for stack, stamp, r, tl in reps:
        rows = []
        for x in r.get("rhythm", []):
            _, a, b = endpoints(x["flow"])
            if is_private(a) and is_private(b):
                continue
            rows += [(x["flow"], s["period_s"]) for s in x.get("scales", []) if s.get("generation_like")]
        if not rows:
            continue
        bands = defaultdict(list)
        for _, per in rows:
            bands["< 1" if per < 1 else "1 to 7" if per < 7 else ">= 7"].append(per)
        desc = ", ".join(f"{k}: {st.median(v):.2f} ({len(v)})" for k, v in sorted(bands.items()))
        out["off_lan_generation"].append(dict(stack=stack, capture=stamp, phase_flows=len(rows),
                                              flows=len({f for f, _ in rows}), bands={k: len(v) for k, v in bands.items()}))
        print(f"| {stack} | {stamp} | {len(rows)} | {len({f for f, _ in rows})} | {desc} |")

    print("\n## LAN host pairs: connections and bytes (pairs with >= 10 flows or >= 100 KB)")
    print("| stack | capture | pair | flows | bytes a->b | bytes b->a |")
    print("|---|---|---|---:|---:|---:|")
    out["lan_pairs"] = []
    for stack, stamp, r, tl in reps:
        agg = defaultdict(lambda: [0, 0, 0])
        for f in r.get("flow_table", []):
            proto, a, b = endpoints(f["flow"])
            if not (is_private(a) and is_private(b)):
                continue
            if any(ipaddress.ip_address(h.strip("[]")).is_multicast for h in (a, b) if _is_ip(h)):
                continue
            g = agg[f"{proto} {a} <-> {b}"]
            g[0] += 1; g[1] += f["payload_ab"]; g[2] += f["payload_ba"]
        for pair, (n, ab, ba) in sorted(agg.items()):
            if n >= 10 or ab + ba >= 100_000:
                out["lan_pairs"].append(dict(stack=stack, capture=stamp, pair=pair, flows=n, ab=ab, ba=ba))
                print(f"| {stack} | {stamp} | {pair} | {n} | {ab} | {ba} |")

    print("\n## decode rate at the client (requests.jsonl): median ms per token after the first, per phase")
    print("| stack | capture | phase | requests | ms per token |")
    print("|---|---|---|---:|---:|")
    out["client_rate"] = []
    for stack, stamp, r, tl in reps:
        path = f"captures/{stack}/{stamp.split('.')[0]}.requests.jsonl"
        if "." in stamp or not os.path.exists(path):
            continue
        per_phase = defaultdict(list)
        with open(path) as fh:
            for line in fh:
                q = json.loads(line)
                if q.get("t_first_token") and q.get("tokens", 0) > 1:
                    ph = ""
                    for tt, p in tl:
                        if tt <= q["t_request"]:
                            ph = p
                    per_phase[ph].append(1000 * (q["t_end"] - q["t_first_token"]) / (q["tokens"] - 1))
        for ph, v in per_phase.items():
            out["client_rate"].append(dict(stack=stack, capture=stamp, phase=ph, n=len(v), ms=round(st.median(v), 1)))
            print(f"| {stack} | {stamp} | {ph} | {len(v)} | {st.median(v):.1f} |")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=1)


if __name__ == "__main__":
    main()
