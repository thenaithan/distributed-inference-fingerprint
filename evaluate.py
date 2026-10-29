"""The README's tables, from the committed reports (captures/<stack>/<stamp>.report.json)
and timelines. No pcap needed.

    python3 evaluate.py            # prints every table
    python3 evaluate.py --json out.json

Tables: time to first match per rule per capture (§2); generation-like exchanges per
stack and phase (§3); periodicities per stack in idle (§3); false positives on the
background set (§2, §3); flows that left private address ranges (§4); capture quality
(packets, drops).
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
    print("| stack | capture | rule | first match s | phase |")
    print("|---|---|---|---:|---|")
    out["first_match"] = []
    for stack, stamp, r, tl in reps:
        t0 = r["t0"]
        for rule, t in sorted(r.get("first_match_s", {}).items(), key=lambda x: x[1]):
            ph = ""
            for tt, p in tl:
                if tt - t0 <= t:
                    ph = p
            out["first_match"].append(dict(stack=stack, capture=stamp, rule=rule, t=t, phase=ph))
            print(f"| {stack} | {stamp} | {rule} | {t:.2f} | {ph} |")

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

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=1)


if __name__ == "__main__":
    main()
