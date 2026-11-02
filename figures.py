"""Figures from the committed per-capture reports (captures/<stack>/<stamp>.report.json,
written by `analysis/classify.py --json`) and their timelines. No pcap is needed.

    python3 figures.py            # writes figures/*.png

One figure per finding, one stack per figure where the stacks differ:
    detect-<stack>.png      seconds of capture before each rule first matched
    exchanges-<stack>.png   bytes per token-scale exchange, each leg
    timeline-<stack>.png    the headline capture: at most ten rows of flows, hosts by role,
                            phases as a strip; data plane in the stack's hue
    nodeloss-<stack>.png    the same, zoomed to the two minutes around the kill
    periods.png             the rhythms found in idle, per stack
    offlan.png              bytes that left the LAN, per stack and phase

One hue per stack (STYLE.md §4). savefig drops the Software tag so a rerun reproduces
the committed files byte for byte on the machine that made them with the pinned
matplotlib (text anti-aliasing differs across freetype builds).
"""

from __future__ import annotations

import csv
import glob
import ipaddress
import json
import os
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

OUT = "figures"
os.makedirs(OUT, exist_ok=True)
STACK = {"exo": "#2a78d6", "llamacpp": "#1baf7a", "localai": "#eda100", "background": "#52514e"}
NAME = {"exo": "exo", "llamacpp": "llama.cpp RPC", "localai": "LocalAI P2P", "background": "background"}
INK, INK2, GRID, SHADE = "#0b0b0b", "#52514e", "#e6e5e1", "#f3f2ef"
META = {"Software": None}
# the capture each stack's figures are drawn from (the full run of each)
HEADLINE = {"llamacpp": "20261030-083513", "exo": "20261028-125140", "localai": "20261029-144115",
            "background": "20261028-081447"}
EXTRA_TIMELINES = {"localai-dht": ("localai", "20261029-151923")}
# which port names a stack's data plane and control plane; anything else is "other"
ROLE_PORTS = {
    "llamacpp": {"data": {50052}, "control": set()},
    "exo": {"data": set(), "control": {52413, 52414, 52415}},        # data: random high ports, found by rhythm
    "localai": {"data": set(), "control": set()},                      # QUIC tunnels carry both; found by rhythm
    "background": {"data": set(), "control": set()},
}

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2,
    "ytick.color": INK2, "axes.titlecolor": INK, "axes.spines.top": False, "axes.spines.right": False,
    "figure.facecolor": "white", "axes.facecolor": "white", "savefig.dpi": 160,
})


# ---------------------------------------------------------------- loading

def reports():
    """{stack: {stamp: (report, timeline rows)}}, loopback reports left out."""
    out = defaultdict(dict)
    for path in sorted(glob.glob("captures/*/*.report.json")):
        if ".lo.report" in path:
            continue
        stack = path.split(os.sep)[1]
        stamp = os.path.basename(path).replace(".report.json", "")
        with open(path) as fh:
            r = json.load(fh)
        tl = []
        tlp = os.path.join(os.path.dirname(path), stamp + ".timeline.csv")
        if os.path.exists(tlp):
            with open(tlp) as fh:
                for row in csv.reader(fh):
                    if row and not row[0].startswith("#") and len(row) >= 2:
                        try:
                            tl.append((float(row[0]), row[1]))
                        except ValueError:
                            pass
        out[stack][stamp] = (r, sorted(tl))
    return out


def headline(reps, stack):
    d = reps.get(stack, {})
    if not d:
        return None
    stamp = HEADLINE.get(stack) if HEADLINE.get(stack) in d else sorted(d)[-1]
    return (stamp,) + d[stamp]


def split_flow(flow):
    proto, rest = flow.split(" ", 1)
    a, b = rest.split(" <-> ")
    ha, pa = a.rsplit(":", 1)
    hb, pb = b.rsplit(":", 1)
    return proto, ha, int(pa), hb, int(pb)


def local_nets(rows):
    """The capture's own segments: /24s and /64s holding >= 5% of flow endpoints."""
    nets = Counter()
    for f in rows:
        _, ha, _, hb, _ = split_flow(f["flow"])
        for h in (ha, hb):
            try:
                ip = ipaddress.ip_address(h.strip("[]"))
            except ValueError:
                continue
            nets[ipaddress.ip_network(f"{h}/24" if ip.version == 4 else f"{h}/64", strict=False)] += 1
    total = sum(nets.values()) or 1
    return {n for n, c in nets.items() if c / total >= 0.05}


def classify_host(h, nets):
    """'local' | 'multicast' | 'elsewhere' for a host address."""
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        return "local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_loopback or ip.is_unspecified or (ip.version == 6 and ip.is_link_local):
        return "local"
    net = ipaddress.ip_network(f"{ip}/24" if ip.version == 4 else f"{ip}/64", strict=False)
    return "local" if net in nets else "elsewhere"


def role_names(stack, rows, nets, r):
    """Short names for the local hosts, by role where the stack makes it readable:
    llama.cpp: main and rpc A/B (who serves 50052); otherwise node 1..n in order of
    first appearance. IPv6 link-local and IPv4 addresses of one exo node cannot be
    joined from the capture, so each address is a node of its own."""
    first = {}
    for f in sorted(rows, key=lambda f: f["t"]):
        _, ha, _, hb, _ = split_flow(f["flow"])
        for h in (ha, hb):
            if classify_host(h, nets) == "local" and h not in first:
                first[h] = f["t"]
    names = {}
    if stack == "llamacpp":
        servers = sorted({split_flow(f["flow"])[1] if split_flow(f["flow"])[2] == 50052 else split_flow(f["flow"])[3]
                          for f in rows if 50052 in (split_flow(f["flow"])[2], split_flow(f["flow"])[4])
                          and classify_host(split_flow(f["flow"])[1], nets) == "local"
                          and classify_host(split_flow(f["flow"])[3], nets) == "local"},
                         key=lambda h: first.get(h, 0))
        k = 0
        for h in sorted(first, key=first.get):
            if h in servers:
                names[h] = f"rpc {'AB'[servers.index(h) % 2]}" + (f" ({servers.index(h) // 2 + 1})" if servers.index(h) >= 2 else "")
            elif h.endswith(".1") or h.endswith("::1"):
                names[h] = "gateway"
            else:
                names[h] = "main" + (f" ({k + 1})" if k else ""); k += 1
    elif stack == "localai":
        # the main node is the one with a tunnel to every worker: the most local partners
        # among IPv4 hosts; a restarted cluster's hosts are numbered (2)
        partners = defaultdict(set)
        load = Counter()
        for f in rows:
            _, ha, pa, hb, pb = split_flow(f["flow"])
            if ":" in ha or ":" in hb or classify_host(ha, nets) != "local" or classify_host(hb, nets) != "local":
                continue
            if ha.endswith(".1") or hb.endswith(".1"):
                continue
            partners[ha].add(hb); partners[hb].add(ha)
            load[ha] += f["payload_ab"] + f["payload_ba"]; load[hb] += f["payload_ab"] + f["payload_ba"]
        mains, cluster = [], {}
        for h in sorted(first, key=first.get):
            if h.endswith(".1") or h.endswith("::1"):
                names[h] = "gateway"
            elif ":" in h:
                names[h] = "a node (IPv6)"
            elif h in partners and all(load[o] < load[h] for o in partners[h]):
                mains.append(h)
                names[h] = "main" + (f" ({len(mains)})" if len(mains) > 1 else "")
                cluster[h] = len(mains)
        wk = Counter()
        for h in sorted(first, key=first.get):
            if h in names or ":" in h:
                continue
            m = next((mm for mm in mains if h in partners.get(mm, ())), None)
            c = cluster.get(m, 1)
            wk[c] += 1
            names[h] = f"worker {wk[c]}" + (f" ({c})" if c > 1 else "")
    else:
        k = 0
        for h in sorted(first, key=first.get):
            if h.endswith(".1") or h.endswith("::1"):
                names[h] = "gateway"
            else:
                k += 1
                names[h] = f"node {k}"
    return names


# ---------------------------------------------------------------- timeline

def flow_rows(stack, r):
    """Group the capture's flows into at most ~10 rows: (label, kind, [flows]).
    kind: data | control | discovery | dns | elsewhere | other."""
    rows = [f for f in r.get("flow_table", []) if (f["payload_ab"] + f["payload_ba"]) > 0
            and f["flow"].split(" ")[0] in ("tcp", "udp")]
    nets = local_nets(rows)
    names = role_names(stack, rows, nets, r)
    data_flows = {x["flow"] for x in r.get("rhythm", []) if any(b.get("generation_like") for b in x.get("scales", []))}
    ports = ROLE_PORTS.get(stack, ROLE_PORTS["background"])
    groups = defaultdict(list)
    for f in rows:
        proto, ha, pa, hb, pb = split_flow(f["flow"])
        ca, cb = classify_host(ha, nets), classify_host(hb, nets)
        if "elsewhere" in (ca, cb):
            loc = ha if ca == "local" else hb
            groups[(f"{names.get(loc, loc)} → off-LAN", "elsewhere")].append(f)
            continue
        if "multicast" in (ca, cb):
            loc = ha if ca == "local" else hb
            port = pb if cb == "multicast" else pa
            what = {5353: "mDNS", 1900: "SSDP", 52413: "exo beacon"}.get(port, f"multicast:{port}")
            groups[(f"all nodes → {what}", "discovery")].append(f)
            continue
        if 53 in (pa, pb):
            loc = ha if pb == 53 else hb
            groups[("all nodes → DNS", "dns")].append(f)
            continue
        # local pair: the server side is the port that repeats, else the lower port
        key_pair = tuple(sorted((ha, hb)))
        # a known control port wins over the rhythm flag: exo's 1 Hz status messages on
        # 52414 pass the generation test (README §3) but are control plane
        if pa in ports["control"] or pb in ports["control"]:
            kind = "control"
        elif f["flow"] in data_flows or pa in ports["data"] or pb in ports["data"]:
            kind = "data"
        else:
            kind = "other"
        a, b = names.get(key_pair[0], key_pair[0]), names.get(key_pair[1], key_pair[1])
        groups[(f"{a} ↔ {b}: {kind}", kind)].append(f)
    # order: data, control, other, discovery, dns, elsewhere; within kind by first packet
    order = {"data": 0, "control": 1, "other": 2, "discovery": 3, "dns": 4, "elsewhere": 5}
    items = sorted(groups.items(), key=lambda kv: (order[kv[0][1]], min(f["t"] for f in kv[1])))
    # a row under 10 KB is a teardown or a probe, not a finding; off-LAN rows stay whatever their size
    return [(label, kind, fl) for (label, kind), fl in items
            if kind == "elsewhere" or sum(f["payload_ab"] + f["payload_ba"] for f in fl) >= 10_000]


def phase_strip(ax, tl, t0, t_end, x0, x1):
    """Phases as alternating shading with staggered labels above the axes."""
    if not tl:
        return
    for i, (t, ph) in enumerate(tl):
        t1 = tl[i + 1][0] if i + 1 < len(tl) else t0 + t_end
        a, b = max(t - t0, x0), min(t1 - t0, x1)
        if b <= a or ph == "done":
            continue
        if i % 2 == 0:
            ax.axvspan(a, b, color=SHADE, lw=0, zorder=0)
        ax.text(a + 0.004 * (x1 - x0), 1.01, ph, transform=ax.get_xaxis_transform(),
                fontsize=7.5, color=INK2, ha="left", va="bottom", rotation=45)


def fig_timeline(stack, stamp, r, tl, name=None, window=None):
    rows = flow_rows(stack, r)
    if not rows:
        return
    t0 = r["t0"]
    x0, x1 = (0.0, r["duration"]) if window is None else window
    fig, ax = plt.subplots(figsize=(9, 0.42 * len(rows) + 1.9))
    kind_col = {"data": STACK[stack], "control": INK2, "other": "#9b9a94", "discovery": "#9b9a94",
                "dns": "#9b9a94", "elsewhere": INK}
    for i, (label, kind, fl) in enumerate(rows):
        y = len(rows) - 1 - i
        col = kind_col[kind]
        for f in fl:
            a, b = f["t"], f["t"] + max(f["duration"], 0.004 * (x1 - x0))
            if b < x0 or a > x1:
                continue
            bytes_ = max(f["expected_ab"] + f["expected_ba"], f["payload_ab"] + f["payload_ba"], 1)
            lw = 2 + 1.4 * (len(str(bytes_)) - 1)
            ax.plot([max(a, x0), min(b, x1)], [y, y], color=col, lw=lw, solid_capstyle="butt", alpha=0.85, zorder=2)
            if kind == "data":
                if f.get("fin") is not None and x0 <= f["fin"] <= x1:
                    ax.plot([f["fin"]], [y], marker="|", color=INK, ms=12, mew=1.5, zorder=4)
                if f.get("rst") is not None and x0 <= f["rst"] <= x1:
                    ax.plot([f["rst"]], [y], marker="x", color=INK, ms=7, mew=1.5, zorder=4)
        tot = sum(max(f["expected_ab"] + f["expected_ba"], f["payload_ab"] + f["payload_ba"]) for f in fl)
        n = len(fl)
        ax.text(-0.01, y, f"{label}  ({n} conn, {tot/1e6:.1f} MB)" if n > 1 else f"{label}  ({tot/1e6:.2f} MB)",
                ha="right", va="center", fontsize=8.5, color=INK, transform=ax.get_yaxis_transform())
    phase_strip(ax, tl, t0, r["duration"], x0, x1)
    ax.set_yticks([])
    ax.set_ylim(-0.8, len(rows) - 0.2)
    ax.set_xlim(x0, x1)
    note = {"exo": "exo nodes speak IPv6 link-local (control) and IPv4 (data), so each node appears under two numbers",
            "llamacpp": "hosts of a restarted or second cluster are numbered (2), (3)",
            "localai": "hosts of the second cluster are numbered (2)"}.get(stack, "")
    ax.set_xlabel("seconds from the start of the capture; thickness ~ log bytes; on data rows | FIN, x RST" + ("\n" + note if note else ""))
    ax.set_title(f"{NAME.get(stack, stack)}, {stamp}" + ("" if window is None else ": around the kill"),
                 loc="left", fontsize=11, fontweight="bold", pad=34)
    ax.grid(axis="x", color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    handles = [Line2D([], [], color=STACK[stack], lw=4, label="data plane"), Line2D([], [], color=INK2, lw=4, label="control plane"),
               Line2D([], [], color="#9b9a94", lw=4, label="discovery, DNS, other"), Line2D([], [], color=INK, lw=4, label="off the LAN")]
    fig.legend(handles=handles, loc="lower center", ncol=4, frameon=False, fontsize=8, bbox_to_anchor=(0.5, 0.0))
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(f"{OUT}/{name or 'timeline-' + stack}.png", metadata=META)
    plt.close(fig)


def fig_nodeloss(stack, stamp, r, tl):
    """The timeline zoomed to 10 s before the kill phase and 120 s after it."""
    kill = next((t for t, ph in tl if ph == "kill"), None)
    if kill is None:
        return
    x0 = kill - r["t0"] - 10
    fig_timeline(stack, stamp, r, tl, name=f"nodeloss-{stack}", window=(x0, x0 + 130))


# ---------------------------------------------------------------- per-stack bars

def fig_detect(reps):
    for stack, d in reps.items():
        best = {}
        for stamp, (r, _) in d.items():
            for rule, t in r.get("first_match_s", {}).items():
                best[rule] = min(best.get(rule, t), t)
        if not best:
            continue
        rows = sorted(best.items(), key=lambda x: x[1])
        fig, ax = plt.subplots(figsize=(7, 0.5 * len(rows) + 1.4))
        for i, (rule, t) in enumerate(rows):
            y = len(rows) - 1 - i
            ax.barh(y, max(t, 0.05), color=STACK[stack], height=0.6)
            ax.text(max(t, 0.05) * 1.12, y, f"{t:.1f} s", va="center", fontsize=9, color=INK)
        ax.set_yticks(range(len(rows)))
        ax.set_yticklabels([f"`{r_}`".strip("`") for r_, _ in rows][::-1], fontsize=9, family="monospace")
        ax.set_xscale("log")
        ax.set_xlim(0.03, max(t for _, t in rows) * 4)
        ax.set_xlabel("seconds of capture before the rule first matched (log; earliest over the stack's captures)")
        ax.set_title(f"{NAME.get(stack, stack)}: time to first match", loc="left", fontsize=11, fontweight="bold")
        ax.grid(axis="x", color=GRID, lw=0.6); ax.set_axisbelow(True); ax.tick_params(length=0)
        fig.tight_layout()
        fig.savefig(f"{OUT}/detect-{stack}.png", metadata=META)
        plt.close(fig)


def fig_exchanges(reps):
    for stack, d in reps.items():
        hl = headline(reps, stack)
        if not hl:
            continue
        stamp, r, _ = hl
        rows_all = [f for f in r.get("flow_table", []) if f["flow"].split(" ")[0] in ("tcp", "udp")]
        nets = local_nets(rows_all)
        names = role_names(stack, rows_all, nets, r)
        rows, seen = [], set()
        for x in r.get("rhythm", []):
            for b in x.get("scales", []):
                if b.get("generation_like") and b["period_s"] < 5 and b.get("phase") in ("generate", "warm"):
                    k = (b["req_bytes"], b["resp_bytes"])
                    if k in seen:
                        continue
                    seen.add(k)
                    _, ha, pa, hb, pb = split_flow(x["flow"])
                    rows.append((f"{names.get(ha, ha)} ↔ {names.get(hb, hb)}", b))
        if not rows:
            continue
        fig, ax = plt.subplots(figsize=(8, 0.9 * len(rows) + 1.6))
        for i, (label, b) in enumerate(rows):
            y = len(rows) - 1 - i
            ax.barh(y + 0.2, b["req_bytes"], height=0.36, color=STACK[stack], alpha=0.5)
            ax.barh(y - 0.2, b["resp_bytes"], height=0.36, color=STACK[stack])
            ax.text(b["req_bytes"] * 1.15, y + 0.2, f"{b['req_bytes']:,} B to the server", va="center", fontsize=8.5, color=INK)
            ax.text(b["resp_bytes"] * 1.15, y - 0.2, f"{b['resp_bytes']:,} B back, every {b['period_s']*1000:.1f} ms", va="center", fontsize=8.5, color=INK)
        ax.set_yticks(range(len(rows)))
        ax.set_yticklabels([l for l, _ in rows][::-1], fontsize=9)
        ax.set_xscale("log")
        ax.set_xlim(500, 2e7)
        ax.set_xlabel("bytes per token-scale exchange (log); light = towards the server, dark = back")
        ax.set_title(f"{NAME.get(stack, stack)}: one exchange per token, {stamp}", loc="left", fontsize=11, fontweight="bold")
        ax.grid(axis="x", color=GRID, lw=0.6); ax.set_axisbelow(True); ax.tick_params(length=0)
        fig.tight_layout()
        fig.savefig(f"{OUT}/exchanges-{stack}.png", metadata=META)
        plt.close(fig)


# ---------------------------------------------------------------- cross-stack

def fig_periods(reps):
    """Rhythms found over the whole capture: per stack, the periods (s) with their autocorrelation score,
    from the host-pair rule (pairs with >= 10 flows) and per-flow periods of the control
    plane; one dot per (pair or flow, period)."""
    pts = []
    for stack in ("exo", "llamacpp", "localai", "background"):
        hl = headline(reps, stack)
        if not hl:
            continue
        stamp, r, _ = hl
        for p in r.get("pair_periods", []):
            if p["flows"] >= 10:
                for per, sc in p["periods"][:2]:
                    pts.append((stack, per, sc))
        for x in r.get("rhythm", []):
            if x["packets"] >= 100:
                for per, sc in x.get("periods", [])[:2]:
                    pts.append((stack, per, sc))
    if not pts:
        return
    stacks = [s for s in ("llamacpp", "exo", "localai", "background") if any(p[0] == s for p in pts)]
    fig, ax = plt.subplots(figsize=(9, 0.7 * len(stacks) + 1.6))
    for i, s in enumerate(stacks):
        y = len(stacks) - 1 - i
        xs = [per for st, per, sc in pts if st == s]
        ss = [sc for st, per, sc in pts if st == s]
        ax.scatter(xs, [y] * len(xs), s=[30 + 120 * sc for sc in ss], color=STACK[s], alpha=0.55, edgecolor="white", zorder=3)
    ax.set_yticks(range(len(stacks)))
    ax.set_yticklabels([NAME[s] for s in stacks][::-1])
    ax.set_xscale("log")
    ax.set_xlabel("period in seconds (log), over the whole capture; dot size ~ autocorrelation score\n"
                  "llama.cpp's are its request cadence (5.8 s) and the harness's, it has no rhythm of its own; the README's idle table has the per-phase reading")
    ax.set_title("Periodicities found per flow and per host pair, without reading payload", loc="left", fontsize=11, fontweight="bold")
    ax.grid(axis="x", color=GRID, lw=0.6); ax.set_axisbelow(True); ax.tick_params(length=0)
    fig.tight_layout()
    fig.savefig(f"{OUT}/periods.png", metadata=META)
    plt.close(fig)


def fig_offlan(reps):
    """Bytes to or from addresses outside the capture's own segments, per stack and phase."""
    rows = []
    for stack in ("llamacpp", "exo", "localai"):
        d = reps.get(stack, {})
        for stamp, (r, tl) in sorted(d.items()):
            if stack == "localai" and stamp not in (HEADLINE["localai"], EXTRA_TIMELINES["localai-dht"][1]):
                continue
            if stack != "localai" and stamp != HEADLINE.get(stack):
                continue
            fl = [f for f in r.get("flow_table", []) if f["flow"].split(" ")[0] in ("tcp", "udp")]
            nets = local_nets(fl)
            agg = defaultdict(lambda: [0, 0, set()])
            for f in fl:
                _, ha, _, hb, _ = split_flow(f["flow"])
                ca, cb = classify_host(ha, nets), classify_host(hb, nets)
                if "elsewhere" not in (ca, cb):
                    continue
                up, down = (f["bytes_ab"], f["bytes_ba"]) if ca == "local" else (f["bytes_ba"], f["bytes_ab"])
                g = agg[f.get("phase", "")]
                g[0] += up; g[1] += down; g[2].add(hb if ca == "local" else ha)
            label = NAME[stack] + (" (DHT on)" if stack == "localai" and stamp == EXTRA_TIMELINES["localai-dht"][1] else
                                   " (DHT off)" if stack == "localai" else "")
            for ph, (up, down, hosts) in agg.items():
                rows.append((stack, label, ph, up, down, len(hosts)))
    if not rows:
        return
    rows.sort(key=lambda x: (x[1], x[2]))
    fig, ax = plt.subplots(figsize=(9, 0.42 * len(rows) + 1.6))
    for i, (stack, label, ph, up, down, nh) in enumerate(rows):
        y = len(rows) - 1 - i
        ax.barh(y + 0.18, max(up, 1), height=0.34, color=STACK[stack], alpha=0.5)
        ax.barh(y - 0.18, max(down, 1), height=0.34, color=STACK[stack])
        ax.text(max(up, down, 1) * 1.2, y, f"{nh} remote host{'s' if nh != 1 else ''}", va="center", fontsize=8, color=INK2)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{l}: {ph or '-'}" for _, l, ph, *_ in rows][::-1], fontsize=8.5)
    ax.set_xscale("log")
    ax.set_xlim(100, 1e9)
    ax.set_xlabel("bytes to (light) and from (dark) addresses outside the LAN, per phase (log)")
    ax.set_title("What left the LAN", loc="left", fontsize=11, fontweight="bold")
    ax.grid(axis="x", color=GRID, lw=0.6); ax.set_axisbelow(True); ax.tick_params(length=0)
    fig.tight_layout()
    fig.savefig(f"{OUT}/offlan.png", metadata=META)
    plt.close(fig)


if __name__ == "__main__":
    reps = reports()
    for old in glob.glob(f"{OUT}/*.png"):
        os.remove(old)
    for stack in reps:
        hl = headline(reps, stack)
        if hl:
            fig_timeline(stack, *hl)
            fig_nodeloss(stack, *hl)
    for name, (stack, stamp) in EXTRA_TIMELINES.items():
        if stamp in reps.get(stack, {}):
            fig_timeline(stack, stamp, *reps[stack][stamp], name="timeline-" + name)
    fig_detect(reps)
    fig_exchanges(reps)
    fig_periods(reps)
    fig_offlan(reps)
    print("wrote", sorted(os.listdir(OUT)))
