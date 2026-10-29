"""Figures from the committed per-capture reports (captures/<stack>/<stamp>.report.json,
written by `analysis/classify.py --json`) and their timelines. The pcaps are not needed.

    python3 figures.py            # writes figures/*.png

One hue per stack (STYLE.md §4); phases in neutral greys. savefig drops the Software
tag so a rerun reproduces the committed files byte for byte with the pinned matplotlib.
"""

from __future__ import annotations

import csv
import glob
import ipaddress
import json
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

OUT = "figures"
os.makedirs(OUT, exist_ok=True)
# the capture each stack's timeline is drawn from (the full run of each), and extra
# timelines worth their own figure
HEADLINE = {"llamacpp": "20261027-150104", "exo": "20261028-125140", "localai": "20261029-144115",
            "background": "20261028-081447"}
EXTRA_TIMELINES = {"localai-dht": ("localai", "20261029-151923")}
STACK = {"exo": "#2a78d6", "llamacpp": "#1baf7a", "localai": "#eda100", "background": "#52514e"}
NAME = {"exo": "exo", "llamacpp": "llama.cpp RPC", "localai": "LocalAI P2P", "background": "background"}
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e6e5e1"
PHASE_SHADE = {"load": 0.18, "generate": 0.10, "generate-long": 0.14, "kill": 0.22, "pause": 0.22,
               "cut": 0.22, "recover": 0.10, "place": 0.14, "start": 0.10}
META = {"Software": None}

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2,
    "ytick.color": INK2, "axes.titlecolor": INK, "axes.spines.top": False, "axes.spines.right": False,
    "figure.facecolor": "white", "axes.facecolor": "white", "savefig.dpi": 160,
})


def reports():
    """{stack: [(stamp, report, timeline rows)]}, newest capture first per stack."""
    out = defaultdict(list)
    for path in sorted(glob.glob("captures/*/*.report.json"), reverse=True):
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
                            tl.append((float(row[0]), row[1], row[2] if len(row) > 2 else ""))
                        except ValueError:
                            pass
        out[stack].append((stamp, r, sorted(tl)))
    return out


def shade_phases(ax, tl, t0, t_end):
    """Grey bands for the phases, labelled at the top."""
    if not tl:
        return
    for i, (t, ph, _) in enumerate(tl):
        t1 = tl[i + 1][0] if i + 1 < len(tl) else t0 + t_end
        a = PHASE_SHADE.get(ph, 0.0)
        if a:
            ax.axvspan(t - t0, t1 - t0, color=INK2, alpha=a, lw=0, zorder=0)
        if ph != "done":
            ax.text(t - t0, 1.0, ph, transform=ax.get_xaxis_transform(), fontsize=7, color=INK2,
                    ha="left", va="bottom", rotation=0)


def _groups(rows):
    """Group flows by (proto, host pair, service port): the port that repeats across the
    pair's flows, else the lower one. Returns {label: [flows]} in order of first packet."""
    from collections import Counter

    # "local" is the capture's own segment: the /24s (IPv4) and /64s (IPv6) that hold at
    # least 5% of the flow endpoints, plus link-local and multicast. Everything else folds
    # into one "elsewhere" row per local host: a DHT talks to thousands of peers, and
    # advertises their private LAN addresses too, which get dialled (LocalAI, DHT on)
    nets = Counter()
    ends = []
    for f in rows:
        _, rest = f["flow"].split(" ", 1)
        for e in rest.split(" <-> "):
            h = e.rsplit(":", 1)[0].strip("[]")
            try:
                ip = ipaddress.ip_address(h)
            except ValueError:
                continue
            net = ipaddress.ip_network(f"{h}/24" if ip.version == 4 else f"{h}/64", strict=False)
            nets[net] += 1
            ends.append((h, ip, net))
    total = sum(nets.values()) or 1
    local_nets = {n for n, c in nets.items() if c / total >= 0.05}

    def pub(h):
        try:
            ip = ipaddress.ip_address(h.strip("[]"))
        except ValueError:
            return h
        if ip.is_multicast or ip.is_loopback or ip.is_unspecified or (ip.version == 6 and ip.is_link_local):
            return h
        net = ipaddress.ip_network(f"{ip}/24" if ip.version == 4 else f"{ip}/64", strict=False)
        return h if net in local_nets else "public"

    pairs = defaultdict(list)
    for f in rows:
        proto, rest = f["flow"].split(" ", 1)
        a, b = rest.split(" <-> ")
        ha, pa = a.rsplit(":", 1); hb, pb = b.rsplit(":", 1)
        ha, hb = pub(ha), pub(hb)
        pairs[(proto, min(ha, hb), max(ha, hb))].append((f, ha, int(pa), hb, int(pb)))
    out = {}
    for (proto, h1, h2), lst in pairs.items():
        cnt = Counter()
        for _, ha, pa, hb, pb in lst:
            cnt[(ha, pa)] += 1; cnt[(hb, pb)] += 1
        for f, ha, pa, hb, pb in lst:
            srv = (ha, pa) if (cnt[(ha, pa)], -pa) > (cnt[(hb, pb)], -pb) else (hb, pb)
            cli = hb if srv[0] == ha else ha
            port = srv[1] if "public" not in (ha, hb) else (pa if ha == "public" else pb)
            # QUIC picks a fresh pair of ports per dial, so UDP between two LAN hosts on
            # unregistered ports folds into one row for the pair
            sp = srv[1] if not (proto == "udp" and srv[1] >= 1024 and srv[1] not in (4001, 5004, 9000)) else "*"
            key = f"{proto} {cli} -> {srv[0]}:{sp}" if "public" not in (ha, hb) else \
                  f"{proto} {ha if hb == 'public' else hb} -> elsewhere:{port if port in (4001, 443) else 'other'}"
            out.setdefault(key, []).append(f)
    return dict(sorted(out.items(), key=lambda kv: min(f["t"] for f in kv[1])))


def fig_timeline(stack, stamp, r, tl, name=None):
    """What the wire shows: flows with payload, one row per (client, server:port), each
    connection a bar over capture time with thickness by bytes (log); the stack's own
    ports in its hue, the rest grey."""
    rows = [f for f in r.get("flow_table", []) if (f["payload_ab"] + f["payload_ba"]) > 0
            and f["flow"].split(" ")[0] in ("tcp", "udp")]
    groups = _groups(rows)
    if not groups:
        return
    fig, ax = plt.subplots(figsize=(9, max(3.0, 0.28 * len(groups) + 1.6)))
    own_ports = {"llamacpp": {50052}, "exo": {52413, 52414, 52415}, "localai": set()}.get(stack, set())
    for i, (label, fl) in enumerate(groups.items()):
        y = len(groups) - 1 - i
        try:
            port = int(label.rsplit(":", 1)[1])
        except ValueError:
            port = 0
        own = port in own_ports
        if stack == "localai" and label.startswith("udp") and label.endswith(":*") and "elsewhere" not in label \
                and not any(m in label for m in ("224.", "239.", "ff02")):
            own = True                # the QUIC tunnels between LocalAI nodes
        col = STACK[stack] if own else INK2
        for f in fl:
            b = max(f["expected_ab"] + f["expected_ba"], f["payload_ab"] + f["payload_ba"], 1)
            lw = 1 + 1.3 * (len(str(b)) - 1)
            ax.plot([f["t"], f["t"] + max(f["duration"], 0.4)], [y, y], color=col, lw=lw, solid_capstyle="butt", alpha=0.8)
            if f.get("fin") is not None:
                ax.plot([f["fin"]], [y], marker="|", color=INK, ms=8, zorder=4)
            if f.get("rst") is not None:
                ax.plot([f["rst"]], [y], marker="x", color=INK, ms=5, zorder=4)
        tot = sum(max(f["expected_ab"] + f["expected_ba"], f["payload_ab"] + f["payload_ba"]) for f in fl)
        ax.text(-0.01, y, f"{label}  ({len(fl)} conn, {tot/1e6:.1f} MB)" if len(fl) > 1 else f"{label}  ({tot/1e6:.2f} MB)",
                ha="right", va="center", fontsize=7, color=INK2, transform=ax.get_yaxis_transform())
    shade_phases(ax, tl, r["t0"], r["duration"])
    ax.set_yticks([])
    ax.set_ylim(-1, len(groups))
    ax.set_xlim(0, r["duration"])
    ax.set_xlabel("seconds from the start of the capture; bar thickness ~ log bytes; | FIN, x RST")
    ax.set_title(f"{NAME.get(stack, stack)}: flows with payload, {stamp}", loc="left", fontsize=11, fontweight="bold")
    ax.grid(axis="x", color=GRID, lw=0.6)
    fig.tight_layout()
    fig.savefig(f"{OUT}/timeline-{name or stack}.png", metadata=META)
    plt.close(fig)


def fig_detect(reps):
    """Seconds of capture before each rule's first match, per stack (newest capture)."""
    best = {}
    for stack, lst in reps.items():
        for stamp, r, _ in lst:
            for rule, t in r.get("first_match_s", {}).items():
                k = (stack, rule)
                best[k] = min(best.get(k, t), t)
    rows = [(s_, r_, t) for (s_, r_), t in best.items()]
    if not rows:
        return
    rows.sort(key=lambda x: (x[0], x[2]))
    fig, ax = plt.subplots(figsize=(9, 0.35 * len(rows) + 1.5))
    for i, (stack, rule, t) in enumerate(rows):
        y = len(rows) - 1 - i
        ax.barh(y, max(t, 0.05), color=STACK.get(stack, INK2), height=0.6)
        ax.text(max(t, 0.05) * 1.1, y, f"{t:.2f} s", va="center", fontsize=8, color=INK)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{NAME.get(s, s)}: {r}" for s, r, _ in rows][::-1], fontsize=8)
    ax.set_xscale("log")
    ax.set_xlabel("seconds of capture before the rule first matched (log)")
    ax.set_title("Time to first match, per rule", loc="left", fontsize=11, fontweight="bold")
    ax.grid(axis="x", color=GRID, lw=0.6); ax.set_axisbelow(True); ax.tick_params(length=0)
    fig.tight_layout()
    fig.savefig(f"{OUT}/detect.png", metadata=META)
    plt.close(fig)


def fig_exchanges(reps):
    """Bytes per exchange at the token scale, each direction, for every generation-like flow."""
    rows, seen = [], set()
    for stack, lst in reps.items():
        for stamp, r, _ in lst:
            for x in r.get("rhythm", []):
                for b in x.get("scales", []):
                    # one row per distinct (stack, sizes) signature in the generate phase
                    if b.get("generation_like") and b["period_s"] < 5 and b.get("phase") in ("generate", "warm"):
                        k = (stack, b["req_bytes"], b["resp_bytes"])
                        if k in seen:
                            continue
                        seen.add(k)
                        rows.append((stack, x["flow"].split(" ", 1)[1], b))
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(9, 0.5 * len(rows) + 1.6))
    for i, (stack, flow, b) in enumerate(rows):
        y = len(rows) - 1 - i
        ax.barh(y + 0.18, b["req_bytes"], height=0.32, color=STACK.get(stack, INK2), alpha=0.55)
        ax.barh(y - 0.18, b["resp_bytes"], height=0.32, color=STACK.get(stack, INK2))
        ax.text(max(b["req_bytes"], 1) * 1.15, y + 0.18, f"{b['req_bytes']:,} B in", va="center", fontsize=7, color=INK)
        ax.text(max(b["resp_bytes"], 1) * 1.15, y - 0.18, f"{b['resp_bytes']:,} B out, every {b['period_s']*1000:.1f} ms", va="center", fontsize=7, color=INK)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{NAME.get(s, s)}: {f}" for s, f, _ in rows][::-1], fontsize=7)
    ax.set_xscale("log")
    ax.set_xlabel("bytes per exchange at the token scale (log); light = towards the server, dark = back")
    ax.set_title("Generation on the wire: one exchange per token", loc="left", fontsize=11, fontweight="bold")
    ax.grid(axis="x", color=GRID, lw=0.6); ax.set_axisbelow(True); ax.tick_params(length=0)
    fig.tight_layout()
    fig.savefig(f"{OUT}/exchanges.png", metadata=META)
    plt.close(fig)


if __name__ == "__main__":
    reps = reports()
    for stack, lst in reps.items():
        want = HEADLINE.get(stack)
        pick = next(((st_, r_, tl_) for st_, r_, tl_ in lst if st_ == want), lst[0])
        fig_timeline(stack, *pick)
    for name, (stack, stamp) in EXTRA_TIMELINES.items():
        for st_, r_, tl_ in reps.get(stack, []):
            if st_ == stamp:
                fig_timeline(stack, st_, r_, tl_, name=name)
    fig_detect(reps)
    fig_exchanges(reps)
    print("wrote", sorted(os.listdir(OUT)))
