"""Draw media/live-capture.png from a real fifteen-minute capture.

Takes the interval reports of two captures of the same air — one clustering,
one counting raw addresses (``--no-fingerprint``) — and plots what each one
reported over the run.

    python -m probe_sniffer --iface wlan1mon --interval 30 --window 300 \\
        > clustered.log 2>&1 &
    python -m probe_sniffer --iface wlan1mon --interval 30 --window 300 \\
        --no-fingerprint > raw.log 2>&1 &
    wait
    python tools/plot_capture.py clustered.log raw.log

Only the counts are read: no addresses, no network names, nothing that
identifies a device. Requires matplotlib.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

TICK = re.compile(
    r"^\[(\d\d:\d\d:\d\d)\] (?:devices|unique MACs) in vicinity \(last (\d+)s\): (\d+)"
    r"\s+\(universal=(\d+), randomized=(\d+), macs-seen=(\d+)\)\s+\[unique-ever=(\d+)\]"
)
CHANNELS = re.compile(r"covers (\d+) channels .* across (\d+) band\(s\)")
CROSSINGS = re.compile(r"crossing between them (\d+) times")


def read(path: Path) -> dict:
    ticks, meta = [], {}
    for line in path.read_text(errors="replace").splitlines():
        m = TICK.match(line)
        if m:
            clock, window, count, _uni, _rand, seen, ever = m.groups()
            ticks.append({
                "at": datetime.strptime(clock, "%H:%M:%S"),
                "window": int(window),
                "count": int(count),
                "seen": int(seen),
                "ever": int(ever),
            })
            continue
        m = CHANNELS.search(line)
        if m:
            meta["channels"], meta["bands"] = int(m.group(1)), int(m.group(2))
        m = CROSSINGS.search(line)
        if m:
            meta["crossings"] = int(m.group(1))
    if not ticks:
        raise SystemExit(f"no interval reports found in {path}")
    start = ticks[0]["at"]
    for t in ticks:
        t["minute"] = (t["at"] - start).total_seconds() / 60
    return {"ticks": ticks, **meta}


def render(clustered: dict, raw: dict, out_path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ink = "#1f2328"
    muted = "#6e7781"
    raw_colour = "#cf222e"
    clustered_colour = "#0969da"

    ct, rt = clustered["ticks"], raw["ticks"]
    minutes_c = [t["minute"] for t in ct]
    minutes_r = [t["minute"] for t in rt]

    fig, (top, bottom) = plt.subplots(
        2, 1, figsize=(9, 5.6), dpi=160, sharex=True,
        gridspec_kw={"height_ratios": [1.5, 1], "hspace": 0.18},
    )
    fig.patch.set_facecolor("white")

    # Top: addresses accumulating, which is what counting them raw gives you.
    top.plot(minutes_r, [t["ever"] for t in rt], color=raw_colour, lw=2.2,
             label="Distinct addresses seen")
    top.set_ylim(0, max(t["ever"] for t in rt) * 1.15)
    top.set_ylabel("Addresses", color=muted, fontsize=10)

    # Bottom: what the tool reports, on the scale a person cares about.
    window = ct[0]["window"]
    bottom.plot(minutes_c, [t["count"] for t in ct], color=clustered_colour, lw=2.4,
                label=f"Devices counted (last {window}s)")
    bottom.plot(minutes_r, [t["count"] for t in rt], color=raw_colour, lw=1.5,
                ls=(0, (5, 3)), label=f"Raw addresses (last {window}s)")
    bottom.set_ylim(0, max(t["count"] for t in rt) * 1.55)
    bottom.set_ylabel("Devices", color=muted, fontsize=10)
    bottom.set_xlabel("Minutes", color=muted, fontsize=10)

    end = max(minutes_r[-1], minutes_c[-1])
    for ax, value, colour in (
        (top, rt[-1]["ever"], raw_colour),
        (bottom, ct[-1]["count"], clustered_colour),
    ):
        ax.annotate(f" {value}", xy=(end, value), color=colour, fontsize=11,
                    fontweight="bold", va="center", annotation_clip=False)

    for ax in (top, bottom):
        ax.set_facecolor("white")
        ax.set_xlim(0, end)
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        for spine in ("left", "bottom"):
            ax.spines[spine].set_color("#d0d7de")
        ax.tick_params(colors=muted, labelsize=9)
        ax.grid(axis="y", color="#eaeef2", lw=0.8)
        ax.set_axisbelow(True)
        legend = ax.legend(loc="upper left", frameon=False, fontsize=9.5)
        for text in legend.get_texts():
            text.set_color(ink)

    top.set_title(
        "Fifteen minutes of one room, counted two ways",
        color=ink, fontsize=13, fontweight="bold", loc="left", pad=14,
    )

    fig.subplots_adjust(left=0.09, right=0.94, top=0.90, bottom=0.10)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, facecolor="white")
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("clustered", type=Path, help="log of the clustering capture")
    parser.add_argument("raw", type=Path, help="log of the --no-fingerprint capture")
    parser.add_argument("--out", type=Path, default=here / "media" / "live-capture.png")
    args = parser.parse_args(argv)

    clustered, raw = read(args.clustered), read(args.raw)
    print(
        f"clustered: {len(clustered['ticks'])} reports, "
        f"{clustered['ticks'][-1]['count']} devices at the end, "
        f"{clustered['ticks'][-1]['ever']} ever\n"
        f"raw:       {len(raw['ticks'])} reports, "
        f"{raw['ticks'][-1]['count']} addresses at the end, "
        f"{raw['ticks'][-1]['ever']} ever\n"
        f"capture:   {clustered.get('channels', '?')} channels, "
        f"{clustered.get('bands', '?')} band(s), "
        f"{clustered.get('crossings', 0)} crossings"
    )

    render(clustered, raw, args.out)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
