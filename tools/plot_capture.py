"""Draw the capture figure from a real fifteen-minute run.

Takes the interval reports of two captures of the same air — one clustering,
one counting raw addresses (``--no-fingerprint``) — and plots what each one
reported over the run. tools/capture/live-capture.sh produces the logs and
calls this; run it by hand to redraw a figure from logs you already have.

    python tools/plot_capture.py clustered.log raw.log --out media/live-capture.png
    python tools/plot_capture.py clustered.log raw.log --theme dark \\
        --out media/live-capture-dark.png

Only the counts are read: no addresses, no network names, nothing that
identifies a device. Requires matplotlib.

The default canvas is 2400x1350. Type is sized against the canvas, so any
--size keeps the same proportions.
"""

from __future__ import annotations

import argparse
import re
import sys
import textwrap
from datetime import datetime, timedelta
from pathlib import Path

TICK = re.compile(
    r"^\[(\d\d:\d\d:\d\d)\] (?:devices|unique MACs) in vicinity \(last (\d+)s\): (\d+)"
    r"\s+\(universal=(\d+), randomized=(\d+), macs-seen=(\d+)\)\s+\[unique-ever=(\d+)\]"
    r"(?:\s+at least (\d+):)?"
)
CHANNELS = re.compile(r"covers (\d+) channels .* across (\d+) band\(s\)")
CROSSINGS = re.compile(r"crossing between them (\d+) times")
STARTED = re.compile(r"window=(\d+)s, interval=(\d+)s")

# ---------------------------------------------------------------- palettes --
#
# Light is the README theme, using GitHub's red/blue pair so the figure sits
# on a white page without clashing. Dark is the same figure for a dark page,
# with the hues lightened to stay legible on a near-black surface.
#
# Neither palette relies on hue alone to tell the two series apart: each line
# also carries its own dash pattern and an end label, which is what keeps the
# figure readable in greyscale and to a colour-blind reader.
THEMES = {
    "light": {
        "surface": "#ffffff",
        "ink": "#1f2328",
        "mid": "#424a53",
        "muted": "#6e7781",
        "grid": ("#eaeef2", 1.0),
        "spine": ("#d0d7de", 1.0),
        "raw": "#cf222e",
        "clustered": "#0969da",
        "truth": "#57606a",
    },
    "dark": {
        "surface": "#020204",
        "ink": "#f4f5f8",
        "mid": "#b5b7bb",
        "muted": "#84868b",
        "grid": ("#ffffff", 0.07),
        "spine": ("#ffffff", 0.14),
        "raw": "#dcbb50",
        "clustered": "#40d1f7",
        "truth": "#9fa1a6",
    },
}

SOLID = (0, ())
DASHED = (0, (5, 3))
DOTTED = (0, (1, 2.5))


def read(path: Path) -> dict:
    """Pull the interval reports and the shutdown note out of one log."""
    ticks, meta = [], {"floor": 0}
    for line in path.read_text(errors="replace").splitlines():
        m = TICK.match(line)
        if m:
            clock, window, count, uni, rand, seen, ever, floor = m.groups()
            ticks.append({
                "at": datetime.strptime(clock, "%H:%M:%S"),
                "clock": clock,
                "window": int(window),
                "count": int(count),
                "universal": int(uni),
                "randomized": int(rand),
                "seen": int(seen),
                "ever": int(ever),
                "floor": int(floor) if floor else None,
            })
            if floor:
                meta["floor"] = max(meta["floor"], int(floor))
            continue
        m = CHANNELS.search(line)
        if m:
            meta["channels"], meta["bands"] = int(m.group(1)), int(m.group(2))
        m = CROSSINGS.search(line)
        if m:
            meta["crossings"] = int(m.group(1))
        m = STARTED.search(line)
        if m:
            meta["window"], meta["interval"] = int(m.group(1)), int(m.group(2))
    if not ticks:
        raise SystemExit(f"no interval reports found in {path}")

    # A run that crosses midnight would otherwise step backwards: the clock in
    # the report has no date on it.
    day = timedelta(0)
    previous = ticks[0]["at"]
    for t in ticks:
        if t["at"] + day < previous:
            day += timedelta(days=1)
        t["at"] += day
        previous = t["at"]
    return {"ticks": ticks, **meta}


def align(*runs: dict) -> None:
    """Put every run on one clock, so both runs share an x axis."""
    origin = min(r["ticks"][0]["at"] for r in runs)
    for r in runs:
        for t in r["ticks"]:
            t["minute"] = (t["at"] - origin).total_seconds() / 60


def describe(clustered: dict, raw: dict, plan: str | None) -> str:
    """The caption strip: what the run was, and nothing more.

    Deliberately bare. Anything that qualifies the numbers -- band crossings,
    the overlap floor, the window length -- belongs in the prose around the
    figure, not under it. Pass --caption to say something else entirely.
    """
    ct, rt = clustered["ticks"], raw["ticks"]
    interval = clustered.get("interval", 30)
    # The first report lands one interval in, so the last one is one interval
    # short of the wall-clock length of the run.
    minutes = round((max(ct[-1]["minute"], rt[-1]["minute"]) * 60 + interval) / 60)

    opening = f"Real capture: {minutes} minutes of one room"
    if plan:
        opening += f", {plan}"
    return opening + "."


def render(clustered: dict, raw: dict, out_path: Path, *, theme: str = "light",
           size: tuple[int, int] = (2400, 1350), dpi: int | None = None,
           title: str | None = None, caption: str | None = None,
           headcount: int | None = None) -> None:
    import matplotlib

    # Type is set in points, so a fixed dpi would shrink it relative to a
    # bigger canvas, and shrink it again wherever the figure is displayed
    # scaled down. Holding the figure at a constant 10in wide instead makes
    # every label keep its proportion at any --size.
    if dpi is None:
        dpi = max(72, round(size[0] / 10))

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator

    c = THEMES[theme]
    ct, rt = clustered["ticks"], raw["ticks"]
    mc = [t["minute"] for t in ct]
    mr = [t["minute"] for t in rt]
    end = max(mc[-1], mr[-1])
    window = clustered.get("window", ct[0]["window"])

    fig, ax = plt.subplots(
        1, 1, figsize=(size[0] / dpi, size[1] / dpi), dpi=dpi,
    )
    fig.patch.set_facecolor(c["surface"])

    # -- what counting addresses raw gives you, against the clustered count --
    ax.plot(mr, [t["ever"] for t in rt], color=c["raw"], lw=1.9, ls=SOLID,
            label="Distinct addresses, cumulative", zorder=3)
    ax.plot(mr, [t["count"] for t in rt], color=c["raw"], lw=1.4, ls=DASHED,
            label=f"Addresses in the {window}s window", zorder=3)
    ax.plot(mc, [t["count"] for t in ct], color=c["clustered"], lw=2.0,
            ls=SOLID, label="Devices after clustering", zorder=4)
    # A known headcount, when one was measured, is the only ground truth the
    # figure can carry. It shares this axis with the cumulative curve, so it
    # sits low on the plot -- readable, but not the focus.
    if headcount:
        ax.plot([0, end], [headcount, headcount], color=c["truth"], lw=1.4,
                ls=DOTTED, label="People actually present", zorder=2)
    # The legend rows sit over the plot, so leave them room rather than
    # letting the topmost series run underneath the text.
    ax.set_ylim(0, max(t["ever"] for t in rt) / (0.74 if headcount else 0.80))

    # -- end labels: identity without relying on hue ------------------------
    for value, colour in ((rt[-1]["ever"], c["raw"]),
                          (ct[-1]["count"], c["clustered"])):
        ax.annotate(f" {value}", xy=(end, value), color=colour, fontsize=9.5,
                    fontweight="bold", va="center", annotation_clip=False,
                    zorder=5)

    ax.set_facecolor(c["surface"])
    ax.set_xlim(0, end)
    ax.set_xlabel("Minutes", color=c["muted"], fontsize=9, labelpad=4)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        # Colour and alpha are set separately: an alpha carried inside an
        # RGBA tuple is silently overridden by the grid.alpha rcParam, which
        # turns a 7%-white hairline into a solid white rule.
        ax.spines[spine].set_color(c["spine"][0])
        ax.spines[spine].set_alpha(c["spine"][1])
    # Devices and addresses are whole things; a "12.5 devices" gridline is
    # nonsense, and small counts make matplotlib reach for one by default.
    ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=6))
    ax.xaxis.set_major_locator(MaxNLocator(integer=True, nbins=8))
    ax.tick_params(colors=c["muted"], labelsize=8.5, length=3)
    ax.grid(axis="y", color=c["grid"][0], alpha=c["grid"][1], lw=0.8)
    ax.set_axisbelow(True)
    legend = ax.legend(loc="upper left", frameon=False, fontsize=8.5,
                       handlelength=2.4, borderpad=0, labelspacing=0.35)
    for text in legend.get_texts():
        text.set_color(c["mid"])

    ax.set_ylabel("Count", color=c["muted"], fontsize=9)

    fig.text(0.035, 0.965, title or "Counting devices through MAC randomisation",
             color=c["ink"], fontsize=13.5, fontweight="bold", va="top")

    # Wrapped by hand: matplotlib's own wrap ignores the space actually
    # reserved below the axes, and silently runs the tail off the canvas.
    text = caption or describe(clustered, raw, None)
    width = max(60, int(size[0] / 10.2))
    lines = textwrap.wrap(text, width)
    # A narrower canvas wraps to more lines in less height, so the strip has to
    # be measured rather than assumed: 7.6pt at 1.5 linespacing, plus padding.
    strip = (len(lines) * 7.6 * 1.5 + 26) / 72 * dpi / size[1]
    k = dpi / 160                       # the budgets below were measured at 160
    fig.text(0.035, strip, "\n".join(lines),
             color=c["muted"], fontsize=7.6, va="top", linespacing=1.5)

    # Margins are fractions, so a narrower --size would otherwise crop the y
    # label, the end labels or the caption. Give each a pixel budget instead.
    fig.subplots_adjust(left=max(0.055, 88 * k / size[0]),
                        right=1 - max(0.045, 72 * k / size[0]),
                        top=1 - max(0.10, 132 * k / size[1]),
                        bottom=strip + max(0.09, 62 * k / size[1]))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, facecolor=c["surface"])
    plt.close(fig)


def _size(text: str) -> tuple[int, int]:
    try:
        w, h = (int(part) for part in text.lower().split("x"))
    except ValueError:
        raise argparse.ArgumentTypeError("size must look like 2400x1350") from None
    return w, h


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("clustered", type=Path, help="log of the clustering capture")
    parser.add_argument("raw", type=Path, help="log of the --no-fingerprint capture")
    parser.add_argument("--out", type=Path, default=here / "media" / "live-capture.png")
    parser.add_argument("--theme", choices=sorted(THEMES), default="light")
    parser.add_argument("--size", type=_size, default=(2400, 1350),
                        help="pixels, WIDTHxHEIGHT (default: 2400x1350)")
    parser.add_argument("--title", default=None)
    parser.add_argument("--caption", default=None,
                        help="override the generated caption strip")
    parser.add_argument("--plan", default=None,
                        help="one phrase for the caption, e.g. 'pinned to channel 6'")
    parser.add_argument("--headcount", type=int, default=None,
                        help="people actually in the room, drawn as a reference line")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    clustered, raw = read(args.clustered), read(args.raw)
    align(clustered, raw)
    caption = args.caption or describe(clustered, raw, args.plan)

    if not args.quiet:
        print(
            f"clustered: {len(clustered['ticks'])} reports, "
            f"{clustered['ticks'][-1]['count']} devices at the end, "
            f"{clustered['ticks'][-1]['ever']} ever\n"
            f"raw:       {len(raw['ticks'])} reports, "
            f"{raw['ticks'][-1]['count']} addresses at the end, "
            f"{raw['ticks'][-1]['ever']} ever\n"
            f"capture:   {clustered.get('channels', 1)} channel(s), "
            f"{clustered.get('bands', 1)} band(s), "
            f"{clustered.get('crossings', 0)} crossings"
        )

    render(clustered, raw, args.out, theme=args.theme, size=args.size,
           title=args.title, caption=caption, headcount=args.headcount)
    if not args.quiet:
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
