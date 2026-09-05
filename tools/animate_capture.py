"""Animate the capture figure, one interval report at a time.

The same two logs plot_capture.py draws, played back in the order they were
printed. The sniffer reports every thirty seconds, so the lines step rather
than sweep: each frame is one report, and the readout under the chart is the
line that report actually printed.

    python tools/animate_capture.py clustered.log raw.log --out out.gif
    python tools/animate_capture.py clustered.log raw.log --theme dark \\
        --format mp4 --size 1920x1080 --out out.mp4

Axes are fixed to the finished run before the first frame, so the curves grow
against a scale that never moves. Only the counts are read, exactly as in
plot_capture.py: no addresses, no network names, nothing identifying.

Requires matplotlib. mp4 and webm need ffmpeg on PATH (or --ffmpeg); gif does
not. Frames are written to a temporary directory and removed afterwards.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from plot_capture import (  # noqa: E402
    DASHED,
    SOLID,
    THEMES,
    _size,
    align,
    describe,
    read,
)

# One frame per report. Long enough to read the readout before it changes,
# short enough that the whole fifteen minutes still plays in under twenty
# seconds.
STEP_SECONDS = 0.55
# The finished chart is the point of the thing, so let it rest before looping.
HOLD_SECONDS = 2.5


def readout(tick: dict) -> tuple[str, str]:
    """The two lines of terminal output for one report.

    The sniffer prints this on one line. It is split here because a single
    line of it does not stay legible once the figure is scaled down to a
    README or a page plate -- but every number is the one that was printed.
    """
    head = (f"[{tick['clock']}] devices in vicinity "
            f"(last {tick['window']}s): {tick['count']}")
    tail = (f"(universal={tick['universal']}, randomized={tick['randomized']}, "
            f"macs-seen={tick['seen']})  [unique-ever={tick['ever']}]")
    if tick["floor"]:
        tail += f"  at least {tick['floor']}"
    return head, tail


def build(clustered: dict, raw: dict, *, theme: str, size: tuple[int, int],
          dpi: int, title: str | None, caption: str):
    """Draw everything that never changes, and hand back what does.

    Mirrors plot_capture.render's geometry -- same margins, same type scale --
    with a band added under the axes for the readout.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator

    c = THEMES[theme]
    ct, rt = clustered["ticks"], raw["ticks"]
    end = max(ct[-1]["minute"], rt[-1]["minute"])
    window = clustered.get("window", ct[0]["window"])

    fig, ax = plt.subplots(1, 1, figsize=(size[0] / dpi, size[1] / dpi), dpi=dpi)
    fig.patch.set_facecolor(c["surface"])
    ax.set_facecolor(c["surface"])

    # -- the three series, empty for now --------------------------------------
    ever_line, = ax.plot([], [], color=c["raw"], lw=1.9, ls=SOLID,
                         label="Distinct addresses, cumulative", zorder=3)
    seen_line, = ax.plot([], [], color=c["raw"], lw=1.4, ls=DASHED,
                         label=f"Addresses in the {window}s window", zorder=3)
    dev_line, = ax.plot([], [], color=c["clustered"], lw=2.0, ls=SOLID,
                        label="Devices after clustering", zorder=4)

    # Fixed to the finished run: a scale that grew with the data would make
    # every curve look flat, which is the opposite of what the figure says.
    ax.set_xlim(0, end)
    ax.set_ylim(0, max(t["ever"] for t in rt) / 0.80)
    ax.set_xlabel("Minutes", color=c["muted"], fontsize=9, labelpad=4)
    ax.set_ylabel("Count", color=c["muted"], fontsize=9)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(c["spine"][0])
        ax.spines[spine].set_alpha(c["spine"][1])
    ax.yaxis.set_major_locator(MaxNLocator(integer=True, nbins=6))
    ax.xaxis.set_major_locator(MaxNLocator(integer=True, nbins=8))
    ax.tick_params(colors=c["muted"], labelsize=8.5, length=3)
    ax.grid(axis="y", color=c["grid"][0], alpha=c["grid"][1], lw=0.8)
    ax.set_axisbelow(True)
    legend = ax.legend(loc="upper left", frameon=False, fontsize=8.5,
                       handlelength=2.4, borderpad=0, labelspacing=0.35)
    for text in legend.get_texts():
        text.set_color(c["mid"])

    # -- labels that ride the tip of each curve -------------------------------
    ever_tag = ax.text(0, 0, "", color=c["raw"], fontsize=9.5,
                       fontweight="bold", va="center", clip_on=False, zorder=5)
    dev_tag = ax.text(0, 0, "", color=c["clustered"], fontsize=9.5,
                      fontweight="bold", va="center", clip_on=False, zorder=5)

    fig.text(0.035, 0.965, title or "Counting devices through MAC randomisation",
             color=c["ink"], fontsize=13.5, fontweight="bold", va="top")

    # -- caption strip, then the readout band above it ------------------------
    lines = textwrap.wrap(caption, max(60, int(size[0] / 10.2)))
    strip = (len(lines) * 7.6 * 1.5 + 26) / 72 * dpi / size[1]
    k = dpi / 160
    fig.text(0.035, strip, "\n".join(lines), color=c["muted"], fontsize=7.6,
             va="top", linespacing=1.5)

    mono = 8.4
    line_h = mono * 1.7 / 72 * dpi / size[1]
    band = 2 * line_h + 16 / 72 * dpi / size[1]
    head_text = fig.text(0.035, strip + band, "", color=c["ink"],
                         fontsize=mono, va="top", family="monospace")
    tail_text = fig.text(0.035, strip + band - line_h, "", color=c["muted"],
                         fontsize=mono, va="top", family="monospace")

    # The x label lives in this gap, so it has to clear the readout as well as
    # the tick row -- at 40px they end up on the same line.
    fig.subplots_adjust(left=max(0.055, 88 * k / size[0]),
                        right=1 - max(0.045, 72 * k / size[0]),
                        top=1 - max(0.10, 132 * k / size[1]),
                        bottom=strip + band + max(0.105, 92 * k / size[1]))

    return fig, {
        "ever": ever_line, "seen": seen_line, "dev": dev_line,
        "ever_tag": ever_tag, "dev_tag": dev_tag,
        "head": head_text, "tail": tail_text,
    }


def frames(clustered: dict, raw: dict, out_dir: Path, *, theme: str,
           size: tuple[int, int], dpi: int, title: str | None,
           caption: str, hold: int) -> int:
    """Write one PNG per report, plus `hold` copies of the finished chart."""
    c = THEMES[theme]
    fig, art = build(clustered, raw, theme=theme, size=size, dpi=dpi,
                     title=title, caption=caption)
    ct, rt = clustered["ticks"], raw["ticks"]
    mc = [t["minute"] for t in ct]
    mr = [t["minute"] for t in rt]

    n = 0
    for i in range(len(ct)):
        art["ever"].set_data(mr[:i + 1], [t["ever"] for t in rt[:i + 1]])
        art["seen"].set_data(mr[:i + 1], [t["count"] for t in rt[:i + 1]])
        art["dev"].set_data(mc[:i + 1], [t["count"] for t in ct[:i + 1]])

        art["ever_tag"].set_position((mr[i], rt[i]["ever"]))
        art["ever_tag"].set_text(f" {rt[i]['ever']}")
        art["dev_tag"].set_position((mc[i], ct[i]["count"]))
        art["dev_tag"].set_text(f" {ct[i]['count']}")

        head, tail = readout(ct[i])
        art["head"].set_text(head)
        art["tail"].set_text(tail)

        fig.savefig(out_dir / f"f{n:04d}.png", facecolor=c["surface"])
        n += 1

    last = out_dir / f"f{n - 1:04d}.png"
    for _ in range(hold):
        shutil.copyfile(last, out_dir / f"f{n:04d}.png")
        n += 1

    import matplotlib.pyplot as plt
    plt.close(fig)
    return n


def encode(src: Path, out: Path, fmt: str, ffmpeg: str, rate: float) -> None:
    """Turn the frame sequence into one file."""
    pattern = str(src / "f%04d.png")
    out.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "gif":
        # One shared palette for the whole run, so the flat background does not
        # shift between frames. No dither: the figure is flat colour and areas
        # of it would otherwise crawl.
        palette = src / "palette.png"
        run([ffmpeg, "-y", "-v", "error", "-framerate", f"{rate}",
             "-i", pattern, "-vf", "palettegen=max_colors=64", str(palette)])
        run([ffmpeg, "-y", "-v", "error", "-framerate", f"{rate}",
             "-i", pattern, "-i", str(palette),
             "-lavfi", "paletteuse=dither=none", "-loop", "0", str(out)])
        return

    codec = {
        "mp4": ["-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20",
                "-preset", "slow", "-movflags", "+faststart"],
        "webm": ["-c:v", "libvpx-vp9", "-pix_fmt", "yuv420p", "-crf", "34",
                 "-b:v", "0", "-row-mt", "1"],
    }[fmt]
    # Held frames cost almost nothing once encoded, and a real frame rate keeps
    # browsers and phones from refusing to play it.
    run([ffmpeg, "-y", "-v", "error", "-framerate", f"{rate}", "-i", pattern,
         *codec, "-r", "30", str(out)])


def run(cmd: list[str]) -> None:
    done = subprocess.run(cmd, capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(f"{cmd[0]} failed:\n{done.stderr.strip()}")


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("clustered", type=Path)
    parser.add_argument("raw", type=Path)
    parser.add_argument("--out", type=Path,
                        default=here / "media" / "live-capture.gif")
    parser.add_argument("--format", choices=("gif", "mp4", "webm"), default=None,
                        help="default: from the --out suffix")
    parser.add_argument("--theme", choices=sorted(THEMES), default="light")
    parser.add_argument("--size", type=_size, default=(1200, 675))
    parser.add_argument("--title", default=None)
    parser.add_argument("--caption", default=None)
    parser.add_argument("--plan", default=None)
    parser.add_argument("--step", type=float, default=STEP_SECONDS,
                        help=f"seconds per report (default: {STEP_SECONDS})")
    parser.add_argument("--hold", type=float, default=HOLD_SECONDS,
                        help=f"seconds on the finished chart (default: {HOLD_SECONDS})")
    parser.add_argument("--ffmpeg", default="ffmpeg")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    fmt = args.format or args.out.suffix.lstrip(".").lower()
    if fmt not in ("gif", "mp4", "webm"):
        raise SystemExit(f"cannot tell the format from {args.out.name}; pass --format")
    if fmt != "gif" and not shutil.which(args.ffmpeg):
        raise SystemExit(f"{fmt} needs ffmpeg; not found as {args.ffmpeg!r}")

    clustered, raw = read(args.clustered), read(args.raw)
    align(clustered, raw)
    caption = args.caption or describe(clustered, raw, args.plan)
    dpi = max(72, round(args.size[0] / 10))

    with tempfile.TemporaryDirectory(prefix="probe-anim-") as tmp:
        tmp_path = Path(tmp)
        n = frames(clustered, raw, tmp_path, theme=args.theme, size=args.size,
                   dpi=dpi, title=args.title, caption=caption,
                   hold=max(1, round(args.hold / args.step)))
        encode(tmp_path, args.out, fmt, args.ffmpeg, 1 / args.step)

    if not args.quiet:
        kb = args.out.stat().st_size / 1024
        print(f"wrote {args.out}  ({n} frames, {n * args.step:.1f}s, {kb:.0f} kB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
