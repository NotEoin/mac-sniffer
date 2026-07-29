"""CLI frontend.

Usage:
    sudo python -m probe_sniffer --iface wlan1mon
    sudo python -m probe_sniffer --iface wlan1mon --backend pyshark
    sudo python -m probe_sniffer --iface wlan1mon --no-fingerprint \\
                                 --window 600 --interval 30
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from datetime import datetime

from .backends.base import ProbeEvent, SnifferBackend
from .tracker import DeviceTracker


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="probe-sniffer",
        description=(
            "Count nearby devices by passively sniffing 802.11 probe requests. "
            "Interface MUST already be in monitor mode (see setup.sh)."
        ),
    )
    p.add_argument(
        "--iface", "-i", required=True,
        help="monitor-mode interface, e.g. wlan1mon",
    )
    p.add_argument(
        "--backend", "-b", choices=("scapy", "pyshark"), default="scapy",
        help="sniffing backend (default: scapy)",
    )
    p.add_argument(
        "--interval", type=int, default=30, metavar="SECONDS",
        help="how often to print the device count (default: 30)",
    )
    p.add_argument(
        "--window", type=int, default=300, metavar="SECONDS",
        help="sliding window for 'in vicinity' (default: 300 = 5 min)",
    )
    p.add_argument(
        "--no-fingerprint", dest="fingerprint", action="store_false",
        help=(
            "disable IE-fingerprint clustering. By default randomized MACs "
            "are grouped by probe-request fingerprint so one phone rotating "
            "addresses counts as one device. Disable to count raw unique MACs."
        ),
    )
    p.add_argument(
        "--exclude-randomized", dest="include_randomized", action="store_false",
        help=(
            "drop locally-administered (likely randomized) MACs entirely "
            "rather than clustering them. Useful for cross-checking."
        ),
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="print each probe-request observation as it arrives",
    )
    p.set_defaults(fingerprint=True, include_randomized=True)
    return p


def _build_backend(name: str, iface: str, on_event) -> SnifferBackend:
    if name == "scapy":
        from .backends.scapy_backend import ScapyBackend
        return ScapyBackend(iface=iface, on_event=on_event)
    if name == "pyshark":
        from .backends.pyshark_backend import PysharkBackend
        return PysharkBackend(iface=iface, on_event=on_event)
    raise ValueError(f"unknown backend: {name}")


def _warn_if_not_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "warning: not running as root. Live capture on a monitor-mode "
            "interface usually requires root (or CAP_NET_RAW + CAP_NET_ADMIN).",
            file=sys.stderr,
        )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _warn_if_not_root()

    tracker = DeviceTracker(
        window_seconds=args.window,
        include_randomized=args.include_randomized,
        cluster_by_fingerprint=args.fingerprint,
    )

    def on_event(ev: ProbeEvent) -> None:
        tracker.observe(
            ev.mac,
            ssid=ev.ssid,
            rssi=ev.rssi,
            ts=ev.ts,
            fingerprint=ev.fingerprint,
        )
        if args.verbose:
            ssid = f" ssid={ev.ssid!r}" if ev.ssid else ""
            rssi = f" rssi={ev.rssi}dBm" if ev.rssi is not None else ""
            fp = f" fp={ev.fingerprint[:8]}" if ev.fingerprint else " fp=-"
            print(f"  probe  {ev.mac}{ssid}{rssi}{fp}", file=sys.stderr)

    backend = _build_backend(args.backend, args.iface, on_event)

    # Graceful shutdown on Ctrl-C / SIGTERM.
    stop_requested = False

    def _shutdown(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    mode_bits = []
    mode_bits.append("fingerprint-clustering" if args.fingerprint else "per-MAC")
    if not args.include_randomized:
        mode_bits.append("excluding randomized")
    mode = ", ".join(mode_bits)
    print(
        f"probe-sniffer started on {args.iface} via {args.backend} "
        f"(window={args.window}s, interval={args.interval}s, {mode}).\n"
        "Press Ctrl-C to stop.\n"
    )

    try:
        backend.start()
    except Exception as exc:
        print(f"failed to start backend: {exc}", file=sys.stderr)
        return 2

    # Reporter loop. Sleep in small slices so Ctrl-C is snappy.
    next_report = time.monotonic() + args.interval
    try:
        while not stop_requested:
            now = time.monotonic()
            if now >= next_report:
                stats = tracker.stats()
                ts = datetime.now().strftime("%H:%M:%S")
                extra = (
                    f"  (universal={stats.universal_in_window}, "
                    f"randomized={stats.randomized_in_window}, "
                    f"macs-seen={stats.macs_in_window})"
                )
                label = "devices" if args.fingerprint else "unique MACs"
                print(
                    f"[{ts}] {label} in vicinity (last {args.window}s): "
                    f"{stats.active_in_window}{extra}  "
                    f"[unique-ever={stats.total_unique_ever}]"
                )
                next_report = now + args.interval
            time.sleep(0.25)
    finally:
        print("\nshutting down...", file=sys.stderr)
        backend.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
