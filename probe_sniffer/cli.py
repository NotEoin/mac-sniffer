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


def _band_of(freq_mhz: int) -> str:
    if freq_mhz < 3000:
        return "2.4 GHz"
    if freq_mhz < 5925:
        return "5 GHz"
    return "6 GHz"


def _warn_if_not_root(backend: str) -> None:
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        return
    if backend == "pyshark":
        # tshark captures through dumpcap, which usually ships with the
        # capabilities already granted to members of the wireshark group.
        print(
            "note: not running as root. The pyshark backend can still capture "
            "if your user is in the 'wireshark' group.",
            file=sys.stderr,
        )
    else:
        print(
            "warning: not running as root. The scapy backend opens a raw "
            "socket, which needs root (or CAP_NET_RAW + CAP_NET_ADMIN on the "
            "python binary). The pyshark backend works from the 'wireshark' "
            "group instead.",
            file=sys.stderr,
        )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _warn_if_not_root(args.backend)

    tracker = DeviceTracker(
        window_seconds=args.window,
        include_randomized=args.include_randomized,
        cluster_by_fingerprint=args.fingerprint,
    )

    # A radio that changes channel mid-capture quietly wrecks the count: a
    # handset sends different information elements on 2.4 GHz than on 5 GHz,
    # so crossing bands gives it a second fingerprint and counts it twice.
    # This happens without asking when the monitor interface shares a wiphy
    # with a managed one that is scanning.
    # Within-band hops only cost coverage, so they share a small budget. A
    # band crossing is always reported: that is the one that splits a device
    # in two.
    channel_state: dict[str, object] = {
        "freq": None,
        "hop_warnings": 0,
        "crossings": 0,
    }
    channels_seen: set[int] = set()
    max_hop_warnings = 3

    def note_channel(freq: int | None) -> None:
        if freq is None or freq == channel_state["freq"]:
            return
        channels_seen.add(freq)
        previous = channel_state["freq"]
        channel_state["freq"] = freq
        if previous is None:
            return

        pin = f"pin it with: sudo iw dev {args.iface} set freq {previous}"
        if _band_of(previous) != _band_of(freq):
            # Said once in full, then counted. A radio sharing a wiphy with a
            # scanning interface crosses bands dozens of times in a quarter of
            # an hour, and repeating this each time buries the reports.
            channel_state["crossings"] += 1
            if channel_state["crossings"] == 1:
                print(
                    f"warning: capture crossed bands, {previous} MHz "
                    f"({_band_of(previous)}) to {freq} MHz ({_band_of(freq)}). "
                    "A device probes with different elements on each band, so "
                    f"anything dual-band is counted twice from here on. {pin}",
                    file=sys.stderr,
                    flush=True,
                )
            return

        if channel_state["hop_warnings"] >= max_hop_warnings:
            return
        channel_state["hop_warnings"] += 1
        print(
            f"warning: capture moved from {previous} MHz to {freq} MHz. "
            f"Devices on {previous} MHz stop being heard. {pin}",
            file=sys.stderr,
            flush=True,
        )
        if channel_state["hop_warnings"] == max_hop_warnings:
            print(
                "warning: further hops within the band will not be reported.",
                file=sys.stderr,
                flush=True,
            )

    def on_event(ev: ProbeEvent) -> None:
        note_channel(ev.freq)
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
            # Flushed like the interval reports: piped to a file, stderr is
            # block-buffered, and a killed capture loses whatever is still in
            # the buffer — which is most of a short run.
            print(f"  probe  {ev.mac}{ssid}{rssi}{fp}", file=sys.stderr, flush=True)

    backend = _build_backend(args.backend, args.iface, on_event)

    # Graceful shutdown on Ctrl-C / SIGTERM.
    stop_requested = False

    def _shutdown(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True

    previous_handlers = {
        sig: signal.signal(sig, _shutdown)
        for sig in (signal.SIGINT, signal.SIGTERM)
    }

    def _restore_handlers() -> None:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)

    try:
        backend.start()
    except Exception as exc:
        print(f"failed to start backend: {exc}", file=sys.stderr)
        _restore_handlers()
        return 2

    mode_bits = []
    mode_bits.append("fingerprint-clustering" if args.fingerprint else "per-MAC")
    if not args.include_randomized:
        mode_bits.append("excluding randomized")
    mode = ", ".join(mode_bits)
    print(
        f"probe-sniffer started on {args.iface} via {args.backend} "
        f"(window={args.window}s, interval={args.interval}s, {mode}).\n"
        "Press Ctrl-C to stop.\n",
        flush=True,
    )

    # Reporter loop. Sleep in small slices so Ctrl-C is snappy.
    exit_code = 0
    next_report = time.monotonic() + args.interval
    try:
        while not stop_requested:
            # A capture that dies (interface torn down, tshark refused to
            # start) would otherwise leave us printing zeroes indefinitely.
            if not backend.alive:
                exit_code = 2
                if backend.error is not None:
                    print(
                        f"capture failed: {type(backend.error).__name__}: "
                        f"{backend.error}",
                        file=sys.stderr,
                    )
                else:
                    print(
                        "capture ended unexpectedly (is the interface still "
                        "up and in monitor mode?)",
                        file=sys.stderr,
                    )
                break

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
                    f"[unique-ever={stats.total_unique_ever}]",
                    flush=True,
                )
                next_report = now + args.interval
            time.sleep(0.25)
    finally:
        # Flushed: this is the last thing said about a run, and a capture that
        # is killed rather than stopped would otherwise lose it in the buffer.
        print("\nshutting down...", file=sys.stderr, flush=True)
        if len(channels_seen) > 1:
            bands = sorted({_band_of(f) for f in channels_seen})
            crossings = channel_state["crossings"]
            print(
                f"note: this count covers {len(channels_seen)} channels "
                f"({', '.join(str(f) for f in sorted(channels_seen))} MHz) "
                f"across {len(bands)} band(s): {', '.join(bands)}"
                + (f", crossing between them {crossings} times" if crossings else "")
                + ". One channel at a time gives a count you can trust.",
                file=sys.stderr,
                flush=True,
            )
        backend.stop()
        _restore_handlers()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
