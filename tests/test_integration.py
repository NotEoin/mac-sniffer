"""End-to-end pass over a capture file.

This is as close to a live run as we can get without an interface and root:
scapy reads real radiotap frames off a pcap, the backend handler turns them
into events, and the tracker counts them.
"""

import pytest

from probe_sniffer.backends.scapy_backend import ScapyBackend
from probe_sniffer.tracker import DeviceTracker

pytest.importorskip("scapy.layers.dot11")

from tests.test_backends import build_probe  # noqa: E402


def replay(tmp_path, frames, **tracker_kwargs) -> DeviceTracker:
    from scapy.all import sniff, wrpcap

    path = tmp_path / "probes.pcap"
    wrpcap(str(path), frames)

    tracker = DeviceTracker(**tracker_kwargs)
    backend = ScapyBackend(
        iface="wlan0mon",
        on_event=lambda ev: tracker.observe(
            ev.mac, ssid=ev.ssid, rssi=ev.rssi, ts=ev.ts, fingerprint=ev.fingerprint
        ),
    )
    sniff(offline=str(path), prn=backend.handle_packet, store=False)
    return tracker


def test_one_phone_rotating_macs_reads_back_as_one_device(tmp_path):
    frames = [
        build_probe("aa:11:11:11:11:01", ssid=b"HomeNet"),
        build_probe("ba:22:22:22:22:02", ssid=b""),
        build_probe("ca:33:33:33:33:03", ssid=b"CoffeeShop"),
    ]
    tracker = replay(tmp_path, frames)

    assert tracker.count() == 1
    stats = tracker.stats()
    assert stats.macs_in_window == 3
    assert stats.randomized_in_window == 1


def test_the_same_capture_counts_three_without_clustering(tmp_path):
    frames = [
        build_probe("aa:11:11:11:11:01"),
        build_probe("ba:22:22:22:22:02"),
        build_probe("ca:33:33:33:33:03"),
    ]
    tracker = replay(tmp_path, frames, cluster_by_fingerprint=False)

    assert tracker.count() == 3


def test_tags_after_the_rates_reach_the_fingerprint(tmp_path):
    """Regression: scapy leaves the tags after Dot11EltRates as Raw.

    Walking the dissected layers therefore fingerprints nothing but the rates,
    and two different handsets look identical.
    """
    from scapy.all import sniff, wrpcap

    frames = [
        build_probe("aa:11:11:11:11:01", vendor=b"\x2d\x40\x1b\xff"),
        build_probe("aa:11:11:11:11:01", vendor=b"\x2d\x00\x00\x00"),
    ]
    path = tmp_path / "probes.pcap"
    wrpcap(str(path), frames)

    events = []
    backend = ScapyBackend(iface="wlan0mon", on_event=events.append)
    sniff(offline=str(path), prn=backend.handle_packet, store=False)

    assert events[0].fingerprint != events[1].fingerprint


def test_distinct_chipsets_stay_distinct_across_a_capture(tmp_path):
    frames = [
        build_probe("aa:11:11:11:11:01", vendor=b"\x2d\x40\x1b\xff"),
        build_probe("ba:22:22:22:22:02", vendor=b"\x2d\x40\x1b\xff"),
        build_probe("ca:33:33:33:33:03", vendor=b"\x2d\x00\x00\x00"),
        build_probe("3c:22:fb:11:22:33", vendor=b"\x2d\x40\x1b\xff"),
    ]
    tracker = replay(tmp_path, frames)

    # Two randomised chipsets plus one universal address that is never merged.
    assert tracker.count() == 3
    assert tracker.stats().universal_in_window == 1
