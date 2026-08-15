"""Scapy-based probe-request sniffer.

Scapy listens directly on the interface (which must already be in monitor
mode). We filter to 802.11 management frames where ``type=0`` and
``subtype=4`` (Probe Request).
"""

from __future__ import annotations

import time

from ..utils import compute_ie_fingerprint, parse_ies
from .base import ProbeEvent, SnifferBackend


class ScapyBackend(SnifferBackend):
    def _run(self) -> None:
        # Imported lazily so the CLI still loads when scapy isn't installed.
        from scapy.all import sniff  # type: ignore

        # store=False so packets are not retained in memory.
        # stop_filter is checked after each packet, giving us a clean shutdown.
        sniff(
            iface=self.iface,
            prn=self.handle_packet,
            store=False,
            monitor=True,
            stop_filter=lambda _pkt: self.stopping,
        )

    def handle_packet(self, pkt) -> None:
        """Turn one sniffed scapy packet into a :class:`ProbeEvent`."""
        from scapy.layers.dot11 import Dot11, Dot11ProbeReq, RadioTap  # type: ignore

        if not pkt.haslayer(Dot11ProbeReq):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None or dot11.addr2 is None:
            return

        mac = dot11.addr2

        # Parse the IEs out of the raw frame rather than walking scapy's
        # dissected layers. On a frame that came off the air scapy turns the
        # rates tags into Dot11EltRates and leaves everything after them as
        # Raw, so the layer walk silently drops the HT, extended-capability
        # and vendor tags — the ones that make a fingerprint discriminating.
        raw = getattr(pkt, "original", None) or bytes(pkt)
        ies = parse_ies(raw)

        ssid: str | None = None
        for tag_id, body in ies:
            if tag_id == 0:
                ssid = body.decode("utf-8", errors="replace") or None
                break

        fingerprint = compute_ie_fingerprint(ies)

        rssi: int | None = None
        if pkt.haslayer(RadioTap):
            rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)

        self.on_event(
            ProbeEvent(
                mac=mac,
                ssid=ssid,
                rssi=rssi,
                ts=time.time(),
                fingerprint=fingerprint,
            )
        )
