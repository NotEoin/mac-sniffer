"""Scapy-based probe-request sniffer.

Scapy listens directly on the interface (which must already be in monitor
mode). We filter to 802.11 management frames where ``type=0`` and
``subtype=4`` (Probe Request).
"""

from __future__ import annotations

import time

from ..utils import compute_ie_fingerprint
from .base import ProbeEvent, SnifferBackend


class ScapyBackend(SnifferBackend):
    def _run(self) -> None:
        # Imported lazily so the CLI still loads when scapy isn't installed.
        from scapy.all import sniff  # type: ignore
        from scapy.layers.dot11 import (  # type: ignore
            Dot11,
            Dot11Elt,
            Dot11ProbeReq,
            RadioTap,
        )

        def iter_elts(start):
            cur = start
            while isinstance(cur, Dot11Elt):
                yield cur
                cur = cur.payload

        def handle(pkt) -> None:
            if not pkt.haslayer(Dot11ProbeReq):
                return
            dot11 = pkt.getlayer(Dot11)
            if dot11 is None or dot11.addr2 is None:
                return

            mac = dot11.addr2

            ssid: str | None = None
            ies: list[tuple[int, bytes]] = []
            try:
                first = pkt.getlayer(Dot11ProbeReq).payload
                for elt in iter_elts(first):
                    body = bytes(elt.info or b"")
                    ies.append((int(elt.ID), body))
                    if elt.ID == 0 and ssid is None:
                        try:
                            ssid = body.decode("utf-8", errors="replace") or None
                        except Exception:
                            ssid = None
            except Exception:
                pass

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

        # store=False so packets are not retained in memory.
        # stop_filter is checked after each packet, giving us a clean shutdown.
        sniff(
            iface=self.iface,
            prn=handle,
            store=False,
            monitor=True,
            stop_filter=lambda _pkt: self.stopping,
        )
