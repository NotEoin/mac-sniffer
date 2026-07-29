"""Pyshark-based probe-request sniffer.

Pyshark shells out to ``tshark`` (Wireshark CLI), so Wireshark must be
installed on the system and the user running the sniffer needs permission to
capture (usually the ``wireshark`` group on Debian/Ubuntu, or running as root).

We use a display filter rather than a capture/BPF filter because BPF cannot
match into the 802.11 management header on every driver.
"""

from __future__ import annotations

import time

from ..utils import compute_ie_fingerprint, parse_ies
from .base import ProbeEvent, SnifferBackend

# wlan.fc.type == 0 (management), wlan.fc.subtype == 4 (probe request)
_DISPLAY_FILTER = "wlan.fc.type_subtype == 0x04"


class PysharkBackend(SnifferBackend):
    def _run(self) -> None:
        import pyshark  # type: ignore

        capture = pyshark.LiveCapture(
            interface=self.iface,
            monitor_mode=True,
            display_filter=_DISPLAY_FILTER,
            include_raw=True,
            use_json=True,
        )

        try:
            # sniff_continuously yields packets until we break out.
            for pkt in capture.sniff_continuously():
                if self.stopping:
                    break

                mac = self._extract_mac(pkt)
                if not mac:
                    continue

                self.on_event(
                    ProbeEvent(
                        mac=mac,
                        ssid=self._extract_ssid(pkt),
                        rssi=self._extract_rssi(pkt),
                        ts=time.time(),
                        fingerprint=self._extract_fingerprint(pkt),
                    )
                )
        finally:
            try:
                capture.close()
            except Exception:
                pass

    # ---- field extraction helpers (defensive: tshark field names vary) ----

    @staticmethod
    def _extract_mac(pkt) -> str | None:
        try:
            wlan = pkt.wlan
        except AttributeError:
            return None
        for attr in ("sa", "ta", "addr2"):
            val = getattr(wlan, attr, None)
            if val:
                return str(val)
        return None

    @staticmethod
    def _extract_ssid(pkt) -> str | None:
        try:
            ssid = pkt.wlan_mgt.ssid  # older tshark
        except AttributeError:
            try:
                ssid = pkt.wlan.ssid   # newer tshark merged the layers
            except AttributeError:
                return None
        ssid = str(ssid) if ssid else ""
        return ssid or None

    @staticmethod
    def _extract_rssi(pkt) -> int | None:
        try:
            return int(pkt.radiotap.dbm_antsignal)
        except (AttributeError, ValueError):
            return None

    @staticmethod
    def _extract_fingerprint(pkt) -> str | None:
        # Requires include_raw=True + use_json=True at capture time.
        try:
            raw = pkt.get_raw_packet()
        except Exception:
            return None
        if not raw:
            return None
        return compute_ie_fingerprint(parse_ies(raw))
