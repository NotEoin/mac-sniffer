"""Pyshark-based probe-request sniffer.

Pyshark shells out to ``tshark`` (Wireshark CLI), so Wireshark must be
installed on the system and the user running the sniffer needs permission to
capture (usually the ``wireshark`` group on Debian/Ubuntu, or running as root).

We use a display filter rather than a capture/BPF filter because BPF cannot
match into the 802.11 management header on every driver.
"""

from __future__ import annotations

import asyncio
import threading
import time

from ..utils import compute_ie_fingerprint, parse_channel_mhz, parse_ies
from .base import ProbeEvent, SnifferBackend

# wlan.fc.type == 0 (management), wlan.fc.subtype == 4 (probe request)
_DISPLAY_FILTER = "wlan.fc.type_subtype == 0x04"


class PysharkBackend(SnifferBackend):
    def _run(self) -> None:
        import pyshark  # type: ignore

        # pyshark drives tshark through asyncio, and we run in a worker thread
        # that has no event loop of its own. Older pyshark releases call
        # asyncio.get_event_loop() and blow up here rather than creating one.
        asyncio.set_event_loop(asyncio.new_event_loop())

        # No monitor_mode=True: that asks tshark to *switch* the interface
        # into monitor mode, which the driver refuses for an interface that is
        # already one (the only kind we are given). dumpcap then exits and the
        # capture yields nothing at all.
        capture = pyshark.LiveCapture(
            interface=self.iface,
            display_filter=_DISPLAY_FILTER,
            include_raw=True,
            use_json=True,
        )

        # tshark and dumpcap are separate processes. Kill the one holding the
        # interface and tshark stays up with its output open, so the loop
        # below simply blocks for ever on packets that will never arrive and
        # the count reads zero. Watch the processes instead of waiting.
        watchdog = threading.Thread(
            target=self._watch_processes,
            args=(capture,),
            name=f"{type(self).__name__}-watchdog",
            daemon=True,
        )
        watchdog.start()

        try:
            for pkt in capture.sniff_continuously():
                if self.stopping:
                    break

                mac = self._extract_mac(pkt)
                if not mac:
                    continue

                # Parse the frame once and read the SSID, the fingerprint and
                # the channel out of it. tshark's own field names for these
                # move around between versions and layouts; the bytes do not.
                raw = self._raw_frame(pkt)
                ies = parse_ies(raw) if raw else []

                self.on_event(
                    ProbeEvent(
                        mac=mac,
                        ssid=self._ssid_from_ies(ies) or self._extract_ssid(pkt),
                        rssi=self._extract_rssi(pkt),
                        ts=time.monotonic(),   # matches the tracker's window clock
                        fingerprint=compute_ie_fingerprint(ies) if ies else None,
                        freq=parse_channel_mhz(raw) if raw else None,
                    )
                )
        finally:
            try:
                capture.close()
            except Exception:
                pass

    # ---- field extraction helpers (defensive: tshark field names vary) ----

    def _watch_processes(self, capture, poll_seconds: float = 2.0) -> None:
        """Fail the capture if any of tshark's processes exits under us.

        pyshark tracks the processes it started. The attribute is private, so
        this gives up quietly if a future release renames it — the capture
        still works, it just goes back to being unable to tell a dead pipeline
        from a quiet channel.
        """
        processes = getattr(capture, "_running_processes", None)
        if processes is None:
            return

        # Wait for the processes to be registered before watching them.
        while not processes and not self._stop.wait(poll_seconds):
            processes = getattr(capture, "_running_processes", None) or set()

        while not self._stop.wait(poll_seconds):
            for process in list(processes):
                if process.returncode is not None:
                    self._capture_died(process.returncode)
                    return

    def _capture_died(self, returncode: int) -> None:
        self._error = RuntimeError(
            f"a capture process exited (status {returncode}) while sniffing; "
            "the interface may have gone down or been taken over"
        )
        self._stop.set()
        self._finished.set()

    @staticmethod
    def _extract_mac(pkt) -> str | None:
        try:
            wlan = pkt.wlan
        except AttributeError:
            return None
        for attr in ("sa", "ta", "addr2"):
            val = getattr(wlan, attr, None)
            if val:
                # use_json=True can hand back a list when tshark reports the
                # field more than once; every copy is the same address.
                if isinstance(val, (list, tuple)):
                    val = val[0] if val else None
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
        # A frame heard on several antennas reports the strength once per
        # antenna, so this field arrives as a list as often as not.
        for layer, field in (("radiotap", "dbm_antsignal"),
                             ("wlan_radio", "signal_dbm")):
            value = getattr(getattr(pkt, layer, None), field, None)
            if isinstance(value, (list, tuple)):
                value = value[0] if value else None
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return None

    @staticmethod
    def _raw_frame(pkt) -> bytes | None:
        """The frame as captured. Needs include_raw and use_json."""
        try:
            return pkt.get_raw_packet() or None
        except Exception:
            return None

    @staticmethod
    def _ssid_from_ies(ies) -> str | None:
        for tag_id, body in ies:
            if tag_id == 0:
                return body.decode("utf-8", errors="replace") or None
        return None
