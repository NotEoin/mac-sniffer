"""Tests for the backend lifecycle and packet handling.

The scapy tests craft frames in memory and feed them straight to the handler,
so nothing here needs an interface, monitor mode or root.
"""

import threading
import time

import pytest

from probe_sniffer.backends.base import ProbeEvent, SnifferBackend
from probe_sniffer.backends.pyshark_backend import PysharkBackend
from probe_sniffer.backends.scapy_backend import ScapyBackend

scapy_dot11 = pytest.importorskip("scapy.layers.dot11")


# ---- lifecycle -----------------------------------------------------------


class FailingBackend(SnifferBackend):
    def _run(self):
        raise OSError("no such interface")


class QuietBackend(SnifferBackend):
    """Blocks until stopped, like a real capture on an idle channel."""

    def _run(self):
        while not self.stopping:
            self._stop.wait(0.01)


def test_a_backend_that_fails_immediately_raises_from_start():
    backend = FailingBackend(iface="wlan0mon", on_event=lambda ev: None)
    with pytest.raises(RuntimeError, match="no such interface"):
        backend.start()

    assert not backend.alive
    assert isinstance(backend.error, OSError)


def test_a_running_backend_reports_itself_alive():
    backend = QuietBackend(iface="wlan0mon", on_event=lambda ev: None)
    backend.start(ready_timeout=0.05)

    assert backend.alive
    assert backend.error is None

    backend.stop()
    assert not backend.alive


def test_a_backend_cannot_be_started_twice():
    backend = QuietBackend(iface="wlan0mon", on_event=lambda ev: None)
    backend.start(ready_timeout=0.05)
    try:
        with pytest.raises(RuntimeError, match="already started"):
            backend.start()
    finally:
        backend.stop()


def test_capture_runs_off_the_calling_thread():
    seen = []

    class ThreadNamingBackend(SnifferBackend):
        def _run(self):
            seen.append(threading.current_thread())

    backend = ThreadNamingBackend(iface="wlan0mon", on_event=lambda ev: None)
    backend.start(ready_timeout=1.0)
    backend.stop()

    assert seen and seen[0] is not threading.current_thread()


# ---- scapy packet handling -----------------------------------------------


def build_probe(mac: str, ssid: bytes = b"HomeNet", rssi: int = -42, vendor=b"\x2d\x40\x1b\xff"):
    from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap

    return (
        RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi)
        / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=mac,
                addr3="ff:ff:ff:ff:ff:ff")
        / Dot11ProbeReq()
        / Dot11Elt(ID=0, info=ssid)
        / Dot11Elt(ID=1, info=b"\x02\x04\x0b\x16")
        / Dot11Elt(ID=50, info=b"\x0c\x12\x18\x60")
        / Dot11Elt(ID=45, info=vendor)
    )


@pytest.fixture
def scapy_capture():
    events: list[ProbeEvent] = []
    backend = ScapyBackend(iface="wlan0mon", on_event=events.append)
    return backend, events


def test_scapy_handler_extracts_the_probe_fields(scapy_capture):
    backend, events = scapy_capture
    backend.handle_packet(build_probe("aa:bb:cc:dd:ee:ff"))

    (event,) = events
    assert event.mac == "aa:bb:cc:dd:ee:ff"
    assert event.ssid == "HomeNet"
    assert event.rssi == -42
    assert event.fingerprint is not None
    assert event.ts is not None


def test_scapy_fingerprint_survives_mac_rotation_and_ssid_changes(scapy_capture):
    backend, events = scapy_capture
    backend.handle_packet(build_probe("aa:bb:cc:dd:ee:ff", ssid=b"HomeNet"))
    backend.handle_packet(build_probe("ba:11:22:33:44:55", ssid=b"CoffeeShop"))

    first, second = events
    assert first.mac != second.mac
    assert first.fingerprint == second.fingerprint


def test_scapy_fingerprint_differs_between_chipsets(scapy_capture):
    backend, events = scapy_capture
    backend.handle_packet(build_probe("aa:bb:cc:dd:ee:ff"))
    backend.handle_packet(build_probe("ba:11:22:33:44:55", vendor=b"\x2d\x40\x00\x00"))

    assert events[0].fingerprint != events[1].fingerprint


def test_scapy_handler_reads_a_wildcard_probe(scapy_capture):
    backend, events = scapy_capture
    backend.handle_packet(build_probe("aa:bb:cc:dd:ee:ff", ssid=b""))

    (event,) = events
    assert event.ssid is None
    assert event.fingerprint is not None


def test_scapy_handler_ignores_other_frame_types(scapy_capture):
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

    backend, events = scapy_capture
    beacon = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=b"HomeNet")
    )
    backend.handle_packet(beacon)

    assert events == []


def test_scapy_handler_matches_the_raw_frame_fingerprint(scapy_capture):
    """Both backends must agree, or --backend is not a cross-check."""
    from probe_sniffer.utils import compute_ie_fingerprint, parse_ies

    backend, events = scapy_capture
    packet = build_probe("aa:bb:cc:dd:ee:ff")
    backend.handle_packet(packet)

    assert events[0].fingerprint == compute_ie_fingerprint(parse_ies(bytes(packet)))


@pytest.mark.parametrize("with_timestamp", [False, True])
def test_fcs_detection_matches_the_radiotap_scapy_builds(with_timestamp):
    """Cross-check the hand-rolled header walk against scapy's own layout."""
    from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap

    from probe_sniffer.utils import has_trailing_fcs, parse_ies

    def frame(flags: str) -> bytes:
        present = "Flags+dBm_AntSignal"
        extra = {}
        if with_timestamp:
            present = "TSFT+" + present
            extra["mac_timestamp"] = 99
        header = RadioTap(present=present, Flags=flags, dBm_AntSignal=-42, **extra)
        body = (
            Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                  addr2="aa:bb:cc:dd:ee:ff", addr3="ff:ff:ff:ff:ff:ff")
            / Dot11ProbeReq()
            / Dot11Elt(ID=0, info=b"Net")
            / Dot11Elt(ID=1, info=b"\x02\x04")
            / Dot11Elt(ID=45, info=b"\x2d\x40")
        )
        return bytes(header / body) + b"\xdd\x02\xff\xee"   # stand-in checksum

    tags = [(0, b"Net"), (1, b"\x02\x04"), (45, b"\x2d\x40")]

    assert has_trailing_fcs(frame("FCS"))
    assert parse_ies(frame("FCS")) == tags

    assert not has_trailing_fcs(frame(""))
    assert parse_ies(frame("")) == tags + [(221, b"\xff\xee")]


# ---- pyshark field extraction --------------------------------------------


class StubLayer:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class StubPacket:
    def __init__(self, **layers):
        self.__dict__.update(layers)


def test_pyshark_reads_the_source_address():
    pkt = StubPacket(wlan=StubLayer(sa="aa:bb:cc:dd:ee:ff"))
    assert PysharkBackend._extract_mac(pkt) == "aa:bb:cc:dd:ee:ff"


def test_pyshark_falls_back_through_address_field_names():
    pkt = StubPacket(wlan=StubLayer(addr2="aa:bb:cc:dd:ee:ff"))
    assert PysharkBackend._extract_mac(pkt) == "aa:bb:cc:dd:ee:ff"


def test_pyshark_handles_a_repeated_address_field():
    pkt = StubPacket(wlan=StubLayer(sa=["aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"]))
    assert PysharkBackend._extract_mac(pkt) == "aa:bb:cc:dd:ee:ff"


def test_pyshark_returns_none_without_a_wlan_layer():
    assert PysharkBackend._extract_mac(StubPacket()) is None


def test_pyshark_reads_the_ssid_from_either_layer_name():
    old = StubPacket(wlan_mgt=StubLayer(ssid="HomeNet"))
    new = StubPacket(wlan=StubLayer(ssid="HomeNet"))
    assert PysharkBackend._extract_ssid(old) == "HomeNet"
    assert PysharkBackend._extract_ssid(new) == "HomeNet"


def test_pyshark_treats_a_wildcard_ssid_as_absent():
    pkt = StubPacket(wlan=StubLayer(ssid=""))
    assert PysharkBackend._extract_ssid(pkt) is None
    assert PysharkBackend._extract_ssid(StubPacket()) is None


def test_pyshark_reads_rssi_and_tolerates_junk():
    assert PysharkBackend._extract_rssi(StubPacket(radiotap=StubLayer(dbm_antsignal="-42"))) == -42
    assert PysharkBackend._extract_rssi(StubPacket(radiotap=StubLayer(dbm_antsignal="n/a"))) is None
    assert PysharkBackend._extract_rssi(StubPacket()) is None


def test_pyshark_reads_rssi_reported_once_per_antenna():
    """Measured live: this field arrives as ['-53', '-53'], not a scalar."""
    pkt = StubPacket(radiotap=StubLayer(dbm_antsignal=["-53", "-53"]))
    assert PysharkBackend._extract_rssi(pkt) == -53


def test_pyshark_falls_back_to_the_radio_layer_for_rssi():
    pkt = StubPacket(radiotap=StubLayer(dbm_antsignal="n/a"),
                     wlan_radio=StubLayer(signal_dbm="-61"))
    assert PysharkBackend._extract_rssi(pkt) == -61


def test_pyshark_reads_the_ssid_out_of_the_frame():
    """tshark does not expose wlan.ssid under use_json, but tag 0 is right there."""
    assert PysharkBackend._ssid_from_ies([(0, b"HomeNet"), (1, b"\x02")]) == "HomeNet"
    assert PysharkBackend._ssid_from_ies([(0, b""), (1, b"\x02")]) is None
    assert PysharkBackend._ssid_from_ies([(1, b"\x02")]) is None


def test_both_backends_agree_on_the_same_frame():
    """The raw frame is the shared source of truth for both backends."""
    from probe_sniffer.utils import compute_ie_fingerprint, parse_ies

    packet = build_probe("aa:bb:cc:dd:ee:ff")
    raw = bytes(packet)

    class RawPacket:
        def get_raw_packet(self):
            return raw

    events: list[ProbeEvent] = []
    ScapyBackend(iface="wlan0mon", on_event=events.append).handle_packet(packet)

    ies = parse_ies(PysharkBackend._raw_frame(RawPacket()))
    assert compute_ie_fingerprint(ies) == events[0].fingerprint
    assert PysharkBackend._ssid_from_ies(ies) == events[0].ssid


def test_pyshark_has_no_raw_frame_without_include_raw():
    class NoRawPacket:
        def get_raw_packet(self):
            raise AttributeError("include_raw was not set")

    assert PysharkBackend._raw_frame(NoRawPacket()) is None


# ---- the capture pipeline dying under us ---------------------------------


class FakeProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode


class FakeCapture:
    def __init__(self, processes):
        self._running_processes = set(processes)


def test_pyshark_fails_when_a_capture_process_exits():
    """Killing dumpcap leaves tshark up, so the packet loop blocks for ever.

    Measured: the count read zero for ten minutes after the capture died.
    """
    backend = PysharkBackend(iface="wlan0mon", on_event=lambda ev: None)
    alive, dead = FakeProcess(), FakeProcess(returncode=1)

    backend._watch_processes(FakeCapture([alive, dead]), poll_seconds=0.01)

    assert backend.error is not None
    assert "capture process exited" in str(backend.error)
    assert backend.stopping


def test_pyshark_watchdog_leaves_a_healthy_capture_alone():
    backend = PysharkBackend(iface="wlan0mon", on_event=lambda ev: None)
    capture = FakeCapture([FakeProcess(), FakeProcess()])

    watcher = threading.Thread(
        target=backend._watch_processes, args=(capture, 0.01), daemon=True
    )
    watcher.start()
    time.sleep(0.1)

    assert backend.error is None
    backend._stop.set()
    watcher.join(timeout=1.0)


def test_pyshark_watchdog_gives_up_on_an_unfamiliar_pyshark():
    """The attribute is private; a rename must not break capturing."""
    class Bare:
        pass

    backend = PysharkBackend(iface="wlan0mon", on_event=lambda ev: None)
    backend._watch_processes(Bare(), poll_seconds=0.01)

    assert backend.error is None
    assert not backend.stopping
