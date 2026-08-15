"""Tests for argument parsing and the reporter loop.

The backend is stubbed out throughout — no interface is ever opened.
"""

import os
import signal
import threading

import pytest

from probe_sniffer import cli
from probe_sniffer.backends.base import ProbeEvent

PROBE_ARGS = ["--iface", "wlan0mon", "--interval", "1"]


def test_defaults():
    args = cli._build_parser().parse_args(["--iface", "wlan0mon"])
    assert args.backend == "scapy"
    assert args.interval == 30
    assert args.window == 300
    assert args.fingerprint
    assert args.include_randomized
    assert not args.verbose


def test_flags_switch_the_counting_mode():
    args = cli._build_parser().parse_args(
        ["-i", "wlan0mon", "-b", "pyshark", "--no-fingerprint",
         "--exclude-randomized", "--window", "600", "-v"]
    )
    assert args.backend == "pyshark"
    assert args.window == 600
    assert not args.fingerprint
    assert not args.include_randomized
    assert args.verbose


def test_iface_is_required():
    with pytest.raises(SystemExit):
        cli._build_parser().parse_args([])


def test_unknown_backend_is_rejected():
    with pytest.raises(ValueError, match="unknown backend"):
        cli._build_backend("tcpdump", "wlan0mon", lambda ev: None)


def test_the_permissions_hint_matches_the_backend(monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)

    cli._warn_if_not_root("scapy")
    assert "needs root" in capsys.readouterr().err

    cli._warn_if_not_root("pyshark")
    assert "wireshark" in capsys.readouterr().err


def test_no_permissions_hint_when_root(monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)

    cli._warn_if_not_root("scapy")
    assert capsys.readouterr().err == ""


class StubBackend:
    """Stands in for a capture: replays events, then fails or dies as configured."""

    def __init__(self, events=(), start_error=None, die_after=None):
        self.events = list(events)
        self.start_error = start_error
        self.die_after = die_after
        self.error = None
        self.alive = False
        self.stopped = False
        self.on_event = None

    def start(self):
        if self.start_error is not None:
            raise RuntimeError(self.start_error)
        self.alive = True
        for event in self.events:
            self.on_event(event)
        if self.die_after is not None:
            self.error = self.die_after
            self.alive = False

    def stop(self):
        self.stopped = True


@pytest.fixture
def stub(monkeypatch):
    """Install a stub backend and hand it back for configuration."""
    holder = {}

    def install(backend):
        def _build(name, iface, on_event):
            backend.on_event = on_event
            holder["backend"] = backend
            return backend

        monkeypatch.setattr(cli, "_build_backend", _build)
        return backend

    return install


def test_a_backend_that_will_not_start_exits_two(stub, capsys):
    backend = stub(StubBackend(start_error="Interface 'wlan0mon' not found !"))

    assert cli.main(PROBE_ARGS) == 2
    assert "failed to start backend" in capsys.readouterr().err
    assert not backend.stopped   # nothing was ever running


def test_a_capture_that_dies_exits_two_and_says_why(stub, capsys):
    backend = stub(StubBackend(die_after=OSError("interface went down")))

    assert cli.main(PROBE_ARGS) == 2
    err = capsys.readouterr().err
    assert "capture failed: OSError: interface went down" in err
    assert backend.stopped


def test_a_capture_that_ends_quietly_still_exits_two(stub, capsys):
    # tshark exiting of its own accord: the thread ends without an exception.
    class QuietlyEnding(StubBackend):
        def start(self):
            self.alive = False

    stub(QuietlyEnding())

    assert cli.main(PROBE_ARGS) == 2
    assert "capture ended unexpectedly" in capsys.readouterr().err


def test_ctrl_c_shuts_down_cleanly_after_reporting(stub, capsys):
    events = [
        ProbeEvent(mac="aa:11:11:11:11:01", ssid="HomeNet", rssi=-51,
                   fingerprint="1111111111111111"),
        ProbeEvent(mac="ba:22:22:22:22:02", rssi=-49,
                   fingerprint="1111111111111111"),
        ProbeEvent(mac="3c:22:fb:11:22:33", rssi=-60),
    ]
    backend = stub(StubBackend(events=events))

    # Fires once the reporter loop is running and the handler is installed.
    threading.Timer(1.5, lambda: os.kill(os.getpid(), signal.SIGINT)).start()

    assert cli.main(PROBE_ARGS) == 0
    assert backend.stopped

    out = capsys.readouterr().out
    assert "probe-sniffer started on wlan0mon via scapy" in out
    # Three MACs, but the two randomised ones share a fingerprint.
    assert "devices in vicinity (last 300s): 2" in out
    assert "(universal=1, randomized=1, macs-seen=3)" in out


def test_a_band_crossing_is_reported(stub, capsys):
    events = [
        ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=2412),
        ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=2412),
        ProbeEvent(mac="ba:22:22:22:22:02", fingerprint="2222", freq=5745),
        ProbeEvent(mac="ba:22:22:22:22:02", fingerprint="2222", freq=5745),
    ]
    stub(StubBackend(events=events, die_after=OSError("done")))

    cli.main(PROBE_ARGS)

    err = capsys.readouterr().err
    assert err.count("capture crossed bands, 2412 MHz (2.4 GHz) to 5745 MHz (5 GHz)") == 1
    assert "counted twice" in err
    assert "sudo iw dev wlan0mon set freq 2412" in err


def test_band_crossings_are_never_suppressed(stub, capsys):
    """The hop budget must not hide the change that splits a device in two."""
    # Three hops to exhaust the budget, then three crossings.
    freqs = [2412, 2437, 2462, 2412, 5180, 2412, 5745]
    stub(StubBackend(
        events=[ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=f)
                for f in freqs],
        die_after=OSError("done"),
    ))

    cli.main(PROBE_ARGS)

    err = capsys.readouterr().err
    # Said once in full, then counted and summarised.
    assert err.count("crossed bands") == 1
    assert "crossing between them 3 times" in err
    assert err.count("further hops within the band will not be reported") == 1


def test_the_run_reports_which_channels_it_covered(stub, capsys):
    freqs = [2412, 2437, 5180]
    stub(StubBackend(
        events=[ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=f)
                for f in freqs],
        die_after=OSError("done"),
    ))

    cli.main(PROBE_ARGS)

    err = capsys.readouterr().err
    assert "covers 3 channels (2412, 2437, 5180 MHz) across 2 band(s)" in err
    assert "crossing between them 1 times" in err


def test_a_single_channel_run_says_nothing_about_channels(stub, capsys):
    stub(StubBackend(
        events=[ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=2412)],
        die_after=OSError("done"),
    ))

    cli.main(PROBE_ARGS)
    assert "channels" not in capsys.readouterr().err


def test_the_first_channel_seen_is_not_a_change(stub, capsys):
    stub(StubBackend(
        events=[ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=2412)],
        die_after=OSError("done"),
    ))

    cli.main(PROBE_ARGS)
    assert "capture moved" not in capsys.readouterr().err


def test_within_band_hop_warnings_are_capped(stub, capsys):
    freqs = [2412, 2437, 2462, 2412, 2437, 2462]
    stub(StubBackend(
        events=[ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=f)
                for f in freqs],
        die_after=OSError("done"),
    ))

    cli.main(PROBE_ARGS)

    err = capsys.readouterr().err
    assert err.count("capture moved from") == 3
    assert "further hops within the band will not be reported" in err


def test_probes_without_a_frequency_are_not_a_change(stub, capsys):
    events = [
        ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=2412),
        ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=None),
        ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111", freq=2412),
    ]
    stub(StubBackend(events=events, die_after=OSError("done")))

    cli.main(PROBE_ARGS)
    assert "capture moved" not in capsys.readouterr().err


def test_verbose_prints_each_probe(stub, capsys):
    events = [ProbeEvent(mac="aa:11:11:11:11:01", ssid="HomeNet", rssi=-51,
                         fingerprint="1111111111111111")]
    stub(StubBackend(events=events, die_after=OSError("done")))

    cli.main(PROBE_ARGS + ["--verbose"])

    err = capsys.readouterr().err
    assert "probe  aa:11:11:11:11:01 ssid='HomeNet' rssi=-51dBm fp=11111111" in err


def test_per_mac_mode_relabels_the_count(stub, capsys):
    events = [
        ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111111111111111"),
        ProbeEvent(mac="ba:22:22:22:22:02", fingerprint="1111111111111111"),
    ]
    stub(StubBackend(events=events))
    threading.Timer(1.5, lambda: os.kill(os.getpid(), signal.SIGINT)).start()

    assert cli.main(PROBE_ARGS + ["--no-fingerprint"]) == 0

    out = capsys.readouterr().out
    assert "per-MAC" in out
    assert "unique MACs in vicinity (last 300s): 2" in out


def test_signal_handlers_are_restored_on_the_way_out(stub):
    # main() installs its own; leaving them behind would swallow the next
    # Ctrl-C of whatever called it.
    before = signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)

    stub(StubBackend(die_after=OSError("done")))
    cli.main(PROBE_ARGS)
    assert (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)) == before

    stub(StubBackend(start_error="nope"))
    cli.main(PROBE_ARGS)
    assert (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)) == before


def test_overlapping_addresses_are_reported_alongside_the_count(stub, capsys):
    events = [
        ProbeEvent(mac=mac, fingerprint="1111")
        for mac in ("aa:11:11:11:11:01", "ba:22:22:22:22:02", "ca:33:33:33:33:03")
        for _ in range(2)          # a burst each, not a single straggler
    ]
    backend = stub(StubBackend(events=events))
    threading.Timer(1.5, lambda: os.kill(os.getpid(), signal.SIGINT)).start()

    assert cli.main(PROBE_ARGS) == 0
    out = capsys.readouterr().out
    # One cluster, but three addresses transmitting at once inside it.
    assert "in vicinity (last 300s): 1" in out
    assert "at least 3: addresses overlap inside a device" in out


def test_nothing_extra_when_the_floor_agrees(stub, capsys):
    events = [ProbeEvent(mac="aa:11:11:11:11:01", fingerprint="1111")]
    stub(StubBackend(events=events))
    threading.Timer(1.5, lambda: os.kill(os.getpid(), signal.SIGINT)).start()

    assert cli.main(PROBE_ARGS) == 0
    assert "at least" not in capsys.readouterr().out
