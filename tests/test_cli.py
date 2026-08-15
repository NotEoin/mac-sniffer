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
