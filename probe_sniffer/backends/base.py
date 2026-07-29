"""Common interface for sniffing backends."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable


@dataclass
class ProbeEvent:
    """A single probe-request observation passed to the tracker."""

    mac: str
    ssid: str | None = None
    rssi: int | None = None
    ts: float | None = None
    # IE fingerprint: stable across MAC rotations of the same radio. ``None``
    # when the backend couldn't extract one or the IE set was too sparse.
    fingerprint: str | None = None


class SnifferBackend(ABC):
    """Abstract base for a probe-request sniffer.

    Subclasses run a blocking capture loop in :meth:`_run`. The public
    :meth:`start` spawns a daemon thread, :meth:`stop` requests termination.
    """

    def __init__(self, iface: str, on_event: Callable[[ProbeEvent], None]):
        self.iface = iface
        self.on_event = on_event
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- lifecycle --------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("backend already started")
        self._thread = threading.Thread(
            target=self._safe_run,
            name=f"{type(self).__name__}({self.iface})",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # ---- subclass API -----------------------------------------------------

    def _safe_run(self) -> None:
        try:
            self._run()
        except Exception as exc:  # pragma: no cover - surface in CLI
            import sys
            print(f"\n[backend error] {type(exc).__name__}: {exc}", file=sys.stderr)

    @abstractmethod
    def _run(self) -> None:
        """Blocking sniff loop. Must check :attr:`stopping` periodically."""
        raise NotImplementedError
