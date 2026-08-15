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
        self._finished = threading.Event()
        self._error: BaseException | None = None
        self._thread: threading.Thread | None = None

    # ---- lifecycle --------------------------------------------------------

    def start(self, ready_timeout: float = 1.0) -> None:
        """Spawn the capture thread.

        Blocks for up to ``ready_timeout`` seconds so that a capture which
        fails immediately (missing interface, missing dependency) raises here
        instead of leaving the caller reporting an empty count forever.
        """
        if self._thread is not None:
            raise RuntimeError("backend already started")
        self._thread = threading.Thread(
            target=self._safe_run,
            name=f"{type(self).__name__}({self.iface})",
            daemon=True,
        )
        self._thread.start()
        self._finished.wait(ready_timeout)
        if self._error is not None:
            raise RuntimeError(
                f"{type(self._error).__name__}: {self._error}"
            ) from self._error

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    @property
    def alive(self) -> bool:
        """True while the capture thread is still running."""
        return self._thread is not None and not self._finished.is_set()

    @property
    def error(self) -> BaseException | None:
        """The exception that ended the capture loop, if any."""
        return self._error

    # ---- subclass API -----------------------------------------------------

    def _safe_run(self) -> None:
        try:
            self._run()
        except BaseException as exc:  # noqa: BLE001 - reported via .error
            self._error = exc
        finally:
            self._finished.set()

    @abstractmethod
    def _run(self) -> None:
        """Blocking sniff loop. Must check :attr:`stopping` periodically."""
        raise NotImplementedError
