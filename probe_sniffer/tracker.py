"""Sliding-window device tracker with optional IE-fingerprint clustering.

A "device" is a cluster of probe-request observations. The cluster *key* is:

* the MAC itself, when the MAC looks universally administered (real OUI), or
  when we have no fingerprint to work with.
* the IE fingerprint, when the MAC is locally administered (likely randomized)
  and the probe carried enough IEs to be discriminating.

This collapses the dozens-of-random-MACs-per-phone problem down to roughly one
cluster per physical radio. Same-model devices in the same area will collide
(that is the floor); a single phone rotating MACs becomes one cluster.

A device counts as "in the vicinity" if any of its observations is newer than
``window_seconds``. Stale clusters are evicted on every query (lazy expiry).

Set ``cluster_by_fingerprint=False`` to fall back to per-MAC counting.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .utils import is_locally_administered, is_valid_unicast, normalize_mac


@dataclass
class DeviceRecord:
    key: str
    first_seen: float
    last_seen: float
    hits: int = 0
    last_ssid: str | None = None
    last_rssi: int | None = None
    randomized: bool = False
    macs: set[str] = field(default_factory=set)


@dataclass
class TrackerStats:
    window_seconds: int
    total_unique_ever: int
    active_in_window: int
    randomized_in_window: int
    universal_in_window: int
    macs_in_window: int


class DeviceTracker:
    """Thread-safe sliding-window tracker."""

    def __init__(
        self,
        window_seconds: int = 300,
        include_randomized: bool = True,
        cluster_by_fingerprint: bool = True,
    ):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self.include_randomized = include_randomized
        self.cluster_by_fingerprint = cluster_by_fingerprint

        self._lock = threading.Lock()
        self._devices: dict[str, DeviceRecord] = {}
        self._total_unique_ever: set[str] = set()

    # ---- ingest -----------------------------------------------------------

    def _cluster_key(
        self, mac: str, randomized: bool, fingerprint: str | None
    ) -> str:
        # Universal MACs are already stable identifiers — never merge two of
        # them just because they share a fingerprint. For randomized MACs the
        # fingerprint is the most stable thing we have; fall back to the MAC
        # only when the IE set was too sparse to fingerprint.
        if self.cluster_by_fingerprint and randomized and fingerprint:
            return f"fp:{fingerprint}"
        return f"mac:{mac}"

    def observe(
        self,
        mac: str,
        *,
        ssid: str | None = None,
        rssi: int | None = None,
        ts: float | None = None,
        fingerprint: str | None = None,
    ) -> None:
        """Record a probe-request observation."""
        mac_norm = normalize_mac(mac)
        if not is_valid_unicast(mac_norm):
            return

        randomized = is_locally_administered(mac_norm)
        if randomized and not self.include_randomized:
            return

        now = ts if ts is not None else time.time()
        key = self._cluster_key(mac_norm, randomized, fingerprint)

        with self._lock:
            rec = self._devices.get(key)
            if rec is None:
                rec = DeviceRecord(
                    key=key,
                    first_seen=now,
                    last_seen=now,
                    randomized=randomized,
                )
                self._devices[key] = rec
                self._total_unique_ever.add(key)
            else:
                rec.last_seen = now
            rec.hits += 1
            rec.macs.add(mac_norm)
            if ssid:
                rec.last_ssid = ssid
            if rssi is not None:
                rec.last_rssi = rssi

    # ---- query ------------------------------------------------------------

    def _evict_locked(self, now: float) -> None:
        cutoff = now - self.window_seconds
        stale = [k for k, r in self._devices.items() if r.last_seen < cutoff]
        for k in stale:
            del self._devices[k]

    def count(self) -> int:
        """Number of unique device clusters seen within the sliding window."""
        now = time.time()
        with self._lock:
            self._evict_locked(now)
            return len(self._devices)

    def snapshot(self) -> list[DeviceRecord]:
        """All currently-active device records (deep-ish copies)."""
        now = time.time()
        with self._lock:
            self._evict_locked(now)
            return [
                DeviceRecord(
                    key=r.key,
                    first_seen=r.first_seen,
                    last_seen=r.last_seen,
                    hits=r.hits,
                    last_ssid=r.last_ssid,
                    last_rssi=r.last_rssi,
                    randomized=r.randomized,
                    macs=set(r.macs),
                )
                for r in self._devices.values()
            ]

    def stats(self) -> TrackerStats:
        now = time.time()
        with self._lock:
            self._evict_locked(now)
            randomized = sum(1 for r in self._devices.values() if r.randomized)
            macs_in_window = sum(len(r.macs) for r in self._devices.values())
            return TrackerStats(
                window_seconds=self.window_seconds,
                total_unique_ever=len(self._total_unique_ever),
                active_in_window=len(self._devices),
                randomized_in_window=randomized,
                universal_in_window=len(self._devices) - randomized,
                macs_in_window=macs_in_window,
            )
