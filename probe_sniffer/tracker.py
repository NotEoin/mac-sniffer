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
from typing import Callable

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
    # address -> when it was last heard, so the count can be scoped to the
    # window. A cluster outlives the addresses it was built from.
    macs: dict[str, float] = field(default_factory=dict)


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
        clock: Callable[[], float] = time.time,
    ):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self.include_randomized = include_randomized
        self.cluster_by_fingerprint = cluster_by_fingerprint
        # Swappable so replays and tests can drive the window without sleeping.
        self.clock = clock

        self._lock = threading.Lock()
        self._devices: dict[str, DeviceRecord] = {}
        self._total_unique_ever: set[str] = set()
        # Which cluster an address currently belongs to, and where clusters
        # have been merged away to. See :meth:`_link_locked`.
        self._cluster_of_mac: dict[str, str] = {}
        self._merged_into: dict[str, str] = {}

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

    def _resolve(self, key: str) -> str:
        """Follow a cluster key through any merges it has been through."""
        seen = 0
        while key in self._merged_into and seen < len(self._merged_into) + 1:
            key = self._merged_into[key]
            seen += 1
        return key

    def _link_locked(self, mac: str, key: str, now: float) -> str:
        """Return the cluster this observation belongs to, merging if needed.

        A randomised address is 46 bits of noise, so one turning up under two
        fingerprints is not a coincidence: it is one radio that fingerprints
        differently in different circumstances. The clearest case is a
        dual-band device, which advertises different elements on 2.4 GHz than
        on 5 GHz and so splits in two — measured at 12-39% of the count.

        So join the two clusters, rather than weakening the fingerprint to
        cover it.
        """
        key = self._resolve(key)
        previous = self._cluster_of_mac.get(mac)
        if previous is not None:
            previous = self._resolve(previous)
            if previous != key and previous in self._devices:
                key = self._merge_locked(previous, key, now)
        self._cluster_of_mac[mac] = key
        return key

    def _merge_locked(self, one: str, other: str, now: float) -> str:
        """Fold two clusters together, keeping the one seen first."""
        if one == other:
            return one

        left, right = self._devices.get(one), self._devices.get(other)
        # One side may have no record yet — this is the first probe carrying
        # that fingerprint. Remember the link anyway, or the next probe that
        # carries it starts a second cluster for a device we have already
        # identified.
        if right is None:
            self._merged_into[other] = one
            return one
        if left is None:
            self._merged_into[one] = other
            return other

        survivor, absorbed = (left, right) if left.first_seen <= right.first_seen \
            else (right, left)
        survivor.first_seen = min(left.first_seen, right.first_seen)
        survivor.last_seen = max(left.last_seen, right.last_seen)
        survivor.hits += absorbed.hits
        survivor.macs.update(absorbed.macs)
        survivor.randomized = survivor.randomized or absorbed.randomized
        if survivor.last_ssid is None:
            survivor.last_ssid = absorbed.last_ssid
        if absorbed.last_seen > survivor.last_seen or survivor.last_rssi is None:
            survivor.last_rssi = absorbed.last_rssi if absorbed.last_rssi is not None \
                else survivor.last_rssi

        del self._devices[absorbed.key]
        self._merged_into[absorbed.key] = survivor.key
        self._total_unique_ever.discard(absorbed.key)
        return survivor.key

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

        now = ts if ts is not None else self.clock()
        key = self._cluster_key(mac_norm, randomized, fingerprint)

        with self._lock:
            key = self._link_locked(mac_norm, key, now)
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
            rec.macs[mac_norm] = now
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
        # Drop the addresses a surviving cluster has stopped using. Without
        # this a phone that rotates every few minutes grows its cluster for
        # as long as the capture runs.
        for rec in self._devices.values():
            if any(seen < cutoff for seen in rec.macs.values()):
                rec.macs = {m: t for m, t in rec.macs.items() if t >= cutoff}

        # The merge bookkeeping is scoped to the live clusters for the same
        # reason: neither map should outgrow what is actually in the window.
        if stale:
            self._cluster_of_mac = {
                mac: key
                for key, rec in self._devices.items()
                for mac in rec.macs
            }
            self._merged_into = {
                absorbed: survivor
                for absorbed, survivor in self._merged_into.items()
                if self._resolve(survivor) in self._devices
            }

    def count(self) -> int:
        """Number of unique device clusters seen within the sliding window."""
        now = self.clock()
        with self._lock:
            self._evict_locked(now)
            return len(self._devices)

    def snapshot(self) -> list[DeviceRecord]:
        """All currently-active device records (deep-ish copies)."""
        now = self.clock()
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
                    macs=dict(r.macs),
                )
                for r in self._devices.values()
            ]

    def stats(self) -> TrackerStats:
        now = self.clock()
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
