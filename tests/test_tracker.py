"""Tests for the sliding-window device tracker."""

import pytest

from probe_sniffer.tracker import DeviceTracker

FP_PIXEL = "1111111111111111"
FP_IPHONE = "2222222222222222"

UNIVERSAL_A = "3c:22:fb:11:22:33"
UNIVERSAL_B = "3c:22:fb:44:55:66"


class FakeClock:
    """Manually advanced clock, so window expiry is testable without sleeping."""

    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


def make_tracker(clock, **kwargs) -> DeviceTracker:
    return DeviceTracker(clock=clock, **kwargs)


def test_rejects_non_positive_window():
    with pytest.raises(ValueError):
        DeviceTracker(window_seconds=0)


def test_one_phone_rotating_macs_counts_once(clock):
    tracker = make_tracker(clock)
    for mac in ("aa:11:11:11:11:01", "ba:22:22:22:22:02", "ca:33:33:33:33:03"):
        tracker.observe(mac, fingerprint=FP_PIXEL)

    assert tracker.count() == 1
    stats = tracker.stats()
    assert stats.randomized_in_window == 1
    assert stats.macs_in_window == 3


def test_different_fingerprints_stay_separate(clock):
    tracker = make_tracker(clock)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_PIXEL)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_IPHONE)
    assert tracker.count() == 2


def test_universal_macs_are_never_merged_by_fingerprint(clock):
    # Two laptops with real OUIs and identical chipsets are still two devices.
    tracker = make_tracker(clock)
    tracker.observe(UNIVERSAL_A, fingerprint=FP_PIXEL)
    tracker.observe(UNIVERSAL_B, fingerprint=FP_PIXEL)

    assert tracker.count() == 2
    assert tracker.stats().universal_in_window == 2


def test_randomized_macs_without_a_fingerprint_fall_back_to_the_mac(clock):
    tracker = make_tracker(clock)
    tracker.observe("aa:11:11:11:11:01", fingerprint=None)
    tracker.observe("ba:22:22:22:22:02", fingerprint=None)
    assert tracker.count() == 2


def test_clustering_can_be_disabled(clock):
    tracker = make_tracker(clock, cluster_by_fingerprint=False)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_PIXEL)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_PIXEL)
    assert tracker.count() == 2


def test_randomized_macs_can_be_excluded(clock):
    tracker = make_tracker(clock, include_randomized=False)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_PIXEL)
    tracker.observe(UNIVERSAL_A)

    assert tracker.count() == 1
    assert tracker.stats().randomized_in_window == 0


def test_broadcast_and_malformed_addresses_are_ignored(clock):
    tracker = make_tracker(clock)
    for mac in ("ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb", "00:00:00:00:00:00", "junk"):
        tracker.observe(mac, fingerprint=FP_PIXEL)
    assert tracker.count() == 0


def test_devices_leave_the_window_but_stay_in_the_running_total(clock):
    tracker = make_tracker(clock, window_seconds=300)
    tracker.observe(UNIVERSAL_A)

    clock.advance(299)
    assert tracker.count() == 1

    clock.advance(2)
    assert tracker.count() == 0
    assert tracker.stats().total_unique_ever == 1


def test_a_returning_device_refreshes_the_window(clock):
    tracker = make_tracker(clock, window_seconds=300)
    tracker.observe(UNIVERSAL_A)

    clock.advance(200)
    tracker.observe(UNIVERSAL_A)
    clock.advance(200)

    assert tracker.count() == 1
    assert tracker.stats().total_unique_ever == 1


def test_snapshot_records_metadata_and_does_not_alias_state(clock):
    tracker = make_tracker(clock)
    tracker.observe("aa:11:11:11:11:01", ssid="HomeNet", rssi=-51, fingerprint=FP_PIXEL)
    tracker.observe("ba:22:22:22:22:02", rssi=-48, fingerprint=FP_PIXEL)

    (record,) = tracker.snapshot()
    assert record.hits == 2
    assert record.randomized
    assert record.last_ssid == "HomeNet"   # kept: the later probe was a wildcard
    assert record.last_rssi == -48
    assert set(record.macs) == {"aa:11:11:11:11:01", "ba:22:22:22:22:02"}

    record.macs["spoofed"] = clock.now
    assert tracker.stats().macs_in_window == 2


def test_explicit_timestamps_drive_the_window(clock):
    tracker = make_tracker(clock, window_seconds=60)
    tracker.observe(UNIVERSAL_A, ts=clock.now - 3600)
    assert tracker.count() == 0


def test_addresses_are_normalized_before_clustering(clock):
    tracker = make_tracker(clock)
    tracker.observe("3C-22-FB-11-22-33")
    tracker.observe(UNIVERSAL_A)
    assert tracker.count() == 1


def test_macs_seen_is_scoped_to_the_window(clock):
    """macs-seen is scoped to the window, not to the cluster's lifetime.

    Otherwise clustered and per-MAC counting disagree about macs-seen on the
    same traffic, and the comparison the README invites is nonsense.
    """
    tracker = make_tracker(clock, window_seconds=300)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_PIXEL)

    clock.advance(200)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_PIXEL)
    assert tracker.stats().macs_in_window == 2

    # The first address has now aged out, but the phone is still here.
    clock.advance(200)
    tracker.observe("ca:33:33:33:33:03", fingerprint=FP_PIXEL)

    stats = tracker.stats()
    assert stats.active_in_window == 1
    assert stats.macs_in_window == 2      # not 3: the first one is stale


def test_a_long_lived_cluster_does_not_grow_without_bound(clock):
    tracker = make_tracker(clock, window_seconds=300)
    for i in range(50):
        tracker.observe(f"aa:11:11:11:11:{i:02x}", fingerprint=FP_PIXEL)
        clock.advance(60)

    (record,) = tracker.snapshot()
    assert tracker.count() == 1
    assert len(record.macs) <= 6          # a 300s window at one a minute


# ---- joining clusters through a shared address ---------------------------

FP_24GHZ = "aaaaaaaaaaaaaaaa"   # a dual-band device on 2.4 GHz
FP_5GHZ = "bbbbbbbbbbbbbbbb"    # the same radio on 5 GHz


def test_one_address_under_two_fingerprints_is_one_device(clock):
    """A dual-band radio advertises different elements per band.

    The address is the evidence that the two fingerprints are one device.
    """
    tracker = make_tracker(clock)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_24GHZ)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_5GHZ)

    assert tracker.count() == 1
    stats = tracker.stats()
    assert stats.total_unique_ever == 1
    assert stats.macs_in_window == 1


def test_the_join_survives_a_rotation(clock):
    tracker = make_tracker(clock)
    # Seen on both bands under one address, then rotates and is seen again.
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_24GHZ)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_5GHZ)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_24GHZ)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_5GHZ)

    assert tracker.count() == 1
    assert tracker.stats().macs_in_window == 2


def test_two_established_clusters_join_when_an_address_bridges_them(clock):
    tracker = make_tracker(clock)
    # Two clusters build up separately...
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_24GHZ)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_24GHZ)
    tracker.observe("ca:33:33:33:33:03", fingerprint=FP_5GHZ)
    assert tracker.count() == 2

    # ...then one address turns up under both.
    tracker.observe("ca:33:33:33:33:03", fingerprint=FP_24GHZ)

    assert tracker.count() == 1
    record = tracker.snapshot()[0]
    assert set(record.macs) == {
        "aa:11:11:11:11:01", "ba:22:22:22:22:02", "ca:33:33:33:33:03",
    }
    assert record.hits == 4


def test_joining_keeps_the_earliest_first_seen(clock):
    tracker = make_tracker(clock)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_24GHZ)
    start = clock.now

    clock.advance(30)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_5GHZ)
    clock.advance(10)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_24GHZ)

    (record,) = tracker.snapshot()
    assert record.first_seen == start
    assert record.last_seen == clock.now


def test_unrelated_devices_are_not_joined(clock):
    tracker = make_tracker(clock)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_24GHZ)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_5GHZ)
    assert tracker.count() == 2


def test_universal_addresses_are_untouched_by_joining(clock):
    tracker = make_tracker(clock)
    tracker.observe(UNIVERSAL_A, fingerprint=FP_24GHZ)
    tracker.observe(UNIVERSAL_A, fingerprint=FP_5GHZ)
    tracker.observe(UNIVERSAL_B, fingerprint=FP_24GHZ)

    # Universal addresses were never keyed on the fingerprint to begin with.
    assert tracker.count() == 2


def test_joining_is_off_when_clustering_is(clock):
    tracker = make_tracker(clock, cluster_by_fingerprint=False)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_24GHZ)
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_5GHZ)
    assert tracker.count() == 2


def test_the_join_bookkeeping_does_not_grow_without_bound(clock):
    tracker = make_tracker(clock, window_seconds=60)
    for i in range(40):
        mac = f"aa:11:11:11:11:{i:02x}"
        tracker.observe(mac, fingerprint=f"fp-{i}")
        tracker.observe(mac, fingerprint=f"fp-other-{i}")
        clock.advance(30)

    assert tracker.count() <= 2
    assert len(tracker._cluster_of_mac) <= 4
    assert len(tracker._merged_into) <= 4


def test_a_fingerprint_first_seen_during_a_join_is_remembered(clock):
    """Regression: the second fingerprint had no cluster of its own yet.

    Returning early without recording the link lost it, and the next probe
    carrying that fingerprint opened a second cluster for a known device.
    """
    tracker = make_tracker(clock)
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_24GHZ)
    # First sighting of the 5 GHz fingerprint, under a known address.
    tracker.observe("aa:11:11:11:11:01", fingerprint=FP_5GHZ)
    # A rotated address carrying only that fingerprint must not start afresh.
    tracker.observe("ba:22:22:22:22:02", fingerprint=FP_5GHZ)

    assert tracker.count() == 1
    assert set(tracker.snapshot()[0].macs) == {
        "aa:11:11:11:11:01", "ba:22:22:22:22:02",
    }
