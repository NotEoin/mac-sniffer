"""Tests for MAC helpers and IE fingerprinting."""

import pytest

from probe_sniffer.utils import (
    compute_ie_fingerprint,
    is_locally_administered,
    is_multicast,
    is_valid_unicast,
    normalize_mac,
    parse_ies,
)

RANDOMIZED = "aa:bb:cc:dd:ee:ff"   # 0xaa -> U/L bit set
UNIVERSAL = "3c:22:fb:11:22:33"    # real Apple OUI, U/L bit clear


def test_normalize_mac_accepts_dashes_and_case():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == RANDOMIZED
    assert normalize_mac("  Aa:Bb:Cc:Dd:Ee:Ff  ") == RANDOMIZED


def test_locally_administered_bit():
    assert is_locally_administered(RANDOMIZED)
    assert not is_locally_administered(UNIVERSAL)
    assert not is_locally_administered("nonsense")


def test_multicast_bit():
    assert is_multicast("01:00:5e:00:00:fb")
    assert is_multicast("ff:ff:ff:ff:ff:ff")
    assert not is_multicast(UNIVERSAL)


@pytest.mark.parametrize(
    "mac",
    [
        "ff:ff:ff:ff:ff:ff",       # broadcast
        "00:00:00:00:00:00",       # all zeroes
        "01:00:5e:00:00:fb",       # multicast
        "3c:22:fb:11:22",          # too short
        "3c:22:fb:11:22:zz",       # not hex
        "",
    ],
)
def test_invalid_macs_are_rejected(mac):
    assert not is_valid_unicast(mac)


def test_valid_unicast_accepts_real_addresses():
    assert is_valid_unicast(UNIVERSAL)
    assert is_valid_unicast(RANDOMIZED)


# ---- IE parsing ----------------------------------------------------------


def build_frame(ies: list[tuple[int, bytes]], radiotap_len: int = 8) -> bytes:
    """A minimal radiotap + 802.11 header + IE blob, no scapy required."""
    radiotap = bytes([0, 0, radiotap_len & 0xFF, radiotap_len >> 8])
    radiotap += b"\x00" * (radiotap_len - len(radiotap))
    mac_header = b"\x40\x00" + b"\x00" * 22   # probe request, 24 bytes total
    body = b"".join(bytes([i, len(b)]) + b for i, b in ies)
    return radiotap + mac_header + body


def test_parse_ies_reads_tags_in_order():
    ies = [(0, b"HomeNet"), (1, b"\x02\x04\x0b\x16"), (50, b"\x0c\x12")]
    assert parse_ies(build_frame(ies)) == ies


def test_parse_ies_rejects_frames_without_a_radiotap_header():
    # Raw DLT_IEEE802_11 capture: starts with the frame control field.
    frame = b"\x40\x00" + b"\x00" * 40
    assert parse_ies(frame) == []


def test_parse_ies_rejects_truncated_and_bogus_lengths():
    assert parse_ies(b"") == []
    assert parse_ies(b"\x00" * 20) == []
    # radiotap length that runs past the end of the buffer
    assert parse_ies(bytes([0, 0, 0xFF, 0xFF]) + b"\x00" * 40) == []


def test_parse_ies_stops_at_a_truncated_tag():
    frame = build_frame([(0, b"Net")]) + bytes([45, 20]) + b"\x01\x02"
    assert parse_ies(frame) == [(0, b"Net")]


# ---- fingerprinting ------------------------------------------------------


FULL_IES = [
    (0, b"HomeNet"),
    (1, b"\x02\x04\x0b\x16"),
    (50, b"\x0c\x12\x18\x60"),
    (45, b"\x2d\x40\x1b\xff"),
]


def test_fingerprint_ignores_ssid_and_channel():
    roaming = [
        (0, b"CoffeeShop"),          # different SSID
        (1, b"\x02\x04\x0b\x16"),
        (3, b"\x0b"),                # DS param set: current channel
        (50, b"\x0c\x12\x18\x60"),
        (45, b"\x2d\x40\x1b\xff"),
    ]
    assert compute_ie_fingerprint(roaming) == compute_ie_fingerprint(FULL_IES)


def test_fingerprint_differs_for_different_chipsets():
    other = FULL_IES[:-1] + [(45, b"\x2d\x40\x1b\x00")]
    assert compute_ie_fingerprint(other) != compute_ie_fingerprint(FULL_IES)


def test_fingerprint_depends_on_tag_order():
    reordered = [FULL_IES[0], FULL_IES[2], FULL_IES[1], FULL_IES[3]]
    assert compute_ie_fingerprint(reordered) != compute_ie_fingerprint(FULL_IES)


def test_sparse_probes_have_no_fingerprint():
    # One usable tag is not discriminating enough to merge devices on.
    assert compute_ie_fingerprint([]) is None
    assert compute_ie_fingerprint([(0, b"HomeNet")]) is None
    assert compute_ie_fingerprint([(0, b"HomeNet"), (3, b"\x06")]) is None
    assert compute_ie_fingerprint([(1, b"\x02\x04")]) is None


def test_fingerprint_separates_tag_boundaries():
    # Naive concatenation would hash these two IE sets identically.
    a = [(221, b"\x00\x10\x18"), (1, b"\x02")]
    b = [(221, b"\x00\x10"), (1, b"\x18\x02")]
    assert compute_ie_fingerprint(a) != compute_ie_fingerprint(b)
