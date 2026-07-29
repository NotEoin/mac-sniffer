"""MAC address utilities and 802.11 probe-request fingerprinting.

The IEEE 802 MAC address space carries two flags in the first octet:

    bit 0 (LSB) -> I/G bit:  0 = unicast, 1 = multicast/broadcast
    bit 1       -> U/L bit:  0 = universally administered (OUI assigned by IEEE)
                              1 = locally administered (often randomized)

Modern phones (iOS 14+, Android 10+, recent Windows) rotate locally-administered
MACs when sending probe requests. To re-aggregate them we hash the probe's
Information Elements (capabilities, supported rates, vendor tags) — the IE
fingerprint stays stable across the MAC rotations of a single radio.
"""

from __future__ import annotations

import hashlib
from typing import Iterable


def normalize_mac(mac: str) -> str:
    """Return a canonical lowercase form: ``aa:bb:cc:dd:ee:ff``."""
    return mac.strip().lower().replace("-", ":")


def is_locally_administered(mac: str) -> bool:
    """True if the U/L bit is set on the first octet (likely randomized)."""
    try:
        first_octet = int(mac.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b00000010)


def is_multicast(mac: str) -> bool:
    """True if the I/G bit is set on the first octet (broadcast/multicast)."""
    try:
        first_octet = int(mac.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b00000001)


def is_valid_unicast(mac: str) -> bool:
    """Quick sanity check that a string looks like a real unicast MAC."""
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return False
    if all(o == 0 for o in octets) or all(o == 0xFF for o in octets):
        return False
    return not is_multicast(mac)


# IE IDs that vary per-frame from the same device and would destabilize the
# fingerprint if included. SSID (0) changes between wildcard and directed
# probes; DS Param Set (3) carries the current channel during channel hops.
_FINGERPRINT_SKIP_IDS = frozenset({0, 3})


def parse_ies(raw_frame: bytes) -> list[tuple[int, bytes]]:
    """Parse IEs out of a raw 802.11 frame including a radiotap header.

    Radiotap header: bytes 2-3 (little-endian) hold the total radiotap length.
    Probe request body starts immediately after the 24-byte 802.11 MAC header;
    there is no fixed body, so IEs begin at offset (radiotap_len + 24).
    Returns ``[]`` if the buffer is truncated or malformed.
    """
    if len(raw_frame) < 28:
        return []
    radiotap_len = raw_frame[2] | (raw_frame[3] << 8)
    offset = radiotap_len + 24
    out: list[tuple[int, bytes]] = []
    while offset + 2 <= len(raw_frame):
        tag_id = raw_frame[offset]
        tag_len = raw_frame[offset + 1]
        body_start = offset + 2
        body_end = body_start + tag_len
        if body_end > len(raw_frame):
            break
        out.append((tag_id, raw_frame[body_start:body_end]))
        offset = body_end
    return out


def compute_ie_fingerprint(ies: Iterable[tuple[int, bytes]]) -> str | None:
    """Hash an ordered list of (IE id, IE body) pairs into a stable fingerprint.

    Returns ``None`` if the IE set is too sparse to be discriminating (e.g. a
    bare probe with only "supported rates"). Callers should fall back to per-MAC
    identity in that case rather than collapsing unrelated devices together.
    """
    relevant = [(i, b) for (i, b) in ies if i not in _FINGERPRINT_SKIP_IDS]
    if len(relevant) < 2:
        return None

    h = hashlib.blake2b(digest_size=8)
    for id_, body in relevant:
        h.update(bytes([id_ & 0xFF, len(body) & 0xFF]))
        h.update(body)
    return h.hexdigest()
