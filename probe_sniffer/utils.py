"""MAC address utilities and 802.11 probe-request fingerprinting.

The IEEE 802 MAC address space carries two flags in the first octet:

    bit 0 (LSB) -> I/G bit:  0 = unicast, 1 = multicast/broadcast
    bit 1       -> U/L bit:  0 = universally administered (OUI assigned by IEEE)
                              1 = locally administered (often randomized)

Modern phones (iOS 8+, Android 8+, recent Windows) rotate locally-administered
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


# Radiotap presence bits, and the leading fields as (bit, size, alignment).
# Only the fields up to Channel are needed, and each one has to be stepped
# over in order because they are packed at their natural alignment.
_RADIOTAP_TSFT = 1 << 0
_RADIOTAP_FLAGS = 1 << 1
_RADIOTAP_CHANNEL = 1 << 3
_RADIOTAP_EXT = 1 << 31
_RADIOTAP_FLAG_FCS = 0x10

_RADIOTAP_LEADING_FIELDS = (
    (_RADIOTAP_TSFT, 8, 8),
    (_RADIOTAP_FLAGS, 1, 1),
    (1 << 2, 1, 1),            # Rate
    (_RADIOTAP_CHANNEL, 4, 2),  # u16 frequency, then u16 channel flags
)


def _radiotap_field_offsets(raw_frame: bytes) -> dict[int, int]:
    """Map presence bit -> offset for the leading radiotap fields."""
    if len(raw_frame) < 8 or raw_frame[0] != 0:
        return {}
    present = int.from_bytes(raw_frame[4:8], "little")

    # Chained presence bitmaps sit between the header and the field data.
    offset = 8
    chained = present
    while chained & _RADIOTAP_EXT:
        if offset + 4 > len(raw_frame):
            return {}
        chained = int.from_bytes(raw_frame[offset:offset + 4], "little")
        offset += 4

    offsets: dict[int, int] = {}
    for bit, size, alignment in _RADIOTAP_LEADING_FIELDS:
        if not present & bit:
            continue
        offset += -offset % alignment
        if offset + size > len(raw_frame):
            break
        offsets[bit] = offset
        offset += size
    return offsets


def has_trailing_fcs(raw_frame: bytes) -> bool:
    """True if radiotap says the frame carries its 4-byte FCS at the end.

    Some drivers hand the checksum up with the frame and some strip it. Left
    in place it parses as one more Information Element about 1% of the time,
    which is enough to give a device a fresh fingerprint on every probe.
    """
    offset = _radiotap_field_offsets(raw_frame).get(_RADIOTAP_FLAGS)
    if offset is None:
        return False
    return bool(raw_frame[offset] & _RADIOTAP_FLAG_FCS)


def parse_channel_mhz(raw_frame: bytes) -> int | None:
    """The frequency the frame was captured on, in MHz, if radiotap says.

    Worth knowing because a radio that changes band mid-capture counts every
    dual-band device twice: the same handset emits a different set of
    information elements on 2.4 GHz than it does on 5 GHz, so its fingerprint
    changes with the band.
    """
    offset = _radiotap_field_offsets(raw_frame).get(_RADIOTAP_CHANNEL)
    if offset is None:
        return None
    return int.from_bytes(raw_frame[offset:offset + 2], "little") or None


# IE IDs that vary per-frame from the same device and would destabilize the
# fingerprint if included. SSID (0) changes between wildcard and directed
# probes; DS Param Set (3) carries the current channel during channel hops.
_FINGERPRINT_SKIP_IDS = frozenset({0, 3})

# Elements whose contents describe the radio itself: supported rates, extended
# rates, HT/VHT capabilities, extended capabilities. These are the parts of
# a probe that belong to the chipset and driver, so their bodies are hashed.
_STABLE_BODY_IDS = frozenset({1, 45, 50, 59, 107, 127, 191})

# Element 255 is a container: its first body byte names the extension. Most
# describe the radio (35 is HE Capabilities, measured identical across every
# probe from an address), but 2 is FILS Request Parameters, which carries the
# channel time of the scan in progress and changes from probe to probe. Its
# presence and length still count; only the payload behind it is dropped.
_EXTENSION_ID = 255
_VOLATILE_EXTENSION_IDS = frozenset({2})

# Every other element contributes only its id and length. Peer-to-peer and
# Wi-Fi Aware devices put session state in theirs — counters and nonces that
# change on every single frame — and hashing those bodies hands the device a
# brand new identity with each probe it sends.
_VENDOR_SPECIFIC_ID = 221
_VENDOR_PREFIX_LEN = 4   # OUI plus vendor-specific type: stable, identifying


def parse_ies(raw_frame: bytes) -> list[tuple[int, bytes]]:
    """Parse IEs out of a raw 802.11 frame including a radiotap header.

    Radiotap header: byte 0 is the version (always 0) and bytes 2-3
    (little-endian) hold the total radiotap length. Probe request body starts
    immediately after the 24-byte 802.11 MAC header; there is no fixed body, so
    IEs begin at offset (radiotap_len + 24).

    A trailing FCS is dropped when radiotap reports one, so it cannot be read
    as an extra IE.

    Returns ``[]`` if the buffer is truncated or does not start with a radiotap
    header — a capture taken as plain DLT_IEEE802_11 begins with the frame
    control field instead, and parsing that as radiotap yields IEs made of
    whatever bytes happen to line up.
    """
    if len(raw_frame) < 28 or raw_frame[0] != 0:
        return []
    radiotap_len = raw_frame[2] | (raw_frame[3] << 8)
    if radiotap_len < 8 or radiotap_len + 24 > len(raw_frame):
        return []

    end = len(raw_frame) - 4 if has_trailing_fcs(raw_frame) else len(raw_frame)
    offset = radiotap_len + 24
    out: list[tuple[int, bytes]] = []
    while offset + 2 <= end:
        tag_id = raw_frame[offset]
        tag_len = raw_frame[offset + 1]
        body_start = offset + 2
        body_end = body_start + tag_len
        if body_end > end:
            break
        out.append((tag_id, raw_frame[body_start:body_end]))
        offset = body_end
    return out


def compute_ie_fingerprint(ies: Iterable[tuple[int, bytes]]) -> str | None:
    """Hash an ordered list of (IE id, IE body) pairs into a stable fingerprint.

    The id, length and order of every element are hashed. Bodies are hashed
    only where they describe the radio (see :data:`_STABLE_BODY_IDS`), plus the
    OUI of each vendor-specific element — the rest carry per-frame session
    state on some devices.

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
        if id_ in _STABLE_BODY_IDS:
            h.update(body)
        elif id_ == _VENDOR_SPECIFIC_ID:
            h.update(body[:_VENDOR_PREFIX_LEN])
        elif id_ == _EXTENSION_ID and body:
            h.update(body[:1])
            if body[0] not in _VOLATILE_EXTENSION_IDS:
                h.update(body[1:])
    return h.hexdigest()
