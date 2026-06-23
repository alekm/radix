"""Unit tests for the pure crypto / parsing helpers in dpsk.py.

These lock in the PTK/MIC algorithm and the TP-Link blob byte offsets that were
reverse-engineered from live captures, so a stray off-by-one is caught instantly.
"""
import hashlib
import hmac

import dpsk

AP_MAC     = 'aa:bb:cc:dd:ee:ff'
CLIENT_MAC = '11:22:33:44:55:66'


def _derive_kck(pmk, ap_mac, client_mac, anonce, snonce):
    """Mirror the sorting dpsk._verify_mic does, then take the KCK (ptk[:16])."""
    macs = sorted([
        bytes.fromhex(ap_mac.replace(':', '')),
        bytes.fromhex(client_mac.replace(':', '')),
    ])
    nonces = sorted([anonce, snonce])
    ptk = dpsk._derive_ptk(pmk, macs[0], macs[1], nonces[0], nonces[1])
    return ptk[:16]


def _build_eapol(kck, snonce, snonce_offset=34, length=121):
    """Build a frame whose MIC at [81:97] matches HMAC-SHA1 over the zeroed frame."""
    eapol = bytearray(length)
    eapol[snonce_offset:snonce_offset + 32] = snonce
    # MIC region starts zeroed; compute MIC over the zeroed frame, then insert it.
    mic = hmac.new(kck, bytes(eapol), hashlib.sha1).digest()[:16]
    eapol[81:97] = mic
    return bytes(eapol)


def test_mic_roundtrip_accepts_valid_frame():
    pmk    = bytes(range(32))
    anonce = bytes([0x11]) * 32
    snonce = bytes([0x22]) * 32
    kck    = _derive_kck(pmk, AP_MAC, CLIENT_MAC, anonce, snonce)
    eapol  = _build_eapol(kck, snonce, snonce_offset=34)

    assert dpsk._verify_mic(pmk, AP_MAC, CLIENT_MAC, anonce.hex(), eapol.hex(), 34) is True


def test_mic_roundtrip_tplink_offset():
    # TP-Link carries SNonce at offset 17 rather than the usual 34.
    pmk    = bytes(range(32))
    anonce = bytes([0xAB]) * 32
    snonce = bytes([0xCD]) * 32
    kck    = _derive_kck(pmk, AP_MAC, CLIENT_MAC, anonce, snonce)
    eapol  = _build_eapol(kck, snonce, snonce_offset=17)

    assert dpsk._verify_mic(pmk, AP_MAC, CLIENT_MAC, anonce.hex(), eapol.hex(), 17) is True


def test_mic_rejects_tampered_mic():
    pmk    = bytes(range(32))
    anonce = bytes([0x11]) * 32
    snonce = bytes([0x22]) * 32
    kck    = _derive_kck(pmk, AP_MAC, CLIENT_MAC, anonce, snonce)
    eapol  = bytearray(_build_eapol(kck, snonce, snonce_offset=34))
    eapol[81] ^= 0xFF  # flip a MIC byte

    assert dpsk._verify_mic(pmk, AP_MAC, CLIENT_MAC, anonce.hex(), bytes(eapol).hex(), 34) is False


def test_mic_rejects_wrong_pmk():
    anonce = bytes([0x11]) * 32
    snonce = bytes([0x22]) * 32
    kck    = _derive_kck(bytes(range(32)), AP_MAC, CLIENT_MAC, anonce, snonce)
    eapol  = _build_eapol(kck, snonce, snonce_offset=34)

    wrong_pmk = bytes([0xFF]) * 32
    assert dpsk._verify_mic(wrong_pmk, AP_MAC, CLIENT_MAC, anonce.hex(), eapol.hex(), 34) is False


def _tlv(t, value):
    """Encode one sub-TLV the way _tplink_parse decodes it: [type, len, value...] where len = len(value)+2."""
    return bytes([t, len(value) + 2]) + value


def test_tplink_parse_extracts_fields():
    eapol_body = bytes([0x01, 0x02, 0x03, 0x04])
    anonce     = bytes(range(32))
    ssid       = b'TestNet'
    bssid      = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

    blob = (
        _tlv(1, eapol_body) +
        _tlv(2, anonce) +
        _tlv(3, ssid) +
        _tlv(6, bssid)
    )

    eapol, anonce_hex, parsed_ssid, ap_mac = dpsk._tplink_parse(
        {'TPLink-Authentication-FindKey': blob}
    )

    assert eapol == eapol_body
    assert anonce_hex == anonce.hex()
    assert parsed_ssid == 'TestNet'
    assert ap_mac == 'aa:bb:cc:dd:ee:ff'


def test_tplink_parse_falls_back_to_sub4_for_bssid():
    bssid = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    blob  = _tlv(1, b'\x00\x00') + _tlv(4, bssid)

    _, _, _, ap_mac = dpsk._tplink_parse({'TPLink-Authentication-FindKey': blob})
    assert ap_mac == '01:02:03:04:05:06'


def test_build_reply_vlan_uses_enum_name_not_integer():
    # Regression: Tunnel-Medium-Type '6' is silently dropped by FreeRADIUS.
    reply = dpsk._build_reply('openwifi', pmk=b'', psk='secret', vlan_id=42)
    assert reply['Tunnel-Medium-Type'] == 'IEEE-802'
    assert reply['Tunnel-Private-Group-Id'] == '42'
    assert reply['Tunnel-Password'] == 'secret'
