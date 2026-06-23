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


def test_extract_openwifi():
    attrs = {
        'Called-Station-Id': 'AA-BB-CC-DD-EE-FF:MySSID',
        'FreeRADIUS-802.1X-EAPoL-Key-Msg': 'deadbeef',
        'FreeRADIUS-802.1X-Anonce': 'cafe',
    }
    ssid, ap_mac, eapol_hex, anonce_hex = dpsk._extract('openwifi', attrs)
    assert ssid == 'MySSID'
    assert ap_mac == 'aa:bb:cc:dd:ee:ff'
    assert eapol_hex == 'deadbeef'
    assert anonce_hex == 'cafe'


def test_extract_ruckus_slices_packed_attr():
    anonce  = 'ab' * 32                       # 64 hex chars at offset 22
    msg_len = 5
    body    = 'cd' * (msg_len + 4)            # (msg_len*2 + 8) hex chars at offset 90
    packed  = (
        '00' * 11 +                           # offsets 0..21
        anonce +                              # 22..85
        '00' * 2 +                            # 86..89
        body +                                # 90..
        '00' * 50                             # padding past msg_len marker
    )
    # Patch the msg_len marker (offset 96, 2 hex chars) to match `body` length.
    packed = packed[:96] + f'{msg_len:02x}' + packed[98:]
    attrs = {
        'Attr-26.25053.153': packed,
        'Ruckus-SSID': 'CorpWiFi',
        'NAS-Identifier': 'AA-BB-CC-00-11-22',
    }
    ssid, ap_mac, eapol_hex, anonce_hex = dpsk._extract('ruckus', attrs)
    assert ssid == 'CorpWiFi'
    assert ap_mac == 'aa:bb:cc:00:11:22'
    assert anonce_hex == anonce
    assert eapol_hex == packed[90:90 + (msg_len * 2) + 8]


def test_build_reply_vlan_uses_enum_name_not_integer():
    # Regression: Tunnel-Medium-Type '6' is silently dropped by FreeRADIUS.
    reply = dpsk._build_reply('openwifi', pmk=b'', psk='secret', vlan_id=42)
    assert reply['Tunnel-Medium-Type'] == 'IEEE-802'
    assert reply['Tunnel-Private-Group-Id'] == '42'
    assert reply['Tunnel-Password'] == 'secret'


def test_tplink_reply_no_vlan_omits_tunnel_attrs():
    # Blank VLAN => no Tunnel-* attrs, so the AP keeps the client on the SSID's
    # own (untagged/local) network instead of a forced tagged VLAN.
    reply = dpsk._build_tplink_reply('secret', None, pmk=b'\x01' * 32)
    assert reply['Tunnel-Password'] == 'secret'
    assert reply['TPLink-EAPOL-Found-PMK'] == b'\x01' * 32
    assert 'Tunnel-Type' not in reply
    assert 'Tunnel-Private-Group-Id' not in reply
    assert 'Tunnel-Medium-Type' not in reply


def test_tplink_reply_with_vlan_includes_tunnel_attrs():
    reply = dpsk._build_tplink_reply('secret', 30)
    assert reply['Tunnel-Type'] == '13'
    assert reply['Tunnel-Medium-Type'] == 'IEEE-802'
    assert reply['Tunnel-Private-Group-Id'] == '30'


def test_evict_pmk_removes_only_matching_entries():
    dpsk._cache.clear()
    dpsk._to_cache('aa:aa', 'Net1', 5, b'pmk', 'psk', 100)
    dpsk._to_cache('bb:bb', 'Net1', 5, b'pmk', 'psk', 100)
    dpsk._to_cache('cc:cc', 'Net2', 6, b'pmk', 'psk', 100)

    assert dpsk._evict_pmk(5) == 2
    assert dpsk._from_cache('aa:aa', 'Net1') == (None, None, None)
    assert dpsk._from_cache('bb:bb', 'Net1') == (None, None, None)
    # A different PMK is untouched.
    pmk, psk, vlan = dpsk._from_cache('cc:cc', 'Net2')
    assert (pmk, psk, vlan) == (b'pmk', 'psk', 100)
    dpsk._cache.clear()


def test_on_revoke_all_flushes_cache():
    dpsk._cache.clear()
    dpsk._to_cache('aa:aa', 'Net1', 1, b'p', 'k', 1)
    dpsk._on_revoke('all')
    assert dpsk._cache == {}


def test_on_revoke_evicts_by_id():
    dpsk._cache.clear()
    dpsk._to_cache('aa:aa', 'Net1', 7, b'p', 'k', 1)
    dpsk._on_revoke('7')          # payload arrives as a string over NOTIFY
    assert dpsk._from_cache('aa:aa', 'Net1') == (None, None, None)


def test_on_revoke_ignores_bad_payload():
    dpsk._cache.clear()
    dpsk._to_cache('aa:aa', 'Net1', 1, b'p', 'k', 1)
    dpsk._on_revoke('not-an-int')
    assert len(dpsk._cache) == 1
    dpsk._cache.clear()


# -- Tier-3 rate limiter ------------------------------------------------------

class _FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def _limiter(clock, **kw):
    params = dict(rate=1e9, burst=1e9, max_failures=3, fail_window=60,
                  cooldown=100, max_tracked=1000)
    params.update(kw)
    return dpsk._Tier3Limiter(clock=clock, **params)


def test_per_mac_cooldown_after_repeated_failures():
    clk = _FakeClock()
    lim = _limiter(clk)
    mac = 'de:ad:be:ef:00:01'

    assert lim.allow(mac) is True
    for _ in range(3):
        lim.record_failure(mac)
    # Tripped: further scans are short-circuited.
    assert lim.allow(mac) is False
    # Recovers after the cooldown elapses.
    clk.advance(101)
    assert lim.allow(mac) is True


def test_failures_outside_window_do_not_accumulate():
    clk = _FakeClock()
    lim = _limiter(clk)
    mac = 'de:ad:be:ef:00:02'

    lim.record_failure(mac)
    lim.record_failure(mac)
    clk.advance(61)              # window expires, count resets
    lim.record_failure(mac)
    assert lim.allow(mac) is True


def test_record_success_clears_cooldown():
    clk = _FakeClock()
    lim = _limiter(clk)
    mac = 'de:ad:be:ef:00:03'

    for _ in range(3):
        lim.record_failure(mac)
    assert lim.allow(mac) is False
    lim.record_success(mac)
    assert lim.allow(mac) is True


def test_global_token_bucket_throttles_mac_rotation():
    clk = _FakeClock()
    # No per-MAC help here (every MAC distinct); only the bucket can save us.
    lim = _limiter(clk, rate=1.0, burst=2.0, max_failures=999)

    assert lim.allow('aa:00:00:00:00:01') is True
    assert lim.allow('aa:00:00:00:00:02') is True
    assert lim.allow('aa:00:00:00:00:03') is False   # bucket empty
    clk.advance(1.0)                                  # refills one token
    assert lim.allow('aa:00:00:00:00:04') is True
