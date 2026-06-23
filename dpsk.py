import hashlib
import hmac
import os
import threading
import time
import db

# (mac, ssid) -> (pmk_bytes, psk, vlan_id, expires_at)
_cache = {}
_CACHE_TTL = int(os.environ.get('PMK_CACHE_TTL', 86400))

PKE_LABEL = b"Pairwise key expansion\x00"


def handle(attrs):
    """Three-tier lookup: cache → known MAC binding → brute-force MIC scan.
    Falls back to MAC auth path when no DPSK blob is present."""
    vendor = _detect_vendor(attrs)
    if vendor is None:
        return _handle_mac_auth(attrs)

    mac = attrs.get('Calling-Station-Id', '').lower().replace('-', ':')

    # Parse the vendor blob exactly once.
    try:
        ssid, ap_mac, eapol_hex, anonce_hex = _extract(vendor, attrs)
    except Exception as exc:
        _log_err(f"RADIX extract error ({vendor}): {exc}")
        return {'reject': True}

    snonce_offset = 17 if vendor == 'tplink' else 34

    # Any DB/crypto failure here is fail-closed: we cannot verify, so reject —
    # but reset the pool so a dropped connection doesn't poison later requests.
    try:
        return _authenticate(vendor, mac, ssid, ap_mac, anonce_hex, eapol_hex, snonce_offset)
    except Exception as exc:
        _log_err(f"RADIX auth error ({vendor}) mac={mac}: {exc}")
        db.reset_conn()
        return {'reject': True}


def _authenticate(vendor, mac, ssid, ap_mac, anonce_hex, eapol_hex, snonce_offset):
    # Tier 1: in-memory cache
    pmk, psk, vlan_id = _from_cache(mac, ssid)
    if pmk is not None:
        if _verify_mic(pmk, ap_mac, mac, anonce_hex, eapol_hex, snonce_offset):
            db.log_auth(mac, ssid, vendor, 'accept', cache_hit=True)
            return {'reply': _build_reply(vendor, pmk, psk, vlan_id)}
        db.log_auth(mac, ssid, vendor, 'reject', cache_hit=True)
        return {'reject': True}

    # Tier 2: known MAC binding in DB
    row = db.lookup_pmk_by_mac(mac, ssid)
    if row is not None:
        pmk = row['pmk_bytes']
        if _verify_mic(pmk, ap_mac, mac, anonce_hex, eapol_hex, snonce_offset):
            _to_cache(mac, ssid, row['id'], pmk, row['psk'], row['vlan_id'])
            db.log_auth(mac, ssid, vendor, 'accept', cache_hit=False)
            return {'reply': _build_reply(vendor, pmk, row['psk'], row['vlan_id'])}
        db.log_auth(mac, ssid, vendor, 'reject', cache_hit=False)
        return {'reject': True}

    # Tier 3: new device — try every PMK for this SSID
    for row in db.lookup_all_pmks(ssid):
        pmk = row['pmk_bytes']
        if _verify_mic(pmk, ap_mac, mac, anonce_hex, eapol_hex, snonce_offset):
            db.bind_mac(row['id'], mac)
            _to_cache(mac, ssid, row['id'], pmk, row['psk'], row['vlan_id'])
            db.log_auth(mac, ssid, vendor, 'accept', cache_hit=False)
            return {'reply': _build_reply(vendor, pmk, row['psk'], row['vlan_id'])}

    db.log_auth(mac, ssid, vendor, 'reject', cache_hit=False)
    return {'reject': True}


def _log_err(msg):
    try:
        import radiusd
        radiusd.radlog(radiusd.L_ERR, msg)
    except Exception:
        pass


# -- MAC auth (no DPSK blob) --------------------------------------------------

def _handle_mac_auth(attrs):
    """Return PSK for a returning device identified only by MAC address.
    Always Accepts for TP-Link — unknown MACs get VLAN-only (PSK comes via DPSK blob)."""
    import radiusd

    client_mac = attrs.get('Calling-Station-Id', '').lower().replace('-', ':')
    if not client_mac:
        return None

    # Only handle TP-Link MAC auth (NAS-Identifier has "TP-Link" prefix)
    nas_id = attrs.get('NAS-Identifier', '')
    if 'TP-Link' not in nas_id and 'TPLink' not in nas_id:
        return None

    # Extract SSID from Called-Station-Id ("bssid:ssid")
    called = attrs.get('Called-Station-Id', '')
    ssid   = called.split(':')[-1] if ':' in called else ''

    try:
        row = db.lookup_pmk_by_mac(client_mac, ssid) if ssid else None
        if row is None:
            row = db.lookup_pmk_by_mac_only(client_mac)
    except Exception as exc:
        radiusd.radlog(radiusd.L_ERR, f"RADIX mac-auth db error: {exc}")
        db.reset_conn()
        row = None

    if row is not None:
        radiusd.radlog(radiusd.L_INFO, f"RADIX mac-auth hit {client_mac} vlan={row['vlan_id']}")
        db.log_auth(client_mac, ssid, 'tplink', 'accept', cache_hit=False)
        return {'reply': _build_tplink_reply(row['psk'], row['vlan_id'])}

    # Unknown device: Accept with default VLAN so DPSK blob can deliver the PMK
    radiusd.radlog(radiusd.L_INFO, f"RADIX mac-auth unknown {client_mac}, accepting with default VLAN")
    db.log_auth(client_mac, ssid, 'tplink', 'accept', cache_hit=False)
    return {'reply': _vlan_attrs(1)}


# -- vendor detection ---------------------------------------------------------

def _detect_vendor(attrs):
    if 'FreeRADIUS-802.1X-Anonce' in attrs:
        return 'openwifi'
    if 'TPLink-Authentication-FindKey' in attrs:
        return 'tplink'
    if 'Attr-26.25053.153' in attrs:
        return 'ruckus'
    return None


# -- TP-Link blob parser -------------------------------------------------------

def _tplink_parse(attrs):
    """Parse vendor 11863 attr-3 blob. Returns (eapol, anonce_hex, ssid, ap_mac)."""
    raw = attrs['TPLink-Authentication-FindKey']
    if isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
    elif raw.startswith('0x') or raw.startswith('0X'):
        data = bytes.fromhex(raw[2:].replace(' ', ''))
    else:
        data = raw.encode('latin-1')

    sub = {}
    i = 0
    while i + 1 < len(data):
        t, l = data[i], data[i + 1]
        if l < 2 or i + l > len(data):
            break
        sub[t] = data[i + 2:i + l]
        i += l

    eapol      = sub.get(1)                                          # 121-byte EAPOL frame
    anonce_hex = sub.get(2, b'').hex()                               # 32-byte ANonce
    ssid       = sub.get(3, b'').decode('utf-8', errors='replace')
    bssid_b    = sub.get(6, sub.get(4, b''))                        # sub[6]=radio BSSID, fallback sub[4]
    ap_mac     = ':'.join(f'{b:02x}' for b in bssid_b) if bssid_b else ''
    return eapol, anonce_hex, ssid, ap_mac


# -- attribute extraction -----------------------------------------------------

def _extract(vendor, attrs):
    """Return (ssid, ap_mac, eapol_hex, anonce_hex) for the detected vendor.

    Parses the vendor blob once per request (the TP-Link blob in particular is
    a packed sub-TLV structure that we don't want to walk four times)."""
    if vendor == 'openwifi':
        called = attrs['Called-Station-Id']
        ssid   = called.split(':')[-1]
        ap_mac = called.split(':')[0].lower().replace('-', ':')
        return ssid, ap_mac, attrs['FreeRADIUS-802.1X-EAPoL-Key-Msg'], attrs['FreeRADIUS-802.1X-Anonce']

    if vendor == 'tplink':
        eapol, anonce_hex, ssid, ap_mac = _tplink_parse(attrs)
        return ssid, ap_mac, (eapol.hex() if eapol else ''), anonce_hex

    if vendor == 'ruckus':
        packed     = attrs['Attr-26.25053.153']
        msg_len    = int(packed[96:98], 16)
        eapol_hex  = packed[90:90 + (msg_len * 2) + 8]
        anonce_hex = packed[22:22 + 64]
        ssid       = attrs['Ruckus-SSID']
        ap_mac     = attrs['NAS-Identifier'].lower().replace('-', ':')
        return ssid, ap_mac, eapol_hex, anonce_hex

    raise ValueError(f"unknown vendor {vendor!r}")


# -- MIC verification ---------------------------------------------------------

def _verify_mic(pmk, ap_mac, client_mac, anonce_hex, eapol_hex, snonce_offset=34):
    anonce = bytes.fromhex(anonce_hex)
    eapol  = bytes.fromhex(eapol_hex)

    snonce       = eapol[snonce_offset:snonce_offset + 32]
    received_mic = eapol[81:97]

    macs = sorted([
        bytes.fromhex(ap_mac.replace(':', '')),
        bytes.fromhex(client_mac.replace(':', '')),
    ])

    nonces = sorted([anonce, snonce])
    ptk = _derive_ptk(pmk, macs[0], macs[1], nonces[0], nonces[1])

    zeroed   = eapol[:81] + b'\x00' * 16 + eapol[97:]
    computed = hmac.new(ptk[:16], zeroed, hashlib.sha1).digest()
    return computed[:16] == received_mic


def _derive_ptk(pmk, mac1, mac2, anonce, snonce):
    data = mac1 + mac2 + anonce + snonce
    ptk  = b''
    for i in range(4):
        ptk += hmac.new(pmk, PKE_LABEL + data + bytes([i]), hashlib.sha1).digest()
    return ptk


# -- reply builder ------------------------------------------------------------

def _vlan_attrs(vlan_id):
    # Tunnel-Medium-Type must be the enum NAME "IEEE-802"; the integer "6"
    # is silently dropped by FreeRADIUS.
    return {
        'Tunnel-Type':             '13',
        'Tunnel-Medium-Type':      'IEEE-802',
        'Tunnel-Private-Group-Id': str(vlan_id),
    }


def _build_tplink_reply(psk, vlan_id, pmk=None):
    reply = _vlan_attrs(vlan_id or 1)
    reply['Tunnel-Password'] = psk
    if pmk is not None:
        reply['TPLink-EAPOL-Found-PMK'] = pmk
    return reply


def _build_reply(vendor, pmk, psk, vlan_id):
    reply = {}

    if vendor == 'openwifi':
        reply['Tunnel-Password'] = psk
    elif vendor == 'tplink':
        return _build_tplink_reply(psk, vlan_id, pmk=pmk)
    elif vendor == 'ruckus':
        # SZ uses Ruckus-DPSK; ZD/Unleashed uses MS-MPPE-Recv-Key.
        # TODO: distinguish SZ vs ZD via a request attribute.
        reply['Ruckus-DPSK'] = bytes([0]) + pmk

    if vlan_id:
        reply.update(_vlan_attrs(vlan_id))

    return reply


# -- cache --------------------------------------------------------------------

def _from_cache(mac, ssid):
    entry = _cache.get((mac, ssid))
    if entry is None:
        return None, None, None
    pmk_id, pmk, psk, vlan_id, expires_at = entry
    if time.time() > expires_at:
        _cache.pop((mac, ssid), None)
        return None, None, None
    return pmk, psk, vlan_id


def _to_cache(mac, ssid, pmk_id, pmk, psk, vlan_id):
    _cache[(mac, ssid)] = (pmk_id, pmk, psk, vlan_id, time.time() + _CACHE_TTL)


# -- revocation eviction ------------------------------------------------------

def _evict_pmk(pmk_id):
    """Drop every cache entry bound to a given PMK id. Returns count removed."""
    keys = [k for k, v in list(_cache.items()) if v[0] == pmk_id]
    for k in keys:
        _cache.pop(k, None)
    return len(keys)


def _on_revoke(payload):
    """Handle a NOTIFY payload from the web UI: a pmk id, or 'all'."""
    if payload == 'all':
        n = len(_cache)
        _cache.clear()
        _log_err(f"RADIX cache flushed ({n} entries) on revoke-all")
        return
    try:
        pmk_id = int(payload)
    except (TypeError, ValueError):
        return
    n = _evict_pmk(pmk_id)
    if n:
        _log_err(f"RADIX evicted {n} cache entries for revoked pmk {pmk_id}")


_listener_started = False
_listener_lock = threading.Lock()


def start_revocation_listener():
    """Spawn a daemon thread that evicts cached PMKs when the web UI revokes one.
    Safe to call repeatedly; only the first call starts a thread. Degrades to
    plain TTL expiry if the DB/listener is unavailable."""
    global _listener_started
    with _listener_lock:
        if _listener_started:
            return
        _listener_started = True

    def _run():
        while True:
            try:
                db.listen_revocations(_on_revoke)
            except Exception as exc:
                _log_err(f"RADIX revocation listener down, retrying: {exc}")
                time.sleep(5)

    threading.Thread(target=_run, name='radix-revoke-listener', daemon=True).start()
