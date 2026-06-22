import hashlib
import hmac
import os
import time
import db

# (mac, ssid) -> (pmk_bytes, psk, vlan_id, expires_at)
_cache = {}
_CACHE_TTL = int(os.environ.get('PMK_CACHE_TTL', 86400))

PKE_LABEL = b"Pairwise key expansion\x00"


def handle(attrs):
    """Detect vendor, verify MIC, return reply dict or {'reject': True} or None."""
    vendor = _detect_vendor(attrs)
    if vendor is None:
        return None

    mac   = attrs.get('Calling-Station-Id', '').lower().replace('-', ':')
    ssid  = _get_ssid(vendor, attrs)
    ap_mac = _get_ap_mac(vendor, attrs)

    pmk, psk, vlan_id = _from_cache(mac, ssid)
    cache_hit = pmk is not None
    if pmk is None:
        row = db.lookup_pmk(mac, ssid)
        if row is None:
            db.log_auth(mac, ssid, vendor, 'reject')
            return {'reject': True}
        pmk     = row['pmk_bytes']
        psk     = row['psk']
        vlan_id = row['vlan_id']
        _to_cache(mac, ssid, pmk, psk, vlan_id)

    eapol_hex  = _get_eapol(vendor, attrs)
    anonce_hex = _get_anonce(vendor, attrs, eapol_hex)

    if not _verify_mic(pmk, ap_mac, mac, anonce_hex, eapol_hex):
        db.log_auth(mac, ssid, vendor, 'reject', cache_hit)
        return {'reject': True}

    db.log_auth(mac, ssid, vendor, 'accept', cache_hit)
    return {'reply': _build_reply(vendor, pmk, psk, vlan_id)}


# -- vendor detection ---------------------------------------------------------

def _detect_vendor(attrs):
    if 'FreeRADIUS-802.1X-Anonce' in attrs:
        return 'openwifi'
    if 'TPLink-EAPOL-Frame-2' in attrs:
        return 'tplink'
    if 'Attr-26.25053.153' in attrs:
        return 'ruckus'
    return None


# -- attribute extraction -----------------------------------------------------

def _get_ssid(vendor, attrs):
    if vendor == 'openwifi':
        return attrs['Called-Station-Id'].split(':')[-1]
    if vendor == 'tplink':
        return attrs['TPLink-EAPOL-SSID']
    if vendor == 'ruckus':
        return attrs['Ruckus-SSID']

def _get_ap_mac(vendor, attrs):
    raw = {
        'openwifi': attrs['Called-Station-Id'].split(':')[0],
        'tplink':   attrs['TPLink-EAPOL-BSSID'],
        'ruckus':   attrs['NAS-Identifier'],
    }[vendor]
    return raw.lower().replace('-', ':')

def _get_eapol(vendor, attrs):
    if vendor == 'openwifi':
        return attrs['FreeRADIUS-802.1X-EAPoL-Key-Msg']
    if vendor == 'tplink':
        return attrs['TPLink-EAPOL-Frame-2']
    if vendor == 'ruckus':
        packed  = attrs['Attr-26.25053.153']
        msg_len = int(packed[96:98], 16)
        return packed[90:90 + (msg_len * 2) + 8]

def _get_anonce(vendor, attrs, eapol_hex):
    if vendor == 'openwifi':
        return attrs['FreeRADIUS-802.1X-Anonce']
    if vendor == 'tplink':
        return attrs['TPLink-EAPOL-ANonce']
    if vendor == 'ruckus':
        return attrs['Attr-26.25053.153'][22:22 + 64]


# -- MIC verification ---------------------------------------------------------

def _verify_mic(pmk, ap_mac, client_mac, anonce_hex, eapol_hex):
    anonce = bytes.fromhex(anonce_hex)
    eapol  = bytes.fromhex(eapol_hex)

    snonce       = eapol[34:66]
    received_mic = eapol[81:97]

    macs = sorted([
        bytes.fromhex(ap_mac.replace(':', '')),
        bytes.fromhex(client_mac.replace(':', '')),
    ])

    ptk = _derive_ptk(pmk, macs[0], macs[1], anonce, snonce)

    zeroed   = eapol[:81] + b'\x00' * 16 + eapol[97:]
    computed = hmac.new(ptk[:16], zeroed, hashlib.sha1).digest()
    return computed[1:17] == received_mic


def _derive_ptk(pmk, mac1, mac2, anonce, snonce):
    data = mac1 + mac2 + anonce + snonce
    ptk  = b''
    for i in range(4):
        ptk += hmac.new(pmk, PKE_LABEL + data + bytes([i]), hashlib.sha1).digest()
    return ptk


# -- reply builder ------------------------------------------------------------

def _build_reply(vendor, pmk, psk, vlan_id):
    reply = {}

    if vendor == 'openwifi':
        reply['Tunnel-Password'] = psk
    elif vendor == 'tplink':
        reply['TPLink-EAPOL-Found-PMK'] = pmk.hex()
    elif vendor == 'ruckus':
        # SZ uses Ruckus-DPSK; ZD/Unleashed uses MS-MPPE-Recv-Key.
        # TODO: distinguish SZ vs ZD via a request attribute (NAS type or VSA).
        reply['Ruckus-DPSK'] = bytes([0]) + pmk

    if vlan_id:
        reply['Tunnel-Type']            = '13'   # VLAN
        reply['Tunnel-Medium-Type']     = '6'    # IEEE-802
        reply['Tunnel-Private-Group-Id'] = str(vlan_id)

    return reply


# -- cache --------------------------------------------------------------------

def _from_cache(mac, ssid):
    entry = _cache.get((mac, ssid))
    if entry is None:
        return None, None, None
    pmk, psk, vlan_id, expires_at = entry
    if time.time() > expires_at:
        del _cache[(mac, ssid)]
        return None, None, None
    return pmk, psk, vlan_id


def _to_cache(mac, ssid, pmk, psk, vlan_id):
    _cache[(mac, ssid)] = (pmk, psk, vlan_id, time.time() + _CACHE_TTL)
