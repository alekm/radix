"""RADIUS accounting handler.

The NAS sends Accounting-Request packets (Start / Interim-Update / Stop) over
the lifetime of a session. We upsert one row per Acct-Session-Id, accumulating
octet counters and session time. Octet counters are 32-bit and wrap; the paired
Gigawords attribute carries the high 32 bits.
"""
import db

# Acct-Status-Type arrives as either the enum name or its integer code.
_STATUS = {
    'Start': 'start',           '1': 'start',
    'Stop': 'stop',             '2': 'stop',
    'Interim-Update': 'interim', '3': 'interim',
    'Alive': 'interim',
}


def _norm_mac(v):
    return (v or '').lower().replace('-', ':') or None


def _int(attrs, key):
    try:
        return int(attrs.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _octets(attrs, base, giga):
    """Combine a 32-bit octet counter with its Gigawords high word."""
    return _int(attrs, base) + (_int(attrs, giga) << 32)


def parse(attrs):
    """Map a RADIUS accounting request to an acct_sessions row, or None if it's
    not a session event we track (e.g. Accounting-On/Off, or missing keys)."""
    status = _STATUS.get(str(attrs.get('Acct-Status-Type', '')))
    session_id = attrs.get('Acct-Session-Id')
    if status is None or not session_id:
        return None

    called = attrs.get('Called-Station-Id', '') or ''
    ssid   = called.split(':')[-1] if ':' in called else None

    return {
        'session_id':      session_id,
        'mac':             _norm_mac(attrs.get('Calling-Station-Id')),
        'username':        attrs.get('User-Name') or None,
        'ssid':            ssid,
        'nas_ip':          attrs.get('NAS-IP-Address') or None,
        'framed_ip':       attrs.get('Framed-IP-Address') or None,
        'in_octets':       _octets(attrs, 'Acct-Input-Octets', 'Acct-Input-Gigawords'),
        'out_octets':      _octets(attrs, 'Acct-Output-Octets', 'Acct-Output-Gigawords'),
        'session_time':    _int(attrs, 'Acct-Session-Time'),
        'status':          status,
        'terminate_cause': attrs.get('Acct-Terminate-Cause') or None,
    }


_LIFECYCLE = {'7', 'Accounting-On', '8', 'Accounting-Off'}


def handle(attrs):
    """Persist one accounting event. Returns True if handled, False otherwise.
    Never raises into the RADIUS path."""
    # Accounting-On/Off signal a NAS reboot/shutdown — close its open sessions.
    if str(attrs.get('Acct-Status-Type', '')) in _LIFECYCLE:
        try:
            db.close_nas_sessions(attrs.get('NAS-IP-Address'))
            return True
        except Exception as exc:
            _acct_err(f"RADIX accounting lifecycle error: {exc}")
            db.reset_conn()
            return False

    record = parse(attrs)
    if record is None:
        return False
    try:
        db.upsert_acct_session(record)
        return True
    except Exception as exc:
        _acct_err(f"RADIX accounting db error: {exc}")
        db.reset_conn()
        return False


def _acct_err(msg):
    try:
        import radiusd
        radiusd.radlog(radiusd.L_ERR, msg)
    except Exception:
        pass
