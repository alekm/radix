import os
import radiusd
import dpsk
import db
import acct

_DEBUG = os.environ.get('RADIX_DEBUG', '').lower() in ('1', 'true', 'yes')

# Evict cached PMKs as soon as the web UI revokes one (falls back to TTL expiry
# if the listener can't connect).
try:
    dpsk.start_revocation_listener()
except Exception as exc:
    radiusd.radlog(radiusd.L_ERR, f"RADIX could not start revocation listener: {exc}")

def authorize(p):
    attrs = dict(p)
    if _DEBUG:
        radiusd.radlog(radiusd.L_DBG, f"RADIX keys: {list(attrs.keys())}")
    result = dpsk.handle(attrs)
    if result is None:
        return radiusd.RLM_MODULE_NOOP
    if result.get('reject'):
        return radiusd.RLM_MODULE_REJECT
    # Stash PMK bytes for post_auth via reply tuple
    reply = tuple((k, v) for k, v in result.get('reply', {}).items())
    return (radiusd.RLM_MODULE_OK, reply, (('Auth-Type', 'Accept'),))

def post_auth(p):
    return radiusd.RLM_MODULE_NOOP

def accounting(p):
    attrs = dict(p)
    try:
        acct.handle(attrs)
    except Exception as exc:
        radiusd.radlog(radiusd.L_ERR, f"RADIX accounting error: {exc}")
    # Always ACK so the NAS doesn't retransmit endlessly.
    return radiusd.RLM_MODULE_OK
