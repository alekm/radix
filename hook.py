import radiusd
import dpsk
import db

def authorize(p):
    attrs = dict(p)
    result = dpsk.handle(attrs)
    if result is None:
        return radiusd.RLM_MODULE_NOOP
    if result.get('reject'):
        return radiusd.RLM_MODULE_REJECT
    # Stash PMK bytes for post_auth via reply tuple
    reply = tuple((k, v) for k, v in result.get('reply', {}).items())
    return (radiusd.RLM_MODULE_OK, reply, ())

def post_auth(p):
    return radiusd.RLM_MODULE_NOOP
