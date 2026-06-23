import os
import sys
import types

# Make the project root importable (dpsk.py lives there).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# dpsk imports `db` at module load and `radiusd` lazily inside the MAC-auth
# path. Stub both so the pure crypto/parsing functions can be tested in
# isolation, without psycopg2 or a running FreeRADIUS.
if 'db' not in sys.modules:
    db_stub = types.ModuleType('db')
    db_stub.log_auth            = lambda *a, **k: None
    db_stub.lookup_pmk_by_mac   = lambda *a, **k: None
    db_stub.lookup_pmk_by_mac_only = lambda *a, **k: None
    db_stub.lookup_all_pmks     = lambda *a, **k: []
    db_stub.bind_mac            = lambda *a, **k: None
    db_stub.reset_conn          = lambda *a, **k: None
    db_stub.upsert_acct_session = lambda *a, **k: None
    db_stub.close_nas_sessions  = lambda *a, **k: None
    sys.modules['db'] = db_stub

if 'radiusd' not in sys.modules:
    rad = types.ModuleType('radiusd')
    rad.L_INFO = rad.L_ERR = rad.L_DBG = 0
    rad.radlog = lambda *a, **k: None
    sys.modules['radiusd'] = rad
