import asyncio
import base64
import csv
import io
import os
import secrets
import socket
from contextlib import asynccontextmanager
from pydantic import BaseModel
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional
import db

# -- admin auth ---------------------------------------------------------------
# All routes require HTTP Basic auth. Static assets (CSS) are mounted separately
# and intentionally left open.
_ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


def _is_admin(user, password):
    return bool(_ADMIN_PASSWORD) and \
        secrets.compare_digest(user, _ADMIN_USER) and \
        secrets.compare_digest(password, _ADMIN_PASSWORD)


def require_auth(request: Request):
    """Accept admin HTTP Basic (browser/UI) OR an API client credential
    (Bearer "<key>:<secret>", or Basic with the key as user / secret as pass)."""
    auth = request.headers.get("Authorization", "")
    try:
        if auth.startswith("Bearer "):
            key, sep, secret = auth[7:].strip().partition(":")
            if sep and db.verify_api_client(key, secret):
                return
        elif auth.startswith("Basic "):
            user, _, password = base64.b64decode(auth[6:]).decode("utf-8", "replace").partition(":")
            if _is_admin(user, password) or db.verify_api_client(user, password):
                return
    except Exception:
        pass
    raise HTTPException(
        status_code=401, detail="Unauthorized",
        headers={"WWW-Authenticate": "Basic"},
    )


# -- log/session retention ----------------------------------------------------
# Auth and accounting rows accumulate forever otherwise. A daily background
# sweep trims anything older than RETENTION_DAYS (set <= 0 to disable).
_RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", 90))
_RETENTION_INTERVAL_HOURS = float(os.environ.get("RETENTION_INTERVAL_HOURS", 24))


async def _retention_loop():
    while True:
        try:
            auth_n, acct_n = await asyncio.to_thread(db.purge_old, _RETENTION_DAYS)
            if auth_n or acct_n:
                print(f"[retention] purged auth_log={auth_n} acct_sessions={acct_n} "
                      f"(older than {_RETENTION_DAYS}d)", flush=True)
        except Exception as exc:
            print(f"[retention] error: {exc}", flush=True)
        await asyncio.sleep(_RETENTION_INTERVAL_HOURS * 3600)


# -- analytics (Pi-friendly: sample + aggregate on a timer, serve from cache) --
_ANALYTICS = {"data": None}
_ANALYTICS_INTERVAL = float(os.environ.get("ANALYTICS_INTERVAL_SECONDS", 300))


async def _analytics_loop():
    while True:
        try:
            await asyncio.to_thread(db.sample_metrics)
            _ANALYTICS["data"] = await asyncio.to_thread(db.compute_analytics)
        except Exception as exc:
            print(f"[analytics] error: {exc}", flush=True)
        await asyncio.sleep(_ANALYTICS_INTERVAL)


@asynccontextmanager
async def lifespan(app):
    tasks = []
    if _RETENTION_DAYS > 0:
        tasks.append(asyncio.create_task(_retention_loop()))
    else:
        print("[retention] disabled (RETENTION_DAYS <= 0)", flush=True)
    tasks.append(asyncio.create_task(_analytics_loop()))
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()


app = FastAPI(lifespan=lifespan, dependencies=[Depends(require_auth)])
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def _duration(seconds):
    try:
        seconds = int(seconds or 0)
    except (TypeError, ValueError):
        return "—"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


templates.env.filters["duration"] = _duration

_PSK_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'

def _generate_psk(length=20):
    return ''.join(secrets.choice(_PSK_CHARS) for _ in range(length))


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "stats": db.get_stats(),
        "logs": db.get_recent_logs(10),
    })


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/favicon.ico")


@app.get("/api/analytics")
async def analytics(request: Request):
    data = _ANALYTICS["data"]
    if data is None:  # cold start before the first refresh — compute once
        data = await asyncio.to_thread(db.compute_analytics)
        _ANALYTICS["data"] = data
    return JSONResponse(data)


# -- JSON API (admin or API-client auth) --------------------------------------
# Programmatic surface for the MCP / external callers. Authenticated by the
# app-level require_auth dependency (admin Basic or API client key/secret).

class AccountIn(BaseModel):
    username: str
    email: Optional[str] = None


class PskIn(BaseModel):
    ssid: str
    psk: Optional[str] = None        # generated if omitted
    vlan_id: Optional[int] = None    # omit/null = untagged


class VlanIn(BaseModel):
    vlan_id: Optional[int] = None


class RekeyIn(BaseModel):
    psk: Optional[str] = None        # generated if omitted


@app.get("/api/whoami")
async def api_whoami():
    return {"authenticated": True}


@app.get("/api/stats")
async def api_stats():
    return db.get_stats()


@app.get("/api/accounts")
async def api_accounts():
    return db.get_accounts()


@app.post("/api/accounts", status_code=201)
async def api_account_create(body: AccountIn):
    return {"id": db.create_account(body.username, body.email or "")}


@app.get("/api/accounts/{account_id}")
async def api_account_get(account_id: int):
    account, psks = db.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="account not found")
    return {"account": account, "psks": psks}


@app.patch("/api/accounts/{account_id}")
async def api_account_update(account_id: int, body: AccountIn):
    db.update_account(account_id, body.username, body.email or "")
    return {"ok": True}


@app.delete("/api/accounts/{account_id}")
async def api_account_delete(account_id: int):
    db.delete_account(account_id)
    return {"ok": True}


@app.post("/api/accounts/{account_id}/psks", status_code=201)
async def api_psk_add(account_id: int, body: PskIn):
    psk = body.psk or _generate_psk()
    pid = db.add_psk(account_id, psk, body.ssid, body.vlan_id)
    return {"id": pid, "psk": psk, "ssid": body.ssid, "vlan_id": body.vlan_id}


@app.post("/api/psks/{psk_id}/rekey")
async def api_psk_rekey(psk_id: int, body: RekeyIn):
    psk = body.psk or _generate_psk()
    if not db.rekey_psk(psk_id, psk):
        raise HTTPException(status_code=404, detail="psk not found")
    return {"id": psk_id, "psk": psk}


@app.patch("/api/psks/{psk_id}/vlan")
async def api_psk_vlan(psk_id: int, body: VlanIn):
    db.update_psk_vlan(psk_id, body.vlan_id)
    return {"ok": True}


@app.delete("/api/psks/{psk_id}")
async def api_psk_revoke(psk_id: int):
    db.revoke_psk(psk_id)
    return {"ok": True}


@app.get("/api/sessions")
async def api_sessions(active: bool = False):
    return db.get_sessions(active_only=active)


@app.get("/api/logs")
async def api_logs(mac: Optional[str] = None, ssid: Optional[str] = None, result: Optional[str] = None):
    return db.get_logs(mac=mac, ssid=ssid, result=result)


# -- accounts -----------------------------------------------------------------

@app.get("/accounts", response_class=HTMLResponse)
async def accounts_list(request: Request):
    return templates.TemplateResponse("accounts.html", {
        "request": request,
        "accounts": db.get_accounts(),
    })


@app.post("/accounts")
async def accounts_create(
    username: str = Form(...),
    email: str = Form(""),
):
    db.create_account(username, email)
    return RedirectResponse("/accounts", status_code=303)


@app.get("/accounts/{account_id}", response_class=HTMLResponse)
async def account_detail(request: Request, account_id: int):
    account, psks = db.get_account(account_id)
    if account is None:
        return RedirectResponse("/accounts", status_code=303)
    return templates.TemplateResponse("account.html", {
        "request": request,
        "account": account,
        "psks": psks,
        "sessions": db.get_account_sessions(account_id),
    })


@app.post("/accounts/{account_id}/delete")
async def account_delete(account_id: int):
    db.delete_account(account_id)
    return RedirectResponse("/accounts", status_code=303)


@app.post("/accounts/{account_id}/edit")
async def account_edit(
    account_id: int,
    username: str = Form(...),
    email: str = Form(""),
):
    db.update_account(account_id, username, email)
    return RedirectResponse(f"/accounts/{account_id}", status_code=303)


@app.post("/accounts/{account_id}/psks/{psk_id}/vlan")
async def psk_set_vlan(account_id: int, psk_id: int, vlan_id: str = Form("")):
    db.update_psk_vlan(psk_id, vlan_id.strip() or None)
    return RedirectResponse(f"/accounts/{account_id}", status_code=303)


@app.post("/accounts/{account_id}/psks/{psk_id}/rekey")
async def psk_rekey(account_id: int, psk_id: int, psk: str = Form("")):
    db.rekey_psk(psk_id, psk.strip() or _generate_psk())
    return RedirectResponse(f"/accounts/{account_id}", status_code=303)


@app.post("/accounts/{account_id}/psks")
async def psk_add(
    account_id: int,
    psk: str = Form(...),
    ssid: str = Form(...),
    vlan_id: str = Form(""),
):
    db.add_psk(account_id, psk, ssid, vlan_id.strip() or None)
    return RedirectResponse(f"/accounts/{account_id}", status_code=303)


@app.post("/accounts/{account_id}/psks/{psk_id}/revoke")
async def psk_revoke(account_id: int, psk_id: int):
    db.revoke_psk(psk_id)
    return RedirectResponse(f"/accounts/{account_id}", status_code=303)


# -- bulk create --------------------------------------------------------------

@app.get("/bulk", response_class=HTMLResponse)
async def bulk_page(request: Request):
    return templates.TemplateResponse("bulk.html", {"request": request})


@app.post("/bulk")
async def bulk_create(
    ssid: str = Form(...),
    file: UploadFile = File(...),
):
    content = await file.read()
    text = content.decode('utf-8-sig')  # strip Excel BOM if present
    reader = csv.DictReader(io.StringIO(text))

    rows = []
    for row in reader:
        username = (row.get('username') or row.get('name') or '').strip()
        email    = (row.get('email') or '').strip()
        vlan     = (row.get('vlan') or row.get('vlan_id') or '').strip()
        if not username:
            continue
        psk        = _generate_psk()
        account_id = db.create_account(username, email)
        db.add_psk(account_id, psk, ssid, vlan or None)
        rows.append({'username': username, 'email': email, 'vlan': vlan, 'ssid': ssid, 'psk': psk})

    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=['username', 'email', 'vlan', 'ssid', 'psk'])
    writer.writeheader()
    writer.writerows(rows)

    return StreamingResponse(
        iter([out.getvalue()]),
        media_type='text/csv',
        headers={'Content-Disposition': f'attachment; filename="radix-{ssid}.csv"'},
    )


# -- sessions -----------------------------------------------------------------

@app.get("/sessions", response_class=HTMLResponse)
async def sessions(request: Request, active: Optional[str] = None):
    active_only = active in ("1", "true", "on")
    return templates.TemplateResponse("sessions.html", {
        "request": request,
        "sessions": db.get_sessions(active_only=active_only),
        "active_only": active_only,
    })


# -- settings -----------------------------------------------------------------

def _settings_ctx(request, new_client=None):
    return {
        "request": request,
        "radius_ip": os.environ.get("RADIUS_HOST", "—"),
        "radius_port": int(os.environ.get("RADIUS_PORT", 1812)),
        "radius_secret": os.environ.get("RADIUS_SECRET", ""),
        "api_clients": db.get_api_clients(),
        "new_client": new_client,
    }


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", _settings_ctx(request))


@app.post("/settings/api-clients", response_class=HTMLResponse)
async def api_client_create(request: Request, name: str = Form(...)):
    key, secret = db.generate_api_credentials()
    db.create_api_client(name.strip() or "client", key, secret)
    # Render directly (no redirect) so the one-time secret can be shown once.
    return templates.TemplateResponse(
        "settings.html",
        _settings_ctx(request, new_client={"name": name, "key": key, "secret": secret}),
    )


@app.post("/settings/api-clients/{client_id}/revoke")
async def api_client_revoke(client_id: int):
    db.revoke_api_client(client_id)
    return RedirectResponse("/settings", status_code=303)


# -- logs ---------------------------------------------------------------------

@app.get("/logs", response_class=HTMLResponse)
async def logs(
    request: Request,
    mac: Optional[str] = None,
    ssid: Optional[str] = None,
    result: Optional[str] = None,
):
    return templates.TemplateResponse("logs.html", {
        "request": request,
        "logs": db.get_logs(mac=mac, ssid=ssid, result=result),
        "filters": {"mac": mac or "", "ssid": ssid or "", "result": result or ""},
    })
