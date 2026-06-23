import asyncio
import csv
import io
import os
import secrets
import socket
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
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
_security = HTTPBasic()


def require_admin(credentials: HTTPBasicCredentials = Depends(_security)):
    if not _ADMIN_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ADMIN_PASSWORD is not set; admin UI is disabled.",
        )
    ok_user = secrets.compare_digest(credentials.username, _ADMIN_USER)
    ok_pass = secrets.compare_digest(credentials.password, _ADMIN_PASSWORD)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
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


app = FastAPI(lifespan=lifespan, dependencies=[Depends(require_admin)])
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


@app.get("/api/analytics")
async def analytics(request: Request):
    data = _ANALYTICS["data"]
    if data is None:  # cold start before the first refresh — compute once
        data = await asyncio.to_thread(db.compute_analytics)
        _ANALYTICS["data"] = data
    return JSONResponse(data)


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
    db.add_psk(account_id, psk, ssid, vlan_id.strip() or '1')
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
        db.add_psk(account_id, psk, ssid, vlan or '1')
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

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "radius_ip": os.environ.get("RADIUS_HOST", "—"),
        "radius_port": int(os.environ.get("RADIUS_PORT", 1812)),
        "radius_secret": os.environ.get("RADIUS_SECRET", ""),
    })


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
