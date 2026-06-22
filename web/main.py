import csv
import io
import os
import secrets
import socket
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional
import db

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

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
    })


@app.post("/accounts/{account_id}/delete")
async def account_delete(account_id: int):
    db.delete_account(account_id)
    return RedirectResponse("/accounts", status_code=303)


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


# -- settings -----------------------------------------------------------------

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    try:
        server_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        server_ip = "unknown"
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "radius_ip": server_ip,
        "radius_port": 1812,
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
