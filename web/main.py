from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional
import db

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


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
    mac: str = Form(...),
):
    db.create_account(username, email, mac)
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
    db.add_psk(account_id, psk, ssid, vlan_id.strip() or None)
    return RedirectResponse(f"/accounts/{account_id}", status_code=303)


@app.post("/accounts/{account_id}/psks/{psk_id}/revoke")
async def psk_revoke(account_id: int, psk_id: int):
    db.revoke_psk(psk_id)
    return RedirectResponse(f"/accounts/{account_id}", status_code=303)


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
