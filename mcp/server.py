#!/usr/bin/env python3
"""RADIX MCP server (stdio).

A thin Model Context Protocol server that exposes RADIX management as tools by
calling its JSON API. It holds an API client credential (key/secret) — generate
one in the RADIX web UI under Settings → API Clients — and needs no database
access or business logic of its own.

Configure via environment variables:
    RADIX_URL        e.g. http://192.168.1.10:8050   (required)
    RADIX_KEY        rdx_...                          (required)
    RADIX_SECRET     the secret shown once at creation (required)
    RADIX_VERIFY_TLS "false" to skip TLS verification (default: true)
    RADIX_TIMEOUT    request timeout seconds          (default: 15)

Run directly (Claude Desktop/Code launches it over stdio):
    python server.py
"""
import os
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("radix")


def _cfg():
    url = os.environ.get("RADIX_URL")
    key = os.environ.get("RADIX_KEY")
    secret = os.environ.get("RADIX_SECRET")
    if not (url and key and secret):
        raise RuntimeError(
            "Set RADIX_URL, RADIX_KEY and RADIX_SECRET (generate a client in "
            "RADIX Settings → API Clients)."
        )
    return url.rstrip("/"), key, secret


def _call(method: str, path: str, *, json: Any = None, params: dict | None = None) -> Any:
    url, key, secret = _cfg()
    verify = os.environ.get("RADIX_VERIFY_TLS", "true").lower() not in ("0", "false", "no")
    timeout = float(os.environ.get("RADIX_TIMEOUT", "15"))
    headers = {"Authorization": f"Bearer {key}:{secret}"}
    try:
        r = httpx.request(method, f"{url}{path}", headers=headers, json=json,
                          params=params, timeout=timeout, verify=verify)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Request to RADIX failed: {exc}")
    if r.status_code == 401:
        raise RuntimeError("Unauthorized — check RADIX_KEY/RADIX_SECRET (client may be revoked).")
    if r.status_code >= 400:
        raise RuntimeError(f"RADIX API error {r.status_code}: {r.text[:300]}")
    if r.headers.get("content-type", "").startswith("application/json"):
        return r.json()
    return r.text


# -- read tools ---------------------------------------------------------------

@mcp.tool()
def whoami() -> Any:
    """Verify the RADIX connection and credentials."""
    return _call("GET", "/api/whoami")


@mcp.tool()
def get_stats() -> Any:
    """Dashboard counts: accounts, active PSKs, 24h auths/rejects, active sessions."""
    return _call("GET", "/api/stats")


@mcp.tool()
def list_accounts() -> Any:
    """List all accounts with their PSK and device counts."""
    return _call("GET", "/api/accounts")


@mcp.tool()
def get_account(account_id: int) -> Any:
    """Get one account with its (active) PSKs and bound MACs."""
    return _call("GET", f"/api/accounts/{account_id}")


@mcp.tool()
def list_sessions(active: bool = True) -> Any:
    """List accounting sessions. active=True shows only currently-online sessions."""
    return _call("GET", "/api/sessions", params={"active": str(active).lower()})


@mcp.tool()
def get_logs(mac: Optional[str] = None, ssid: Optional[str] = None,
             result: Optional[str] = None) -> Any:
    """Recent auth log entries, optionally filtered by MAC, SSID, or result (accept/reject)."""
    params = {k: v for k, v in (("mac", mac), ("ssid", ssid), ("result", result)) if v}
    return _call("GET", "/api/logs", params=params or None)


# -- write tools --------------------------------------------------------------

@mcp.tool()
def create_account(username: str, email: Optional[str] = None) -> Any:
    """Create an account. Returns the new account id."""
    return _call("POST", "/api/accounts", json={"username": username, "email": email})


@mcp.tool()
def update_account(account_id: int, username: str, email: Optional[str] = None) -> Any:
    """Rename an account / change its email."""
    return _call("PATCH", f"/api/accounts/{account_id}",
                 json={"username": username, "email": email})


@mcp.tool()
def delete_account(account_id: int) -> Any:
    """Delete an account and all of its PSKs (cascades). Irreversible."""
    return _call("DELETE", f"/api/accounts/{account_id}")


@mcp.tool()
def add_psk(account_id: int, ssid: str, psk: Optional[str] = None,
            vlan_id: Optional[int] = None) -> Any:
    """Assign a PSK to an account on an SSID. If psk is omitted, one is generated
    and returned. Leave vlan_id null for the SSID's untagged/local network."""
    return _call("POST", f"/api/accounts/{account_id}/psks",
                 json={"ssid": ssid, "psk": psk, "vlan_id": vlan_id})


@mcp.tool()
def rekey_psk(psk_id: int, psk: Optional[str] = None) -> Any:
    """Replace a PSK's key (re-keys the PMK; the device must be reconfigured).
    If psk is omitted, a new one is generated and returned."""
    return _call("POST", f"/api/psks/{psk_id}/rekey", json={"psk": psk})


@mcp.tool()
def set_psk_vlan(psk_id: int, vlan_id: Optional[int] = None) -> Any:
    """Set a PSK's VLAN. Pass null for untagged/local (no VLAN override)."""
    return _call("PATCH", f"/api/psks/{psk_id}/vlan", json={"vlan_id": vlan_id})


@mcp.tool()
def revoke_psk(psk_id: int) -> Any:
    """Revoke a PSK (soft-delete; stops authenticating, keeps history)."""
    return _call("DELETE", f"/api/psks/{psk_id}")


if __name__ == "__main__":
    mcp.run()
