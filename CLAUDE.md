# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

RADIX is a FreeRADIUS DPSK (Dynamic Pre-Shared Key) authentication backend for enterprise WiFi. It hooks into FreeRADIUS via `rlm_python3` (in-process, no network hop) and supports three AP vendors: OpenWiFi, TP-Link Omada, and Ruckus (SZ, ZD, Unleashed).

## Architecture

The implementation lives in five files under `radix/`:

| File | Role |
|------|------|
| `hook.py` | FreeRADIUS `rlm_python3` entry points (`authorize`, `post_auth`) |
| `dpsk.py` | Vendor detection, EAPOL parsing, MIC verification, PTK derivation |
| `db.py` | PSK/account lookups via PostgreSQL (`psycopg2`) |
| `schema.sql` | DB schema (`accounts`, `pairwise_master_keys`) |
| `raddb/` | FreeRADIUS config snippets |

## Vendor Detection & Attributes

Vendor is detected by which radius attribute is present in the request:

| Vendor | Detect via | SSID attr | ANonce attr | EAPOL frame attr | AP MAC |
|--------|-----------|-----------|-------------|-----------------|--------|
| OpenWiFi | `FreeRADIUS-802.1X-Anonce` | `Called-Station-Id` (after `:`) | `FreeRADIUS-802.1X-Anonce` | `FreeRADIUS-802.1X-EAPoL-Key-Msg` | `Called-Station-Id` (before `:`) |
| TP-Link | `TPLink-EAPOL-Frame-2` | `TPLink-EAPOL-SSID` | `TPLink-EAPOL-ANonce` | `TPLink-EAPOL-Frame-2` | `TPLink-EAPOL-BSSID` |
| Ruckus | `Attr-26.25053.153` | `Ruckus-SSID` | offset 22 of packed attr | `Attr-26.25053.153` | `NAS-Identifier` |

## Response Attributes (what to return on success)

| Vendor | Attribute | Value |
|--------|-----------|-------|
| OpenWiFi | `Tunnel-Password` | Raw PSK string |
| TP-Link | `TPLink-EAPOL-Found-PMK` | PBKDF2-HMAC-SHA1(psk, ssid, 4096, 32) |
| Ruckus SZ | `Ruckus-DPSK` | `\x00` + PBKDF2-HMAC-SHA1(psk, ssid, 4096, 32) |
| Ruckus ZD/Unleashed | `MS-MPPE-Recv-Key` | PBKDF2-HMAC-SHA1(psk, ssid, 4096, 32) |

## MIC Verification Algorithm

All vendors (except OpenWiFi, which skips MIC) follow this flow:

1. Extract ANonce, SNonce (EAPOL offset 34, 32 bytes), MIC (offset 81, 16 bytes)
2. Sort AP MAC and client MAC (`Calling-Station-Id`) lexicographically
3. Derive PTK via 4 rounds of `HMAC-SHA1(PMK, b"Pairwise key expansion\x00" + sorted_macs + nonces + counter_byte)`
4. Re-compute `HMAC-SHA1(eapol_with_zeroed_mic, ptk[:16])`
5. Compare bytes 1–16 of result to the received MIC

## Ruckus Packed Attr Offsets (`Attr-26.25053.153`, hex string)

- ANonce: offset 22, length 64 hex chars
- msg_len: offset 96, 2 hex chars
- SNonce: offset 124, 64 hex chars
- MIC: offset 252, 32 hex chars
- msg body: offset 90, length = (msg_len * 2) + 8

## DB Schema

```sql
accounts(id, username, email, created_at)
pairwise_master_keys(id, account_id, psk, ssid, pmk_b64, wlan_id, created_at)
```

## Running / Testing

No build system yet — project is in implementation phase. To test manually:
- Load `hook.py` via FreeRADIUS `rlm_python3` module config
- Use `radtest` or a real AP association to exercise the `authorize` / `post_auth` paths
- Check `/var/log/freeradius/radius.log` for Python tracebacks
