# RADIX — Project Notes

A custom FreeRADIUS DPSK service targeting OpenWiFi, TP-Link Omada, and Ruckus APs.

## Architecture Decision

- **FreeRADIUS** with `rlm_python3` hook (in-process, no network hop)
- **Python** for the hook script (~300 lines)
- **PostgreSQL** for PSK/account storage (`psycopg2`)
## Vendor Matrix

| Vendor | Detection Attr | SSID | ANonce | EAPOL Frame | AP MAC |
|--------|---------------|------|--------|-------------|--------|
| OpenWiFi | `FreeRADIUS-802.1X-Anonce` | `Called-Station-Id` (split `:`) | `FreeRADIUS-802.1X-Anonce` | `FreeRADIUS-802.1X-EAPoL-Key-Msg` | `Called-Station-Id` (split `:`) |
| TP-Link | `TPLink-EAPOL-Frame-2` | `TPLink-EAPOL-SSID` | `TPLink-EAPOL-ANonce` | `TPLink-EAPOL-Frame-2` | `TPLink-EAPOL-BSSID` |
| Ruckus | `Attr-26.25053.153` | `Ruckus-SSID` | offset 22 of packed attr | `Attr-26.25053.153` | `NAS-Identifier` |

## Response Attributes

| Vendor | Attribute | Value |
|--------|-----------|-------|
| OpenWiFi | `Tunnel-Password` | Plain PSK (no hashing) |
| TP-Link | `TPLink-EAPOL-Found-PMK` | PBKDF2-HMAC-SHA1(psk, salt=ssid, iter=4096, len=32) |
| Ruckus SZ | `Ruckus-DPSK` | `\x00` + PBKDF2-HMAC-SHA1(psk, salt=ssid, iter=4096, len=32) |
| Ruckus ZD/Unleashed | `MS-MPPE-Recv-Key` | PBKDF2-HMAC-SHA1(psk, salt=ssid, iter=4096, len=32) |

## MIC Verification (all vendors)

1. Parse ANonce, SNonce (offset 34, len 32 bytes from EAPOL frame), MIC (offset 81, len 16 bytes)
2. Sort AP MAC and client MAC (Calling-Station-Id) lexicographically
3. Derive PTK: 4 rounds of `HMAC-SHA1(PMK, PKE_LABEL + sorted_macs + nonces + counter)`
   - `PKE_LABEL = b"Pairwise key expansion\x00"`
4. Compute `HMAC-SHA1(eapol_msg_with_zeroed_mic, ptk[:16])`
5. Compare bytes 1–16 of result with received MIC

## EAPOL Frame Offsets (hex string)

- msg_len: bytes 6–7 (2 hex chars)
- SNonce: bytes 34–97 (64 hex chars)
- MIC: bytes 162–193 (32 hex chars)

## Ruckus Packed Attr (`Attr-26.25053.153`) Offsets

- ANonce: offset 22, length 64 hex chars
- msg body: offset 90, length = (msg_len * 2) + 8
- msg_len: offset 96, 2 hex chars
- SNonce: offset 124, 64 hex chars
- MIC: offset 252, 32 hex chars

## Proposed File Structure

```
radix/
  hook.py        # FreeRADIUS rlm_python3 entry points (authorize, post_auth)
  dpsk.py        # Vendor detection, MIC verification, PTK derivation
  db.py          # PSK/account lookup (PostgreSQL)
  schema.sql     # DB schema
  raddb/         # FreeRADIUS config snippets
```

## DB Schema (rough)

```sql
accounts (id, username, email, created_at)
pairwise_master_keys (id, account_id, psk, ssid, pmk_b64, wlan_id, created_at)
```
