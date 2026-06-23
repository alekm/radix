# RADIX MCP server

A small [Model Context Protocol](https://modelcontextprotocol.io) server that lets
an AI client (Claude Desktop, Claude Code, etc.) manage a RADIX instance — create
accounts, issue/rekey/revoke PSKs, and inspect sessions and logs — by calling
RADIX's JSON API.

It's a **stdio** server: the AI client launches `server.py` as a subprocess. It
holds a RADIX API client credential and needs no database access.

## Setup

1. **Generate a credential** in RADIX: **Settings → API Clients → Generate**.
   Copy the client key (`rdx_…`) and the secret (shown once).

2. **Install dependencies** (Python 3.10+):

   ```bash
   cd mcp
   pip install -r requirements.txt
   ```

3. **Configure your MCP client.** Example Claude Desktop config
   (`claude_desktop_config.json`):

   ```json
   {
     "mcpServers": {
       "radix": {
         "command": "python",
         "args": ["/absolute/path/to/radix/mcp/server.py"],
         "env": {
           "RADIX_URL": "http://192.168.1.10:8050",
           "RADIX_KEY": "rdx_xxxxxxxxxxxxxxxx",
           "RADIX_SECRET": "your-secret-here"
         }
       }
     }
   }
   ```

   For Claude Code: `claude mcp add radix -- python /path/to/radix/mcp/server.py`
   (then set the env vars), or add an equivalent entry to your MCP config.

The machine running the MCP client must be able to reach `RADIX_URL` over the network.

## Environment variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `RADIX_URL` | yes | — | Base URL of the RADIX web service (e.g. `http://host:8050`) |
| `RADIX_KEY` | yes | — | API client key (`rdx_…`) |
| `RADIX_SECRET` | yes | — | API client secret |
| `RADIX_VERIFY_TLS` | no | `true` | Set `false` to skip TLS verification (self-signed certs) |
| `RADIX_TIMEOUT` | no | `15` | Per-request timeout, seconds |

## Tools

- **Read:** `whoami`, `get_stats`, `list_accounts`, `get_account`, `list_sessions`, `get_logs`
- **Write:** `create_account`, `update_account`, `delete_account`, `add_psk`,
  `rekey_psk`, `set_psk_vlan`, `revoke_psk`

`add_psk` / `rekey_psk` generate a key when you don't supply one and return it.

## Security

The credential has full management access to RADIX (it can read PSKs in cleartext
and create/delete accounts). Treat it like a password, scope network access to the
RADIX host, and **revoke it in Settings** if it leaks. Prefer running RADIX behind
TLS if the MCP client connects across an untrusted network.
