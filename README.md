# claude-code-el-ipc

Inter-agent IPC message queue for [claude-code-event-listeners](https://github.com/mividtim/claude-code-event-listeners). SQLite-backed channels with per-agent watermarks, Ed25519 identity verification, HTTP long-poll, CLI mode, and optional ngrok exposure.

## Install

```bash
# From the marketplace (recommended)
claude plugin marketplace add mividtim/claude-code-el-ipc
claude plugin install el-ipc

# Or manually
git clone https://github.com/mividtim/claude-code-el-ipc.git
```

## Prerequisites

- Python 3.6+
- `cryptography` package for identity verification: `pip install cryptography`
- [claude-code-event-listeners](https://github.com/mividtim/claude-code-event-listeners) plugin
- ngrok (optional, for remote agent communication)

## Quick Start (Open Mode)

Without identity verification, any agent can send and read messages:

```bash
# Start the server
python3 sources.d/ipc-server.py serve

# Send a message (CLI — no server needed for local agents)
python3 sources.d/ipc-server.py send my-channel agent-a "Hello from Agent A"

# Read messages
python3 sources.d/ipc-server.py read my-channel agent-b

# Long-poll for new messages
python3 sources.d/ipc-server.py read my-channel agent-b --wait
```

## Setup (Secure Mode)

Identity verification uses Ed25519 asymmetric keys. Security activates automatically when the first operator is seeded — all messages must then be signed.

### 1. Seed an operator

The operator is the admin who authorizes agents. Run this once per deployment:

```bash
python3 sources.d/ipc-server.py seed my-operator > operator.key
chmod 600 operator.key
```

**Save the private key file.** It cannot be recovered. The public key is stored in the database.

### 2. Generate agent keypairs

For each agent that will send messages:

```bash
python3 sources.d/ipc-server.py keygen --out herald
# Creates: herald.key (private, chmod 600) and herald.pub (public)
```

### 3. Register agents

The operator authorizes each agent by signing their registration:

```bash
python3 sources.d/ipc-server.py register herald \
  --pubkey herald.pub \
  --as my-operator \
  --key operator.key \
  --identity "a9e6db87-b090-47e0-a509-2bc624896d0f"
```

The `--identity` flag is optional — use it for UUIDs, descriptions, or any secondary identifier.

### 4. Send signed messages

Once secure mode is active, all sends require the sender's private key:

```bash
# CLI (direct DB)
python3 sources.d/ipc-server.py send my-channel herald "Hello" --key herald.key

# HTTP
curl -X POST http://localhost:9876/send \
  -H 'Content-Type: application/json' \
  -d '{"channel":"my-channel","sender":"herald","content":"Hello","signature":"<base64>"}'
```

For HTTP, the signature is `base64(Ed25519_sign(private_key, "channel\nsender\ncontent"))`.

### 5. View the agent directory

```bash
python3 sources.d/ipc-server.py agents
```

## Architecture

```
Agent A  ---[CLI: direct SQLite write]---> ipc.db <---[CLI: direct read]--- Agent B
                                              ^
Agent C  ---[HTTP POST /send]---> ipc-server.py ---[HTTP GET /messages?wait=true]--- Agent D
                                       |
                                    (ngrok)
                                       |
Remote   ---[HTTPS POST /send]--------'
```

- **Local agents** can read/write the SQLite DB directly via CLI (no server needed)
- **Remote agents** use HTTP endpoints through the server
- **Hybrid** — local CLI writes + remote HTTP reads work together on the same DB

## Server Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/send` | POST | Send a message. Body: `{channel, sender, content, signature?}` |
| `/register` | POST | Register an agent. Body: `{name, public_key, operator, operator_key, identity?}` |
| `/messages` | GET | Read messages. Params: `channel`, `agent`, `wait=true` (long-poll, 30s) |
| `/channels` | GET | List all channels with message counts |
| `/agents` | GET | List registered agents (names, roles, identities) |
| `/health` | GET | Status + pending count + secure mode flag |

## Identity Verification

The system uses Ed25519 asymmetric cryptography:

- **Operators** are seeded with `seed` — they authorize agent registrations
- **Agents** are registered with `register` — their public key is stored
- **Messages** are signed with the sender's private key and verified against their stored public key
- **Impersonation is impossible** — signing as "herald" with a different key is rejected
- **Progressive security** — the system runs in open mode until the first operator is seeded

### Signature Format

Messages are signed over the canonical payload `channel\nsender\ncontent` (newline-separated, UTF-8 encoded). The signature is base64-encoded Ed25519.

### Multiple Operators

You can seed multiple operators. Each can independently register agents:

```bash
python3 sources.d/ipc-server.py seed ops-team-1 > ops1.key
python3 sources.d/ipc-server.py seed ops-team-2 > ops2.key
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IPC_DB_PATH` | `/tmp/el-ipc.db` | SQLite database path |
| `IPC_PORT` | `9876` | HTTP server port |
| `IPC_API_KEY` | *(none)* | Legacy API key auth (pre-identity, still works alongside Ed25519) |

## CLI Commands

| Command | Description |
|---------|-------------|
| `serve [port]` | Start HTTP server |
| `send <channel> <from> <msg> [--key <file>]` | Send a message |
| `read <channel> <agent> [--wait]` | Read unread messages |
| `channels` | List channels |
| `seed <name>` | Generate operator keypair, store in DB |
| `keygen [--out <prefix>]` | Generate Ed25519 keypair (utility) |
| `register <name> --pubkey <f> --as <op> --key <f> [--identity <s>]` | Register agent |
| `agents` | List registered agents |

## Using with el

Listen for IPC messages as an event source:

```bash
event-listen.sh listen python3 sources.d/ipc-server.py read my-channel my-agent --wait
```

## ngrok Exposure

To allow remote agents to send messages:

```bash
ngrok http 9876 --subdomain my-ipc-server
```

Remote agents POST to `https://my-ipc-server.ngrok.io/send` with signed payloads.

## Requirements

- [claude-code-event-listeners](https://github.com/mividtim/claude-code-event-listeners) plugin
- Python 3.6+
- `cryptography` package (`pip install cryptography`) for identity features
- ngrok (optional, for remote communication)

## License

MIT
