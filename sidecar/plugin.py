"""IPC sidecar plugin for el-sidecar.

Inter-agent persistent communication via SQLite-backed message queue.
Receives messages from remote agents as sidecar events through the drain.
Sending is an HTTP POST to the remote agent's sidecar URL.

Supports Ed25519 asymmetric identity verification: operators seed their
keypair, register agents with public keys, and all messages are signed
and verified. Security activates automatically when the first operator
is registered -- before that, the system runs in open mode.

Routes (all namespaced under /ipc):
    POST /ipc/send         -- Receive a message (store + emit event)
    POST /ipc/register     -- Register an agent identity
    GET  /ipc/messages     -- Read message history
    GET  /ipc/agents       -- List registered agents
    GET  /ipc/channels     -- List channels with counts
    GET  /.well-known/agent-card.json -- A2A Agent Card

Env vars:
    IPC_AGENT_NAME   -- Agent name for Agent Card (default: 'el-ipc agent')
    IPC_AGENT_DESC   -- Description for Agent Card
    IPC_AGENT_URL    -- Public URL (ngrok) for Agent Card
"""

import base64
import json
import os
import sys
import time
import urllib.request

# --- Optional crypto (graceful degradation) ---

try:
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# --- Configuration ---

AGENT_CARD_NAME = os.environ.get('IPC_AGENT_NAME', '')
AGENT_CARD_DESC = os.environ.get('IPC_AGENT_DESC', '')
AGENT_CARD_URL = os.environ.get('IPC_AGENT_URL', '')

# Also check .env in project root for env vars not already set
_dotenv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
if os.path.exists(_dotenv_path):
    try:
        with open(_dotenv_path, 'r') as _f:
            for _line in _f:
                _line = _line.strip()
                if not _line or _line.startswith('#') or '=' not in _line:
                    continue
                _key, _val = _line.split('=', 1)
                _key = _key.strip()
                _val = _val.strip().strip('"').strip("'")
                if _key == 'IPC_AGENT_NAME' and not AGENT_CARD_NAME:
                    AGENT_CARD_NAME = _val
                elif _key == 'IPC_AGENT_DESC' and not AGENT_CARD_DESC:
                    AGENT_CARD_DESC = _val
                elif _key == 'IPC_AGENT_URL' and not AGENT_CARD_URL:
                    AGENT_CARD_URL = _val
    except Exception:
        pass

# Sidecar API reference (set during register())
_api = {}  # type: dict


# ===================================================================
# Ed25519 Identity / Crypto
# ===================================================================

def _sign_payload(channel, sender, content):
    """Canonical bytes to sign: channel\\nsender\\ncontent."""
    return f"{channel}\n{sender}\n{content}".encode('utf-8')


def _verify_signature(channel, sender, content, signature_b64, public_key_pem):
    """Verify a message signature against the sender's public key."""
    if not HAS_CRYPTO:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw_pem = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        public_key = serialization.load_pem_public_key(raw_pem)  # type: ignore[possibly-undefined]
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        payload = _sign_payload(channel, sender, content)
        sig = base64.b64decode(signature_b64)
        public_key.verify(sig, payload)
        return True
    except Exception:
        return False


def _is_secure_mode(conn):
    """Security is active once at least one operator exists."""
    row = conn.execute(
        "SELECT COUNT(*) FROM ipc_agents WHERE role = 'operator'"
    ).fetchone()
    return row[0] > 0


def _get_agent_pubkey(conn, name):
    """Look up an agent's public key. Returns (public_key_pem, role) or (None, None)."""
    row = conn.execute(
        "SELECT public_key, role FROM ipc_agents WHERE name = ?", (name,)
    ).fetchone()
    return (row[0], row[1]) if row else (None, None)


# ===================================================================
# DID:key (W3C)
# ===================================================================

_B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_ED25519_MULTICODEC = bytes([0xed, 0x01])
_ED25519_SPKI_PREFIX = bytes([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x03, 0x21, 0x00
])


def _b58_encode(data: bytes) -> str:
    """Base58btc encode raw bytes."""
    num = int.from_bytes(data, 'big')
    result = []
    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(_B58_ALPHABET[remainder:remainder + 1])
    for byte in data:
        if byte == 0:
            result.append(_B58_ALPHABET[0:1])
        else:
            break
    return b''.join(reversed(result)).decode('ascii')


def _pem_to_raw_pubkey(pem_text: str) -> bytes:
    """Extract raw 32-byte Ed25519 public key from PEM (SubjectPublicKeyInfo)."""
    lines = [l for l in pem_text.strip().splitlines() if not l.startswith('-----')]
    der = base64.b64decode(''.join(lines))
    if der[:len(_ED25519_SPKI_PREFIX)] == _ED25519_SPKI_PREFIX:
        return der[len(_ED25519_SPKI_PREFIX):]
    raise ValueError("Not an Ed25519 SubjectPublicKeyInfo PEM")


def _pubkey_to_did(raw_pubkey: bytes) -> str:
    """Convert raw 32-byte Ed25519 public key to did:key identifier."""
    multicodec_key = _ED25519_MULTICODEC + raw_pubkey
    return f"did:key:z{_b58_encode(multicodec_key)}"


# ===================================================================
# Agent Card
# ===================================================================

def _build_agent_card(name, description, endpoint, did=None):
    """Build an A2A Agent Card (/.well-known/agent-card.json)."""
    card = {
        "name": name,
        "description": description,
        "url": endpoint,
        "version": "1.0.0",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
        },
        "authentication": {
            "schemes": ["Ed25519Signature"]
        },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {
                "id": "ipc",
                "name": "Inter-Agent Messaging",
                "description": "Send and receive signed messages via el-ipc",
                "tags": ["ipc", "messaging", "ed25519"]
            }
        ]
    }
    if did:
        card["did"] = did
    return card


# ===================================================================
# Database Init
# ===================================================================

def _init_db():
    """Create IPC tables in the sidecar's database."""
    with _api['db_lock']:
        conn = _api['get_db']()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ipc_messages (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel     TEXT NOT NULL,
                    sender      TEXT NOT NULL,
                    content     TEXT NOT NULL,
                    created_at  REAL NOT NULL,
                    read_by     TEXT DEFAULT '',
                    signature   TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ipc_watermarks (
                    agent       TEXT NOT NULL,
                    channel     TEXT NOT NULL,
                    last_id     INTEGER DEFAULT 0,
                    PRIMARY KEY (agent, channel)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ipc_agents (
                    name          TEXT PRIMARY KEY,
                    identity      TEXT NOT NULL DEFAULT '',
                    public_key    TEXT NOT NULL,
                    role          TEXT NOT NULL DEFAULT 'agent',
                    registered_by TEXT,
                    created_at    REAL NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()
    sys.stderr.write("[el-ipc] Database tables initialized\n")


# ===================================================================
# Route Handlers
# ===================================================================

def _handle_send(handler):
    """POST /ipc/send -- Receive a message from another agent.

    Body: {channel, sender, content, signature?, forward_to?}

    Stores in ipc_messages, inserts a sidecar event, optionally forwards
    to a remote agent URL.
    """
    body = handler._read_body()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        handler._send_json({"error": "invalid json"}, 400)
        return

    channel = data.get('channel', '')
    sender = data.get('sender', '')
    content = data.get('content', '')
    signature = data.get('signature', '')
    forward_to = data.get('forward_to', '')

    if not channel or not sender or not content:
        handler._send_json({"error": "channel, sender, and content required"}, 400)
        return

    # Signature verification in secure mode
    with _api['db_lock']:
        conn = _api['get_db']()
        try:
            secure = _is_secure_mode(conn)
            if secure:
                if not signature:
                    handler._send_json(
                        {"error": "signature required (secure mode active)"}, 403)
                    return
                pubkey_pem, _ = _get_agent_pubkey(conn, sender)
                if not pubkey_pem:
                    handler._send_json(
                        {"error": f"unknown sender: {sender}"}, 403)
                    return
                if not _verify_signature(channel, sender, content,
                                         signature, pubkey_pem):
                    handler._send_json({"error": "invalid signature"}, 403)
                    return

            # Store the message
            cursor = conn.execute(
                "INSERT INTO ipc_messages "
                "(channel, sender, content, created_at, signature) "
                "VALUES (?, ?, ?, ?, ?)",
                (channel, sender, content, time.time(), signature),
            )
            msg_id = cursor.lastrowid
            conn.commit()
        finally:
            conn.close()

    # Insert sidecar event so it appears in the drain
    metadata = {
        'sender': sender,
        'channel': channel,
        'message_id': msg_id,
    }
    if signature:
        metadata['signature'] = signature

    inserted = _api['insert_event'](
        source='ipc',
        type='ipc_message',
        text=content,
        user_id=sender,
        channel=channel,
        metadata=metadata,
    )
    if inserted:
        _api['notify_waiters']()

    # Forward to remote agent if requested
    forward_result = None
    if forward_to:
        forward_result = _forward_message(
            forward_to, channel, sender, content, signature)

    response = {'ok': True, 'id': msg_id}
    if forward_result is not None:
        response['forwarded'] = forward_result

    handler._send_json(response)


def _forward_message(url, channel, sender, content, signature):
    """Forward a message to a remote agent's /ipc/send endpoint."""
    payload = json.dumps({
        'channel': channel,
        'sender': sender,
        'content': content,
        'signature': signature,
    }).encode('utf-8')

    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read())
        return {'ok': True, 'remote_response': result}
    except Exception as e:
        sys.stderr.write(f"[el-ipc] forward to {url} failed: {e}\n")
        return {'ok': False, 'error': str(e)}


def _handle_register(handler):
    """POST /ipc/register -- Register an agent identity.

    Body: {name, public_key, identity?, operator?, operator_key?}

    In open mode (no operators yet), registers directly.
    In secure mode, requires operator authorization.
    """
    body = handler._read_body()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        handler._send_json({"error": "invalid json"}, 400)
        return

    agent_name = data.get('name', '')
    pubkey_pem = data.get('public_key', '')
    identity_str = data.get('identity', '')
    operator_name = data.get('operator', '')
    operator_key_pem = data.get('operator_key', '')
    role = data.get('role', 'agent')

    if not agent_name or not pubkey_pem:
        handler._send_json(
            {"error": "name and public_key required"}, 400)
        return

    with _api['db_lock']:
        conn = _api['get_db']()
        try:
            secure = _is_secure_mode(conn)

            if secure:
                # Require operator authorization
                if not operator_name or not operator_key_pem:
                    handler._send_json({
                        "error": "operator and operator_key required "
                                 "(secure mode active)"
                    }, 403)
                    return

                ok, msg = _register_agent_secure(
                    conn, agent_name, pubkey_pem, identity_str,
                    operator_name, operator_key_pem)
                if not ok:
                    handler._send_json({"error": msg}, 403)
                    return
                handler._send_json({"ok": True, "message": msg})
            else:
                # Open mode -- direct registration
                conn.execute(
                    "INSERT OR REPLACE INTO ipc_agents "
                    "(name, identity, public_key, role, registered_by, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (agent_name, identity_str, pubkey_pem, role,
                     operator_name or None, time.time()),
                )
                conn.commit()
                handler._send_json({
                    "ok": True,
                    "message": f"Agent '{agent_name}' registered (open mode)"
                })
        finally:
            conn.close()


def _register_agent_secure(conn, agent_name, pubkey_pem, identity_str,
                           operator_name, operator_key_pem):
    """Register an agent authorized by operator signature.

    The operator signs: "register\\n{agent_name}\\n{identity}\\n{pubkey_pem}"
    """
    if not HAS_CRYPTO:
        return False, "cryptography package not installed"

    # Look up operator
    op_pubkey_pem, op_role = _get_agent_pubkey(conn, operator_name)
    if not op_pubkey_pem:
        return False, f"Operator '{operator_name}' not found"
    if op_role != 'operator':
        return False, f"'{operator_name}' is not an operator (role: {op_role})"

    # Build registration payload and sign with operator's private key
    reg_payload = (
        f"register\n{agent_name}\n{identity_str}\n{pubkey_pem}"
    ).encode('utf-8')

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey as _Ed25519Pub,
            Ed25519PrivateKey as _Ed25519Priv,
        )
        from cryptography.hazmat.primitives import serialization as _ser
        operator_privkey = _ser.load_pem_private_key(
            operator_key_pem.encode()
            if isinstance(operator_key_pem, str) else operator_key_pem,
            password=None,
        )
        if not isinstance(operator_privkey, _Ed25519Priv):
            return False, "Operator key is not Ed25519"
        reg_sig = operator_privkey.sign(reg_payload)

        # Verify operator's signature
        op_pubkey = _ser.load_pem_public_key(
            op_pubkey_pem.encode()
            if isinstance(op_pubkey_pem, str) else op_pubkey_pem
        )
        if not isinstance(op_pubkey, _Ed25519Pub):
            return False, "Operator key is not Ed25519"
        op_pubkey.verify(reg_sig, reg_payload)
    except Exception as e:
        return False, f"Operator signature verification failed: {e}"

    # Store agent
    conn.execute(
        "INSERT OR REPLACE INTO ipc_agents "
        "(name, identity, public_key, role, registered_by, created_at) "
        "VALUES (?, ?, ?, 'agent', ?, ?)",
        (agent_name, identity_str, pubkey_pem, operator_name, time.time()),
    )
    conn.commit()
    return True, f"Agent '{agent_name}' registered by operator '{operator_name}'"


def _handle_messages(handler, params):
    """GET /ipc/messages?channel=X&agent=Y[&after_id=N]

    Returns message history. If agent is provided, advances watermark.
    If after_id is provided, returns messages after that ID.
    """
    channel = params.get('channel', '')
    agent = params.get('agent', '')
    after_id = params.get('after_id', '')

    if not channel:
        handler._send_json({"error": "channel param required"}, 400)
        return

    with _api['db_lock']:
        conn = _api['get_db']()
        try:
            # Determine starting point
            if after_id:
                try:
                    start_id = int(after_id)
                except ValueError:
                    start_id = 0
            elif agent:
                row = conn.execute(
                    "SELECT last_id FROM ipc_watermarks "
                    "WHERE agent = ? AND channel = ?",
                    (agent, channel),
                ).fetchone()
                start_id = row[0] if row else 0
            else:
                start_id = 0

            rows = conn.execute(
                "SELECT id, sender, content, created_at, signature "
                "FROM ipc_messages "
                "WHERE channel = ? AND id > ? ORDER BY id ASC",
                (channel, start_id),
            ).fetchall()

            messages = []
            max_id = start_id
            for row in rows:
                msg = {
                    'id': row[0],
                    'sender': row[1],
                    'content': row[2],
                    'timestamp': row[3],
                }
                if row[4]:
                    msg['signed'] = True
                messages.append(msg)
                if row[0] > max_id:
                    max_id = row[0]

            # Advance watermark if agent is specified
            if agent and max_id > start_id:
                conn.execute(
                    "INSERT OR REPLACE INTO ipc_watermarks "
                    "(agent, channel, last_id) VALUES (?, ?, ?)",
                    (agent, channel, max_id),
                )
                conn.commit()

            handler._send_json(messages)
        finally:
            conn.close()


def _handle_agents(handler, params):
    """GET /ipc/agents -- List all registered agents."""
    with _api['db_lock']:
        conn = _api['get_db']()
        try:
            rows = conn.execute(
                "SELECT name, identity, role, registered_by, created_at "
                "FROM ipc_agents ORDER BY created_at"
            ).fetchall()

            agents = [
                {
                    'name': r[0],
                    'identity': r[1],
                    'role': r[2],
                    'registered_by': r[3],
                    'created_at': r[4],
                }
                for r in rows
            ]
            handler._send_json(agents)
        finally:
            conn.close()


def _handle_channels(handler, params):
    """GET /ipc/channels -- List channels with message counts."""
    with _api['db_lock']:
        conn = _api['get_db']()
        try:
            rows = conn.execute(
                "SELECT channel, COUNT(*) as cnt, MAX(created_at) as last "
                "FROM ipc_messages GROUP BY channel ORDER BY last DESC"
            ).fetchall()

            channels = [
                {'channel': r[0], 'count': r[1], 'last_message': r[2]}
                for r in rows
            ]
            handler._send_json(channels)
        finally:
            conn.close()


def _handle_agent_card(handler, params):
    """GET /.well-known/agent-card.json -- A2A Agent Card with DID:key."""
    name = AGENT_CARD_NAME or 'el-ipc agent'
    description = (AGENT_CARD_DESC
                   or 'An el-ipc agent with Ed25519 identity')
    endpoint = AGENT_CARD_URL or ''

    # Derive DID:key from the first operator's public key
    did = None
    with _api['db_lock']:
        conn = _api['get_db']()
        try:
            row = conn.execute(
                "SELECT public_key FROM ipc_agents "
                "WHERE role = 'operator' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row:
                try:
                    raw = _pem_to_raw_pubkey(row[0])
                    did = _pubkey_to_did(raw)
                except Exception:
                    pass
        finally:
            conn.close()

    card = _build_agent_card(name, description, endpoint, did=did)
    handler._send_json(card)


# ===================================================================
# Plugin Registration
# ===================================================================

def register(api):
    """Register el-ipc as a sidecar plugin.

    api is a dict providing:
        insert_event(source, **fields)  -- insert an event with enrichment
        notify_waiters()                -- wake up drain long-poll
        register_route(method, path, handler)  -- register an HTTP route
        register_poller(name, func)     -- register a background poller
        register_init(name, func)       -- register a startup hook
        register_on_pick(name, func)    -- register a drain callback
        get_db()                        -- get a DB connection
        db_lock                         -- threading lock for DB access
    """
    global _api
    _api = api

    # Init hook: create IPC tables
    api['register_init']('ipc', _init_db)

    # Routes
    api['register_route']('POST', '/ipc/send', _handle_send)
    api['register_route']('POST', '/ipc/register', _handle_register)
    api['register_route']('GET', '/ipc/messages', _handle_messages)
    api['register_route']('GET', '/ipc/agents', _handle_agents)
    api['register_route']('GET', '/ipc/channels', _handle_channels)
    api['register_route']('GET', '/.well-known/agent-card.json',
                          _handle_agent_card)

    sys.stderr.write(
        f"[el-ipc] Registered (agent={AGENT_CARD_NAME or '(default)'}, "
        f"crypto={'yes' if HAS_CRYPTO else 'no'})\n"
    )
