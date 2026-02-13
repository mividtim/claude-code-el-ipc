"""Inter-agent IPC server for claude-code-el-ipc plugin.

Buffers messages between agents in SQLite. Provides HTTP endpoints for
sending, receiving (with long-poll), and health checks. Also provides a
CLI mode for sending messages without HTTP.

Supports Ed25519 asymmetric identity verification: operators seed their
keypair, register agents with public keys, and all messages are signed
and verified. Security activates automatically when the first operator
is seeded — before that, the system runs in open mode (backward compatible).

Usage:
    Server mode:  python3 ipc-server.py serve [port]
    Send mode:    python3 ipc-server.py send <channel> <from> <message> [--key <keyfile>]
    Read mode:    python3 ipc-server.py read <channel> <agent> [--wait]
    Channels:     python3 ipc-server.py channels
    Seed:         python3 ipc-server.py seed <operator-name>
    Keygen:       python3 ipc-server.py keygen [--out <prefix>]
    Register:     python3 ipc-server.py register <name> --pubkey <file> --as <operator> --key <keyfile> [--identity <str>]
    Agents:       python3 ipc-server.py agents
    Agent Card:   python3 ipc-server.py agent-card

Env vars:
    IPC_DB_PATH   - SQLite database path (default: /tmp/el-ipc.db)
    IPC_PORT      - Server port (default: 9876)
    IPC_API_KEY   - Optional API key for HTTP auth (legacy, pre-identity)
"""

import base64
import json
import os
import sqlite3
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote

# --- Optional crypto (graceful degradation) ---

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# --- Configuration ---

DB_PATH = os.environ.get('IPC_DB_PATH', '/tmp/el-ipc.db')
DEFAULT_PORT = int(os.environ.get('IPC_PORT', '9876'))
API_KEY = os.environ.get('IPC_API_KEY', '')  # Legacy auth (pre-identity)
AGENT_CARD_NAME = os.environ.get('IPC_AGENT_NAME', '')
AGENT_CARD_DESC = os.environ.get('IPC_AGENT_DESC', '')
AGENT_CARD_URL = os.environ.get('IPC_AGENT_URL', '')

# --- Database ---

_db_lock = threading.Lock()


def _get_db():
    """Create a new connection for the calling thread."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            channel     TEXT NOT NULL,
            sender      TEXT NOT NULL,
            content     TEXT NOT NULL,
            created_at  REAL NOT NULL,
            read_by     TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS watermarks (
            agent       TEXT NOT NULL,
            channel     TEXT NOT NULL,
            last_id     INTEGER DEFAULT 0,
            PRIMARY KEY (agent, channel)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            name          TEXT PRIMARY KEY,
            identity      TEXT NOT NULL DEFAULT '',
            public_key    TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'agent',
            registered_by TEXT,
            created_at    REAL NOT NULL
        )
    """)
    # Migration: add signature column if missing
    try:
        conn.execute("SELECT signature FROM messages LIMIT 0")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE messages ADD COLUMN signature TEXT DEFAULT ''")
    conn.commit()
    return conn


# --- Identity / Crypto ---

def _require_crypto(action):
    if not HAS_CRYPTO:
        print(f"Error: '{action}' requires the cryptography package.", file=sys.stderr)
        print("Install it:  pip install cryptography", file=sys.stderr)
        sys.exit(1)


def _sign_payload(channel, sender, content):
    """Canonical bytes to sign: channel\\nsender\\ncontent."""
    return f"{channel}\n{sender}\n{content}".encode('utf-8')


def _sign_message(channel, sender, content, private_key_pem):
    """Sign a message. Returns base64-encoded Ed25519 signature."""
    _require_crypto('sign')
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
        password=None,
    )
    payload = _sign_payload(channel, sender, content)
    sig = private_key.sign(payload)
    return base64.b64encode(sig).decode()


def _verify_signature(channel, sender, content, signature_b64, public_key_pem):
    """Verify a message signature against the sender's public key."""
    _require_crypto('verify')
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        )
        payload = _sign_payload(channel, sender, content)
        sig = base64.b64decode(signature_b64)
        public_key.verify(sig, payload)
        return True
    except Exception:
        return False


def _is_secure_mode():
    """Security is active once at least one operator exists."""
    conn = _get_db()
    try:
        row = conn.execute("SELECT COUNT(*) FROM agents WHERE role = 'operator'").fetchone()
        return row[0] > 0
    finally:
        conn.close()


def _get_agent_pubkey(name):
    """Look up an agent's public key. Returns (public_key_pem, role) or (None, None)."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT public_key, role FROM agents WHERE name = ?", (name,)
        ).fetchone()
        return (row[0], row[1]) if row else (None, None)
    finally:
        conn.close()


def _seed_operator(name):
    """Generate Ed25519 keypair, register as operator. Returns private key PEM."""
    _require_crypto('seed')
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    with _db_lock:
        conn = _get_db()
        try:
            existing = conn.execute(
                "SELECT name FROM agents WHERE name = ?", (name,)
            ).fetchone()
            if existing:
                raise ValueError(f"Agent '{name}' already exists")
            conn.execute(
                "INSERT INTO agents (name, public_key, role, created_at) VALUES (?, ?, 'operator', ?)",
                (name, public_pem, time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    return private_pem, public_pem


def _keygen():
    """Generate an Ed25519 keypair. Returns (private_pem, public_pem)."""
    _require_crypto('keygen')
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return private_pem, public_pem


# --- DID:key (W3C) ---
# Converts Ed25519 public keys to did:key:z... identifiers.
# Base58btc encoding with Ed25519 multicodec prefix (0xed01).

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


def _build_agent_card(name: str, description: str, endpoint: str,
                      did: str | None = None, skills: list | None = None) -> dict:
    """Build an A2A Agent Card (/.well-known/agent-card.json)."""
    card: dict = {
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
        "skills": skills or [
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


def _register_agent(agent_name, agent_pubkey_pem, identity_str, operator_name, operator_key_pem):
    """Register a new agent, authorized by operator signature.

    The operator signs: "register\\n{agent_name}\\n{identity}\\n{agent_pubkey_pem}"
    This proves the operator authorized this specific registration.
    """
    _require_crypto('register')

    # Look up operator
    op_pubkey_pem, op_role = _get_agent_pubkey(operator_name)
    if not op_pubkey_pem:
        return False, f"Operator '{operator_name}' not found"
    if op_role != 'operator':
        return False, f"'{operator_name}' is not an operator (role: {op_role})"

    # Build registration payload and sign with operator's private key
    reg_payload = f"register\n{agent_name}\n{identity_str}\n{agent_pubkey_pem}".encode('utf-8')

    operator_privkey = serialization.load_pem_private_key(
        operator_key_pem.encode() if isinstance(operator_key_pem, str) else operator_key_pem,
        password=None,
    )
    reg_sig = operator_privkey.sign(reg_payload)

    # Verify operator's signature (proves we have the right operator key)
    op_pubkey = serialization.load_pem_public_key(
        op_pubkey_pem.encode() if isinstance(op_pubkey_pem, str) else op_pubkey_pem
    )
    try:
        op_pubkey.verify(reg_sig, reg_payload)
    except Exception as e:
        return False, f"Operator signature verification failed: {e}"

    # Store agent
    with _db_lock:
        conn = _get_db()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO agents (name, identity, public_key, role, registered_by, created_at) "
                "VALUES (?, ?, ?, 'agent', ?, ?)",
                (agent_name, identity_str, agent_pubkey_pem, operator_name, time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    return True, f"Agent '{agent_name}' registered by operator '{operator_name}'"


def _list_agents():
    """List all registered agents."""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT name, identity, role, registered_by, created_at FROM agents ORDER BY created_at"
        ).fetchall()
        return [
            {
                'name': r[0],
                'identity': r[1],
                'role': r[2],
                'registered_by': r[3],
                'created_at': r[4],
            }
            for r in rows
        ]
    finally:
        conn.close()


# --- Message Operations ---

def _send_message(channel, sender, content, signature=''):
    """Insert a message into the buffer. Returns the message ID."""
    with _db_lock:
        conn = _get_db()
        try:
            cursor = conn.execute(
                "INSERT INTO messages (channel, sender, content, created_at, signature) VALUES (?, ?, ?, ?, ?)",
                (channel, sender, content, time.time(), signature),
            )
            msg_id = cursor.lastrowid
            conn.commit()
            _notify_waiters()
            return msg_id
        finally:
            conn.close()


def _read_messages(channel, agent, mark_read=True):
    """Return unread messages for an agent on a channel."""
    with _db_lock:
        conn = _get_db()
        try:
            row = conn.execute(
                "SELECT last_id FROM watermarks WHERE agent = ? AND channel = ?",
                (agent, channel),
            ).fetchone()
            last_id = row[0] if row else 0

            rows = conn.execute(
                "SELECT id, sender, content, created_at, signature FROM messages "
                "WHERE channel = ? AND id > ? ORDER BY id ASC",
                (channel, last_id),
            ).fetchall()

            if not rows:
                return []

            messages = []
            max_id = last_id
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

            if mark_read and max_id > last_id:
                conn.execute(
                    "INSERT OR REPLACE INTO watermarks (agent, channel, last_id) VALUES (?, ?, ?)",
                    (agent, channel, max_id),
                )
                conn.commit()

            return messages
        finally:
            conn.close()


def _pending_count(channel, agent):
    """Count unread messages for an agent on a channel."""
    with _db_lock:
        conn = _get_db()
        try:
            row = conn.execute(
                "SELECT last_id FROM watermarks WHERE agent = ? AND channel = ?",
                (agent, channel),
            ).fetchone()
            last_id = row[0] if row else 0

            row = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE channel = ? AND id > ?",
                (channel, last_id),
            ).fetchone()
            return row[0] if row else 0
        finally:
            conn.close()


def _list_channels():
    """List all channels with message counts."""
    with _db_lock:
        conn = _get_db()
        try:
            rows = conn.execute(
                "SELECT channel, COUNT(*) as cnt, MAX(created_at) as last "
                "FROM messages GROUP BY channel ORDER BY last DESC"
            ).fetchall()
            return [{'channel': r[0], 'count': r[1], 'last_message': r[2]} for r in rows]
        finally:
            conn.close()


# --- Notification for long-poll waiters ---

_waiter_event = threading.Event()


def _notify_waiters():
    _waiter_event.set()


# --- HTTP Handler ---

class IPCHandler(BaseHTTPRequestHandler):

    def _check_auth(self):
        """Verify API key if configured (legacy auth). Returns True if authorized."""
        if not API_KEY:
            return True
        auth = self.headers.get('Authorization', '')
        if auth == f'Bearer {API_KEY}':
            return True
        self._json_response(401, {'error': 'unauthorized'})
        return False

    def do_POST(self):
        try:
            if not self._check_auth():
                return
            path = self.path.split('?')[0]
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))

            if path == '/send':
                self._handle_send(body)
            elif path == '/register':
                self._handle_register(body)
            else:
                self._json_response(404, {'error': 'not found'})

        except Exception as e:
            sys.stderr.write(f"[ipc-server] POST error: {e}\n")
            self._json_response(500, {'error': str(e)})

    def _handle_send(self, body):
        """POST /send — send a message (with signature verification in secure mode)."""
        channel = body.get('channel', '')
        sender = body.get('sender', '')
        content = body.get('content', '')
        signature = body.get('signature', '')

        if not channel or not sender or not content:
            self._json_response(400, {'error': 'channel, sender, and content required'})
            return

        # Identity verification in secure mode
        if _is_secure_mode():
            if not signature:
                self._json_response(403, {'error': 'signature required (secure mode active)'})
                return
            pubkey_pem, _ = _get_agent_pubkey(sender)
            if not pubkey_pem:
                self._json_response(403, {'error': f'unknown sender: {sender}'})
                return
            if not _verify_signature(channel, sender, content, signature, pubkey_pem):
                self._json_response(403, {'error': 'invalid signature'})
                return

        msg_id = _send_message(channel, sender, content, signature)
        self._json_response(200, {'ok': True, 'id': msg_id})

    def _handle_register(self, body):
        """POST /register — register a new agent (requires operator key)."""
        if not HAS_CRYPTO:
            self._json_response(500, {'error': 'cryptography package not installed on server'})
            return

        agent_name = body.get('name', '')
        pubkey_pem = body.get('public_key', '')
        identity_str = body.get('identity', '')
        operator_name = body.get('operator', '')
        operator_key_pem = body.get('operator_key', '')

        if not agent_name or not pubkey_pem or not operator_name or not operator_key_pem:
            self._json_response(400, {
                'error': 'name, public_key, operator, and operator_key required'
            })
            return

        ok, msg = _register_agent(agent_name, pubkey_pem, identity_str, operator_name, operator_key_pem)
        if ok:
            self._json_response(200, {'ok': True, 'message': msg})
        else:
            self._json_response(403, {'error': msg})

    def do_GET(self):
        try:
            if not self._check_auth():
                return
            path = self.path.split('?')[0]
            params = self._parse_params()

            if path == '/messages':
                self._handle_messages(params)
            elif path == '/channels':
                self._handle_channels()
            elif path == '/agents':
                self._handle_agents()
            elif path == '/health':
                self._handle_health(params)
            elif path == '/.well-known/agent-card.json':
                self._handle_agent_card()
            else:
                self._json_response(404, {'error': 'not found'})
        except Exception as e:
            sys.stderr.write(f"[ipc-server] GET error: {e}\n")
            self._json_response(500, {'error': str(e)})

    def _handle_messages(self, params):
        """GET /messages?channel=X&agent=Y[&wait=true]"""
        channel = unquote(params.get('channel', ''))
        agent = unquote(params.get('agent', ''))
        wait = params.get('wait', '').lower() == 'true'

        if not channel or not agent:
            self._json_response(400, {'error': 'channel and agent params required'})
            return

        if wait:
            deadline = time.time() + 30.0
            while time.time() < deadline:
                if _pending_count(channel, agent) > 0:
                    break
                _waiter_event.clear()
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                _waiter_event.wait(timeout=min(0.5, remaining))

            # Burst collection
            if _pending_count(channel, agent) > 0:
                time.sleep(0.3)

        messages = _read_messages(channel, agent)
        self._json_response(200, messages)

    def _handle_channels(self):
        channels = _list_channels()
        self._json_response(200, channels)

    def _handle_agents(self):
        """GET /agents — list registered agents (public keys + roles)."""
        agents = _list_agents()
        self._json_response(200, agents)

    def _handle_health(self, params):
        channel = unquote(params.get('channel', ''))
        agent = unquote(params.get('agent', ''))
        pending = _pending_count(channel, agent) if channel and agent else 0
        secure = _is_secure_mode()
        self._json_response(200, {'status': 'ok', 'pending': pending, 'secure_mode': secure})

    def _handle_agent_card(self):
        """GET /.well-known/agent-card.json — A2A Agent Card with DID:key."""
        name = AGENT_CARD_NAME or 'el-ipc agent'
        description = AGENT_CARD_DESC or 'An el-ipc agent with Ed25519 identity'
        endpoint = AGENT_CARD_URL or f'http://localhost:{DEFAULT_PORT}'

        # Try to derive DID:key from the first operator's public key
        did = None
        conn = _get_db()
        try:
            row = conn.execute(
                "SELECT public_key FROM agents WHERE role = 'operator' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row:
                try:
                    raw = _pem_to_raw_pubkey(row[0])
                    did = _pubkey_to_did(raw)
                except Exception:
                    pass  # No DID if key can't be parsed
        finally:
            conn.close()

        card = _build_agent_card(name, description, endpoint, did=did)
        self._json_response(200, card)

    def _json_response(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_params(self):
        params = {}
        if '?' in self.path:
            query = self.path.split('?')[1]
            for part in query.split('&'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    params[k] = v
        return params

    def log_message(self, format, *args):
        pass


# --- CLI Commands ---

def cli_send(args):
    """Send a message via direct DB write (no server needed)."""
    # Parse --key flag
    key_file = None
    clean_args = []
    i = 0
    while i < len(args):
        if args[i] == '--key' and i + 1 < len(args):
            key_file = args[i + 1]
            i += 2
        else:
            clean_args.append(args[i])
            i += 1

    if len(clean_args) < 3:
        print("Usage: ipc-server.py send <channel> <from> <message> [--key <keyfile>]", file=sys.stderr)
        sys.exit(1)

    channel, sender, content = clean_args[0], clean_args[1], ' '.join(clean_args[2:])

    signature = ''

    # In secure mode, signing is required
    if _is_secure_mode():
        if not key_file:
            print("Error: secure mode active — --key <private-key-file> required", file=sys.stderr)
            sys.exit(1)
        with open(key_file, 'r') as f:
            private_pem = f.read()
        signature = _sign_message(channel, sender, content, private_pem)

        # Verify against stored public key
        pubkey_pem, _ = _get_agent_pubkey(sender)
        if not pubkey_pem:
            print(f"Error: unknown sender '{sender}' — not registered", file=sys.stderr)
            sys.exit(1)
        if not _verify_signature(channel, sender, content, signature, pubkey_pem):
            print("Error: signature does not match registered public key", file=sys.stderr)
            sys.exit(1)
    elif key_file:
        # Optional signing in open mode
        with open(key_file, 'r') as f:
            private_pem = f.read()
        signature = _sign_message(channel, sender, content, private_pem)

    msg_id = _send_message(channel, sender, content, signature)
    print(json.dumps({'ok': True, 'id': msg_id, 'channel': channel, 'signed': bool(signature)}))


def cli_read(args):
    """Read messages via direct DB read (no server needed)."""
    if len(args) < 2:
        print("Usage: ipc-server.py read <channel> <agent> [--wait]", file=sys.stderr)
        sys.exit(1)
    channel = args[0]
    agent = args[1]
    wait = '--wait' in args

    if wait:
        deadline = time.time() + 30.0
        while time.time() < deadline:
            if _pending_count(channel, agent) > 0:
                break
            time.sleep(0.5)

    messages = _read_messages(channel, agent)
    if messages:
        print(json.dumps(messages, indent=2))
    else:
        print('[]')


def cli_channels(args):
    """List all channels."""
    channels = _list_channels()
    print(json.dumps(channels, indent=2))


def cli_seed(args):
    """Seed an operator: generate keypair, store public key, print private key."""
    if len(args) < 1:
        print("Usage: ipc-server.py seed <operator-name>", file=sys.stderr)
        sys.exit(1)

    name = args[0]
    try:
        private_pem, public_pem = _seed_operator(name)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Output the private key — user must save this
    sys.stderr.write(f"[ipc] Operator '{name}' seeded. Public key stored in DB.\n")
    sys.stderr.write(f"[ipc] SAVE THE PRIVATE KEY BELOW — it cannot be recovered.\n\n")
    print(private_pem)


def cli_keygen(args):
    """Generate an Ed25519 keypair (utility, does not register anything)."""
    out_prefix = None
    i = 0
    while i < len(args):
        if args[i] == '--out' and i + 1 < len(args):
            out_prefix = args[i + 1]
            i += 2
        else:
            i += 1

    private_pem, public_pem = _keygen()

    if out_prefix:
        key_path = f"{out_prefix}.key"
        pub_path = f"{out_prefix}.pub"
        with open(key_path, 'w') as f:
            f.write(private_pem)
        os.chmod(key_path, 0o600)
        with open(pub_path, 'w') as f:
            f.write(public_pem)
        sys.stderr.write(f"[ipc] Private key: {key_path} (chmod 600)\n")
        sys.stderr.write(f"[ipc] Public key:  {pub_path}\n")
    else:
        sys.stderr.write("--- PRIVATE KEY ---\n")
        print(private_pem)
        sys.stderr.write("--- PUBLIC KEY ---\n")
        print(public_pem)


def cli_register(args):
    """Register an agent, authorized by an operator's private key."""
    # Parse flags
    agent_name = args[0] if args else ''
    pubkey_file = identity_str = operator_name = operator_key_file = ''

    i = 1
    while i < len(args):
        if args[i] == '--pubkey' and i + 1 < len(args):
            pubkey_file = args[i + 1]
            i += 2
        elif args[i] == '--identity' and i + 1 < len(args):
            identity_str = args[i + 1]
            i += 2
        elif args[i] == '--as' and i + 1 < len(args):
            operator_name = args[i + 1]
            i += 2
        elif args[i] == '--key' and i + 1 < len(args):
            operator_key_file = args[i + 1]
            i += 2
        else:
            i += 1

    if not agent_name or not pubkey_file or not operator_name or not operator_key_file:
        print("Usage: ipc-server.py register <name> --pubkey <file> --as <operator> --key <keyfile> [--identity <str>]",
              file=sys.stderr)
        sys.exit(1)

    with open(pubkey_file, 'r') as f:
        agent_pubkey_pem = f.read().strip()
    with open(operator_key_file, 'r') as f:
        operator_key_pem = f.read().strip()

    ok, msg = _register_agent(agent_name, agent_pubkey_pem, identity_str, operator_name, operator_key_pem)
    if ok:
        print(json.dumps({'ok': True, 'message': msg}))
    else:
        print(f"Error: {msg}", file=sys.stderr)
        sys.exit(1)


def cli_agents(args):
    """List all registered agents."""
    agents = _list_agents()
    if not agents:
        print("No agents registered (open mode — anyone can send)")
        return
    for a in agents:
        role_tag = f"[{a['role']}]"
        reg = f" (registered by {a['registered_by']})" if a['registered_by'] else ""
        ident = f" id={a['identity']}" if a['identity'] else ""
        print(f"  {role_tag:10s} {a['name']}{ident}{reg}")


def cli_agent_card(args):
    """Print the A2A Agent Card JSON."""
    name = AGENT_CARD_NAME or 'el-ipc agent'
    description = AGENT_CARD_DESC or 'An el-ipc agent with Ed25519 identity'
    endpoint = AGENT_CARD_URL or f'http://localhost:{DEFAULT_PORT}'

    did = None
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT public_key FROM agents WHERE role = 'operator' ORDER BY created_at LIMIT 1"
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
    print(json.dumps(card, indent=2))


def cli_serve(args):
    """Start the HTTP server."""
    port = int(args[0]) if args else DEFAULT_PORT
    _get_db()  # Initialize DB + migrations
    secure = _is_secure_mode()
    server = HTTPServer(('0.0.0.0', port), IPCHandler)
    sys.stderr.write(f"[ipc-server] Listening on 0.0.0.0:{port}\n")
    sys.stderr.write(f"[ipc-server] DB: {DB_PATH}\n")
    sys.stderr.write(f"[ipc-server] Security: {'ACTIVE (Ed25519)' if secure else 'OPEN (no operators seeded)'}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[ipc-server] Shutting down.\n")
        server.shutdown()


# --- Main ---

COMMANDS = {
    'serve': cli_serve,
    'send': cli_send,
    'read': cli_read,
    'channels': cli_channels,
    'seed': cli_seed,
    'keygen': cli_keygen,
    'register': cli_register,
    'agents': cli_agents,
    'agent-card': cli_agent_card,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        cmds = '|'.join(COMMANDS.keys())
        print(f"Usage: ipc-server.py <{cmds}> [args...]", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]
    COMMANDS[cmd](sys.argv[2:])


if __name__ == '__main__':
    main()
