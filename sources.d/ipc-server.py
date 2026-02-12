"""Inter-agent IPC server for claude-code-el-ipc plugin.

Buffers messages between agents in SQLite. Provides HTTP endpoints for
sending, receiving (with long-poll), and health checks. Also provides a
CLI mode for sending messages without HTTP.

Usage:
    Server mode:  python3 ipc-server.py serve [port]
    Send mode:    python3 ipc-server.py send <channel> <from> <message>
    Read mode:    python3 ipc-server.py read <channel> [--wait]
    Channels:     python3 ipc-server.py channels

Env vars:
    IPC_DB_PATH   - SQLite database path (default: /tmp/el-ipc.db)
    IPC_PORT      - Server port (default: 9876)
"""

import json
import os
import sqlite3
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

# --- Configuration ---

DB_PATH = os.environ.get('IPC_DB_PATH', '/tmp/el-ipc.db')
DEFAULT_PORT = int(os.environ.get('IPC_PORT', '9876'))
API_KEY = os.environ.get('IPC_API_KEY', '')  # Set to require auth on HTTP endpoints

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
    conn.commit()
    return conn


def _send_message(channel, sender, content):
    """Insert a message into the buffer. Returns the message ID."""
    with _db_lock:
        conn = _get_db()
        try:
            cursor = conn.execute(
                "INSERT INTO messages (channel, sender, content, created_at) VALUES (?, ?, ?, ?)",
                (channel, sender, content, time.time()),
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
            # Get watermark
            row = conn.execute(
                "SELECT last_id FROM watermarks WHERE agent = ? AND channel = ?",
                (agent, channel),
            ).fetchone()
            last_id = row[0] if row else 0

            # Get messages after watermark
            rows = conn.execute(
                "SELECT id, sender, content, created_at FROM messages "
                "WHERE channel = ? AND id > ? ORDER BY id ASC",
                (channel, last_id),
            ).fetchall()

            if not rows:
                return []

            messages = []
            max_id = last_id
            for row in rows:
                messages.append({
                    'id': row[0],
                    'sender': row[1],
                    'content': row[2],
                    'timestamp': row[3],
                })
                if row[0] > max_id:
                    max_id = row[0]

            # Advance watermark
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
        """Verify API key if configured. Returns True if authorized."""
        if not API_KEY:
            return True
        auth = self.headers.get('Authorization', '')
        if auth == f'Bearer {API_KEY}':
            return True
        self._json_response(401, {'error': 'unauthorized'})
        return False

    def do_POST(self):
        """POST /send — send a message."""
        try:
            if not self._check_auth():
                return
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))

            channel = body.get('channel', '')
            sender = body.get('sender', '')
            content = body.get('content', '')

            if not channel or not sender or not content:
                self._json_response(400, {'error': 'channel, sender, and content required'})
                return

            msg_id = _send_message(channel, sender, content)
            self._json_response(200, {'ok': True, 'id': msg_id})

        except Exception as e:
            sys.stderr.write(f"[ipc-server] POST error: {e}\n")
            self._json_response(500, {'error': str(e)})

    def do_GET(self):
        """GET /messages, /channels, /health."""
        try:
            if not self._check_auth():
                return
            path = self.path.split('?')[0]
            params = self._parse_params()

            if path == '/messages':
                self._handle_messages(params)
            elif path == '/channels':
                self._handle_channels()
            elif path == '/health':
                self._handle_health(params)
            else:
                self._json_response(404, {'error': 'not found'})
        except Exception as e:
            sys.stderr.write(f"[ipc-server] GET error: {e}\n")
            self._json_response(500, {'error': str(e)})

    def _handle_messages(self, params):
        """GET /messages?channel=X&agent=Y[&wait=true]"""
        channel = params.get('channel', '')
        agent = params.get('agent', '')
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

    def _handle_health(self, params):
        channel = params.get('channel', '')
        agent = params.get('agent', '')
        pending = _pending_count(channel, agent) if channel and agent else 0
        self._json_response(200, {'status': 'ok', 'pending': pending})

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
    if len(args) < 3:
        print("Usage: ipc-server.py send <channel> <from> <message>", file=sys.stderr)
        sys.exit(1)
    channel, sender, content = args[0], args[1], ' '.join(args[2:])
    msg_id = _send_message(channel, sender, content)
    print(json.dumps({'ok': True, 'id': msg_id, 'channel': channel}))


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


def cli_serve(args):
    """Start the HTTP server."""
    port = int(args[0]) if args else DEFAULT_PORT
    _get_db()  # Initialize DB
    server = HTTPServer(('0.0.0.0', port), IPCHandler)
    sys.stderr.write(f"[ipc-server] Listening on 0.0.0.0:{port}\n")
    sys.stderr.write(f"[ipc-server] DB: {DB_PATH}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[ipc-server] Shutting down.\n")
        server.shutdown()


# --- Main ---

def main():
    if len(sys.argv) < 2:
        print("Usage: ipc-server.py <serve|send|read|channels> [args...]", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == 'serve':
        cli_serve(args)
    elif cmd == 'send':
        cli_send(args)
    elif cmd == 'read':
        cli_read(args)
    elif cmd == 'channels':
        cli_channels(args)
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
