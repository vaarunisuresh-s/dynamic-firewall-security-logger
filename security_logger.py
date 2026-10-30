"""log_event(): sends each security event to the central log server over TCP and
also keeps a local copy (logs/security_events.log) so nothing is lost if the server is down."""
import logging
import os
import socket
import time

import firewall_rules as cfg

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

_local = logging.getLogger("security_events_local")
_local.setLevel(logging.INFO)
_local.propagate = False
if not _local.handlers:
    _h = logging.FileHandler(os.path.join(LOG_DIR, "security_events.log"))
    _h.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    _local.addHandler(_h)

_sock = None
_server_up = None  # None=unknown, True/False = last known state


def _send(line):
    global _sock
    for _ in range(2):
        try:
            if _sock is None:
                _sock = socket.create_connection((cfg.LOG_SERVER_HOST, cfg.LOG_SERVER_PORT), timeout=0.3)
            _sock.sendall((line + "\n").encode())
            return True
        except OSError:
            try:
                if _sock:
                    _sock.close()
            except OSError:
                pass
            _sock = None
    return False


def log_event(event):
    global _server_up
    warn = event.startswith(("FIREWALL", "AUTO-BLOCK", "BLOCKED"))
    (_local.warning if warn else _local.info)(event)
    ok = _send("CONTROLLER|%s" % event)
    if ok != _server_up:
        _server_up = ok
        if not ok:
            _local.error("LOG SERVER UNAVAILABLE - events kept in local file only")
        else:
            _local.info("Connected to central log server")
