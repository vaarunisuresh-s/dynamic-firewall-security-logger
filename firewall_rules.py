"""Policy + configuration for the dynamic firewall. Edit here; no controller changes needed."""

# Central security-event logging server (socket server, see log_server.py)
LOG_SERVER_HOST = "127.0.0.1"
LOG_SERVER_PORT = 9999

# Automatic blocking / recovery
AUTO_BLOCK_THRESHOLD = 3   # denied attempts from one source ...
ATTEMPT_WINDOW = 30        # ... within this many seconds trigger an auto-block
BLOCK_SECONDS = 30         # block lasts this long, then the source is auto-recovered
FLOW_IDLE_TIMEOUT = 10     # idle timeout for normal (allowed) flows

# Rules are checked top to bottom. Fields src/dst/proto/dst_port are optional (missing = any).
# action: "allow"  -> forward and install a flow
#         "deny"   -> drop packet; repeated denies from one source trigger an auto-block
#         "block"  -> immediately block the source IP for BLOCK_SECONDS
RULES = [
    {"proto": "tcp", "dst_port": 23,   "action": "deny"},    # telnet
    {"proto": "tcp", "dst_port": 4444, "action": "block"},   # suspicious port
    {"proto": "tcp", "dst_port": 80,   "action": "allow"},
    {"proto": "tcp", "dst_port": 8080, "action": "allow"},
]
DEFAULT_ACTION = "allow"


def match_rule(src_ip, dst_ip, proto, src_port, dst_port):
    """Classify traffic by source, destination, protocol and port. Returns an action string."""
    for r in RULES:
        if r.get("src") not in (None, src_ip):
            continue
        if r.get("dst") not in (None, dst_ip):
            continue
        if r.get("proto") not in (None, proto):
            continue
        if r.get("dst_port") not in (None, dst_port):
            continue
        return r["action"]
    return DEFAULT_ACTION
