import time

BLOCKED_PORTS = {23}
BLOCKED_IPS = set()

FAILED_ATTEMPTS = {}
BLOCK_DURATION = 30
MAX_ATTEMPTS = 3
BLOCKED_UNTIL = {}


def check_traffic(src_ip, dst_ip, dst_port):
    current_time = time.time()

    if src_ip in BLOCKED_UNTIL:
        if current_time < BLOCKED_UNTIL[src_ip]:
            return "BLOCK"

        del BLOCKED_UNTIL[src_ip]
        FAILED_ATTEMPTS[src_ip] = 0
        print("RECOVERY:", src_ip, "unblocked")

    if src_ip in BLOCKED_IPS:
        return "BLOCK"

    if dst_port in BLOCKED_PORTS:
        FAILED_ATTEMPTS[src_ip] = FAILED_ATTEMPTS.get(src_ip, 0) + 1

        if FAILED_ATTEMPTS[src_ip] >= MAX_ATTEMPTS:
            BLOCKED_UNTIL[src_ip] = current_time + BLOCK_DURATION
            print("AUTO-BLOCK:", src_ip, "blocked for 30 seconds")
            return "BLOCK"

        return "DENY"

    return "ALLOW"
