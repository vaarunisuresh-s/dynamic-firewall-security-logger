#!/usr/bin/env python3
"""Multi-client TCP server (low-level sockets, one thread per client).
Protocol (text lines):  MSG <n> <text> -> ACK <n> <len>
                        BULK <bytes>   -> (then <bytes> raw bytes) -> DONE <bytes>
                        QUIT           -> closes the connection
                        anything else  -> ERR unknown command
Run: python3 tcp_server.py <port>"""
import socket
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80


def log(msg):
    print("%s %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def handle(conn, addr):
    log("client connected %s:%d" % addr)
    try:
        with conn, conn.makefile("rb") as f:
            while True:
                line = f.readline()
                if not line:
                    break
                parts = line.split()
                try:
                    cmd = parts[0].upper() if parts else b""
                    if cmd == b"MSG":
                        conn.sendall(b"ACK %s %d\n" % (parts[1], len(line)))
                    elif cmd == b"BULK":
                        n = int(parts[1])
                        left = n
                        while left > 0:
                            chunk = f.read(min(65536, left))
                            if not chunk:
                                raise ConnectionError("client closed during BULK")
                            left -= len(chunk)
                        conn.sendall(b"DONE %d\n" % n)
                    elif cmd == b"QUIT":
                        break
                    else:
                        conn.sendall(b"ERR unknown command\n")
                except (IndexError, ValueError):
                    conn.sendall(b"ERR malformed request\n")
    except (OSError, ConnectionError) as e:
        log("client %s:%d error: %s" % (addr[0], addr[1], e))
    log("client disconnected %s:%d" % addr)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(32)
    log("TCP server listening on port %d" % PORT)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
