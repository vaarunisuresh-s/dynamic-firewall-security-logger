#!/usr/bin/env python3
"""Centralized security-event logging server (TCP, one thread per client).
Run:  python3 log_server.py [port]
Writes every received event to logs/central_security_events.log"""
import os
import socket
import sys
import threading
import time

HOST = "0.0.0.0"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "central_security_events.log")
lock = threading.Lock()


def record(addr, line):
    entry = "%s [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), addr[0], line)
    with lock:
        print(entry, flush=True)
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")


def handle(conn, addr):
    try:
        with conn, conn.makefile("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    record(addr, line)
    except OSError as e:
        print("client %s error: %s" % (addr, e), flush=True)


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(16)
    print("Central log server listening on %s:%d" % (HOST, PORT), flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nLog server stopped")
