#!/usr/bin/env python3
"""TCP client. Examples:
  python3 tcp_client.py 10.0.0.4 80                       # 10 request/response messages
  python3 tcp_client.py 10.0.0.4 80 --mode bulk --size 50 # 50 MB throughput test
  python3 tcp_client.py 10.0.0.4 80 --mode raw --raw "garbage"   # malformed input test
Last line is machine-readable: RESULT status=ok|timeout|refused|error ..."""
import argparse
import socket
import statistics
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--mode", choices=["msg", "bulk", "raw"], default="msg")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--size", type=int, default=10, help="MB for bulk mode")
    ap.add_argument("--timeout", type=float, default=3.0, help="connect timeout (s)")
    ap.add_argument("--raw", default="hello")
    a = ap.parse_args()

    t0 = time.perf_counter()
    try:
        s = socket.create_connection((a.host, a.port), timeout=a.timeout)
    except socket.timeout:
        print("RESULT status=timeout")
        return 2
    except ConnectionRefusedError:
        print("RESULT status=refused")
        return 3
    except OSError as e:
        print("RESULT status=error reason=%s" % type(e).__name__)
        return 4
    connect_ms = (time.perf_counter() - t0) * 1000
    s.settimeout(15)
    try:
        f = s.makefile("rb")
        if a.mode == "msg":
            rtts = []
            for i in range(a.count):
                t = time.perf_counter()
                s.sendall(("MSG %d hello-from-client\n" % i).encode())
                if not f.readline():
                    raise ConnectionError("server closed connection")
                rtts.append((time.perf_counter() - t) * 1000)
            s.sendall(b"QUIT\n")
            print("RESULT status=ok connect_ms=%.3f avg_rtt_ms=%.3f max_rtt_ms=%.3f msgs=%d"
                  % (connect_ms, statistics.mean(rtts), max(rtts), len(rtts)))
        elif a.mode == "bulk":
            n = a.size * 1024 * 1024
            chunk = b"x" * 65536
            t = time.perf_counter()
            s.sendall(("BULK %d\n" % n).encode())
            sent = 0
            while sent < n:
                m = min(len(chunk), n - sent)
                s.sendall(chunk[:m])
                sent += m
            if not f.readline():
                raise ConnectionError("no DONE from server")
            dt = time.perf_counter() - t
            s.sendall(b"QUIT\n")
            print("RESULT status=ok connect_ms=%.3f throughput_mbps=%.2f seconds=%.3f"
                  % (connect_ms, n * 8 / 1e6 / dt, dt))
        else:
            s.sendall((a.raw + "\n").encode())
            reply = f.readline().decode(errors="replace").strip()
            print("server replied: %s" % reply)
            print("RESULT status=ok connect_ms=%.3f reply=%s" % (connect_ms, reply.replace(" ", "_")))
    except (OSError, ConnectionError) as e:
        print("RESULT status=error reason=%s" % type(e).__name__)
        return 5
    finally:
        s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
