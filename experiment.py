#!/usr/bin/env python3
"""Automated performance + robustness experiments.
  sudo python3 experiment.py --label dynamic   (with controller.py running)
  sudo python3 experiment.py --label baseline  (with baseline_controller.py running)
Results are appended to results/results.csv"""
import argparse
import csv
import os
import re
import statistics
import time

from mininet.log import setLogLevel

from topology import BASE, build_net, start_servers

CLIENT = os.path.join(BASE, "tcp_client.py")
SRV = "10.0.0.4"


def parse(out):
    for line in out.splitlines():
        if line.startswith("RESULT"):
            return dict(re.findall(r"(\w+)=(\S+)", line))
    return {"status": "noresult"}


def client_cmd(port, mode="msg", count=10, size=10, timeout=3.0):
    return "python3 %s %s %d --mode %s --count %d --size %d --timeout %s" % (
        CLIENT, SRV, port, mode, count, size, timeout)


def run(host, **kw):
    return parse(host.cmd(client_cmd(**kw)))


def ms_stats(vals):
    return statistics.mean(vals), (statistics.stdev(vals) if len(vals) > 1 else 0.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, choices=["dynamic", "baseline"])
    ap.add_argument("--trials", type=int, default=5)
    a = ap.parse_args()
    setLogLevel("warning")
    net = build_net()
    net.start()
    time.sleep(2)
    start_servers(net)
    time.sleep(1)
    h1, h2, h3, h4 = [net.get("h%d" % i) for i in range(1, 5)]
    rows = []

    def record(metric, vals, unit):
        m, s = ms_stats(vals)
        rows.append([a.label, metric, len(vals), "%.3f" % m, "%.3f" % s, unit])
        print("%-9s %-34s n=%d mean=%.3f sd=%.3f %s" % (a.label, metric, len(vals), m, s, unit))

    print("pingall loss: %s%%" % net.pingAll())
    run(h1, port=80, count=30)  # warm-up

    # 1) latency, single client
    record("latency_single_client", [float(run(h1, port=80, count=200)["avg_rtt_ms"]) for _ in range(a.trials)], "ms")
    # 2) throughput, single client
    record("throughput_single_client",
           [float(run(h1, port=80, mode="bulk", size=50)["throughput_mbps"]) for _ in range(a.trials)], "Mbit/s")
    # 3) multiple clients concurrently
    lat, ok = [], 0
    for _ in range(a.trials):
        hs = [h1, h2, h3]
        for h in hs:
            h.sendCmd(client_cmd(80, count=200))
        res = [parse(h.waitOutput()) for h in hs]
        ok += sum(r["status"] == "ok" for r in res)
        lat.append(statistics.mean(float(r["avg_rtt_ms"]) for r in res if r["status"] == "ok"))
    record("latency_3_concurrent_clients", lat, "ms")
    record("concurrent_success_rate", [ok / (3.0 * a.trials) * 100], "%")

    # 4) security scenario
    if a.label == "baseline":
        r = run(h1, port=23, timeout=2)
        record("port23_reachable (1=yes)", [1.0 if r["status"] == "ok" else 0.0], "bool")
    else:
        t_trig = t_conf = None
        for i in range(6):
            t_att = time.time()
            run(h1, port=23, timeout=0.3)                       # denied attempt
            if run(h1, port=80, timeout=0.5)["status"] != "ok":  # legit traffic from h1 now dropped?
                t_conf, t_trig = time.time(), t_att
                print("auto-block confirmed after %d denied attempts" % (i + 1))
                break
        if t_conf:
            record("block_confirm_after_trigger (upper bound)", [(t_conf - t_trig) * 1000], "ms")
            record("other_client_h2_unaffected (1=yes)", [1.0 if run(h2, port=80)["status"] == "ok" else 0.0], "bool")
            t0 = time.time()
            while time.time() - t0 < 60:                          # wait for auto-recovery
                if run(h1, port=80, timeout=0.5)["status"] == "ok":
                    record("recovery_time_after_block", [time.time() - t_conf], "s")
                    break
                time.sleep(0.5)
        else:
            print("WARNING: block was not observed - check the controller output")

    # 5) robustness: malformed input must not crash the server
    r = parse(h1.cmd("python3 %s %s 80 --mode raw --raw 'garbage ???'" % (CLIENT, SRV)))
    after = run(h1, port=80, count=3)
    record("server_alive_after_malformed (1=yes)", [1.0 if after["status"] == "ok" else 0.0], "bool")

    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    path = os.path.join(BASE, "results", "results.csv")
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["label", "metric", "trials", "mean", "stdev", "unit"])
        w.writerows(rows)
    print("\nSaved to %s" % path)
    net.stop()


if __name__ == "__main__":
    main()
