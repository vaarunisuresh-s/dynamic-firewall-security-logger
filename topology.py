#!/usr/bin/env python3
"""Mininet topology: 1 OVS switch (s1), 4 hosts.  h1,h2,h3 = clients, h4 = server host.
Remote OS-Ken controller at 127.0.0.1:6653.  Run:  sudo python3 topology.py"""
import os
from functools import partial

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

BASE = os.path.dirname(os.path.abspath(__file__))
SERVER_PORTS = (80, 8080, 23, 4444)   # 23 and 4444 exist so denial comes from the firewall, not a closed port


class FirewallTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")
        for i in range(1, 5):
            h = self.addHost("h%d" % i, ip="10.0.0.%d/24" % i)
            self.addLink(h, s1)


def build_net():
    return Mininet(topo=FirewallTopo(),
                   controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
                   switch=partial(OVSSwitch, protocols="OpenFlow13"),
                   autoSetMacs=True)


def start_servers(net):
    h4 = net.get("h4")
    os.makedirs(os.path.join(BASE, "logs"), exist_ok=True)
    for p in SERVER_PORTS:
        h4.cmd("python3 %s/tcp_server.py %d >> %s/logs/server_%d.log 2>&1 &" % (BASE, p, BASE, p))


if __name__ == "__main__":
    setLogLevel("info")
    net = build_net()
    net.start()
    start_servers(net)
    print("\nServers running on h4 (10.0.0.4) ports %s" % (SERVER_PORTS,))
    print("Try:  h1 python3 tcp_client.py 10.0.0.4 80      (allowed)")
    print("      h1 python3 tcp_client.py 10.0.0.4 23      (denied; 3 attempts -> auto-block)")
    print("      sh ovs-ofctl -O OpenFlow13 dump-flows s1\n")
    CLI(net)
    net.stop()
