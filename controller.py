"""Dynamic firewall SDN controller (OS-Ken, OpenFlow 1.3).
- Learning switch; allowed traffic gets per-flow rules (L2/L3/L4 match) so later packets bypass the controller
- Rules from firewall_rules.py classify traffic by source, destination, protocol and port
- 'deny'  : packet dropped, repeated denies from one source -> automatic block flow (priority 20, hard timeout)
- 'block' : immediate block flow
- Block flow removal (hard timeout) -> RECOVERY event
- Every event is sent to the central log server via security_logger.log_event
"""
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, tcp, icmp

import firewall_rules as cfg
from security_logger import log_event

FLOW_PRIORITY = 10
BLOCK_PRIORITY = 20


class DynamicFirewall(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.attempts = {}       # src_ip -> [timestamps of denied attempts]
        self.blocked_until = {}  # src_ip -> epoch seconds
        log_event("Dynamic Firewall Started")

    # ---------- helpers ----------
    def add_flow(self, dp, priority, match, actions, idle=0, hard=0, flags=0):
        parser = dp.ofproto_parser
        inst = []
        if actions:
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle,
                                      hard_timeout=hard, flags=flags))

    def _block(self, dp, src, reason, t_start):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src)
        self.add_flow(dp, BLOCK_PRIORITY, match, [], hard=cfg.BLOCK_SECONDS,
                      flags=ofp.OFPFF_SEND_FLOW_REM)
        self.blocked_until[src] = time.time() + cfg.BLOCK_SECONDS
        self.attempts.pop(src, None)
        ms = (time.perf_counter() - t_start) * 1000
        log_event("AUTO-BLOCK: %s blocked for %d seconds (reason: %s, rule installed in %.2f ms)"
                  % (src, cfg.BLOCK_SECONDS, reason, ms))

    def _recover(self, src):
        if src in self.blocked_until:
            del self.blocked_until[src]
            self.attempts.pop(src, None)
            log_event("RECOVERY: %s unblocked" % src)

    def _firewall_allows(self, dp, ip, proto, sport, dport, t_start):
        src, dst = ip.src, ip.dst
        now = time.time()
        until = self.blocked_until.get(src)
        if until is not None:
            if now < until:
                log_event("BLOCKED: %s -> %s dropped (source is blocked)" % (src, dst))
                return False
            self._recover(src)  # fallback if FlowRemoved was missed
        action = cfg.match_rule(src, dst, proto, sport, dport)
        if action == "allow":
            return True
        if action == "block":
            log_event("FIREWALL BLOCK-RULE: %s -> %s %s port %s" % (src, dst, proto, dport))
            self._block(dp, src, "block rule", t_start)
            return False
        # deny
        ts = [t for t in self.attempts.get(src, []) if now - t < cfg.ATTEMPT_WINDOW] + [now]
        self.attempts[src] = ts
        if len(ts) >= cfg.AUTO_BLOCK_THRESHOLD:
            log_event("FIREWALL DENY: %s -> %s %s port %s (attempt %d/%d)"
                      % (src, dst, proto.upper(), dport, len(ts), cfg.AUTO_BLOCK_THRESHOLD))
            self._block(dp, src, "%d denied attempts" % len(ts), t_start)
        else:
            log_event("FIREWALL DENY: %s -> %s %s port %s (attempt %d/%d)"
                      % (src, dst, proto.upper(), dport, len(ts), cfg.AUTO_BLOCK_THRESHOLD))
        return False

    # ---------- OpenFlow events ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, parser.OFPMatch(), actions)
        log_event("Switch connected: %s" % dp.id)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        if msg.priority == BLOCK_PRIORITY and "ipv4_src" in msg.match:
            self._recover(msg.match["ipv4_src"])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        t_start = time.perf_counter()
        msg = ev.msg
        dp = msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == 0x88cc:  # ignore LLDP
            return
        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port

        ip = pkt.get_protocol(ipv4.ipv4)
        proto = sport = dport = None
        if ip:
            t = pkt.get_protocol(tcp.tcp)
            if t:
                proto, sport, dport = "tcp", t.src_port, t.dst_port
            elif pkt.get_protocol(icmp.icmp):
                proto = "icmp"
            if not self._firewall_allows(dp, ip, proto, sport, dport, t_start):
                return

        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            if ip is None:
                match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
                                        eth_src=eth.src, eth_dst=eth.dst)
            elif proto == "tcp":
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, eth_src=eth.src,
                                        eth_dst=eth.dst, ipv4_src=ip.src, ipv4_dst=ip.dst,
                                        ip_proto=6, tcp_src=sport, tcp_dst=dport)
            elif proto == "icmp":
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, eth_src=eth.src,
                                        eth_dst=eth.dst, ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=1)
            else:
                match = None
            if match is not None:
                self.add_flow(dp, FLOW_PRIORITY, match, actions, idle=cfg.FLOW_IDLE_TIMEOUT)
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions, data=msg.data))
