
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, tcp
from security_logger import log_event
import time


class DynamicFirewall(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)
        self.failed_attempts = {}
        self.blocked_until = {}
        log_event("Dynamic Firewall Started")

    def add_flow(self, datapath, priority, match, actions,
                 hard_timeout=0):
        parser = datapath.ofproto_parser
        instructions = []

        if actions:
            instructions = [
                parser.OFPInstructionActions(
                    datapath.ofproto.OFPIT_APPLY_ACTIONS, actions
                )
            ]

        flow = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(flow)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]
        self.add_flow(dp, 0, parser.OFPMatch(), actions)
        log_event("Switch connected: " + str(dp.id))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None or eth.ethertype == 0x88cc:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            now = time.time()

            if src_ip in self.blocked_until:
                if now < self.blocked_until[src_ip]:
                    log_event("BLOCKED: " + src_ip + " -> " + dst_ip)
                    return

                del self.blocked_until[src_ip]
                self.failed_attempts[src_ip] = 0
                log_event("RECOVERY: " + src_ip + " unblocked")

            if tcp_pkt and tcp_pkt.dst_port == 23:
                attempts = self.failed_attempts.get(src_ip, 0) + 1
                self.failed_attempts[src_ip] = attempts

                if attempts >= 3:
                    self.blocked_until[src_ip] = now + 30
                    match = parser.OFPMatch(
                        eth_type=0x0800, ipv4_src=src_ip
                    )
                    self.add_flow(dp, 20, match, [], hard_timeout=30)
                    log_event(
                        "AUTO-BLOCK: " + src_ip + " blocked for 30 seconds"
                    )
                else:
                    log_event(
                        "FIREWALL DENY: " + src_ip + " -> " +
                        dst_ip + " TCP port 23 (attempt " +
                        str(attempts) + ")"
                    )
                return

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        packet_out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(packet_out)

