from __future__ import annotations

from collections.abc import Callable

from scapy.all import IP, TCP, UDP, sniff

from .flows import Flow, FlowTable


class PacketCapture:
    """Capture live packets or accept packets from a PCAP replay."""

    def __init__(
        self,
        interface: str | None = None,
        flow_timeout: float = 120.0,
        active_timeout: float = 600.0,
        on_flow: Callable[[Flow], None] | None = None,
    ):
        self.interface = interface
        self.flow_table = FlowTable(flow_timeout, active_timeout)
        self.on_flow = on_flow
        self.packet_count = 0
        self.flow_count = 0

    def handle_packet(self, packet) -> None:
        if not packet.haslayer(IP):
            return
        ip = packet[IP]
        src_port = dst_port = tcp_flags = 0
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port, dst_port, tcp_flags = int(tcp.sport), int(tcp.dport), int(tcp.flags)
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port, dst_port = int(udp.sport), int(udp.dport)
        timestamp = float(packet.time)
        flow = self.flow_table.add_packet(
            ip.src, ip.dst, src_port, dst_port, int(ip.proto),
            len(packet), timestamp, tcp_flags,
        )
        self.packet_count += 1
        self._complete(self.flow_table.expire(timestamp))

    def _complete(self, flows: list[Flow]) -> None:
        for flow in flows:
            self.flow_count += 1
            if self.on_flow:
                self.on_flow(flow)

    def finish(self) -> None:
        self._complete(self.flow_table.clear())

    def start(self) -> None:
        sniff(iface=self.interface, prn=self.handle_packet, store=False)
