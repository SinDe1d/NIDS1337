import time

from scapy.all import IP, TCP, UDP, sniff

from .flows import FlowTable


class PacketCapture:
    def __init__(self, interface=None):
        self.interface = interface
        self.flow_table = FlowTable()

    def handle_packet(self, packet):
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto

        src_port = 0
        dst_port = 0
        tcp_flags = 0

        if packet.haslayer(TCP):
            tcp = packet[TCP]

            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_flags = int(tcp.flags)

        elif packet.haslayer(UDP):
            udp = packet[UDP]

            src_port = udp.sport
            dst_port = udp.dport

        timestamp = float(packet.time)
        packet_size = len(packet)

        flow = self.flow_table.add_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=packet_size,
            timestamp=timestamp,
            tcp_flags=tcp_flags,
        )

        self._print_packet(flow)

        self._expire_flows(timestamp)

    def _print_packet(self, flow):
        print(
            f"{flow.src_ip}:{flow.src_port} "
            f"-> {flow.dst_ip}:{flow.dst_port} "
            f"packets={flow.total_packets()} "
            f"bytes={flow.total_bytes()}"
        )

    def _expire_flows(self, current_time):
        expired = self.flow_table.expire(current_time)

        for flow in expired:
            self._handle_completed_flow(flow)

    def _handle_completed_flow(self, flow):
        print(
            "\n[FLOW COMPLETE]"
            f"\n  {flow.src_ip}:{flow.src_port}"
            f" -> {flow.dst_ip}:{flow.dst_port}"
            f"\n  protocol: {flow.protocol}"
            f"\n  duration: {flow.duration():.3f}s"
            f"\n  packets: {flow.total_packets()}"
            f"\n  bytes: {flow.total_bytes()}"
            f"\n"
        )

    def finish(self):
        """
        Finish all currently active flows.

        This is useful when stopping a capture or
        finishing a PCAP replay.
        """
        for flow in self.flow_table.clear():
            self._handle_completed_flow(flow)

    def start(self):
        print("Starting packet capture...")

        if self.interface:
            print(f"Interface: {self.interface}")

        try:
            sniff(
                iface=self.interface,
                prn=self.handle_packet,
                store=False,
            )
        except KeyboardInterrupt:
            print("\nStopping capture...")
            self.finish()