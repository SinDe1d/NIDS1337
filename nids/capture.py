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

        print(
            f"{flow.src_ip}:{flow.src_port} "
            f"-> {flow.dst_ip}:{flow.dst_port} "
            f"packets={flow.total_packets()} "
            f"bytes={flow.total_bytes()}"
        )

    def start(self):
        print("Starting packet capture...")

        if self.interface:
            print(f"Interface: {self.interface}")

        sniff(
            iface=self.interface,
            prn=self.handle_packet,
            store=False,
        )
