from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class Flow:
    """Bidirectional flow keyed by the first packet's 5-tuple."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start_time: float
    last_seen: float
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    packet_sizes: list[int] = field(default_factory=list)
    forward_packet_sizes: list[int] = field(default_factory=list)
    backward_packet_sizes: list[int] = field(default_factory=list)
    packet_times: list[float] = field(default_factory=list)

    def duration(self) -> float:
        return max(0.0, self.last_seen - self.start_time)

    def total_packets(self) -> int:
        return self.forward_packets + self.backward_packets

    def total_bytes(self) -> int:
        return self.forward_bytes + self.backward_bytes

    def add_packet(
        self,
        packet_size: int,
        timestamp: float,
        forward: bool,
        tcp_flags: int = 0,
    ) -> None:
        self.last_seen = timestamp
        self.packet_sizes.append(packet_size)
        self.packet_times.append(timestamp)
        if forward:
            self.forward_packets += 1
            self.forward_bytes += packet_size
            self.forward_packet_sizes.append(packet_size)
        else:
            self.backward_packets += 1
            self.backward_bytes += packet_size
            self.backward_packet_sizes.append(packet_size)

        if tcp_flags:
            self.syn_count += int(bool(tcp_flags & 0x02))
            self.ack_count += int(bool(tcp_flags & 0x10))
            self.fin_count += int(bool(tcp_flags & 0x01))
            self.rst_count += int(bool(tcp_flags & 0x04))
            self.psh_count += int(bool(tcp_flags & 0x08))
            self.urg_count += int(bool(tcp_flags & 0x20))

    def as_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "total_packets": self.total_packets(),
            "total_bytes": self.total_bytes(),
        }


class FlowTable:
    def __init__(self, idle_timeout: float = 120.0, active_timeout: float = 600.0):
        self.flows: dict[tuple, Flow] = {}
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout

    @staticmethod
    def make_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> tuple:
        return src_ip, dst_ip, src_port, dst_port, protocol

    def get_or_create(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      protocol: int, timestamp: float) -> tuple[Flow, bool]:
        forward_key = self.make_key(src_ip, dst_ip, src_port, dst_port, protocol)
        reverse_key = self.make_key(dst_ip, src_ip, dst_port, src_port, protocol)
        if forward_key in self.flows:
            return self.flows[forward_key], True
        if reverse_key in self.flows:
            return self.flows[reverse_key], False
        flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol, timestamp, timestamp)
        self.flows[forward_key] = flow
        return flow, True

    def add_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                   protocol: int, packet_size: int, timestamp: float,
                   tcp_flags: int = 0) -> Flow:
        flow, forward = self.get_or_create(
            src_ip, dst_ip, src_port, dst_port, protocol, timestamp
        )
        flow.add_packet(packet_size, timestamp, forward, tcp_flags)
        return flow

    def expire(self, current_time: float) -> list[Flow]:
        expired: list[Flow] = []
        for key, flow in list(self.flows.items()):
            if (
                current_time - flow.last_seen >= self.idle_timeout
                or current_time - flow.start_time >= self.active_timeout
            ):
                expired.append(flow)
                del self.flows[key]
        return expired

    def clear(self) -> list[Flow]:
        flows = list(self.flows.values())
        self.flows.clear()
        return flows

    def active_count(self) -> int:
        return len(self.flows)
