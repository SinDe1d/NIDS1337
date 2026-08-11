from dataclasses import dataclass, field


@dataclass
class Flow:
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
    packet_times: list[float] = field(default_factory=list)

    def duration(self) -> float:
        return self.last_seen - self.start_time

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
        else:
            self.backward_packets += 1
            self.backward_bytes += packet_size

        if tcp_flags:
            if tcp_flags & 0x02:
                self.syn_count += 1

            if tcp_flags & 0x10:
                self.ack_count += 1

            if tcp_flags & 0x01:
                self.fin_count += 1

            if tcp_flags & 0x04:
                self.rst_count += 1

            if tcp_flags & 0x08:
                self.psh_count += 1

            if tcp_flags & 0x20:
                self.urg_count += 1


class FlowTable:
    def __init__(
        self,
        idle_timeout: float = 120.0,
        active_timeout: float = 600.0,
    ):
        self.flows: dict[tuple, Flow] = {}

        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout

    @staticmethod
    def make_key(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
    ) -> tuple:
        return (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        )

    def get_or_create(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        timestamp: float,
    ) -> tuple[Flow, bool]:
        forward_key = self.make_key(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        )

        reverse_key = self.make_key(
            dst_ip,
            src_ip,
            dst_port,
            src_port,
            protocol,
        )

        flow = self.flows.get(forward_key)

        if flow is not None:
            return flow, True

        flow = self.flows.get(reverse_key)

        if flow is not None:
            return flow, False

        flow = Flow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            start_time=timestamp,
            last_seen=timestamp,
        )

        self.flows[forward_key] = flow

        return flow, True

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        packet_size: int,
        timestamp: float,
        tcp_flags: int = 0,
    ) -> Flow:
        flow, forward = self.get_or_create(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            timestamp=timestamp,
        )

        flow.add_packet(
            packet_size=packet_size,
            timestamp=timestamp,
            forward=forward,
            tcp_flags=tcp_flags,
        )

        return flow

    def expire(self, current_time: float) -> list[Flow]:
        expired = []

        for key, flow in list(self.flows.items()):
            idle_time = current_time - flow.last_seen
            active_time = current_time - flow.start_time

            if (
                idle_time >= self.idle_timeout
                or active_time >= self.active_timeout
            ):
                expired.append(flow)
                del self.flows[key]

        return expired

    def remove(self, flow: Flow) -> None:
        key = self.make_key(
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol,
        )

        self.flows.pop(key, None)

    def active_count(self) -> int:
        return len(self.flows)

    def clear(self) -> list[Flow]:
        flows = list(self.flows.values())
        self.flows.clear()
        return flows
