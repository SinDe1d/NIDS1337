from __future__ import annotations

import math
from typing import Iterable

from .flows import Flow


FEATURE_NAMES = [
    "duration", "total_fwd_packets", "total_bwd_packets",
    "total_fwd_bytes", "total_bwd_bytes", "packet_size_mean",
    "packet_size_std", "packet_size_min", "packet_size_max",
    "fwd_packet_size_mean", "bwd_packet_size_mean", "iat_mean",
    "iat_std", "iat_min", "iat_max", "syn_count", "ack_count",
    "fin_count", "rst_count", "psh_count", "urg_count",
    "flow_bytes_per_second", "flow_packets_per_second",
    "bwd_fwd_packet_ratio", "bwd_fwd_byte_ratio", "down_up_byte_ratio",
    "active_packet_span", "tcp_flag_total",
]


class FeatureExtractor:
    """Convert a completed flow into the 28 numerical features used by the model."""

    def extract(self, flow: Flow) -> dict[str, float]:
        duration = flow.duration()
        sizes = flow.packet_sizes
        iats = self._inter_arrival_times(flow)
        features = {
            "duration": duration,
            "total_fwd_packets": flow.forward_packets,
            "total_bwd_packets": flow.backward_packets,
            "total_fwd_bytes": flow.forward_bytes,
            "total_bwd_bytes": flow.backward_bytes,
            "packet_size_mean": self._mean(sizes),
            "packet_size_std": self._std(sizes),
            "packet_size_min": self._minimum(sizes),
            "packet_size_max": self._maximum(sizes),
            "fwd_packet_size_mean": self._mean(flow.forward_packet_sizes),
            "bwd_packet_size_mean": self._mean(flow.backward_packet_sizes),
            "iat_mean": self._mean(iats),
            "iat_std": self._std(iats),
            "iat_min": self._minimum(iats),
            "iat_max": self._maximum(iats),
            "syn_count": flow.syn_count,
            "ack_count": flow.ack_count,
            "fin_count": flow.fin_count,
            "rst_count": flow.rst_count,
            "psh_count": flow.psh_count,
            "urg_count": flow.urg_count,
            "flow_bytes_per_second": self._rate(flow.total_bytes(), duration),
            "flow_packets_per_second": self._rate(flow.total_packets(), duration),
            "bwd_fwd_packet_ratio": self._ratio(flow.backward_packets, flow.forward_packets),
            "bwd_fwd_byte_ratio": self._ratio(flow.backward_bytes, flow.forward_bytes),
            "down_up_byte_ratio": self._ratio(flow.backward_bytes, flow.forward_bytes),
            "active_packet_span": (max(flow.packet_times) - min(flow.packet_times))
            if flow.packet_times else 0.0,
            "tcp_flag_total": sum(
                (flow.syn_count, flow.ack_count, flow.fin_count,
                 flow.rst_count, flow.psh_count, flow.urg_count)
            ),
        }
        return {name: float(features.get(name, 0.0)) for name in FEATURE_NAMES}

    @staticmethod
    def _inter_arrival_times(flow: Flow) -> list[float]:
        times = sorted(flow.packet_times)
        return [current - previous for previous, current in zip(times, times[1:])]

    @staticmethod
    def _mean(values: Iterable[float]) -> float:
        values = list(values)
        return sum(values) / len(values) if values else 0.0

    @staticmethod
    def _std(values: Iterable[float]) -> float:
        values = list(values)
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return math.sqrt(sum((value - mean) ** 2 for value in values) / len(values))

    @staticmethod
    def _minimum(values: Iterable[float]) -> float:
        values = list(values)
        return min(values) if values else 0.0

    @staticmethod
    def _maximum(values: Iterable[float]) -> float:
        values = list(values)
        return max(values) if values else 0.0

    @staticmethod
    def _rate(value: int, duration: float) -> float:
        return value / duration if duration > 0 else float(value)

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else float(numerator)
