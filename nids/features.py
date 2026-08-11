from dataclasses import asdict

import math

from .flows import Flow


class FeatureExtractor:
    """Turn a completed network flow into numerical features."""

    def extract(self, flow: Flow) -> dict[str, float]:
        duration = flow.duration()

        packet_sizes = flow.packet_sizes
        inter_arrival_times = self._inter_arrival_times(flow)

        features = {
            "duration": duration,

            "total_fwd_packets": flow.forward_packets,
            "total_bwd_packets": flow.backward_packets,

            "total_fwd_bytes": flow.forward_bytes,
            "total_bwd_bytes": flow.backward_bytes,

            "packet_size_mean": self._mean(packet_sizes),
            "packet_size_std": self._std(packet_sizes),
            "packet_size_min": self._minimum(packet_sizes),
            "packet_size_max": self._maximum(packet_sizes),

            "iat_mean": self._mean(inter_arrival_times),
            "iat_std": self._std(inter_arrival_times),
            "iat_min": self._minimum(inter_arrival_times),
            "iat_max": self._maximum(inter_arrival_times),

            "syn_count": flow.syn_count,
            "ack_count": flow.ack_count,
            "fin_count": flow.fin_count,
            "rst_count": flow.rst_count,
            "psh_count": flow.psh_count,
            "urg_count": flow.urg_count,

            "flow_bytes_per_second": self._rate(
                flow.total_bytes(),
                duration,
            ),

            "flow_packets_per_second": self._rate(
                flow.total_packets(),
                duration,
            ),
        }

        return features

    @staticmethod
    def _inter_arrival_times(flow: Flow) -> list[float]:
        if len(flow.packet_times) < 2:
            return []

        times = sorted(flow.packet_times)

        return [
            current - previous
            for previous, current in zip(times, times[1:])
        ]

    @staticmethod
    def _mean(values: list[float]) -> float:
        if not values:
            return 0.0

        return sum(values) / len(values)

    @staticmethod
    def _std(values: list[float]) -> float:
        if len(values) < 2:
            return 0.0

        mean = sum(values) / len(values)

        variance = sum(
            (value - mean) ** 2
            for value in values
        ) / len(values)

        return math.sqrt(variance)

    @staticmethod
    def _minimum(values: list[float]) -> float:
        if not values:
            return 0.0

        return min(values)

    @staticmethod
    def _maximum(values: list[float]) -> float:
        if not values:
            return 0.0

        return max(values)

    @staticmethod
    def _rate(value: int, duration: float) -> float:
        if duration <= 0:
            return 0.0

        return value / duration