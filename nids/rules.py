from __future__ import annotations

from collections import defaultdict, deque
from time import time

from .flows import Flow


class RuleEngine:
    """Small explainable rule engine that complements the ML detector."""

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self.source_history: dict[str, deque[tuple[float, int, str]]] = defaultdict(deque)

    def inspect(self, flow: Flow) -> tuple[str | None, float, str | None]:
        now = flow.last_seen or time()
        history = self.source_history[flow.src_ip]
        syn_only = flow.protocol == 6 and flow.syn_count > 0 and flow.backward_packets == 0
        history.append((now, flow.dst_port, flow.dst_ip, syn_only))
        while history and now - history[0][0] > self.window_seconds:
            history.popleft()
        unique_ports = {entry[1] for entry in history}
        unique_destinations = {entry[2] for entry in history}
        syn_only_count = sum(1 for entry in history if entry[3])
        if flow.protocol == 6 and (
            (flow.syn_count >= 5 and flow.backward_packets == 0)
            or (syn_only_count >= 10 and len(unique_destinations) <= 2)
        ):
            return "SYN flood", 0.98, (
                f"{syn_only_count} SYN-only flows observed in "
                f"{self.window_seconds:.0f}s"
            )
        if len(unique_ports) >= 8 and len(history) >= 8:
            return "Port scan", 0.96, (
                f"{len(unique_ports)} destination ports targeted in "
                f"{len(unique_destinations)} host(s)"
            )
        auth_ports = {21, 22, 23, 25, 3389}
        auth_attempts = [
            entry for entry in history
            if entry[1] in auth_ports and not entry[3]
        ]
        if len(auth_attempts) >= 6 and len({entry[2] for entry in auth_attempts}) == 1:
            return "Brute Force", 0.93, (
                f"{len(auth_attempts)} repeated authentication attempts "
                f"against {next(iter({entry[2] for entry in auth_attempts}))}"
            )
        return None, 0.0, None
