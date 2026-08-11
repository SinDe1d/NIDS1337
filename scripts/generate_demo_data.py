#!/usr/bin/env python3
"""Create a small deterministic PCAP with benign traffic and three attack patterns."""
from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import IP, TCP, UDP, Raw, wrpcap


def packet(src: str, dst: str, sport: int, dport: int, flags: str,
           payload: bytes = b"", timestamp: float = 0.0):
    layer = TCP(sport=sport, dport=dport, flags=flags) if flags else UDP(
        sport=sport, dport=dport
    )
    item = IP(src=src, dst=dst) / layer
    if payload:
        item = item / Raw(payload)
    item.time = timestamp
    return item


def build() -> list:
    packets = []
    t = 1.0
    for index in range(6):
        packets += [
            packet("10.0.0.10", "10.0.0.20", 4000, 443, "S", timestamp=t),
            packet("10.0.0.20", "10.0.0.10", 443, 4000, "SA", timestamp=t + 0.01),
            packet("10.0.0.10", "10.0.0.20", 4000, 443, "A",
                   b"GET /index.html", timestamp=t + 0.02),
        ]
        t += 0.2
    for port in range(20, 32):
        packets.append(packet(
            "10.0.0.50", f"10.0.0.{100 + port}", 50000 + port, port, "S", timestamp=t
        ))
        t += 0.01
    for index in range(40):
        packets.append(packet("10.0.0.77", "10.0.0.88", 53000 + index, 80, "S", timestamp=t))
        t += 0.005
    for index in range(10):
        packets += [
            packet("10.0.0.60", "10.0.0.40", 6200 + index, 22, "S", timestamp=t),
            packet("10.0.0.40", "10.0.0.60", 22, 6200 + index, "SA", timestamp=t + 0.01),
            packet("10.0.0.60", "10.0.0.40", 6200 + index, 22, "PA",
                   b"login failed", timestamp=t + 0.02),
        ]
        t += 0.1
    for index in range(4):
        packets += [
            packet("10.0.0.60", "10.0.0.70", 6100 + index, 53, "", b"query", t),
            packet("10.0.0.70", "10.0.0.60", 53, 6100 + index, "", b"answer", t + 0.03),
        ]
        t += 0.2
    return packets


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/demo_attacks.pcap")
    args = parser.parse_args()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = build()
    wrpcap(str(path), packets)
    print(f"Wrote {len(packets)} packets to {path}")


if __name__ == "__main__":
    main()
