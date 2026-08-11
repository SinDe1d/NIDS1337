```python
import argparse
from pathlib import Path

from scapy.utils import PcapReader

from nids.capture import PacketCapture


def replay_pcap(pcap_path: str) -> None:
    path = Path(pcap_path)

    if not path.exists():
        raise FileNotFoundError(
            f"PCAP file not found: {path}"
        )

    print(f"Reading PCAP: {path}")

    capture = PacketCapture()

    packet_count = 0

    try:
        with PcapReader(str(path)) as packets:
            for packet in packets:
                packet_count += 1
                capture.handle_packet(packet)

    finally:
        capture.finish()

    print(
        f"\nReplay finished. "
        f"Packets processed: {packet_count}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Replay a PCAP file through the NIDS"
    )

    parser.add_argument(
        "pcap",
        help="Path to the PCAP file",
    )

    args = parser.parse_args()

    replay_pcap(args.pcap)


if __name__ == "__main__":
    main()
```
