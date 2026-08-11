#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scapy.utils import PcapReader

from nids.capture import PacketCapture
from nids.pipeline import DetectionPipeline
from nids.storage import Storage


def replay(pcap: str, db: str, model: str, idle_timeout: float) -> None:
    path = Path(pcap)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")
    storage = Storage(db)
    pipeline = DetectionPipeline(storage, model)
    capture = PacketCapture(flow_timeout=idle_timeout, on_flow=pipeline.process_flow)
    with PcapReader(str(path)) as packets:
        for packet in packets:
            capture.handle_packet(packet)
    capture.finish()
    print(json.dumps({
        "pcap": str(path), "packets": capture.packet_count,
        "flows": capture.flow_count, "database": db,
        "alerts": storage.stats()["alerts"],
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a PCAP through the NIDS pipeline.")
    parser.add_argument("pcap", help="PCAP file to replay")
    parser.add_argument("--db", default="data/nids.db")
    parser.add_argument("--model", default="models/nids_model.joblib")
    parser.add_argument("--idle-timeout", type=float, default=2.0,
                        help="Idle timeout in seconds; lower is convenient for replay.")
    args = parser.parse_args()
    replay(args.pcap, args.db, args.model, args.idle_timeout)


if __name__ == "__main__":
    main()
