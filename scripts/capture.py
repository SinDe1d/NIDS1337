#!/usr/bin/env python3
from __future__ import annotations

import argparse

from nids.capture import PacketCapture
from nids.pipeline import DetectionPipeline
from nids.storage import Storage


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture live traffic and detect intrusions.")
    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("--db", default="data/nids.db")
    parser.add_argument("--model", default="models/nids_model.joblib")
    parser.add_argument("--idle-timeout", type=float, default=120.0)
    args = parser.parse_args()
    pipeline = DetectionPipeline(Storage(args.db), args.model)
    capture = PacketCapture(
        interface=args.interface, flow_timeout=args.idle_timeout,
        on_flow=pipeline.process_flow,
    )
    print("Starting NIDS capture. Stop with Ctrl+C.")
    try:
        capture.start()
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        capture.finish()


if __name__ == "__main__":
    main()
