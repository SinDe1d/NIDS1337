import argparse

from nids.capture import PacketCapture


def main():
    parser = argparse.ArgumentParser(
        description="Capture network traffic and track flows"
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to capture from",
    )

    args = parser.parse_args()

    capture = PacketCapture(
        interface=args.interface
    )

    try:
        capture.start()
    except KeyboardInterrupt:
        print("\nCapture stopped.")


if __name__ == "__main__":
    main()
