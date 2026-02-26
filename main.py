"""
SentinelNet — AI-Powered Network Intrusion Detection System
============================================================
Real-time network monitoring with adaptive machine learning.
The model learns from YOUR network traffic and improves over time.

Usage
-----
    sudo python main.py --interface en0          # start monitoring
    sudo python main.py --interface en0 --port 8080  # custom dashboard port
    sudo python main.py --list-interfaces        # list available interfaces
    sudo python main.py --demo                   # run without root (simulated)

Author  : Merve Sude Boler
GitHub  : https://github.com/mervesudeboler
License : MIT
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def list_interfaces() -> None:
    """Print all available network interfaces."""
    try:
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        print("\nAvailable interfaces:")
        for iface in interfaces:
            print(f"  • {iface}")
        print()
    except ImportError:
        print("Scapy not installed. Run: pip install -r requirements.txt")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinelnet",
        description="SentinelNet — AI-Powered Network Intrusion Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python main.py --interface en0\n"
            "  sudo python main.py --demo\n"
            "  python main.py --list-interfaces\n"
        ),
    )
    parser.add_argument("--interface", "-i", type=str, metavar="IFACE",
                        help="Network interface to monitor (e.g. en0, eth0)")
    parser.add_argument("--port", "-p", type=int, default=5000,
                        help="Dashboard port (default: 5000)")
    parser.add_argument("--demo", action="store_true",
                        help="Run in demo mode with simulated traffic (no root required)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available network interfaces and exit")
    parser.add_argument("--reset-model", action="store_true",
                        help="Reset the learned model and start fresh")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING"],
                        help="Logging verbosity (default: INFO)")

    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    if not args.demo and not args.interface:
        parser.print_help()
        print("\n[!] Specify --interface or use --demo mode.\n")
        sys.exit(1)

    # Import here to avoid slow startup for --list-interfaces / --help
    from core.engine import SentinelEngine
    from dashboard.app import create_app

    engine = SentinelEngine(
        interface=args.interface,
        demo_mode=args.demo,
        reset_model=args.reset_model,
    )

    app = create_app(engine)

    # Start engine in background thread
    engine_thread = threading.Thread(target=engine.start, daemon=True)
    engine_thread.start()

    print(f"""
╔══════════════════════════════════════════════╗
║           SentinelNet is running             ║
╠══════════════════════════════════════════════╣
║  Dashboard  →  http://localhost:{args.port:<5}        ║
║  Mode       →  {'DEMO' if args.demo else f'LIVE ({args.interface})':<20}        ║
║  Press Ctrl+C to stop                        ║
╚══════════════════════════════════════════════╝
""")

    try:
        app.run(host="0.0.0.0", port=args.port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[*] Shutting down SentinelNet...")
        engine.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
