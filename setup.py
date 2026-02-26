"""
SentinelNet Setup Script
Installs all dependencies and verifies the environment.

Usage:
    python setup.py
"""

import subprocess
import sys
import os

REQUIRED = ["flask", "scapy", "sklearn", "numpy", "joblib"]

def check(pkg):
    try:
        __import__(pkg)
        return True
    except ImportError:
        return False

def main():
    print("""
╔══════════════════════════════════════════╗
║       SentinelNet — Setup                ║
╚══════════════════════════════════════════╝
""")
    print("[1/3] Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

    print("\n[2/3] Checking environment...")
    missing = []
    for pkg in ["flask", "scapy", "sklearn", "numpy", "joblib"]:
        ok = check(pkg)
        print(f"  {'✓' if ok else '✗'} {pkg}")
        if not ok:
            missing.append(pkg)

    print("\n[3/3] Creating directories...")
    for d in ["models", "logs", "outputs"]:
        os.makedirs(d, exist_ok=True)
        print(f"  ✓ {d}/")

    if missing:
        print(f"\n[!] Missing packages: {missing}")
        print("    Try: pip3 install -r requirements.txt")
        sys.exit(1)

    print("""
✓ Setup complete!

To start SentinelNet:

  Demo mode (no root required):
    python3 main.py --demo

  Live mode (requires root):
    python3 main.py --list-interfaces   # find your interface
    sudo python3 main.py --interface en0

  Then open: http://localhost:5000
""")

if __name__ == "__main__":
    main()
