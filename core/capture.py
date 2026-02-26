"""
core.capture — Packet capture: live (Scapy) and simulated modes
"""

from __future__ import annotations

import logging
import random
import time
from typing import Callable

import numpy as np

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Live packet capture using Scapy.
    Requires root/admin privileges.
    """

    def __init__(self, interface: str) -> None:
        try:
            from scapy.all import conf
            conf.verb = 0
        except ImportError:
            raise ImportError("Install scapy: pip install scapy")
        self.interface = interface
        self._running  = False

    def stream(self, callback: Callable) -> None:
        from scapy.all import sniff
        self._running = True
        logger.info("Live capture started on %s", self.interface)
        sniff(
            iface=self.interface,
            prn=callback,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def stop(self) -> None:
        self._running = False


class SimulatedPacket:
    """A fake packet that mimics Scapy's interface for demo mode."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port,
                 protocol, size, flags, ttl, payload_size, is_attack, attack_type):
        self.src_ip      = src_ip
        self.dst_ip      = dst_ip
        self.src_port    = src_port
        self.dst_port    = dst_port
        self.protocol    = protocol
        self.size        = size
        self.flags       = flags   # dict: syn, ack, rst, fin
        self.ttl         = ttl
        self.payload_size = payload_size
        self.is_attack   = is_attack
        self.attack_type = attack_type  # "normal"|"dos"|"portscan"|"bruteforce"
        self._simulated  = True


class SimulatedCapture:
    """
    Generates realistic simulated network traffic for demo mode.
    Produces ~20 packets/second with ~15% attack ratio.
    """

    _NORMAL_IPS  = [f"192.168.1.{i}"  for i in range(2, 60)]
    _ATTACK_IPS  = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
                    for _ in range(30)]
    _GATEWAY_IPS = [f"192.168.1.1", "8.8.8.8", "1.1.1.1", "172.217.0.0"]

    def __init__(self, attack_ratio: float = 0.15, pps: float = 20.0) -> None:
        self.attack_ratio = attack_ratio
        self.interval     = 1.0 / pps
        self._running     = False
        self._rng         = np.random.default_rng()

    def stream(self, callback: Callable) -> None:
        self._running = True
        logger.info("Simulated capture started (~%.0f pps, %.0f%% attacks)",
                    1.0 / self.interval, self.attack_ratio * 100)
        while self._running:
            pkt = self._generate()
            callback(pkt)
            time.sleep(self.interval + random.gauss(0, self.interval * 0.1))

    def stop(self) -> None:
        self._running = False

    def _generate(self) -> SimulatedPacket:
        rng = self._rng
        is_attack   = random.random() < self.attack_ratio
        attack_type = random.choice(["dos", "portscan", "bruteforce"]) if is_attack else "normal"

        if attack_type == "dos":
            return SimulatedPacket(
                src_ip      = random.choice(self._ATTACK_IPS),
                dst_ip      = random.choice(self._GATEWAY_IPS),
                src_port    = int(rng.integers(1024, 65535)),
                dst_port    = random.choice([80, 443]),
                protocol    = "TCP",
                size        = int(rng.integers(40, 80)),
                flags       = {"syn": 1, "ack": 0, "rst": 0, "fin": 0},
                ttl         = int(rng.integers(1, 32)),
                payload_size= 0,
                is_attack   = True,
                attack_type = "DoS/DDoS",
            )
        elif attack_type == "portscan":
            return SimulatedPacket(
                src_ip      = random.choice(self._ATTACK_IPS),
                dst_ip      = random.choice(self._GATEWAY_IPS),
                src_port    = int(rng.integers(1024, 65535)),
                dst_port    = int(rng.integers(1, 1024)),
                protocol    = "TCP",
                size        = int(rng.integers(40, 60)),
                flags       = {"syn": 1, "ack": 0, "rst": 0, "fin": 0},
                ttl         = int(rng.integers(48, 64)),
                payload_size= 0,
                is_attack   = True,
                attack_type = "Port Scan",
            )
        elif attack_type == "bruteforce":
            return SimulatedPacket(
                src_ip      = random.choice(self._ATTACK_IPS),
                dst_ip      = random.choice(self._NORMAL_IPS),
                src_port    = int(rng.integers(1024, 65535)),
                dst_port    = random.choice([22, 21, 23, 3389]),
                protocol    = "TCP",
                size        = int(rng.integers(100, 300)),
                flags       = {"syn": 1, "ack": 1, "rst": 0, "fin": 0},
                ttl         = int(rng.integers(48, 128)),
                payload_size= int(rng.integers(50, 200)),
                is_attack   = True,
                attack_type = "Brute-Force",
            )
        else:
            return SimulatedPacket(
                src_ip      = random.choice(self._NORMAL_IPS),
                dst_ip      = random.choice(self._GATEWAY_IPS),
                src_port    = int(rng.integers(1024, 65535)),
                dst_port    = random.choice([80, 443, 53, 8080]),
                protocol    = random.choice(["TCP", "UDP"]),
                size        = int(rng.integers(64, 1500)),
                flags       = {"syn": 0, "ack": 1, "rst": 0, "fin": 0},
                ttl         = int(rng.integers(48, 128)),
                payload_size= int(rng.integers(0, 1400)),
                is_attack   = False,
                attack_type = "normal",
            )
