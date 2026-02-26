"""
core.features — Feature extraction from both live Scapy and simulated packets
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "packet_size",
    "is_tcp",
    "is_udp",
    "is_icmp",
    "src_port",
    "dst_port",
    "tcp_flag_syn",
    "tcp_flag_ack",
    "tcp_flag_rst",
    "tcp_flag_fin",
    "payload_size",
    "ttl",
    "ip_frag",
    "header_length",
]

N_FEATURES = len(FEATURE_NAMES)


class FeatureExtractor:
    """
    Converts packets (Scapy or SimulatedPacket) into a fixed-length
    numpy feature vector of shape (14,).
    """

    def extract(self, packet) -> Optional[np.ndarray]:
        try:
            if getattr(packet, "_simulated", False):
                return self._from_simulated(packet)
            return self._from_scapy(packet)
        except Exception as exc:
            logger.debug("Feature extraction error: %s", exc)
            return None

    def get_meta(self, packet) -> Tuple[str, str, int, int, str]:
        """Return (src_ip, dst_ip, src_port, dst_port, protocol)."""
        try:
            if getattr(packet, "_simulated", False):
                return (
                    packet.src_ip, packet.dst_ip,
                    packet.src_port, packet.dst_port,
                    packet.protocol,
                )
            return self._scapy_meta(packet)
        except Exception:
            return ("?", "?", 0, 0, "?")

    # ------------------------------------------------------------------
    #  Simulated packets
    # ------------------------------------------------------------------
    def _from_simulated(self, pkt) -> np.ndarray:
        is_tcp  = int(pkt.protocol == "TCP")
        is_udp  = int(pkt.protocol == "UDP")
        is_icmp = int(pkt.protocol == "ICMP")
        f = pkt.flags or {}
        return np.array([
            pkt.size,
            is_tcp, is_udp, is_icmp,
            pkt.src_port, pkt.dst_port,
            f.get("syn", 0), f.get("ack", 0),
            f.get("rst", 0), f.get("fin", 0),
            pkt.payload_size,
            pkt.ttl,
            0,   # ip_frag
            20,  # header_length
        ], dtype=np.float32)

    # ------------------------------------------------------------------
    #  Live Scapy packets
    # ------------------------------------------------------------------
    def _from_scapy(self, packet) -> Optional[np.ndarray]:
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
        except ImportError:
            return None

        if not packet.haslayer(IP):
            return None

        ip     = packet[IP]
        is_tcp = int(packet.haslayer(TCP))
        is_udp = int(packet.haslayer(UDP))
        is_icmp= int(packet.haslayer(ICMP))

        src_port = dst_port = 0
        syn = ack = rst = fin = 0

        if is_tcp:
            tcp      = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags    = tcp.flags
            syn = int(bool(flags & 0x02))
            rst = int(bool(flags & 0x04))
            fin = int(bool(flags & 0x01))
            ack = int(bool(flags & 0x10))
        elif is_udp:
            udp      = packet["UDP"]
            src_port = udp.sport
            dst_port = udp.dport

        payload_size = len(bytes(packet.payload.payload)) if packet.payload else 0
        ip_frag      = int(ip.flags.MF or ip.frag > 0)
        header_len   = ip.ihl * 4 if ip.ihl else 20

        return np.array([
            len(packet), is_tcp, is_udp, is_icmp,
            src_port, dst_port,
            syn, ack, rst, fin,
            payload_size, ip.ttl, ip_frag, header_len,
        ], dtype=np.float32)

    def _scapy_meta(self, packet) -> Tuple[str, str, int, int, str]:
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            ip       = packet[IP]
            src_ip   = ip.src
            dst_ip   = ip.dst
            src_port = dst_port = 0
            proto    = "OTHER"
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto    = "TCP"
            elif packet.haslayer(UDP):
                src_port = packet["UDP"].sport
                dst_port = packet["UDP"].dport
                proto    = "UDP"
            elif packet.haslayer(ICMP):
                proto = "ICMP"
            return src_ip, dst_ip, src_port, dst_port, proto
        except Exception:
            return ("?", "?", 0, 0, "?")

    @staticmethod
    def feature_names() -> list:
        return FEATURE_NAMES
