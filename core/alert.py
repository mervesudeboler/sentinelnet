"""
core.alert — AlertManager and Alert dataclass
"""

from __future__ import annotations

import csv
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

ALERT_LOG = "logs/alerts.csv"
CSV_HEADER = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
              "protocol", "attack_type", "confidence", "severity"]

SEVERITY = {
    "LOW":    (0.70, 0.84),
    "MEDIUM": (0.85, 0.94),
    "HIGH":   (0.95, 1.01),
}


@dataclass
class Alert:
    timestamp:   str
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    protocol:    str
    attack_type: str
    confidence:  float
    severity:    str = field(init=False)

    def __post_init__(self):
        self.severity = self._classify()

    def _classify(self) -> str:
        for level, (lo, hi) in SEVERITY.items():
            if lo <= self.confidence < hi:
                return level
        return "HIGH"

    def to_dict(self) -> dict:
        return {
            "timestamp":   self.timestamp,
            "src_ip":      self.src_ip,
            "dst_ip":      self.dst_ip,
            "src_port":    self.src_port,
            "dst_port":    self.dst_port,
            "protocol":    self.protocol,
            "attack_type": self.attack_type,
            "confidence":  round(self.confidence * 100, 1),
            "severity":    self.severity,
        }


class AlertManager:
    def __init__(self) -> None:
        os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
        if not os.path.isfile(ALERT_LOG):
            with open(ALERT_LOG, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(CSV_HEADER)

    def process(self, record: dict) -> Optional[Alert]:
        if not record.get("is_attack"):
            return None
        conf = record["confidence"] / 100.0
        alert = Alert(
            timestamp   = record["timestamp"],
            src_ip      = record["src_ip"],
            dst_ip      = record["dst_ip"],
            src_port    = record["src_port"],
            dst_port    = record["dst_port"],
            protocol    = record["protocol"],
            attack_type = record["label"],
            confidence  = conf,
        )
        self._write(alert)
        return alert

    def _write(self, alert: Alert) -> None:
        with open(ALERT_LOG, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                alert.timestamp, alert.src_ip, alert.dst_ip,
                alert.src_port, alert.dst_port, alert.protocol,
                alert.attack_type, f"{alert.confidence:.4f}", alert.severity,
            ])
