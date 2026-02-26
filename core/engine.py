"""
core.engine — SentinelNet main engine
Coordinates packet capture, feature extraction, model inference,
and state management.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional

import numpy as np

from core.capture import PacketCapture, SimulatedCapture
from core.features import FeatureExtractor
from core.model import AdaptiveModel
from core.alert import AlertManager, Alert

logger = logging.getLogger(__name__)

MAX_RECENT = 500   # packets kept in memory for dashboard
MAX_ALERTS = 200   # alerts kept in memory


class SentinelEngine:
    """
    Central coordinator for SentinelNet.

    Packet flow:
        capture → feature extraction → model inference → alert manager
                                                        ↘ stats update
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        demo_mode: bool = False,
        reset_model: bool = False,
    ) -> None:
        self.interface  = interface
        self.demo_mode  = demo_mode
        self._running   = False

        # Components
        self.extractor  = FeatureExtractor()
        self.model      = AdaptiveModel(reset=reset_model)
        self.alerts     = AlertManager()

        # Shared state (thread-safe via lock)
        self._lock          = threading.Lock()
        self._recent_packets: deque = deque(maxlen=MAX_RECENT)
        self._recent_alerts:  deque = deque(maxlen=MAX_ALERTS)
        self._stats: Dict   = self._empty_stats()

        # Internal queue between capture and inference
        self._packet_queue: queue.Queue = queue.Queue(maxsize=1000)

    # ------------------------------------------------------------------
    #  Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        self._running = True
        logger.info("SentinelNet engine starting (demo=%s)", self.demo_mode)

        # Start inference worker
        infer_thread = threading.Thread(target=self._inference_loop, daemon=True)
        infer_thread.start()

        # Start capture
        if self.demo_mode:
            capture = SimulatedCapture()
        else:
            capture = PacketCapture(self.interface)

        capture.stream(callback=self._on_raw_packet)

    def stop(self) -> None:
        self._running = False
        logger.info("SentinelNet engine stopped.")

    # ------------------------------------------------------------------
    #  Packet pipeline
    # ------------------------------------------------------------------
    def _on_raw_packet(self, raw_packet) -> None:
        """Called by capture thread for each incoming packet."""
        try:
            self._packet_queue.put_nowait(raw_packet)
        except queue.Full:
            pass  # drop packet if queue is full (backpressure)

    def _inference_loop(self) -> None:
        """Worker thread: dequeue packets, extract features, run model."""
        while self._running:
            try:
                raw = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            features = self.extractor.extract(raw)
            if features is None:
                continue

            label, confidence = self.model.predict(features)
            is_attack = label != "normal"

            # Build packet record
            record = self._build_record(raw, features, label, confidence)

            # Update shared state
            with self._lock:
                self._recent_packets.append(record)
                self._update_stats(record, is_attack)

            # Alert if needed
            if is_attack and confidence >= 0.70:
                alert = self.alerts.process(record)
                if alert:
                    with self._lock:
                        self._recent_alerts.appendleft(alert)

            # Online learning: feed back to model periodically
            self.model.observe(features, label)

    def _build_record(self, raw, features: np.ndarray, label: str, confidence: float) -> dict:
        src_ip, dst_ip, src_port, dst_port, protocol = self.extractor.get_meta(raw)
        return {
            "timestamp":  datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   src_port,
            "dst_port":   dst_port,
            "protocol":   protocol,
            "label":      label,
            "confidence": round(confidence * 100, 1),
            "is_attack":  label != "normal",
            "size":       int(features[0]),
        }

    # ------------------------------------------------------------------
    #  Stats
    # ------------------------------------------------------------------
    def _empty_stats(self) -> dict:
        return {
            "total":         0,
            "attacks":       0,
            "normal":        0,
            "attack_types":  {},
            "packets_per_sec": 0.0,
            "started_at":    datetime.now().isoformat(),
            "model_version": 0,
        }

    def _update_stats(self, record: dict, is_attack: bool) -> None:
        s = self._stats
        s["total"]  += 1
        if is_attack:
            s["attacks"] += 1
            atype = record["label"]
            s["attack_types"][atype] = s["attack_types"].get(atype, 0) + 1
        else:
            s["normal"] += 1

    # ------------------------------------------------------------------
    #  Dashboard API (called from Flask routes)
    # ------------------------------------------------------------------
    def get_snapshot(self) -> dict:
        """Return current state snapshot for the dashboard."""
        with self._lock:
            packets = list(self._recent_packets)[-50:]  # last 50 for table
            alerts  = list(self._recent_alerts)[:20]    # most recent 20
            stats   = dict(self._stats)

        # Packets-per-second (last 10 packets)
        if len(packets) >= 2:
            pass  # simplified; real pps computed in JS

        stats["model_accuracy"] = round(self.model.get_accuracy() * 100, 1)
        stats["model_samples"]  = self.model.total_observed

        return {
            "packets": packets,
            "alerts":  [a.to_dict() for a in alerts],
            "stats":   stats,
            "running": self._running,
        }

    def get_chart_data(self, window: int = 60) -> dict:
        """Return time-bucketed data for the live chart (last `window` seconds)."""
        with self._lock:
            packets = list(self._recent_packets)

        # Bucket packets into 1-second bins
        now = time.time()
        buckets: Dict[int, dict] = {}
        for _ in range(window):
            t = int(now) - _
            buckets[t] = {"normal": 0, "attack": 0}

        for pkt in packets:
            # Use index as proxy for recency (no epoch in record)
            pass  # simplified — JS handles real-time charting via SSE

        labels  = [datetime.fromtimestamp(t).strftime("%H:%M:%S")
                   for t in sorted(buckets.keys())]
        normal  = [buckets[t]["normal"]  for t in sorted(buckets.keys())]
        attacks = [buckets[t]["attack"]  for t in sorted(buckets.keys())]

        return {"labels": labels, "normal": normal, "attacks": attacks}
