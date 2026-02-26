"""
dashboard.app — Flask web dashboard for SentinelNet
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
from datetime import datetime
from typing import TYPE_CHECKING

from flask import Flask, Response, jsonify, render_template, send_file, stream_with_context

if TYPE_CHECKING:
    from core.engine import SentinelEngine


def create_app(engine: "SentinelEngine") -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "..", "static"),
    )
    app.config["engine"] = engine

    # ------------------------------------------------------------------
    #  Pages
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        return render_template("index.html")

    # ------------------------------------------------------------------
    #  REST API
    # ------------------------------------------------------------------
    @app.route("/api/snapshot")
    def snapshot():
        return jsonify(engine.get_snapshot())

    @app.route("/api/stats")
    def stats():
        snap = engine.get_snapshot()
        return jsonify(snap["stats"])

    @app.route("/api/alerts")
    def alerts():
        snap = engine.get_snapshot()
        return jsonify(snap["alerts"])

    # ------------------------------------------------------------------
    #  Server-Sent Events (live feed)
    # ------------------------------------------------------------------
    @app.route("/api/stream")
    def stream():
        """
        SSE endpoint — pushes a snapshot every second to the dashboard.
        The JS client uses this for real-time chart and table updates.
        """
        def generate():
            while True:
                snap = engine.get_snapshot()
                data = json.dumps({
                    "stats":   snap["stats"],
                    "packets": snap["packets"][-10:],  # last 10 only
                    "alerts":  snap["alerts"][:5],
                })
                yield f"data: {data}\n\n"
                time.sleep(1)

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # ------------------------------------------------------------------
    #  Reports
    # ------------------------------------------------------------------
    @app.route("/api/report/csv")
    def report_csv():
        """Download full alert log as CSV."""
        log_path = "logs/alerts.csv"
        if not os.path.isfile(log_path):
            return jsonify({"error": "No alerts yet"}), 404
        return send_file(
            log_path,
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"sentinelnet_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )

    @app.route("/api/report/json")
    def report_json():
        """Download full snapshot as JSON report."""
        snap = engine.get_snapshot()
        snap["generated_at"] = datetime.now().isoformat()
        buf = io.BytesIO(json.dumps(snap, indent=2).encode())
        buf.seek(0)
        return send_file(
            buf,
            mimetype="application/json",
            as_attachment=True,
            download_name=f"sentinelnet_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )

    return app
