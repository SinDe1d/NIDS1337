from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from nids.storage import Storage


ROOT = Path(__file__).parent
app = Flask(__name__, static_folder="static")
storage = Storage(os.getenv("NIDS_DB", str(ROOT / "data" / "nids.db")))


@app.get("/")
def dashboard():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "nids-dashboard"})


@app.get("/api/summary")
def summary():
    return jsonify(storage.stats())


@app.get("/api/alerts")
def alerts():
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100
    return jsonify(storage.list_alerts(limit, request.args.get("type")))


@app.get("/api/alerts/<int:alert_id>")
def alert_detail(alert_id: int):
    result = storage.get_alert(alert_id)
    if result is None:
        return jsonify({"error": "alert not found"}), 404
    if result.get("flow_id"):
        flows = [flow for flow in storage.list_flows(500)
                 if flow["id"] == result["flow_id"]]
        result["flow"] = flows[0] if flows else None
    return jsonify(result)


@app.post("/api/alerts/<int:alert_id>/feedback")
def alert_feedback(alert_id: int):
    body = request.get_json(silent=True) or {}
    value = body.get("value")
    if not storage.feedback(alert_id, value):
        return jsonify({"error": "value must be true_positive or false_positive"}), 400
    return jsonify({"ok": True, "alert_id": alert_id, "feedback": value})


@app.get("/api/flows")
def flows():
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100
    return jsonify(storage.list_flows(limit, request.args.get("search")))


if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )
