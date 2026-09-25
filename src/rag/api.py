"""
Flask API Blueprint for Guardian RAG Service.
Exposes semantic threat retrieval, CVE lookup, analyst feedback, and health/stats endpoints.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from flask import Blueprint, g, jsonify, request

from src.rag.feedback import (
    VALID_LABELS,
    find_similar_feedback,
    get_feedback_stats,
    record_feedback,
)
from src.rag.knowledge_base import KnowledgeBase
from src.rag.retriever import retrieve_context

logger = logging.getLogger(__name__)

rag_bp = Blueprint("rag", __name__, url_prefix="/api/v1/rag")

# In-memory rate limiting store: {ip: [timestamp, ...]}
_RATE_LIMIT_STORE: Dict[str, List[float]] = {}
RATE_LIMIT_MAX_REQUESTS = 100
RATE_LIMIT_WINDOW_SECONDS = 60.0


def _get_client_ip() -> str:
    """Extract client IP from request headers or remote address."""
    x_forwarded = request.headers.get("X-Forwarded-For")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


@rag_bp.before_request
def rate_limit_and_timing() -> Optional[Any]:
    """Enforce per-IP rate limiting (100 req/min) and record request start time."""
    g.start_time = time.time()
    client_ip = _get_client_ip()
    now = time.time()

    timestamps = _RATE_LIMIT_STORE.get(client_ip, [])
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    timestamps = [t for t in timestamps if t > cutoff]

    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        _RATE_LIMIT_STORE[client_ip] = timestamps
        logger.warning("Rate limit exceeded for IP: %s", client_ip)
        return jsonify({"error": "rate_limited"}), 429

    timestamps.append(now)
    _RATE_LIMIT_STORE[client_ip] = timestamps
    return None


@rag_bp.after_request
def log_request(response: Any) -> Any:
    """Log HTTP request summary with elapsed latency."""
    start_time = getattr(g, "start_time", None)
    elapsed_ms = (time.time() - start_time) * 1000.0 if start_time else 0.0
    client_ip = _get_client_ip()

    logger.info(
        "%s %s %s status=%d elapsed=%.2fms",
        request.method,
        request.path,
        client_ip,
        response.status_code,
        elapsed_ms,
    )
    return response


@rag_bp.route("/query", methods=["POST"])
def query_rag() -> Any:
    """
    Query knowledge base for threat patterns and CVEs matching an agent event.
    Also returns similar historical analyst feedback.
    """
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or "event" not in data or not isinstance(data.get("event"), dict):
            return jsonify({"error": "missing event"}), 400

        event = data["event"]
        top_k = data.get("top_k", 5)
        try:
            top_k = int(top_k)
        except (ValueError, TypeError):
            top_k = 5
        top_k = max(1, min(top_k, 20))

        context = retrieve_context(event, top_k=top_k)
        raw_feedback = find_similar_feedback(event, top_k=top_k)

        similar_feedback = [
            {
                "label": f.get("label", ""),
                "notes": f.get("notes", ""),
                "distance": f.get("distance", 0.0),
            }
            for f in raw_feedback
        ]

        response_payload = {
            "query": context.get("query", ""),
            "similar_threats": context.get("similar_threats", []),
            "related_cves": context.get("related_cves", []),
            "remediation_hint": context.get("remediation_hint", ""),
            "total_retrieved": context.get("total_retrieved", 0),
            "similar_feedback": similar_feedback,
        }
        return jsonify(response_payload), 200

    except Exception as exc:
        logger.error("Internal error processing RAG query: %s", exc, exc_info=True)
        return jsonify({"error": "internal_error"}), 500


@rag_bp.route("/feedback", methods=["POST"])
def submit_feedback() -> Any:
    """Record analyst feedback (TP/FP/uncertain) for an alert event."""
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "missing alert_id or event"}), 400

        alert_id = data.get("alert_id")
        event = data.get("event")
        label = data.get("label")
        notes = data.get("notes", "")

        if not alert_id or not event or not isinstance(event, dict):
            return jsonify({"error": "missing alert_id or event"}), 400

        if label not in VALID_LABELS:
            return jsonify({"error": "invalid_label"}), 400

        feedback_id = record_feedback(
            alert_id=str(alert_id),
            event=event,
            label=str(label),
            notes=str(notes),
        )
        return jsonify({"status": "ok", "feedback_id": feedback_id}), 200

    except Exception as exc:
        logger.error("Internal error recording feedback: %s", exc, exc_info=True)
        return jsonify({"error": "internal_error"}), 500


@rag_bp.route("/stats", methods=["GET"])
def get_stats() -> Any:
    """Retrieve document count and feedback distribution statistics."""
    try:
        kb = KnowledgeBase()
        total_documents = kb.count()
        feedback_counts = get_feedback_stats()
        return (
            jsonify(
                {
                    "total_documents": total_documents,
                    "feedback_counts": feedback_counts,
                }
            ),
            200,
        )
    except Exception as exc:
        logger.error("Internal error fetching RAG stats: %s", exc, exc_info=True)
        return jsonify({"error": "internal_error"}), 500


@rag_bp.route("/health", methods=["GET"])
def health_check() -> Any:
    """Service health check endpoint."""
    return (
        jsonify({"status": "ok", "service": "guardian-rag", "version": "1.0.0"}),
        200,
    )


if __name__ == "__main__":
    from flask import Flask
    from src.rag.register import register_rag

    app = Flask(__name__)
    register_rag(app)
    app.run(host="127.0.0.1", port=5001, debug=False)
