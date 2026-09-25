import os
import pytest
from flask import Flask


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Set up Flask test client with an isolated temporary ChromaDB path."""
    kb_dir = str(tmp_path / "chroma_api")
    monkeypatch.setenv("RAG_VECTOR_STORE_PATH", kb_dir)

    import src.rag.feedback as feedback_mod
    import src.rag.retriever as retriever_mod
    from src.rag.api import _RATE_LIMIT_STORE
    from src.rag.register import register_rag

    _RATE_LIMIT_STORE.clear()
    retriever_mod._DEFAULT_KB = None
    feedback_mod._default_store = None

    app = Flask(__name__)
    register_rag(app)
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client


def test_health_ok(client):
    """Assert health endpoint returns 200 with service metadata."""
    resp = client.get("/api/v1/rag/health")
    assert resp.status_code == 200
    assert resp.get_json() == {
        "status": "ok",
        "service": "guardian-rag",
        "version": "1.0.0",
    }


def test_query_missing_event_returns_400(client):
    """Assert query endpoint returns 400 when event is missing or malformed."""
    resp_empty = client.post("/api/v1/rag/query", json={})
    assert resp_empty.status_code == 400
    assert resp_empty.get_json() == {"error": "missing event"}

    resp_invalid = client.post("/api/v1/rag/query", json={"event": "not_a_dict"})
    assert resp_invalid.status_code == 400
    assert resp_invalid.get_json() == {"error": "missing event"}


def test_query_returns_expected_keys(client):
    """Assert query endpoint returns all expected response schema keys."""
    event = {
        "main_agent": {"name": "ChatGPT", "framework": "browser"},
        "action": {"tool": "execute:code", "target": "sandbox.py"},
    }
    resp = client.post("/api/v1/rag/query", json={"event": event, "top_k": 5})
    assert resp.status_code == 200
    data = resp.get_json()

    expected_keys = {
        "query",
        "similar_threats",
        "related_cves",
        "remediation_hint",
        "total_retrieved",
        "similar_feedback",
    }
    assert expected_keys.issubset(data.keys())
    assert isinstance(data["similar_threats"], list)
    assert isinstance(data["related_cves"], list)
    assert isinstance(data["similar_feedback"], list)
    assert isinstance(data["total_retrieved"], int)


def test_feedback_valid(client):
    """Assert valid feedback submission succeeds and returns feedback_id."""
    event = {
        "main_agent": {"name": "ChatGPT"},
        "action": {"tool": "execute:code"},
    }
    payload = {
        "alert_id": "alert-test-001",
        "event": event,
        "label": "false_positive",
        "notes": "Benign developer execution",
    }
    resp = client.post("/api/v1/rag/feedback", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "feedback_id" in data
    assert data["feedback_id"].startswith("fb:alert-test-001:")


def test_feedback_invalid_label(client):
    """Assert invalid feedback label returns 400."""
    event = {
        "main_agent": {"name": "ChatGPT"},
    }
    payload = {
        "alert_id": "alert-test-002",
        "event": event,
        "label": "unrecognized_label",
    }
    resp = client.post("/api/v1/rag/feedback", json=payload)
    assert resp.status_code == 400
    assert resp.get_json() == {"error": "invalid_label"}


def test_rate_limit_blocks_after_100(client):
    """Assert IP rate limiter allows 100 requests and blocks the 101st with 429."""
    for _ in range(100):
        resp = client.get("/api/v1/rag/health")
        assert resp.status_code == 200

    blocked_resp = client.get("/api/v1/rag/health")
    assert blocked_resp.status_code == 429
    assert blocked_resp.get_json() == {"error": "rate_limited"}
