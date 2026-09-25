import os
import pytest
from flask import Flask


def test_full_rag_pipeline(tmp_path):
    # 1. Set up isolated KB
    kb_path = str(tmp_path / "chroma_e2e")
    os.environ["RAG_VECTOR_STORE_PATH"] = kb_path

    import src.rag.feedback as feedback_mod
    import src.rag.retriever as retriever_mod
    from src.rag.api import _RATE_LIMIT_STORE, rag_bp
    from src.rag.knowledge_base import Document, KnowledgeBase

    _RATE_LIMIT_STORE.clear()
    retriever_mod._QUERY_CACHE.clear()
    retriever_mod._DEFAULT_KB = None
    feedback_mod._default_store = None

    kb = KnowledgeBase(persist_directory=kb_path)
    kb.reset()

    # 2. Seed with 2 threat docs and 2 CVE docs
    kb.add_documents([
        Document(
            "LLM Prompt Injection. Adversaries may craft malicious prompts.",
            {"source": "MITRE_ATLAS", "technique_id": "AML.T0051"},
        ),
        Document(
            "Command and Scripting Interpreter. Adversaries may execute code.",
            {"source": "MITRE_ATTACK", "technique_id": "T1059"},
        ),
        Document(
            "CVE-2024-1234 (CRITICAL, CVSS 9.8): Remote code execution in test lib.",
            {
                "source": "NVD_CVE",
                "cve_id": "CVE-2024-1234",
                "severity": "CRITICAL",
                "cvss": 9.8,
            },
        ),
        Document(
            "CVE-2024-5678 (MEDIUM, CVSS 5.0): Info disclosure in test lib.",
            {
                "source": "NVD_CVE",
                "cve_id": "CVE-2024-5678",
                "severity": "MEDIUM",
                "cvss": 5.0,
            },
        ),
    ])
    assert kb.count() >= 4

    # 3. Retrieve context
    from src.rag.retriever import retrieve_context

    event = {
        "main_agent": {"name": "ChatGPT", "framework": "browser"},
        "sub_agent": {"name": "code_runner"},
        "action": {"tool": "execute:code", "target": "sandbox.py"},
    }
    ctx = retrieve_context(event, top_k=2, kb=kb)
    assert ctx["query"]
    assert isinstance(ctx["similar_threats"], list)
    assert isinstance(ctx["related_cves"], list)
    assert "remediation_hint" in ctx
    # Should find the CRITICAL CVE
    assert any(c["cve_id"] == "CVE-2024-1234" for c in ctx["related_cves"])

    # 4. Record feedback
    from src.rag.feedback import FeedbackStore

    store = FeedbackStore(kb=kb)
    fid = store.record("alert-001", event, "false_positive", "my test")
    assert fid.startswith("fb:alert-001")

    # 5. Verify feedback retrieval
    similar = store.find_similar(event, top_k=2)
    assert len(similar) >= 1
    assert similar[0]["label"] == "false_positive"

    # 6. Verify stats
    stats = store.stats()
    assert stats["false_positive"] == 1
    assert stats["total"] == 1

    # 7. Hit the API
    app = Flask(__name__)
    app.register_blueprint(rag_bp)
    client = app.test_client()

    r = client.get("/api/v1/rag/health")
    assert r.status_code == 200

    r = client.post("/api/v1/rag/query", json={"event": event, "top_k": 2})
    assert r.status_code == 200
    body = r.get_json()
    assert "similar_threats" in body
    assert "related_cves" in body
    assert "remediation_hint" in body

    r = client.post(
        "/api/v1/rag/feedback",
        json={"alert_id": "alert-002", "event": event, "label": "true_positive"},
    )
    assert r.status_code == 200
