import pytest
from src.rag.feedback import FeedbackStore
from src.rag.knowledge_base import KnowledgeBase


@pytest.fixture
def kb(tmp_path):
    return KnowledgeBase(persist_directory=str(tmp_path / "chroma_fb"))


def test_record_and_stats(kb):
    store = FeedbackStore(kb)
    store.clear()

    event = {
        "main_agent": {"name": "ChatGPT"},
        "action": {"tool": "execute:code"},
    }

    store.record("alert-1", event, "false_positive", notes="benign testing")
    store.record("alert-2", event, "false_positive", notes="dev environment")
    store.record("alert-3", event, "true_positive", notes="real injection")

    assert store.stats() == {
        "true_positive": 1,
        "false_positive": 2,
        "uncertain": 0,
        "total": 3,
    }


def test_invalid_label_raises(kb):
    store = FeedbackStore(kb)
    with pytest.raises(ValueError):
        store.record("a1", {}, "garbage")


def test_find_similar_returns_feedback(kb):
    store = FeedbackStore(kb)
    store.clear()

    event_a = {
        "main_agent": {"name": "ChatGPT"},
        "sub_agent": {"name": "code_runner"},
        "action": {"tool": "execute:code", "target": "sandbox.py"},
    }

    doc_id = store.record("alert-a", event_a, "false_positive", notes="safe sandbox")
    assert doc_id.startswith("fb:alert-a:")

    results = store.find_similar(event_a, top_k=3)
    assert len(results) >= 1
    assert results[0]["label"] == "false_positive"
    assert results[0]["alert_id"] == "alert-a"
    assert "alert_id" in results[0]
    assert "label" in results[0]
    assert "notes" in results[0]
    assert "timestamp" in results[0]
    assert "text" in results[0]
    assert "distance" in results[0]


def test_find_similar_empty_store(kb):
    store = FeedbackStore(kb)
    store.clear()

    event = {
        "main_agent": {"name": "NewAgent"},
        "action": {"tool": "read_file"},
    }
    results = store.find_similar(event)
    assert results == []


def test_clear_resets_collection(kb):
    store = FeedbackStore(kb)
    store.clear()

    event = {"main_agent": {"name": "TestAgent"}}
    store.record("alert-x", event, "true_positive")
    assert store.stats()["total"] == 1

    store.clear()
    assert store.stats()["total"] == 0
