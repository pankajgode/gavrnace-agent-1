import pytest
from src.rag.knowledge_base import KnowledgeBase, Document


def test_init_creates_store(tmp_path):
    kb = KnowledgeBase(persist_directory=str(tmp_path / "test_init"))
    assert kb.count() >= 0


def test_add_and_search(tmp_path):
    kb = KnowledgeBase(persist_directory=str(tmp_path / "test_search"))
    docs = [
        Document(
            page_content="Ransomware encrypts server files and demands Bitcoin payment.",
            metadata={"source": "threat_intel", "type": "ransomware"},
        ),
        Document(
            page_content="Cross-site scripting allows execution of scripts in user browser.",
            metadata={"source": "owasp", "type": "xss"},
        ),
        Document(
            page_content="Buffer overflow in memory execution leads to remote code execution.",
            metadata={"source": "cve", "type": "bof"},
        ),
    ]
    added = kb.add_documents(docs)
    assert added == 3

    results = kb.similarity_search("ransomware encrypts files", k=1)
    assert len(results) == 1
    assert isinstance(results[0], Document)
    assert "Ransomware" in results[0].page_content


def test_get_context_for_action_returns_string(tmp_path):
    kb = KnowledgeBase(persist_directory=str(tmp_path / "test_context"))
    context = kb.get_context_for_action("SQL Injection query execution", k=2)
    assert isinstance(context, str)
    assert len(context) > 0
    assert "[1]" in context

    # Test empty collection returns empty string
    empty_kb = KnowledgeBase(persist_directory=str(tmp_path / "test_empty"))
    empty_kb.reset()
    empty_context = empty_kb.get_context_for_action("any random action", k=2)
    assert isinstance(empty_context, str)
    assert empty_context == ""


def test_reset(tmp_path):
    kb = KnowledgeBase(persist_directory=str(tmp_path / "test_reset"))
    kb.add_text("Temporary test record", metadata={"source": "test"})
    assert kb.count() > 0

    kb.reset()
    assert kb.count() == 0
