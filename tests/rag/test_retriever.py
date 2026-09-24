import pytest
from src.rag.knowledge_base import Document, KnowledgeBase
from src.rag.retriever import (
    _QUERY_CACHE,
    build_query_from_event,
    format_for_llm,
    retrieve_context,
)


@pytest.fixture(autouse=True)
def clear_cache():
    _QUERY_CACHE.clear()
    yield
    _QUERY_CACHE.clear()


@pytest.fixture
def seeded_kb(tmp_path):
    kb_path = tmp_path / "chroma_retriever"
    kb = KnowledgeBase(persist_directory=str(kb_path))
    docs = [
        Document(
            page_content="LLM Prompt Injection. Adversaries inject malicious inputs.",
            metadata={
                "source": "MITRE_ATLAS",
                "technique_id": "AML.T0051",
                "ai_relevant": True,
            },
        ),
        Document(
            page_content="Command and Scripting Interpreter. Adversaries execute arbitrary commands.",
            metadata={
                "source": "MITRE_ATTACK",
                "technique_id": "T1059",
                "ai_relevant": False,
            },
        ),
        Document(
            page_content="CVE-2024-12345 (CRITICAL, CVSS 9.8): Remote Code Execution in server.",
            metadata={
                "source": "CISA_KEV",
                "cve_id": "CVE-2024-12345",
                "severity": "CRITICAL",
                "cvss": 9.8,
            },
        ),
        Document(
            page_content="CVE-2024-54321 (MEDIUM, CVSS 5.0): Denial of service in machine learning library.",
            metadata={
                "source": "NVD_CVE",
                "cve_id": "CVE-2024-54321",
                "severity": "MEDIUM",
                "cvss": 5.0,
            },
        ),
    ]
    kb.add_documents(docs)
    return kb


def test_build_query_from_event_full():
    event = {
        "main_agent": {"name": "ChatGPT", "framework": "browser", "pid": 1234},
        "sub_agent": {"name": "code_runner", "role": "execution"},
        "action": {
            "type": "tool_call",
            "tool": "execute:code",
            "target": "sandbox.py",
            "status": "started",
        },
        "permissions_granted": ["read:files"],
        "permissions_used": ["read:files", "execute:code"],
    }
    query = build_query_from_event(event)
    assert "ChatGPT" in query
    assert "execute:code" in query


def test_build_query_from_event_empty():
    assert build_query_from_event({}) == "suspicious AI agent activity"


def test_retrieve_context_separates_sources(seeded_kb):
    event = {
        "main_agent": {"name": "TestAgent"},
        "action": {"tool": "execute:code", "target": "system"},
    }
    res = retrieve_context(event, top_k=5, kb=seeded_kb)

    assert "query" in res
    assert "similar_threats" in res
    assert "related_cves" in res
    assert "remediation_hint" in res
    assert "total_retrieved" in res

    assert len(res["similar_threats"]) > 0
    for threat in res["similar_threats"]:
        assert "source" in threat
        assert "id" in threat
        assert "text" in threat
        assert "distance" in threat

    assert len(res["related_cves"]) > 0
    for cve in res["related_cves"]:
        assert "cve_id" in cve
        assert "severity" in cve
        assert "cvss" in cve
        assert "text" in cve


def test_remediation_hint_prioritizes_critical_cvss(seeded_kb):
    event = {
        "action": {"tool": "exploit", "target": "Remote Code Execution server"},
    }
    res = retrieve_context(event, top_k=5, kb=seeded_kb)
    assert "CRITICAL" in res["remediation_hint"]


def test_cache_hit_returns_same_object(seeded_kb):
    event = {
        "main_agent": {"name": "CachedAgent"},
        "action": {"tool": "run_analysis"},
    }
    res1 = retrieve_context(event, top_k=3, kb=seeded_kb)
    res2 = retrieve_context(event, top_k=3, kb=seeded_kb)

    assert res1 == res2
    assert res1 is res2


def test_retrieve_context_returns_threats_and_cves(tmp_path):
    kb_path = tmp_path / "chroma_dual_query"
    kb = KnowledgeBase(persist_directory=str(kb_path))
    docs = [
        Document(
            page_content="Adversary performs arbitrary code execution on agent runtime.",
            metadata={
                "source": "MITRE_ATLAS",
                "technique_id": "AML.T0052",
                "ai_relevant": True,
            },
        ),
        Document(
            page_content="Remote code execution vulnerability via prompt injection payload.",
            metadata={
                "source": "MITRE_ATLAS",
                "technique_id": "AML.T0053",
                "ai_relevant": True,
            },
        ),
        Document(
            page_content="CVE-2024-99001 (CRITICAL, CVSS 9.0): Remote code execution flaw in langchain.",
            metadata={
                "source": "NVD_CVE",
                "cve_id": "CVE-2024-99001",
                "severity": "CRITICAL",
                "cvss": 9.0,
            },
        ),
        Document(
            page_content="CVE-2024-99002 (CRITICAL, CVSS 9.0): Arbitrary code execution flaw in transformers.",
            metadata={
                "source": "NVD_CVE",
                "cve_id": "CVE-2024-99002",
                "severity": "CRITICAL",
                "cvss": 9.0,
            },
        ),
    ]
    kb.add_documents(docs)

    event = {
        "main_agent": {"name": "ChatGPT", "framework": "browser"},
        "action": {"tool": "execute:code", "target": "sandbox.py"},
    }

    result = retrieve_context(event, top_k=2, kb=kb)

    assert len(result["similar_threats"]) >= 1
    assert len(result["related_cves"]) >= 1
    assert "CRITICAL" in result["remediation_hint"]
