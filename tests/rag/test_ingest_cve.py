from unittest.mock import MagicMock, patch
import pytest
import requests

from src.rag.knowledge_base import KnowledgeBase
from src.rag.ingest_cve import (
    cve_to_document,
    fetch_cves_for_keyword,
    ingest_nvd,
)


def test_cve_to_document_produces_expected_fields():
    fake_cve = {
        "id": "CVE-2024-99999",
        "descriptions": [
            {"lang": "es", "value": "Descripcion en espanol"},
            {"lang": "en", "value": "Remote code execution in langchain-core."},
        ],
        "published": "2024-05-10T12:00:00.000",
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        },
    }

    doc = cve_to_document(fake_cve, keyword="langchain-core")
    assert doc is not None
    assert "CVE-2024-99999" in doc.page_content
    assert "CRITICAL" in doc.page_content
    assert "9.8" in doc.page_content
    assert "Remote code execution in langchain-core." in doc.page_content

    metadata = doc.metadata
    assert metadata["source"] == "NVD_CVE"
    assert metadata["cve_id"] == "CVE-2024-99999"
    assert metadata["severity"] == "CRITICAL"
    assert metadata["cvss"] == 9.8
    assert metadata["published"] == "2024-05-10T12:00:00.000"
    assert metadata["matched_keyword"] == "langchain-core"


def test_fetch_handles_http_error():
    with patch(
        "src.rag.ingest_cve.requests.get",
        side_effect=requests.RequestException("Connection error"),
    ):
        results = fetch_cves_for_keyword("torch")
        assert results == []


def test_ingest_deduplicates_across_keywords(tmp_path):
    kb_path = tmp_path / "chroma_cve"
    kb = KnowledgeBase(persist_directory=str(kb_path))
    initial_count = kb.count()

    fake_cve = {
        "id": "CVE-2024-11111",
        "descriptions": [{"lang": "en", "value": "Memory corruption flaw."}],
        "published": "2024-01-01T00:00:00.000",
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
    }

    # Mock fetch_cves_for_keyword to return the same CVE for any keyword
    with patch("src.rag.ingest_cve.fetch_cves_for_keyword", return_value=[fake_cve]), \
         patch("src.rag.ingest_cve.time.sleep", return_value=None):
        added = ingest_nvd(keywords=["keyword1", "keyword2"], kb=kb)

    assert added == 1
    assert kb.count() == initial_count + 1
