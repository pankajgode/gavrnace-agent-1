import csv
import json
import pytest
from src.rag.knowledge_base import KnowledgeBase
from src.rag.ingest_cti import ingest_mitre_atlas, ingest_cisa_kev


def test_ingest_atlas_with_sample(tmp_path):
    kb_path = tmp_path / "chroma_atlas"
    kb = KnowledgeBase(persist_directory=str(kb_path))
    initial_count = kb.count()

    sample_atlas = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-001",
                "name": "LLM Prompt Injection",
                "description": "Adversary crafts malicious inputs to override system instructions.",
                "external_references": [
                    {"source_name": "mitre-atlas", "external_id": "AML.T0051"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas-attack", "phase_name": "execution"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--atlas-002",
                "name": "Model Inversion Attack",
                "description": "Adversary reconstructs training data by querying the ML model repeatedly.",
                "external_references": [
                    {"source_name": "mitre-atlas", "external_id": "AML.T0002"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-atlas-attack", "phase_name": "exfiltration"}
                ],
            },
            {
                "type": "identity",
                "id": "identity--dummy",
                "name": "Non Attack Pattern Object",
            },
        ]
    }

    atlas_file = tmp_path / "sample_atlas.json"
    atlas_file.write_text(json.dumps(sample_atlas), encoding="utf-8")

    added = ingest_mitre_atlas(str(atlas_file), kb)
    assert added == 2
    assert kb.count() == initial_count + 2

    # Verify search retrieves the ingested document
    results = kb.similarity_search("prompt injection inputs override", k=1)
    assert len(results) == 1
    assert "Prompt Injection" in results[0].page_content
    assert results[0].metadata.get("source") == "MITRE_ATLAS"
    assert results[0].metadata.get("ai_relevant") is True


def test_ingest_kev_with_sample(tmp_path):
    kb_path = tmp_path / "chroma_kev"
    kb = KnowledgeBase(persist_directory=str(kb_path))
    initial_count = kb.count()

    kev_file = tmp_path / "sample_kev.csv"
    with open(kev_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "cveID",
            "vendorProject",
            "product",
            "vulnerabilityName",
            "shortDescription",
            "dateAdded",
            "dueDate",
        ])
        writer.writerow([
            "CVE-2024-12345",
            "Apache",
            "HTTP Server",
            "Apache Path Traversal",
            "Path traversal vulnerability allowing arbitrary file read.",
            "2024-01-15",
            "2024-02-05",
        ])
        writer.writerow([
            "CVE-2024-67890",
            "Microsoft",
            "Windows",
            "Kernel Privilege Escalation",
            "Elevation of privilege in Windows kernel driver.",
            "2024-02-10",
            "2024-03-01",
        ])

    added = ingest_cisa_kev(str(kev_file), kb)
    assert added == 2
    assert kb.count() == initial_count + 2

    results = kb.similarity_search("Apache Path Traversal vulnerability", k=1)
    assert len(results) == 1
    assert "Apache" in results[0].page_content
    assert results[0].metadata.get("source") == "CISA_KEV"
    assert results[0].metadata.get("cve_id") == "CVE-2024-12345"


def test_missing_file_does_not_crash(tmp_path):
    kb_path = tmp_path / "chroma_missing"
    kb = KnowledgeBase(persist_directory=str(kb_path))
    initial_count = kb.count()

    non_existent = str(tmp_path / "non_existent_file.json")
    added = ingest_mitre_atlas(non_existent, kb)
    assert added == 0
    assert kb.count() == initial_count


def test_ingest_atlas_yaml_with_sample(tmp_path):
    kb_path = tmp_path / "chroma_atlas_yaml"
    kb = KnowledgeBase(persist_directory=str(kb_path))
    initial_count = kb.count()

    yaml_content = """id: test
name: test
version: 1
matrices:
  - id: m1
    name: Matrix
    tactics:
      - id: AML.TA0002
        name: Reconnaissance
    techniques:
      - id: AML.T0000
        name: Search Open Technical Databases
        description: Adversaries may search...
        object-type: technique
        tactics:
          - AML.TA0002
        maturity: demonstrated
      - id: AML.T0051
        name: LLM Prompt Injection
        description: Adversaries may inject...
        object-type: technique
        tactics:
          - AML.TA0002
        maturity: demonstrated
"""
    yaml_file = tmp_path / "sample_atlas.yaml"
    yaml_file.write_text(yaml_content, encoding="utf-8")

    added = ingest_mitre_atlas(str(yaml_file), kb)
    assert added == 2
    assert kb.count() == initial_count + 2

    results = kb.similarity_search("prompt injection LLM")
    matched_doc = next(
        (
            doc
            for doc in results
            if doc.metadata.get("source") == "MITRE_ATLAS"
            and doc.metadata.get("technique_id") == "AML.T0051"
        ),
        None,
    )
    assert matched_doc is not None
    assert matched_doc.metadata["source"] == "MITRE_ATLAS"
    assert matched_doc.metadata["technique_id"] == "AML.T0051"
