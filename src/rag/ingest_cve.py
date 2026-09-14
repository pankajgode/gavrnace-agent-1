"""
Ingest NVD CVE vulnerability intelligence filtered to AI/ML libraries into the Knowledge Base.
Uses NVD API 2.0 with keyword search and rate limiting.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
from tqdm import tqdm

from src.rag.knowledge_base import Document, KnowledgeBase

logger = logging.getLogger(__name__)

AI_PACKAGES: List[str] = [
    "langchain",
    "langchain-core",
    "langchain-community",
    "openai",
    "anthropic",
    "transformers",
    "huggingface-hub",
    "torch",
    "tensorflow",
    "llama-index",
    "chromadb",
    "sentence-transformers",
    "vllm",
    "gradio",
    "streamlit",
]

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
DELAY_BETWEEN_CALLS = 0.6 if NVD_API_KEY else 6.0
MAX_RESULTS_PER_KEYWORD = 200


def _extract_cvss(metrics: dict) -> Tuple[float, str]:
    """
    Extract CVSS base score and severity from metrics dictionary.
    Tries cvssMetricV31, then cvssMetricV30, then cvssMetricV2.
    Returns (baseScore, baseSeverity) or (0.0, "UNKNOWN").
    """
    if not isinstance(metrics, dict):
        return 0.0, "UNKNOWN"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key)
        if isinstance(metric_list, list) and len(metric_list) > 0:
            first = metric_list[0]
            if isinstance(first, dict):
                cvss_data = first.get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or first.get("baseSeverity")
                if score is not None:
                    try:
                        return float(score), str(severity or "UNKNOWN")
                    except (ValueError, TypeError):
                        pass
    return 0.0, "UNKNOWN"


def _extract_description(descriptions: list) -> str:
    """Extract English description from list of description objects."""
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            return item.get("value", "") or ""
    return ""


def fetch_cves_for_keyword(keyword: str, max_results: int = 200) -> List[dict]:
    """
    Fetch CVE records for a keyword from NVD API 2.0.
    Handles 403/429 rate limit with a single 30s retry.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 2000),
    }
    headers: Dict[str, str] = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(2):
        try:
            response = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=30
            )
            if response.status_code in (403, 429):
                if attempt == 0:
                    logger.warning(
                        "Rate limited (%d) for keyword '%s'. Retrying after 30s...",
                        response.status_code,
                        keyword,
                    )
                    time.sleep(30)
                    continue
                else:
                    logger.warning(
                        "Rate limit retry failed (%d) for keyword '%s'.",
                        response.status_code,
                        keyword,
                    )
                    return []

            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            cve_list: List[dict] = []
            if isinstance(vulnerabilities, list):
                for item in vulnerabilities:
                    if isinstance(item, dict):
                        if "cve" in item and isinstance(item["cve"], dict):
                            cve_list.append(item["cve"])
                        else:
                            cve_list.append(item)
            return cve_list
        except requests.RequestException as exc:
            logger.warning("Request error fetching CVEs for keyword '%s': %s", keyword, exc)
            return []
        except Exception as exc:
            logger.warning("Unexpected error fetching CVEs for keyword '%s': %s", keyword, exc)
            return []

    return []


def cve_to_document(cve: dict, keyword: str) -> Optional[Document]:
    """
    Convert a raw CVE dictionary to a RAG Document.
    Returns None if no description is found.
    """
    cve_id = cve.get("id", "")
    desc = _extract_description(cve.get("descriptions", []))
    if not desc:
        return None

    score, severity = _extract_cvss(cve.get("metrics", {}))
    published = cve.get("published", "")
    text = f"{cve_id} ({severity}, CVSS {score}): {desc}"
    metadata = {
        "source": "NVD_CVE",
        "cve_id": cve_id,
        "severity": severity,
        "cvss": float(score),
        "published": published,
        "matched_keyword": keyword,
    }
    return Document(page_content=text, metadata=metadata)


def ingest_nvd(
    keywords: Optional[List[str]] = None,
    kb: Optional[KnowledgeBase] = None,
    max_per_keyword: int = 200,
) -> int:
    """
    Ingest NVD CVE data for given keywords into the KnowledgeBase.
    Deduplicates across keywords and respects rate limits.
    """
    if kb is None:
        kb = KnowledgeBase()
    if keywords is None:
        keywords = AI_PACKAGES

    seen_cve_ids: Set[str] = set()
    total_added = 0

    for keyword in keywords:
        logger.info("Fetching CVEs for keyword: %s", keyword)
        cves = fetch_cves_for_keyword(keyword, max_per_keyword)
        docs: List[Document] = []
        for cve in cves:
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen_cve_ids:
                continue
            doc = cve_to_document(cve, keyword)
            if doc:
                docs.append(doc)
                seen_cve_ids.add(cve_id)

        if docs:
            total_added += kb.add_documents(docs)
        logger.info("  keyword=%s new_docs=%d", keyword, len(docs))
        time.sleep(DELAY_BETWEEN_CALLS)

    return total_added


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ingest AI package CVEs from NVD")
    parser.add_argument(
        "--keywords",
        nargs="*",
        default=None,
        help="override AI_PACKAGES",
    )
    parser.add_argument("--max-per-keyword", type=int, default=200)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    kb = KnowledgeBase()
    before = kb.count()
    added = ingest_nvd(args.keywords, kb, args.max_per_keyword)
    after = kb.count()
    print(f"Added {added} CVE documents")
    print(f"KB size: {before} -> {after}")
