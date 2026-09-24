# KnowledgeBase Attribute Inspection:
# - ChromaDB collection attribute: kb.collection (chromadb.Collection, initialized via kb.initialize() at line 78 & 97)
# - Embedding model attribute: kb.embedding_model (string name e.g. 'BAAI/bge-small-en-v1.5' at line 72-74; resolved via _get_embedding_model() at line 240)
# - How embeddings are computed: model.encode([query], show_progress_bar=False).tolist() (line 241; normalize_embeddings is not set, defaulting to False)

"""
Retriever module for AI Security Intelligence Knowledge Base.
Constructs natural language queries from agent events, retrieves similar threats
and CVEs from the Knowledge Base using per-source filtered retrieval, caches queries,
and formats context for LLMs.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from src.rag.knowledge_base import Document, KnowledgeBase

logger = logging.getLogger(__name__)

# In-memory query cache: (query, top_k) -> context_dict
_QUERY_CACHE: OrderedDict[Tuple[str, int], Dict[str, Any]] = OrderedDict()
MAX_CACHE_SIZE = 100

_DEFAULT_KB: Optional[KnowledgeBase] = None


def _get_default_kb() -> KnowledgeBase:
    """Lazily instantiate and return the module-level default KnowledgeBase."""
    global _DEFAULT_KB
    if _DEFAULT_KB is None:
        _DEFAULT_KB = KnowledgeBase()
    return _DEFAULT_KB


def _get_encoder(kb: KnowledgeBase) -> Any:
    """Get the embedding model instance from KnowledgeBase."""
    model = getattr(kb, "embedding_model", None)
    if isinstance(model, str):
        from src.rag.knowledge_base import _get_embedding_model

        return _get_embedding_model(model)
    if model is not None and hasattr(model, "encode"):
        return model
    from src.rag.knowledge_base import _get_embedding_model

    return _get_embedding_model("BAAI/bge-small-en-v1.5")


def build_query_from_event(event: dict) -> str:
    """
    Build a natural language search query from an agent event dictionary.
    Handles missing fields gracefully and returns a default query if empty.
    """
    if not isinstance(event, dict) or not event:
        return "suspicious AI agent activity"

    main_agent = event.get("main_agent") if isinstance(event.get("main_agent"), dict) else {}
    sub_agent = event.get("sub_agent") if isinstance(event.get("sub_agent"), dict) else {}
    action = event.get("action") if isinstance(event.get("action"), dict) else {}

    parts: List[str] = []

    agent_name = str(main_agent.get("name", "")).strip()
    framework = str(main_agent.get("framework", "")).strip()
    sub_name = str(sub_agent.get("name", "")).strip()
    tool = str(action.get("tool") or action.get("type", "")).strip()
    target = str(action.get("target", "")).strip()

    if agent_name:
        if framework:
            parts.append(f"AI agent {agent_name} ({framework})")
        else:
            parts.append(f"AI agent {agent_name}")
    elif framework:
        parts.append(f"AI agent ({framework})")

    if sub_name:
        parts.append(f"using {sub_name}")

    if tool:
        parts.append(f"performed {tool}")

    if target:
        parts.append(f"on {target}")

    query = " ".join(parts).strip()
    return query if query else "suspicious AI agent activity"


def _compute_remediation_hint(
    related_cves: List[Dict[str, Any]],
    similar_threats: List[Dict[str, Any]],
) -> str:
    """Compute remediation hint based on severity and source priority."""
    # 1. Any related CVE with CVSS >= 9.0
    for cve in related_cves:
        try:
            if float(cve.get("cvss", 0.0)) >= 9.0:
                return "CRITICAL: patch affected package immediately (CVSS >= 9.0)."
        except (ValueError, TypeError):
            continue

    # 2. Any source == CISA_KEV in CVEs or threats
    for cve in related_cves:
        if cve.get("source") == "CISA_KEV":
            return "Known exploited vulnerability. Escalate to security team."

    sources = {t.get("source") for t in similar_threats}

    # 3. MITRE_ATLAS
    if "MITRE_ATLAS" in sources:
        return "AI-specific adversarial technique detected. Review agent permissions."

    # 4. MITRE_ATTACK
    if "MITRE_ATTACK" in sources:
        return "General attack pattern matched. Investigate the action."

    # 5. Default
    return "No high-confidence match found in threat intelligence."


def retrieve_context(
    event: dict,
    top_k: int = 5,
    kb: Optional[KnowledgeBase] = None,
) -> Dict[str, Any]:
    """
    Retrieve threat intelligence and CVE context for an agent event using
    two separate metadata-filtered queries (techniques vs vulnerabilities).
    Applies remediation hints and caches responses in memory.
    """
    if kb is None:
        kb = _get_default_kb()

    query = build_query_from_event(event)
    cache_key = (query, top_k)

    if cache_key in _QUERY_CACHE:
        logger.info("Cache hit for query: '%s' (top_k=%d)", query, top_k)
        _QUERY_CACHE.move_to_end(cache_key)
        return _QUERY_CACHE[cache_key]

    if kb.collection is None:
        kb.initialize()
    collection = kb.collection

    total_count = collection.count() if collection is not None else 0
    if total_count == 0 or top_k <= 0 or collection is None:
        result = {
            "query": query,
            "similar_threats": [],
            "related_cves": [],
            "remediation_hint": "No high-confidence match found in threat intelligence.",
            "total_retrieved": 0,
        }
        if len(_QUERY_CACHE) >= MAX_CACHE_SIZE:
            _QUERY_CACHE.popitem(last=False)
        _QUERY_CACHE[cache_key] = result
        return result

    encoder = _get_encoder(kb)
    query_embedding = encoder.encode([query], show_progress_bar=False).tolist()

    n_results = min(top_k, total_count)

    # 1. Query techniques (MITRE_ATLAS, MITRE_ATTACK)
    try:
        threat_results = collection.query(
            query_embeddings=query_embedding,
            n_results=n_results,
            where={"source": {"$in": ["MITRE_ATLAS", "MITRE_ATTACK"]}},
        )
    except Exception as exc:
        logger.warning("Error querying threat techniques: %s", exc)
        threat_results = {}

    # 2. Query vulnerabilities (CISA_KEV, NVD_CVE)
    try:
        cve_results = collection.query(
            query_embeddings=query_embedding,
            n_results=n_results,
            where={"source": {"$in": ["CISA_KEV", "NVD_CVE"]}},
        )
    except Exception as exc:
        logger.warning("Error querying vulnerabilities: %s", exc)
        cve_results = {}

    similar_threats: List[Dict[str, Any]] = []
    if threat_results and "documents" in threat_results and threat_results["documents"]:
        docs = threat_results["documents"][0]
        metas = (
            threat_results["metadatas"][0]
            if ("metadatas" in threat_results and threat_results["metadatas"])
            else [{}] * len(docs)
        )
        distances = (
            threat_results["distances"][0]
            if ("distances" in threat_results and threat_results["distances"])
            else [0.0] * len(docs)
        )
        for text, meta, dist in zip(docs, metas, distances):
            meta = meta or {}
            source = meta.get("source", "")
            threat_id = meta.get("technique_id") or meta.get("id") or ""
            similar_threats.append({
                "source": source,
                "id": str(threat_id),
                "text": text,
                "distance": float(dist) if dist is not None else 0.0,
            })

    raw_cves: List[Dict[str, Any]] = []
    if cve_results and "documents" in cve_results and cve_results["documents"]:
        docs = cve_results["documents"][0]
        metas = (
            cve_results["metadatas"][0]
            if ("metadatas" in cve_results and cve_results["metadatas"])
            else [{}] * len(docs)
        )
        for text, meta in zip(docs, metas):
            meta = meta or {}
            source = meta.get("source", "")
            cve_id = str(meta.get("cve_id") or "")
            severity = str(meta.get("severity") or "UNKNOWN")
            try:
                cvss_val = float(meta.get("cvss", 0.0))
            except (ValueError, TypeError):
                cvss_val = 0.0
            raw_cves.append({
                "source": source,
                "cve_id": cve_id,
                "severity": severity,
                "cvss": cvss_val,
                "text": text,
            })

    similar_threats = similar_threats[:top_k]
    raw_cves = raw_cves[:top_k]

    remediation_hint = _compute_remediation_hint(raw_cves, similar_threats)

    cleaned_cves = [
        {
            "cve_id": c["cve_id"],
            "severity": c["severity"],
            "cvss": c["cvss"],
            "text": c["text"],
        }
        for c in raw_cves
    ]

    result = {
        "query": query,
        "similar_threats": similar_threats,
        "related_cves": cleaned_cves,
        "remediation_hint": remediation_hint,
        "total_retrieved": len(similar_threats) + len(cleaned_cves),
    }

    if len(_QUERY_CACHE) >= MAX_CACHE_SIZE:
        _QUERY_CACHE.popitem(last=False)
    _QUERY_CACHE[cache_key] = result
    logger.info("Cached result for query: '%s' (top_k=%d)", query, top_k)

    return result


def format_for_llm(context: dict) -> str:
    """
    Format the retrieved context dictionary into a string suitable for LLM prompts.
    Returns empty string if context is empty.
    """
    if not isinstance(context, dict) or not context:
        return ""

    similar_threats = context.get("similar_threats", [])
    related_cves = context.get("related_cves", [])
    remediation_hint = context.get("remediation_hint", "")

    if not similar_threats and not related_cves and not remediation_hint:
        return ""

    sections: List[str] = []

    if similar_threats:
        lines = ["Similar threats:"]
        for i, threat in enumerate(similar_threats, start=1):
            src = threat.get("source", "")
            t_id = threat.get("id", "")
            text = threat.get("text", "").strip()
            id_info = f"({src}, {t_id}) " if (src and t_id) else f"({src or t_id}) " if (src or t_id) else ""
            lines.append(f"[{i}] {id_info}{text}")
        sections.append("\n".join(lines))

    if related_cves:
        lines = ["Related CVEs:"]
        for i, cve in enumerate(related_cves, start=1):
            cve_id = cve.get("cve_id", "")
            severity = cve.get("severity", "UNKNOWN")
            cvss = cve.get("cvss", 0.0)
            text = cve.get("text", "").strip()
            if text.startswith(f"{cve_id} ("):
                lines.append(f"[{i}] {text}")
            else:
                lines.append(f"[{i}] {cve_id} ({severity}, CVSS {cvss}): {text}")
        sections.append("\n".join(lines))

    if remediation_hint:
        sections.append(f"Remediation hint: {remediation_hint}")

    return "\n\n".join(sections)
