"""
Feedback store module for AI Security Intelligence.
Stores False Positive (FP) and True Positive (TP) analyst feedback in a dedicated
ChromaDB collection ('guardian_feedback') for continuous improvement and retrieval.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Set

from src.rag.knowledge_base import KnowledgeBase
from src.rag.retriever import build_query_from_event

logger = logging.getLogger(__name__)

FEEDBACK_COLLECTION = os.getenv("RAG_FEEDBACK_COLLECTION", "guardian_feedback")
VALID_LABELS: Set[str] = {"true_positive", "false_positive", "uncertain"}


class FeedbackStore:
    """Store and retrieve analyst feedback for agent security alerts."""

    def __init__(self, kb: Optional[KnowledgeBase] = None) -> None:
        self.kb = kb or KnowledgeBase()

        client = getattr(self.kb, "client", None) or getattr(self.kb, "_client", None)
        if client is None:
            self.kb.initialize()
            client = getattr(self.kb, "client", None) or getattr(self.kb, "_client", None)

        self.client = client
        self.collection = self.client.get_or_create_collection(name=FEEDBACK_COLLECTION)
        logger.info(
            "Feedback collection ready: %s, count=%d",
            FEEDBACK_COLLECTION,
            self.collection.count(),
        )

    def _get_encoder(self) -> Any:
        """Get the embedding model instance from KnowledgeBase."""
        model = getattr(self.kb, "embedding_model", None)
        if isinstance(model, str):
            from src.rag.knowledge_base import _get_embedding_model

            return _get_embedding_model(model)
        if model is not None and hasattr(model, "encode"):
            return model
        from src.rag.knowledge_base import _get_embedding_model

        return _get_embedding_model("BAAI/bge-small-en-v1.5")

    def _encode(self, text: str, normalize: bool = False) -> List[float]:
        """Encode text to embedding vector."""
        encoder = self._get_encoder()
        try:
            if normalize:
                embedding = encoder.encode(text, normalize_embeddings=True)
            else:
                embedding = encoder.encode(text)
        except TypeError:
            embedding = encoder.encode(text)

        if hasattr(embedding, "tolist"):
            return embedding.tolist()
        return list(embedding)

    def record(
        self,
        alert_id: str,
        event: dict,
        label: str,
        notes: str = "",
        metadata_extra: Optional[dict] = None,
    ) -> str:
        """
        Record analyst feedback for an alert event.
        Raises ValueError if label is not in VALID_LABELS.
        """
        if label not in VALID_LABELS:
            raise ValueError(
                f"Invalid feedback label '{label}'. Must be one of: {sorted(VALID_LABELS)}"
            )

        query_text = build_query_from_event(event)
        doc_id = f"fb:{alert_id}:{uuid.uuid4().hex[:8]}"

        main_agent = event.get("main_agent") if isinstance(event.get("main_agent"), dict) else {}
        sub_agent = event.get("sub_agent") if isinstance(event.get("sub_agent"), dict) else {}
        action = event.get("action") if isinstance(event.get("action"), dict) else {}

        metadata: Dict[str, Any] = {
            "alert_id": alert_id,
            "label": label,
            "notes": str(notes)[:500],
            "timestamp": time.time(),
            "agent_name": str(main_agent.get("name", "")),
            "sub_agent_name": str(sub_agent.get("name", "")),
            "action_tool": str(action.get("tool", "")),
        }

        if metadata_extra and isinstance(metadata_extra, dict):
            metadata.update(metadata_extra)

        cleaned_metadata: Dict[str, Any] = {}
        for k, v in metadata.items():
            if isinstance(v, (str, int, float, bool)):
                cleaned_metadata[k] = v
            elif v is None:
                cleaned_metadata[k] = ""
            else:
                cleaned_metadata[k] = str(v)

        embedding = self._encode(query_text)

        self.collection.add(
            ids=[doc_id],
            documents=[query_text],
            embeddings=[embedding],
            metadatas=[cleaned_metadata],
        )

        logger.info("Recorded feedback %s for alert %s", label, alert_id)
        return doc_id

    def find_similar(self, event: dict, top_k: int = 3) -> List[dict]:
        """
        Find previously recorded feedback similar to the given event.
        Returns empty list if store is empty.
        """
        total_docs = self.collection.count()
        if total_docs == 0:
            return []

        query_text = build_query_from_event(event)
        embedding = self._encode(query_text, normalize=True)

        n_results = min(top_k, total_docs)
        if n_results <= 0:
            return []

        results = self.collection.query(
            query_embeddings=[embedding],
            n_results=n_results,
        )

        feedback_list: List[dict] = []
        if results and "documents" in results and results["documents"]:
            docs = results["documents"][0]
            metas = (
                results["metadatas"][0]
                if ("metadatas" in results and results["metadatas"])
                else [{}] * len(docs)
            )
            distances = (
                results["distances"][0]
                if ("distances" in results and results["distances"])
                else [0.0] * len(docs)
            )

            for text, meta, dist in zip(docs, metas, distances):
                meta = meta or {}
                feedback_list.append({
                    "alert_id": str(meta.get("alert_id", "")),
                    "label": str(meta.get("label", "")),
                    "notes": str(meta.get("notes", "")),
                    "timestamp": float(meta.get("timestamp", 0.0) or 0.0),
                    "text": text,
                    "distance": float(dist) if dist is not None else 0.0,
                })

        return feedback_list

    def stats(self) -> Dict[str, int]:
        """Return counts of recorded feedback by label and total."""
        counts = {
            "true_positive": 0,
            "false_positive": 0,
            "uncertain": 0,
            "total": 0,
        }

        data = self.collection.get(include=["metadatas"])
        metadatas = data.get("metadatas") or []

        for meta in metadatas:
            if isinstance(meta, dict):
                lbl = meta.get("label")
                if lbl in counts:
                    counts[lbl] += 1

        counts["total"] = len(metadatas)
        return counts

    def clear(self) -> None:
        """Delete the entire collection and recreate it."""
        client = getattr(self.kb, "client", None) or getattr(self.kb, "_client", None)
        if client is not None:
            try:
                client.delete_collection(name=FEEDBACK_COLLECTION)
            except Exception as exc:
                logger.warning("Error deleting feedback collection during clear: %s", exc)
            self.collection = client.get_or_create_collection(name=FEEDBACK_COLLECTION)
            logger.info("Feedback collection cleared and recreated.")


_default_store: Optional[FeedbackStore] = None


def get_feedback_store() -> FeedbackStore:
    """Return the module-level default FeedbackStore singleton."""
    global _default_store
    if _default_store is None:
        _default_store = FeedbackStore()
    return _default_store


def record_feedback(
    alert_id: str,
    event: dict,
    label: str,
    notes: str = "",
) -> str:
    """Convenience function to record feedback in the default FeedbackStore."""
    return get_feedback_store().record(alert_id, event, label, notes)


def find_similar_feedback(event: dict, top_k: int = 3) -> List[dict]:
    """Convenience function to find similar feedback in the default FeedbackStore."""
    return get_feedback_store().find_similar(event, top_k)


def get_feedback_stats() -> Dict[str, int]:
    """Convenience function to retrieve feedback stats from the default FeedbackStore."""
    return get_feedback_store().stats()
