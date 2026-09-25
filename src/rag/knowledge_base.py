"""
RAG Knowledge Base for AI Security Intelligence using ChromaDB and SentenceTransformers.
Stores threat intelligence, compliance policies, and security incident patterns.
"""

from __future__ import annotations

import os
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

import chromadb
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

# Module-level cache for lazy loaded embedding model
_EMBEDDING_MODEL_CACHE: Optional[SentenceTransformer] = None
_EMBEDDING_MODEL_NAME_CACHE: Optional[str] = None


@dataclass
class Document:
    """Document representation for RAG storage and retrieval."""
    page_content: str
    metadata: dict = field(default_factory=dict)


def _get_embedding_model(model_name: str) -> SentenceTransformer:
    """Lazily load and cache the SentenceTransformer embedding model."""
    global _EMBEDDING_MODEL_CACHE, _EMBEDDING_MODEL_NAME_CACHE

    if _EMBEDDING_MODEL_CACHE is not None and _EMBEDDING_MODEL_NAME_CACHE == model_name:
        return _EMBEDDING_MODEL_CACHE

    try:
        logger.info("Loading embedding model: %s", model_name)
        model = SentenceTransformer(model_name)
        _EMBEDDING_MODEL_CACHE = model
        _EMBEDDING_MODEL_NAME_CACHE = model_name
        return model
    except Exception as exc:
        raise RuntimeError(
            f"Failed to load embedding model '{model_name}'. "
            f"Ensure network connectivity or a valid local model cache: {exc}"
        ) from exc


class KnowledgeBase:
    """
    RAG Knowledge Base for AI Security Intelligence.
    Provides vector storage, semantic search, and context formatting for agents.
    """

    def __init__(
        self,
        persist_directory: str = "./data/vectorstore",
        embedding_model: str = "BAAI/bge-small-en-v1.5",
    ):
        # Allow override via environment variables if default parameter values are passed
        env_persist = os.getenv("RAG_VECTOR_STORE_PATH")
        if env_persist and persist_directory == "./data/vectorstore":
            self.persist_directory = env_persist
        else:
            self.persist_directory = persist_directory

        env_model = os.getenv("RAG_EMBEDDING_MODEL")
        if env_model and embedding_model == "BAAI/bge-small-en-v1.5":
            self.embedding_model = env_model
        else:
            self.embedding_model = embedding_model

        self.collection_name = os.getenv("RAG_COLLECTION_NAME", "guardian_threats")
        self.client: Optional[chromadb.PersistentClient] = None
        self.collection: Optional[chromadb.Collection] = None

        self.initialize()

    def initialize(self) -> None:
        """Initialize or load existing vector store and seed if empty."""
        try:
            os.makedirs(self.persist_directory, exist_ok=True)
            test_file = os.path.join(self.persist_directory, ".write_test")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(test_file)
        except Exception as exc:
            raise RuntimeError(
                f"ChromaDB persist directory '{self.persist_directory}' is not writable: {exc}"
            ) from exc

        try:
            self.client = chromadb.PersistentClient(path=self.persist_directory)
            self.collection = self.client.get_or_create_collection(name=self.collection_name)
        except Exception as exc:
            raise RuntimeError(f"Failed to initialize ChromaDB client: {exc}") from exc

        if self.count() == 0:
            logger.info("Initializing knowledge base with default seed data...")
            self._ingest_default_data()

    def _get_default_documents(self) -> List[Document]:
        """Return the 10 default security and compliance seed documents."""
        return [
            # Threat Intelligence
            Document(
                page_content="""SQL Injection: Attacker injects malicious SQL queries through input fields.
Impact: Data theft, data manipulation, authentication bypass.
Prevention: Parameterized queries, input validation, WAF.
Detection: Monitor for suspicious SQL keywords in inputs.
Risk Level: CRITICAL""",
                metadata={"category": "threat_intel", "type": "sql_injection", "severity": "critical", "source": "threat_intel"},
            ),
            Document(
                page_content="""Data Exfiltration: Unauthorized transfer of sensitive data.
Indicators: Large file reads, unusual API calls, data transfers to unknown IPs.
Impact: Loss of intellectual property, customer data, trade secrets.
Prevention: DLP, encryption, access controls, monitoring.
Risk Level: CRITICAL""",
                metadata={"category": "threat_intel", "type": "data_exfiltration", "severity": "critical", "source": "threat_intel"},
            ),
            Document(
                page_content="""Privilege Escalation: Agent gains higher permissions than intended.
Indicators: Access to system files, admin commands, security bypass.
Impact: Full system compromise, data access, lateral movement.
Prevention: Least privilege, RBAC, audit logging, monitoring.
Risk Level: HIGH""",
                metadata={"category": "threat_intel", "type": "privilege_escalation", "severity": "high", "source": "threat_intel"},
            ),
            Document(
                page_content="""Prompt Injection: Malicious instructions in prompts that cause agents to act inappropriately.
Indicators: Unexpected behavior, ignoring safety guidelines, executing unauthorized commands.
Impact: Data breach, system compromise, reputational damage.
Prevention: Input sanitization, prompt validation, monitoring.
Risk Level: HIGH""",
                metadata={"category": "threat_intel", "type": "prompt_injection", "severity": "high", "source": "threat_intel"},
            ),
            # Compliance Policies
            Document(
                page_content="""GDPR Article 32: Security of Processing.
Requirements: Implement appropriate technical measures to ensure security.
Includes: Encryption, pseudonymization, confidentiality, integrity, availability.
Penalty: Up to €20M or 4% of global turnover.""",
                metadata={"category": "compliance", "type": "gdpr", "article": "32", "source": "GDPR"},
            ),
            Document(
                page_content="""SOC2 CC6.1: Logical Access Controls.
Requirements: Implement logical access controls to protect against unauthorized access.
Includes: Authentication, authorization, segregation of duties.
Audit: Demonstrate access control effectiveness annually.""",
                metadata={"category": "compliance", "type": "soc2", "control": "CC6.1", "source": "SOC2"},
            ),
            Document(
                page_content="""HIPAA Security Rule: Technical Safeguards.
Requirements: Protect electronic protected health information (ePHI).
Includes: Access controls, audit controls, integrity controls, transmission security.
Penalty: Up to $1.5M per violation category per year.""",
                metadata={"category": "compliance", "type": "hipaa", "source": "HIPAA"},
            ),
            # Suspicious Patterns
            Document(
                page_content="""Suspicious Pattern: AI Agent accessing sensitive system files.
Pattern: Agent reading /etc/passwd, /etc/shadow, or Windows system directories.
Risk: HIGH - Potential privilege escalation or system compromise.
Response: Block action, isolate agent, investigate immediately.""",
                metadata={"category": "patterns", "type": "suspicious", "risk": "high", "source": "patterns"},
            ),
            Document(
                page_content="""Suspicious Pattern: AI Agent executing system commands.
Pattern: Agent executing commands like rm -rf, chmod, sudo, or systemctl.
Risk: CRITICAL - Potential system damage or compromise.
Response: Immediate block, notify security team, isolate system.""",
                metadata={"category": "patterns", "type": "suspicious", "risk": "critical", "source": "patterns"},
            ),
            Document(
                page_content="""AI Agent Tool Usage: Web Search.
Normal: Searching for information, research, data collection.
Suspicious: Excessive searches, searches for exploit code, defense evasion techniques.
Risk: MEDIUM - May indicate reconnaissance for attacks.""",
                metadata={"category": "patterns", "type": "tool_usage", "tool": "web_search", "source": "patterns"},
            ),
        ]

    def _ingest_default_data(self) -> None:
        """Ingest default security and compliance seed documents."""
        default_docs = self._get_default_documents()
        self.add_documents(default_docs)
        logger.info("Successfully ingested %d default seed documents.", len(default_docs))

    def add_documents(self, documents: List[Document]) -> int:
        """Add a list of Document objects to the knowledge base."""
        if not documents:
            return 0

        if self.collection is None:
            self.initialize()

        texts = [doc.page_content for doc in documents]
        cleaned_metadatas = []
        for doc in documents:
            meta = doc.metadata or {}
            cleaned = {}
            for k, v in meta.items():
                if isinstance(v, (str, int, float, bool)):
                    cleaned[k] = v
                else:
                    cleaned[k] = json.dumps(v)
            cleaned_metadatas.append(cleaned)

        model = _get_embedding_model(self.embedding_model)
        embeddings = model.encode(texts, show_progress_bar=False).tolist()

        ids = [f"doc_{uuid.uuid4().hex}" for _ in documents]

        self.collection.add(
            ids=ids,
            documents=texts,
            metadatas=cleaned_metadatas,
            embeddings=embeddings,
        )
        return len(documents)

    def add_text(self, text: str, metadata: dict = None) -> int:
        """Add raw text directly to the knowledge base."""
        doc = Document(page_content=text, metadata=metadata or {})
        return self.add_documents([doc])

    def similarity_search(self, query: str, k: int = 5) -> List[Document]:
        """Search knowledge base for documents semantically similar to the query."""
        if self.collection is None:
            self.initialize()

        total_count = self.count()
        if total_count == 0 or k <= 0:
            return []

        model = _get_embedding_model(self.embedding_model)
        query_embedding = model.encode([query], show_progress_bar=False).tolist()

        n_results = min(k, total_count)
        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=n_results,
        )

        documents: List[Document] = []
        if results and "documents" in results and results["documents"]:
            retrieved_texts = results["documents"][0]
            retrieved_metas = (
                results["metadatas"][0]
                if ("metadatas" in results and results["metadatas"])
                else [{}] * len(retrieved_texts)
            )

            for text, meta in zip(retrieved_texts, retrieved_metas):
                documents.append(Document(page_content=text, metadata=meta or {}))

        return documents

    def get_context_for_action(self, query: str, k: int = 3) -> str:
        """
        Retrieve formatted context string for an action query.
        Returns empty string if no relevant documents found.
        """
        docs = self.similarity_search(query, k=k)
        if not docs:
            return ""

        context_parts = []
        for i, doc in enumerate(docs, start=1):
            source = (
                doc.metadata.get("source")
                or doc.metadata.get("category")
                or doc.metadata.get("type")
                or "unknown"
            )
            text = doc.page_content.strip()
            context_parts.append(f"[{i}] (source={source}) {text}")

        return "\n".join(context_parts)

    def count(self) -> int:
        """Return the total number of documents in the collection."""
        if self.collection is None:
            return 0
        return self.collection.count()

    def reset(self) -> None:
        """Clear all documents from the collection."""
        if self.client is not None and self.collection_name:
            try:
                self.client.delete_collection(self.collection_name)
            except Exception as exc:
                logger.warning("Error deleting collection during reset: %s", exc)
            self.collection = self.client.get_or_create_collection(name=self.collection_name)
            logger.info("Knowledge base collection '%s' reset to 0 documents.", self.collection_name)