# src/rag/knowledge_base.py
# RAG Knowledge Base with ChromaDB

import os
import json
from typing import List, Dict, Optional, Any
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import Chroma
from langchain.schema import Document
from langchain.document_loaders import TextLoader, CSVLoader, JSONLoader

class KnowledgeBase:
    """
    RAG Knowledge Base for AI Security Intelligence
    Stores threat intelligence, compliance policies, past incidents
    """
    
    def __init__(
        self,
        persist_directory: str = "./data/knowledge_base",
        embedding_model: str = "text-embedding-ada-002"
    ):
        self.persist_directory = persist_directory
        self.embeddings = OpenAIEmbeddings(model=embedding_model)
        self.vector_store = None
        
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
        
        self.initialize()
    
    def initialize(self):
        """Initialize or load existing vector store"""
        os.makedirs(self.persist_directory, exist_ok=True)
        
        if os.path.exists(os.path.join(self.persist_directory, "chroma.sqlite3")):
            try:
                self.vector_store = Chroma(
                    persist_directory=self.persist_directory,
                    embedding_function=self.embeddings
                )
                count = self.vector_store._collection.count()
                print(f"✅ Loaded knowledge base with {count} documents")
            except Exception as e:
                print(f"⚠️ Could not load existing knowledge base: {e}")
                self._create_new()
        else:
            self._create_new()
    
    def _create_new(self):
        """Create new knowledge base with default data"""
        self.vector_store = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=self.embeddings
        )
        self._ingest_default_data()
        self.vector_store.persist()
        print("✅ Created new knowledge base")
    
    def _ingest_default_data(self):
        """Ingest default security data"""
        default_documents = [
            # Threat Intelligence
            Document(
                page_content="""
                SQL Injection: Attacker injects malicious SQL queries through input fields.
                Impact: Data theft, data manipulation, authentication bypass.
                Prevention: Parameterized queries, input validation, WAF.
                Detection: Monitor for suspicious SQL keywords in inputs.
                Risk Level: CRITICAL
                """,
                metadata={"category": "threat_intel", "type": "sql_injection", "severity": "critical"}
            ),
            Document(
                page_content="""
                Data Exfiltration: Unauthorized transfer of sensitive data.
                Indicators: Large file reads, unusual API calls, data transfers to unknown IPs.
                Impact: Loss of intellectual property, customer data, trade secrets.
                Prevention: DLP, encryption, access controls, monitoring.
                Risk Level: CRITICAL
                """,
                metadata={"category": "threat_intel", "type": "data_exfiltration", "severity": "critical"}
            ),
            Document(
                page_content="""
                Privilege Escalation: Agent gains higher permissions than intended.
                Indicators: Access to system files, admin commands, security bypass.
                Impact: Full system compromise, data access, lateral movement.
                Prevention: Least privilege, RBAC, audit logging, monitoring.
                Risk Level: HIGH
                """,
                metadata={"category": "threat_intel", "type": "privilege_escalation", "severity": "high"}
            ),
            Document(
                page_content="""
                Prompt Injection: Malicious instructions in prompts that cause agents to act inappropriately.
                Indicators: Unexpected behavior, ignoring safety guidelines, executing unauthorized commands.
                Impact: Data breach, system compromise, reputational damage.
                Prevention: Input sanitization, prompt validation, monitoring.
                Risk Level: HIGH
                """,
                metadata={"category": "threat_intel", "type": "prompt_injection", "severity": "high"}
            ),
            # Compliance Policies
            Document(
                page_content="""
                GDPR Article 32: Security of Processing.
                Requirements: Implement appropriate technical measures to ensure security.
                Includes: Encryption, pseudonymization, confidentiality, integrity, availability.
                Penalty: Up to €20M or 4% of global turnover.
                """,
                metadata={"category": "compliance", "type": "gdpr", "article": "32"}
            ),
            Document(
                page_content="""
                SOC2 CC6.1: Logical Access Controls.
                Requirements: Implement logical access controls to protect against unauthorized access.
                Includes: Authentication, authorization, segregation of duties.
                Audit: Demonstrate access control effectiveness annually.
                """,
                metadata={"category": "compliance", "type": "soc2", "control": "CC6.1"}
            ),
            Document(
                page_content="""
                HIPAA Security Rule: Technical Safeguards.
                Requirements: Protect electronic protected health information (ePHI).
                Includes: Access controls, audit controls, integrity controls, transmission security.
                Penalty: Up to $1.5M per violation category per year.
                """,
                metadata={"category": "compliance", "type": "hipaa"}
            ),
            # Suspicious Patterns
            Document(
                page_content="""
                Suspicious Pattern: AI Agent accessing sensitive system files.
                Pattern: Agent reading /etc/passwd, /etc/shadow, or Windows system directories.
                Risk: HIGH - Potential privilege escalation or system compromise.
                Response: Block action, isolate agent, investigate immediately.
                """,
                metadata={"category": "patterns", "type": "suspicious", "risk": "high"}
            ),
            Document(
                page_content="""
                Suspicious Pattern: AI Agent executing system commands.
                Pattern: Agent executing commands like rm -rf, chmod, sudo, or systemctl.
                Risk: CRITICAL - Potential system damage or compromise.
                Response: Immediate block, notify security team, isolate system.
                """,
                metadata={"category": "patterns", "type": "suspicious", "risk": "critical"}
            ),
            Document(
                page_content="""
                AI Agent Tool Usage: Web Search.
                Normal: Searching for information, research, data collection.
                Suspicious: Excessive searches, searches for exploit code, defense evasion techniques.
                Risk: MEDIUM - May indicate reconnaissance for attacks.
                """,
                metadata={"category": "patterns", "type": "tool_usage", "tool": "web_search"}
            )
        ]
        
        self.add_documents(default_documents)
    
    def add_documents(self, documents: List[Document]) -> int:
        """Add documents to knowledge base"""
        if not documents:
            return 0
        
        chunks = self.text_splitter.split_documents(documents)
        
        if self.vector_store:
            self.vector_store.add_documents(chunks)
        else:
            self.vector_store = Chroma.from_documents(
                documents=chunks,
                embedding=self.embeddings,
                persist_directory=self.persist_directory
            )
        
        self.vector_store.persist()
        return len(chunks)
    
    def add_text(self, text: str, metadata: Dict = None) -> int:
        """Add text directly to knowledge base"""
        doc = Document(page_content=text, metadata=metadata or {})
        return self.add_documents([doc])
    
    def similarity_search(
        self, 
        query: str, 
        k: int = 5,
       