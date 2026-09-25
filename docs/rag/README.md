# Guardian RAG Layer Integration Guide

## 1. What the RAG layer does
The Guardian RAG layer enriches live AI agent telemetry with contextual threat intelligence, known vulnerabilities, and past analyst feedback to detect malicious actions and policy violations. It maps agent actions to MITRE attack patterns and library CVEs, delivering prioritized remediation guidance directly to downstream LLM risk analyzers.

## 2. Architecture
- **Vector Store**: ChromaDB persistent store located at `data/vectorstore/`.
- **Collections**:
  - `guardian_threats`: Threat intelligence and vulnerability patterns (3,305 documents).
  - `guardian_feedback`: Historical True Positive (TP) and False Positive (FP) analyst labels.
- **Embedding Model**: `BAAI/bge-small-en-v1.5` running locally via SentenceTransformers (offline, zero external API costs).
- **Service API**: Flask REST API service listening on `http://127.0.0.1:5001` with Blueprint prefix `/api/v1/rag`.

## 3. Data sources
| Source | Count | Purpose |
| :--- | :--- | :--- |
| `MITRE_ATLAS` | 170 | AI-specific adversarial tactics and techniques (YAML matrix) |
| `MITRE_ATTACK` | 858 | General enterprise cyberattack patterns and techniques |
| `CISA_KEV` | 1,709 | Actively exploited real-world software vulnerabilities |
| `NVD_CVE` | 558 | Vulnerabilities filtered specifically to AI/ML libraries |

## 4. How Person C calls it

### Example 1 — Query Context for an Agent Event
**Endpoint**: `POST http://127.0.0.1:5001/api/v1/rag/query`

**Request Body**:
```json
{
  "event": {
    "main_agent": {"name": "ChatGPT", "framework": "browser", "pid": 1234},
    "sub_agent": {"name": "code_runner", "role": "execution"},
    "action": {"type": "tool_call", "tool": "execute:code", "target": "sandbox.py", "status": "started"},
    "permissions_granted": ["read:files"],
    "permissions_used": ["read:files", "execute:code"]
  },
  "top_k": 5
}
```

**Response Body**:
```json
{
  "query": "AI agent ChatGPT (browser) using code_runner performed execute:code on sandbox.py",
  "similar_threats": [
    {
      "source": "MITRE_ATLAS",
      "id": "AML.T0051",
      "text": "LLM Prompt Injection. Adversaries may craft malicious inputs...",
      "distance": 0.42
    }
  ],
  "related_cves": [
    {
      "cve_id": "CVE-2024-12345",
      "severity": "CRITICAL",
      "cvss": 9.8,
      "text": "CVE-2024-12345 (CRITICAL, CVSS 9.8): Remote code execution in..."
    }
  ],
  "remediation_hint": "CRITICAL: patch affected package immediately (CVSS >= 9.0).",
  "total_retrieved": 2,
  "similar_feedback": [
    {
      "label": "false_positive",
      "notes": "Benign developer code execution in sandbox",
      "distance": 0.15
    }
  ]
}
```

### Example 2 — Record Analyst Feedback
**Endpoint**: `POST http://127.0.0.1:5001/api/v1/rag/feedback`

**Request Body**:
```json
{
  "alert_id": "alert-2026-0924-001",
  "event": {
    "main_agent": {"name": "ChatGPT"},
    "action": {"tool": "execute:code"}
  },
  "label": "true_positive",
  "notes": "Confirmed prompt injection exploit attempted."
}
```

**Response Body**:
```json
{
  "status": "ok",
  "feedback_id": "fb:alert-2026-0924-001:a1b2c3d4"
}
```

### Example 3 — System Statistics
**Endpoint**: `GET http://127.0.0.1:5001/api/v1/rag/stats`

**Response Body**:
```json
{
  "total_documents": 3305,
  "feedback_counts": {
    "true_positive": 12,
    "false_positive": 4,
    "uncertain": 1,
    "total": 17
  }
}
```

## 5. Python example for Person C
Copy-paste integration snippet:

```python
import requests

event_dict = {
    "main_agent": {"name": "ChatGPT", "framework": "browser"},
    "sub_agent": {"name": "code_runner"},
    "action": {"tool": "execute:code", "target": "sandbox.py"},
}

response = requests.post(
    "http://127.0.0.1:5001/api/v1/rag/query",
    json={"event": event_dict, "top_k": 5},
    timeout=10,
)
rag_context = response.json()

# Pass rag_context["remediation_hint"] and rag_context["similar_threats"]
# into the LLM prompt.
remediation_hint = rag_context.get("remediation_hint", "")
threats = rag_context.get("similar_threats", [])
cves = rag_context.get("related_cves", [])
feedback = rag_context.get("similar_feedback", [])
```

## 6. How to start the server
Run the Flask API server locally:
```powershell
.venv-rag\Scripts\python.exe -m src.rag.api
```
The server will start at `http://127.0.0.1:5001`.

## 7. How to re-ingest data
To re-ingest the threat intelligence and vulnerability feeds:
```powershell
# Ingest MITRE ATLAS (YAML), ATT&CK (STIX JSON), and CISA KEV (CSV)
.venv-rag\Scripts\python.exe -m src.rag.ingest_cti --data-dir data/cti

# Ingest AI package CVEs from NVD API 2.0
.venv-rag\Scripts\python.exe -m src.rag.ingest_cve --max-per-keyword 200
```

## 8. Known limitations
- **No authentication**: Designed for local / internal network inter-service communication (localhost).
- **Rate limiting**: Enforced at 100 requests per minute per IP address.
- **Language**: Embedding model is English-only.
- **Continuous Learning**: Recorded feedback in `guardian_feedback` is searched for similar historical context, but not used for fine-tuning or auto-retraining.

## 9. Test suite
Run the full RAG test suite (29 tests):
```powershell
.venv-rag\Scripts\python.exe -m pytest tests/rag/ -v
```
Expect all 29 tests to pass across API, feedback, ingestion, retriever, and end-to-end integration modules.
