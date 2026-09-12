"""
LLM-powered risk analyzer with RAG context retrieval.

Uses GPT-4 (or configured model) for risk scoring with reasoning and compliance mapping.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from dotenv import load_dotenv

from src.core.database import Database
from src.rag.knowledge_base import KnowledgeBase

load_dotenv()


class RiskAnalyzer:
    """Analyze agent/sub-agent risk using LLM + RAG context."""

    def __init__(
        self,
        db: Optional[Database] = None,
        kb: Optional[KnowledgeBase] = None,
        model: Optional[str] = None,
    ):
        self.db = db or Database()
        self.kb = kb or KnowledgeBase()
        self.model = model or os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError('OPENAI_API_KEY not set — required for LLM risk analysis')
            self._client = OpenAI(api_key=api_key)
        return self._client

    def analyze_agent(
        self,
        agent_id: int,
        subagent_id: Optional[int] = None,
    ) -> Dict:
        """Full risk analysis with RAG context, score, reasoning, and compliance mapping."""
        agent = self.db.get_agent_by_id(agent_id)
        if not agent:
            return {'error': f'agent {agent_id} not found'}

        if subagent_id:
            sub = self.db.get_subagent(subagent_id)
            label = sub['name'] if sub else f'subagent#{subagent_id}'
            actions = self.db.get_actions(subagent_id=subagent_id, limit=50)
            granted = (sub or {}).get('granted_permissions', [])
        else:
            label = agent['name']
            actions = self.db.get_actions(agent_id=agent_id, limit=50)
            granted = []

        unauth = [a for a in actions if not a.get('is_authorized')]
        action_summary = [
            f"{a['action']} → {a.get('target', '')} (authorized={a.get('is_authorized')})"
            for a in actions[:20]
        ]

        rag_queries = ' '.join(a['action'] for a in unauth[:5]) or label
        rag_context = self.kb.get_context_for_action(rag_queries, k=3)

        prompt = f"""You are a Shadow AI security analyst. Analyze this agent's risk.

Agent: {agent['name']} ({agent.get('agent_type', 'unknown')})
Sub-agent: {label if subagent_id else 'main agent'}
Granted permissions: {granted}
Recent actions:
{chr(10).join(action_summary) or 'None recorded'}

Unauthorized action count: {len(unauth)}

RAG Context:
{rag_context}

Respond in JSON with keys:
- score (0-100 integer)
- level (low|medium|high|critical)
- reasoning (2-3 sentences)
- compliance_violations (list of {{framework, article, description}})
- recommendations (list of strings)
"""

        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {'role': 'system', 'content': 'Respond only with valid JSON.'},
                    {'role': 'user', 'content': prompt},
                ],
                temperature=0.2,
                response_format={'type': 'json_object'},
            )
            result = json.loads(response.choices[0].message.content or '{}')
        except Exception as exc:
            # Fallback heuristic when LLM unavailable
            result = self._heuristic_analysis(unauth, granted, str(exc))

        score = float(result.get('score', 0))
        level = result.get('level', 'low')
        self.db.save_risk_score(
            agent_id,
            score,
            level,
            {
                'reasoning': result.get('reasoning', ''),
                'compliance_violations': result.get('compliance_violations', []),
                'llm_model': self.model,
                'unauthorized_count': len(unauth),
            },
            subagent_id=subagent_id,
        )

        return {
            'agent_id': agent_id,
            'subagent_id': subagent_id,
            'agent_name': agent['name'],
            'label': label,
            'score': score,
            'level': level,
            'reasoning': result.get('reasoning', ''),
            'compliance_violations': result.get('compliance_violations', []),
            'recommendations': result.get('recommendations', []),
            'rag_context_used': bool(rag_context),
        }

    def analyze_all(self) -> List[Dict]:
        results = []
        for agent in self.db.get_all_agents():
            results.append(self.analyze_agent(agent['id']))
            for sub in self.db.get_subagents(agent['id']):
                results.append(self.analyze_agent(agent['id'], sub['id']))
        return results

    @staticmethod
    def _heuristic_analysis(unauth: List, granted: List, error: str) -> Dict:
        score = min(100, len(unauth) * 15 + len(granted) * 2)
        level = 'critical' if score >= 75 else 'high' if score >= 50 else 'medium' if score >= 25 else 'low'
        violations = []
        for a in unauth:
            act = a.get('action', '')
            if 'database' in act:
                violations.append({'framework': 'GDPR', 'article': 'Art.32', 'description': 'Unauthorized DB access'})
            if 'shell' in act or 'execute' in act:
                violations.append({'framework': 'SOC2', 'article': 'CC6.1', 'description': 'Unauthorized execution'})
        return {
            'score': score,
            'level': level,
            'reasoning': f'Heuristic fallback (LLM unavailable: {error[:80]})',
            'compliance_violations': violations,
            'recommendations': ['Review unauthorized actions', 'Restrict sub-agent permissions'],
        }
