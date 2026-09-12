"""
Natural language interface for querying the Guardian Agent platform.

Parses user queries with GPT-4, executes database lookups, and generates NL responses.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from src.core.database import Database
from src.rag.knowledge_base import KnowledgeBase

load_dotenv()

INTENT_SCHEMA = {
    'intent': 'one of: list_agents, list_subagents, list_alerts, list_actions, risk_summary, compliance_search, general',
    'agent_name': 'optional agent name filter',
    'subagent_name': 'optional sub-agent name filter',
    'search_query': 'optional free-text for RAG/compliance search',
    'limit': 'optional integer limit default 10',
}


class NaturalLanguageInterface:
    """Parse natural language queries and respond with platform data."""

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
                raise ValueError('OPENAI_API_KEY not set')
            self._client = OpenAI(api_key=api_key)
        return self._client

    def parse_query(self, user_query: str) -> Dict:
        """Use GPT-4 to parse user intent into structured query plan."""
        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        'role': 'system',
                        'content': (
                            'Parse Guardian Agent security queries into JSON. '
                            f'Schema: {json.dumps(INTENT_SCHEMA)}'
                        ),
                    },
                    {'role': 'user', 'content': user_query},
                ],
                temperature=0,
                response_format={'type': 'json_object'},
            )
            return json.loads(response.choices[0].message.content or '{}')
        except Exception:
            return self._rule_based_parse(user_query)

    def execute_query(self, parsed: Dict) -> Dict:
        """Execute parsed intent against the database."""
        intent = parsed.get('intent', 'general')
        agent_name = parsed.get('agent_name')
        limit = int(parsed.get('limit') or 10)

        agent = self.db.get_agent_by_name(agent_name) if agent_name else None
        agent_id = agent['id'] if agent else None

        if intent == 'list_agents':
            return {'intent': intent, 'data': self.db.get_all_agents()[:limit]}

        if intent == 'list_subagents':
            if not agent_id:
                all_subs = []
                for a in self.db.get_all_agents()[:limit]:
                    all_subs.extend(self.db.get_subagents(a['id']))
                return {'intent': intent, 'data': all_subs}
            return {'intent': intent, 'data': self.db.get_subagents(agent_id)}

        if intent == 'list_alerts':
            return {
                'intent': intent,
                'data': self.db.get_alerts(unacknowledged_only=True, limit=limit),
            }

        if intent == 'list_actions':
            sub_name = parsed.get('subagent_name')
            sub_id = None
            if sub_name and agent_id:
                for s in self.db.get_subagents(agent_id):
                    if s['name'].lower() == sub_name.lower():
                        sub_id = s['id']
                        break
            return {
                'intent': intent,
                'data': self.db.get_actions(agent_id=agent_id, subagent_id=sub_id, limit=limit),
            }

        if intent == 'risk_summary':
            risks = []
            agents = [agent] if agent else self.db.get_all_agents()[:limit]
            for a in agents:
                if not a:
                    continue
                risk = self.db.get_latest_risk(a['id'])
                if risk:
                    risks.append(risk)
            return {'intent': intent, 'data': risks}

        if intent == 'compliance_search':
            query = parsed.get('search_query') or agent_name or 'unauthorized AI actions'
            return {
                'intent': intent,
                'data': self.kb.similarity_search(query, k=limit),
            }

        return {'intent': 'general', 'data': {'agents': len(self.db.get_all_agents())}}

    def generate_response(self, user_query: str, query_result: Dict) -> str:
        """Generate a natural language answer from query results."""
        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        'role': 'system',
                        'content': (
                            'You are Guardian Agent assistant. Answer concisely based on '
                            'the query results. Highlight security risks and unauthorized actions.'
                        ),
                    },
                    {
                        'role': 'user',
                        'content': (
                            f'User question: {user_query}\n\n'
                            f'Query results: {json.dumps(query_result, default=str)[:4000]}'
                        ),
                    },
                ],
                temperature=0.3,
            )
            return response.choices[0].message.content or 'No response generated.'
        except Exception as exc:
            return self._fallback_response(user_query, query_result, str(exc))

    def ask(self, user_query: str) -> Dict:
        """Full pipeline: parse → execute → respond."""
        parsed = self.parse_query(user_query)
        result = self.execute_query(parsed)
        answer = self.generate_response(user_query, result)
        return {
            'query': user_query,
            'parsed': parsed,
            'result': result,
            'answer': answer,
        }

    @staticmethod
    def _rule_based_parse(query: str) -> Dict:
        q = query.lower()
        if 'alert' in q:
            return {'intent': 'list_alerts', 'limit': 10}
        if 'sub-agent' in q or 'subagent' in q:
            return {'intent': 'list_subagents', 'limit': 20}
        if 'risk' in q:
            return {'intent': 'risk_summary', 'limit': 10}
        if 'action' in q or 'did' in q:
            return {'intent': 'list_actions', 'limit': 20}
        if 'gdpr' in q or 'soc2' in q or 'hipaa' in q or 'compliance' in q:
            return {'intent': 'compliance_search', 'search_query': query, 'limit': 5}
        if 'agent' in q:
            return {'intent': 'list_agents', 'limit': 20}
        return {'intent': 'general'}

    @staticmethod
    def _fallback_response(query: str, result: Dict, error: str) -> str:
        intent = result.get('intent', '')
        data = result.get('data')
        if intent == 'list_agents' and isinstance(data, list):
            names = ', '.join(a.get('name', a.get('model_name', '?')) for a in data[:5])
            return f'Found {len(data)} active agents: {names or "none"}. (LLM unavailable: {error[:60]})'
        if intent == 'list_alerts' and isinstance(data, list):
            return f'There are {len(data)} unacknowledged alerts.'
        return f'Query processed ({intent}). LLM response unavailable: {error[:80]}'
