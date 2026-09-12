"""
Map sub-agents under each main (parent) AI agent.

Discovery of main agents is handled elsewhere — this module only builds
and persists the parent → sub-agent hierarchy and permission grants.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from src.database import Database
from src.core.subagent_discovery import SubAgentDiscovery


# Known multi-agent role templates keyed by framework / parent type hints.
# These describe typical Shadow-AI sub-agent layouts (CrewAI, AutoGen, etc.).
FRAMEWORK_TEMPLATES: Dict[str, List[Dict]] = {
    'crewai': [
        {
            'name': 'researcher',
            'role': 'Gather and summarize information',
            'granted_permissions': ['read:files', 'read:cloud'],
        },
        {
            'name': 'writer',
            'role': 'Draft documents and emails',
            'granted_permissions': ['read:files', 'write:files'],
        },
        {
            'name': 'coder',
            'role': 'Generate and run code',
            'granted_permissions': ['read:files', 'execute:code'],
        },
        {
            'name': 'critic',
            'role': 'Review outputs for quality',
            'granted_permissions': ['read:files'],
        },
    ],
    'autogen': [
        {
            'name': 'assistant',
            'role': 'Primary task executor',
            'granted_permissions': ['read:files', 'read:database'],
        },
        {
            'name': 'user_proxy',
            'role': 'Human proxy / tool runner',
            'granted_permissions': ['execute:code', 'tool:shell', 'write:files'],
        },
        {
            'name': 'planner',
            'role': 'Break down tasks',
            'granted_permissions': ['read:files'],
        },
    ],
    'langchain': [
        {
            'name': 'retriever',
            'role': 'RAG document retrieval',
            'granted_permissions': ['read:files', 'read:database'],
        },
        {
            'name': 'tool_agent',
            'role': 'Invoke external tools',
            'granted_permissions': ['read:cloud', 'send:email'],
        },
        {
            'name': 'executor',
            'role': 'Chain step executor',
            'granted_permissions': ['read:files', 'write:files', 'execute:code'],
        },
    ],
    'default': [
        {
            'name': 'worker',
            'role': 'Generic task worker',
            'granted_permissions': ['read:files'],
        },
        {
            'name': 'tool_caller',
            'role': 'Calls tools on behalf of parent',
            'granted_permissions': ['read:files', 'read:cloud'],
        },
    ],
}


class SubAgentMapper:
    """Build and query the main-agent → sub-agent map."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.db.seed_unauthorized_permissions()
        self.discovery = SubAgentDiscovery(self.db)

    def detect_framework(self, parent: Dict) -> str:
        """Guess multi-agent framework from parent model metadata."""
        haystack = ' '.join(
            str(parent.get(k, '')).lower()
            for k in ('model_name', 'model_type', 'process_name')
        )
        for key in ('crewai', 'autogen', 'langchain'):
            if key in haystack:
                return key
        return 'default'

    def map_sub_agents(
        self,
        parent_model_id: int,
        framework: Optional[str] = None,
        custom_sub_agents: Optional[List[Dict]] = None,
    ) -> List[Dict]:
        """
        Map sub-agents under a main agent and persist them.

        If custom_sub_agents is provided, those are used; otherwise a
        framework template is applied.
        """
        parent = self._get_parent(parent_model_id)
        if not parent:
            return []

        fw = (framework or self.detect_framework(parent)).lower()

        if custom_sub_agents:
            mapped: List[Dict] = []
            for tpl in custom_sub_agents:
                sub_id = self.db.save_subagent(
                    parent_model_id,
                    tpl['name'],
                    tpl.get('role', ''),
                    fw,
                    'manual',
                    tpl.get('granted_permissions', []),
                )
                mapped.append({
                    'id': sub_id,
                    'parent_model_id': parent_model_id,
                    'parent_name': parent['model_name'],
                    'name': tpl['name'],
                    'role': tpl.get('role', ''),
                    'framework': fw,
                    'granted_permissions': tpl.get('granted_permissions', []),
                    'status': 'active',
                    'discovery_source': 'manual',
                })
            return mapped

        # Real discovery first; templates only if nothing found
        return self.discovery.discover_for_agent(
            parent_model_id,
            parent_pid=parent.get('pid'),
            framework=fw,
        )

    def map_all_parents(self) -> Dict[str, List[Dict]]:
        """Map sub-agents for every discovered main agent."""
        result: Dict[str, List[Dict]] = {}
        for parent in self.db.get_all_models():
            result[parent['model_name']] = self.map_sub_agents(parent['id'])
        return result

    def get_tree(self, parent_model_id: int) -> Dict:
        """Return main agent + its mapped sub-agents."""
        parent = self._get_parent(parent_model_id)
        if not parent:
            return {}
        return {
            'parent': parent,
            'sub_agents': self.db.get_sub_agents(parent_model_id),
        }

    def get_all_trees(self) -> List[Dict]:
        return [self.get_tree(m['id']) for m in self.db.get_all_models()]

    def register_sub_agent(
        self,
        parent_model_id: int,
        name: str,
        role: str = '',
        granted_permissions: Optional[List[str]] = None,
        framework: str = 'custom',
    ) -> Dict:
        """Manually register one sub-agent (e.g. from telemetry)."""
        sub_id = self.db.save_sub_agent(
            parent_model_id=parent_model_id,
            name=name,
            role=role,
            framework=framework,
            granted_permissions=granted_permissions or [],
        )
        return self.db.get_sub_agent(sub_id) or {'id': sub_id, 'name': name}

    def _get_parent(self, parent_model_id: int) -> Optional[Dict]:
        for m in self.db.get_all_models():
            if m['id'] == parent_model_id:
                return m
        return None
