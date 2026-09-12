"""
Permission scanner + action/target tracker for Shadow AI sub-agents.

Checks whether an action is allowed under the sub-agent's granted
permissions, records what was attempted, and flags unauthorized use.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from src.database import Database


# How many risk points an unauthorized action contributes by pattern family.
ACTION_RISK_POINTS = {
    'execute:code': 40,
    'tool:shell': 45,
    'write:database': 40,
    'admin:role': 50,
    'write:all': 45,
    'read:all': 35,
    'network:exfil': 50,
    'delete:file': 30,
    'send:email': 20,
    'write:files': 25,
    'write:email': 20,
    'create:user': 30,
    'read:database': 25,
    'read:cloud': 15,
    'read:files': 5,
}


class PermissionScanner:
    """Check permissions and track actions/targets for agents."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.db.seed_unauthorized_permissions()

    def get_granted_permissions(self, sub_agent_id: int) -> List[str]:
        sub = self.db.get_sub_agent(sub_agent_id)
        if not sub:
            return []
        return list(sub.get('granted_permissions') or [])

    def is_action_authorized(
        self,
        action: str,
        granted: List[str],
        also_check_threat_db: bool = True,
    ) -> Tuple[bool, Optional[Dict]]:
        """
        Return (authorized, threat_info).

        Authorized only if action is in the granted list AND (optionally)
        not flagged as a global unauthorized threat when not granted.
        """
        action_norm = action.strip().lower()
        granted_norm = {g.strip().lower() for g in granted}

        if action_norm in granted_norm:
            return True, None

        # Wildcards like read:* or *:files
        for g in granted_norm:
            if self._wildcard_match(g, action_norm):
                return True, None

        threat = None
        if also_check_threat_db:
            threat = self.db.check_unauthorized(action_norm)
        return False, threat

    def check_sub_agent_permissions(self, sub_agent_id: int) -> Dict:
        """
        Summarize granted vs observed permissions for one sub-agent.
        """
        sub = self.db.get_sub_agent(sub_agent_id)
        if not sub:
            return {'error': f'sub-agent {sub_agent_id} not found'}

        granted = self.get_granted_permissions(sub_agent_id)
        actions = self.db.get_agent_actions(sub_agent_id=sub_agent_id, limit=200)

        observed = []
        unauthorized = []
        for act in actions:
            entry = {
                'action': act['action'],
                'target': act['target'],
                'is_authorized': act['is_authorized'],
                'detected_at': act['detected_at'],
            }
            observed.append(entry)
            if not act['is_authorized']:
                unauthorized.append(entry)

        return {
            'sub_agent_id': sub_agent_id,
            'name': sub['name'],
            'role': sub.get('role'),
            'parent_model_id': sub['parent_model_id'],
            'granted_permissions': granted,
            'observed_actions': observed,
            'unauthorized_actions': unauthorized,
            'unauthorized_count': len(unauthorized),
        }

    def check_parent_permissions(self, parent_model_id: int) -> Dict:
        """Permission check across all sub-agents of a main agent."""
        from src.subagent_mapper import SubAgentMapper

        mapper = SubAgentMapper(self.db)
        subs = self.db.get_sub_agents(parent_model_id)
        if not subs:
            mapper.map_sub_agents(parent_model_id)
            subs = self.db.get_sub_agents(parent_model_id)

        reports = [self.check_sub_agent_permissions(s['id']) for s in subs]
        total_unauth = sum(r.get('unauthorized_count', 0) for r in reports)
        return {
            'parent_model_id': parent_model_id,
            'sub_agent_reports': reports,
            'total_unauthorized': total_unauth,
        }

    def track_action(
        self,
        parent_model_id: int,
        action: str,
        target: str,
        sub_agent_id: Optional[int] = None,
        granted_override: Optional[List[str]] = None,
    ) -> Dict:
        """
        Record an action + target, decide authorization, return result.

        This is the core "what they do" tracker.
        """
        if sub_agent_id is not None:
            granted = granted_override or self.get_granted_permissions(sub_agent_id)
        else:
            # Parent-level: treat stored model permissions as grant list
            granted = granted_override or [
                p['action']
                for p in self.db.get_permissions_for_model(parent_model_id)
                if p.get('is_authorized')
            ]

        authorized, threat = self.is_action_authorized(action, granted)
        risk_points = 0 if authorized else self._risk_points_for(action, threat)

        action_id = self.db.save_agent_action(
            parent_model_id=parent_model_id,
            action=action,
            target=target,
            is_authorized=authorized,
            risk_points=risk_points,
            sub_agent_id=sub_agent_id,
        )

        # Mirror into legacy permissions table for existing UI/scan cmds
        perm_type = action.split(':')[0] if ':' in action else 'unknown'
        resource = action.split(':')[1] if ':' in action else target
        self.db.save_permission(
            parent_model_id, perm_type, resource or target, action, authorized
        )

        result = {
            'action_id': action_id,
            'parent_model_id': parent_model_id,
            'sub_agent_id': sub_agent_id,
            'action': action,
            'target': target,
            'is_authorized': authorized,
            'risk_points': risk_points,
            'threat': threat,
        }
        return result

    def track_actions_batch(
        self,
        parent_model_id: int,
        events: List[Dict],
        sub_agent_id: Optional[int] = None,
    ) -> List[Dict]:
        """events: [{action, target}, ...]"""
        return [
            self.track_action(
                parent_model_id=parent_model_id,
                action=e['action'],
                target=e.get('target', ''),
                sub_agent_id=e.get('sub_agent_id', sub_agent_id),
            )
            for e in events
        ]

    def _risk_points_for(self, action: str, threat: Optional[Dict]) -> int:
        action_norm = action.strip().lower()
        if action_norm in ACTION_RISK_POINTS:
            return ACTION_RISK_POINTS[action_norm]
        if threat:
            level = (threat.get('risk_level') or 'medium').lower()
            return {'low': 10, 'medium': 20, 'high': 30, 'critical': 45}.get(level, 20)
        return 15

    @staticmethod
    def _wildcard_match(pattern: str, action: str) -> bool:
        if pattern.endswith(':*'):
            return action.startswith(pattern[:-1])
        if pattern.startswith('*:'):
            return action.endswith(pattern[1:])
        return False
