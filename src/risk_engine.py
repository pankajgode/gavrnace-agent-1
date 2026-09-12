"""
Risk score engine for Shadow AI agents and sub-agents.

Score is 0–100 with levels: low | medium | high | critical.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from src.database import Database


LEVEL_THRESHOLDS = (
    (75, 'critical'),
    (50, 'high'),
    (25, 'medium'),
    (0, 'low'),
)


class RiskEngine:
    """Calculate and persist risk scores for agents / sub-agents."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def score_to_level(self, score: float) -> str:
        for threshold, level in LEVEL_THRESHOLDS:
            if score >= threshold:
                return level
        return 'low'

    def calculate_sub_agent_risk(self, sub_agent_id: int) -> Dict:
        sub = self.db.get_sub_agent(sub_agent_id)
        if not sub:
            return {'error': f'sub-agent {sub_agent_id} not found', 'score': 0, 'level': 'low'}

        actions = self.db.get_agent_actions(sub_agent_id=sub_agent_id, limit=200)
        return self._score_from_actions(
            parent_model_id=sub['parent_model_id'],
            sub_agent_id=sub_agent_id,
            actions=actions,
            label=sub['name'],
            granted=sub.get('granted_permissions') or [],
        )

    def calculate_parent_risk(self, parent_model_id: int) -> Dict:
        """
        Aggregate risk for a main agent from:
        - its own tracked actions
        - all sub-agent risks
        - legacy unauthorized permissions
        """
        actions = self.db.get_agent_actions(parent_model_id=parent_model_id, limit=300)
        parent_only = [a for a in actions if a.get('sub_agent_id') is None]

        base = self._score_from_actions(
            parent_model_id=parent_model_id,
            sub_agent_id=None,
            actions=parent_only,
            label='parent',
            granted=[],
            persist=False,
        )

        sub_scores: List[Dict] = []
        for sub in self.db.get_sub_agents(parent_model_id):
            sub_scores.append(self.calculate_sub_agent_risk(sub['id']))

        # Legacy permission rows (from discovery/demo)
        legacy = self.db.get_permissions_for_model(parent_model_id)
        legacy_unauth = [p for p in legacy if not p.get('is_authorized')]

        sub_max = max((s.get('score', 0) for s in sub_scores), default=0)
        sub_avg = (
            sum(s.get('score', 0) for s in sub_scores) / len(sub_scores)
            if sub_scores
            else 0
        )
        legacy_boost = min(40, len(legacy_unauth) * 8)

        # Weighted blend: parent actions + hottest sub-agent + legacy flags
        score = min(
            100.0,
            round(base['score'] * 0.35 + sub_max * 0.45 + sub_avg * 0.10 + legacy_boost, 1),
        )
        level = self.score_to_level(score)
        factors = {
            'parent_action_score': base['score'],
            'hottest_sub_agent_score': sub_max,
            'avg_sub_agent_score': round(sub_avg, 1),
            'legacy_unauthorized_count': len(legacy_unauth),
            'legacy_boost': legacy_boost,
            'sub_agent_count': len(sub_scores),
            'unauthorized_action_count': base['factors'].get('unauthorized_count', 0)
            + sum(s.get('factors', {}).get('unauthorized_count', 0) for s in sub_scores),
        }

        self.db.save_risk_score(parent_model_id, score, level, factors, sub_agent_id=None)
        return {
            'parent_model_id': parent_model_id,
            'sub_agent_id': None,
            'score': score,
            'level': level,
            'factors': factors,
            'sub_agent_risks': sub_scores,
        }

    def calculate_all(self) -> List[Dict]:
        return [self.calculate_parent_risk(m['id']) for m in self.db.get_all_models()]

    def _score_from_actions(
        self,
        parent_model_id: int,
        sub_agent_id: Optional[int],
        actions: List[Dict],
        label: str,
        granted: List[str],
        persist: bool = True,
    ) -> Dict:
        unauth = [a for a in actions if not a.get('is_authorized')]
        points = sum(a.get('risk_points') or 0 for a in unauth)
        # Frequency dampener: many small hits still climb, but with soft cap
        frequency = min(30, len(unauth) * 3)
        # Over-privilege: granted dangerous perms unused still add base risk
        dangerous_grants = [
            g
            for g in granted
            if any(
                x in g
                for x in ('execute', 'shell', 'admin', 'write:database', 'write:all')
            )
        ]
        grant_risk = min(20, len(dangerous_grants) * 8)

        raw = points * 0.7 + frequency + grant_risk
        score = float(min(100, round(raw, 1)))
        level = self.score_to_level(score)
        factors = {
            'label': label,
            'unauthorized_count': len(unauth),
            'risk_points_sum': points,
            'frequency_boost': frequency,
            'dangerous_grants': dangerous_grants,
            'grant_risk': grant_risk,
            'total_actions': len(actions),
        }

        if persist:
            self.db.save_risk_score(
                parent_model_id, score, level, factors, sub_agent_id=sub_agent_id
            )

        return {
            'parent_model_id': parent_model_id,
            'sub_agent_id': sub_agent_id,
            'score': score,
            'level': level,
            'factors': factors,
        }
