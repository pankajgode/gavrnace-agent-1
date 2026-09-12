"""
Alert manager — notify when a sub-agent (or parent) does something unauthorized.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from src.database import Database
from src.risk_engine import RiskEngine


AlertCallback = Callable[[Dict], None]


class AlertManager:
    """Create, list, and deliver unauthorized-action alerts to the user."""

    def __init__(
        self,
        db: Optional[Database] = None,
        on_alert: Optional[AlertCallback] = None,
    ):
        self.db = db or Database()
        self.risk = RiskEngine(self.db)
        self.on_alert = on_alert or self._default_console_alert

    def alert_unauthorized(
        self,
        track_result: Dict,
        parent_name: str = '',
        sub_agent_name: str = '',
    ) -> Optional[Dict]:
        """
        If a tracked action was unauthorized, create an alert and notify.

        track_result: output of PermissionScanner.track_action(...)
        """
        if track_result.get('is_authorized', True):
            return None

        action = track_result.get('action', 'unknown')
        target = track_result.get('target', '')
        parent_id = track_result.get('parent_model_id')
        sub_id = track_result.get('sub_agent_id')
        risk_points = track_result.get('risk_points', 0)

        # Prefer live risk score when possible
        risk_score = float(risk_points)
        severity = self.risk.score_to_level(min(100, risk_score * 2))
        if parent_id is not None:
            if sub_id is not None:
                live = self.risk.calculate_sub_agent_risk(sub_id)
            else:
                live = self.risk.calculate_parent_risk(parent_id)
            risk_score = live.get('score', risk_score)
            severity = live.get('level', severity)

        who = sub_agent_name or (f'sub-agent#{sub_id}' if sub_id else 'main agent')
        parent_label = parent_name or f'agent#{parent_id}'
        message = (
            f"UNAUTHORIZED: {who} under '{parent_label}' attempted "
            f"'{action}' on target '{target or 'n/a'}' "
            f"(risk={risk_score}, severity={severity})"
        )

        alert_id = self.db.save_alert(
            message=message,
            parent_model_id=parent_id,
            sub_agent_id=sub_id,
            action=action,
            target=target,
            risk_score=risk_score,
            severity=severity,
        )

        # Also feed suspicious_activities for RAG learning path
        if parent_id is not None:
            self.db.add_suspicious_activity(
                parent_id,
                message,
                action,
                severity,
                sub_agent_id=sub_id,
            )

        alert = {
            'id': alert_id,
            'message': message,
            'action': action,
            'target': target,
            'risk_score': risk_score,
            'severity': severity,
            'parent_model_id': parent_id,
            'sub_agent_id': sub_id,
            'parent_name': parent_label,
            'sub_agent_name': who,
        }
        self.on_alert(alert)
        return alert

    def process_track_results(
        self,
        results: List[Dict],
        parent_name: str = '',
        sub_names: Optional[Dict[int, str]] = None,
    ) -> List[Dict]:
        """Run alert_unauthorized over a batch of track_action results."""
        sub_names = sub_names or {}
        alerts = []
        for r in results:
            sub_id = r.get('sub_agent_id')
            alert = self.alert_unauthorized(
                r,
                parent_name=parent_name,
                sub_agent_name=sub_names.get(sub_id, ''),
            )
            if alert:
                alerts.append(alert)
        return alerts

    def get_pending_alerts(self, limit: int = 50) -> List[Dict]:
        return self.db.get_alerts(unacknowledged_only=True, limit=limit)

    def get_all_alerts(self, limit: int = 50) -> List[Dict]:
        return self.db.get_alerts(unacknowledged_only=False, limit=limit)

    def acknowledge(self, alert_id: int) -> None:
        self.db.acknowledge_alert(alert_id)

    @staticmethod
    def _default_console_alert(alert: Dict) -> None:
        try:
            from rich.console import Console
            from rich.panel import Panel

            console = Console()
            severity = (alert.get('severity') or 'medium').lower()
            style = {
                'critical': 'bold red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'cyan',
            }.get(severity, 'yellow')
            console.print(
                Panel(
                    alert['message'],
                    title=f"ALERT [{severity.upper()}]",
                    border_style=style,
                )
            )
        except Exception:
            print(f"\n[ALERT] {alert.get('message')}\n")
