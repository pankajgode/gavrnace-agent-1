"""
Main entry point for Guardian Agent
CLI commands: discover, scan, monitor, inspect, map, risk, alerts, help

Shadow AI focus (this team's work):
  - map / inspect  → sub-agents under each main agent
  - track actions  → what they do + targets
  - permissions    → check grants vs observed
  - risk           → score 0–100
  - alerts         → notify on unauthorized actions

Discovery of main agents is owned separately (DiscoveryEngine).
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console

from src.discovery import DiscoveryEngine
from src.database import Database
from src.ui import GuardianUI
from src.agent_inspector import AgentInspector

console = Console()


class GuardianCLI:
    def __init__(self):
        self.discovery = DiscoveryEngine()
        self.db = Database()
        self.db.seed_unauthorized_permissions()
        self.ui = GuardianUI()
        self.inspector = AgentInspector(self.db)

    def command_discover(self):
        """Discover running AI models (friend's discovery module)."""
        self.ui.show_discover_animation()
        models = self.discovery.discover_running_models()
        self.ui.display_models(models)

        if models:
            print()
            console.print(
                "[dim]Map sub-agents + run Shadow AI inspect? (y/n)[/dim]"
            )
            choice = input("> ").lower().strip()
            if choice == 'y':
                self.command_inspect()

    def command_scan(self, model_name: str = None):
        """Scan permissions for a model (legacy + Shadow AI check)."""
        models = self.db.get_all_models()

        if not models:
            console.print("[red]No models found. Run 'guardian discover' first.[/red]")
            return

        if model_name:
            target = next(
                (m for m in models if m['model_name'].lower() == model_name.lower()),
                None,
            )
            if not target:
                console.print(f"[red]Model '{model_name}' not found[/red]")
                return
            permissions = self.db.get_permissions_for_model(target['id'])
            self.ui.display_model_permissions(target['model_name'], permissions)
            report = self.inspector.check_permissions(parent_model_id=target['id'])
            console.print(
                f"\n[cyan]Shadow AI unauthorized actions: "
                f"{report.get('total_unauthorized', 0)}[/cyan]"
            )
        else:
            for model in models:
                permissions = self.db.get_permissions_for_model(model['id'])
                self.ui.display_model_permissions(model['model_name'], permissions)
                print("\n" + "=" * 60 + "\n")

    def command_live(self, watch: bool = False):
        """Real-time agents on Desktop + Browser (no stale history)."""
        if watch:
            from src.realtime_monitor import run_realtime_loop
            run_realtime_loop(interval=2.0)
            return

        from src.realtime_monitor import RealtimeScanner, render_realtime_panel
        from rich.console import Console

        console.print(
            "[bold green]Realtime snapshot (Desktop + Browser, live only)...[/bold green]"
        )
        scanner = RealtimeScanner(self.db)
        snap = scanner.snapshot()
        by_name = {
            a['model_name'].lower(): a
            for a in (snap.get('desktop') or []) + (snap.get('browser') or [])
        }
        for tree in snap.get('trees') or []:
            p = tree.get('parent') or {}
            raw = by_name.get((p.get('model_name') or '').lower(), {})
            for k in ('window_title', 'url', 'channel', 'source'):
                if raw.get(k):
                    p[k] = raw[k]
        Console(force_terminal=True).print(render_realtime_panel(snap))
        console.print(
            "[dim]For continuous realtime: python run_realtime.py[/dim]"
        )

    def command_map(self, model_name: str = None):
        """Map sub-agents under each main agent."""
        if model_name:
            result = self.inspector.map_sub_agents(parent_name=model_name)
            if result.get('mode') == 'single':
                tree = {
                    'parent': result['parent'],
                    'sub_agents': result['sub_agents'],
                }
                self.ui.display_subagent_map([tree])
            else:
                console.print("[red]Parent agent not found[/red]")
        else:
            # Ensure mapping exists for all discovered parents
            self.inspector.map_sub_agents()
            trees = self.inspector.get_map()
            self.ui.display_subagent_map(trees)

    def command_inspect(self, model_name: str = None, demo: bool = True):
        """Full Shadow AI pipeline for one or all main agents."""
        console.print("[bold green]Running Shadow AI inspect...[/bold green]")
        report = self.inspector.inspect(
            parent_name=model_name,
            run_demo_actions=demo,
        )

        trees = self.inspector.get_map(
            parent_model_id=(report.get('map') or {})
            .get('parent', {})
            .get('id')
        ) if model_name else self.inspector.get_map()

        # If single-mode map, normalize trees
        mapped = report.get('map') or {}
        if mapped.get('mode') == 'single':
            trees = [{
                'parent': mapped['parent'],
                'sub_agents': mapped.get('sub_agents') or [],
            }]
        elif not trees:
            trees = self.inspector.get_map()

        self.ui.display_subagent_map(trees)

        activity = report.get('activity') or {}
        if activity.get('results'):
            self.ui.display_actions(
                activity['results'],
                title=(
                    f"Tracked Actions "
                    f"({activity.get('unauthorized', 0)} unauthorized / "
                    f"{activity.get('tracked', 0)} total)"
                ),
            )

        risk = report.get('risk') or {}
        self.ui.display_risk(risk)
        self.ui.display_alerts(report.get('alerts') or [])

    def command_risk(self, model_name: str = None):
        """Calculate and show risk scores."""
        risk = self.inspector.calculate_risk(parent_name=model_name)
        self.ui.display_risk(risk)

    def command_alerts(self, all_alerts: bool = False):
        """Show unauthorized-action alerts."""
        alerts = self.inspector.get_alerts(pending_only=not all_alerts)
        self.ui.display_alerts(alerts)

    def command_monitor(self):
        """Start continuous monitoring with Shadow AI checks."""
        console.print("[bold green]Guardian Agent Monitoring Started[/bold green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]")

        try:
            import time

            while True:
                models = self.discovery.discover_running_models()

                for model in models:
                    # Ensure sub-agent map exists
                    self.inspector.map_sub_agents(parent_model_id=model['id'])

                    # Track a lightweight heartbeat scan via legacy path
                    permissions = self.discovery.scan_permissions_for_model(
                        model['id'],
                        model,
                    )
                    unauthorized = [
                        p for p in permissions if not p.get('is_authorized', False)
                    ]
                    if unauthorized:
                        model_perms = self.db.get_permissions_for_model(model['id'])
                        risky = [
                            p for p in model_perms if not p.get('is_authorized', False)
                        ]
                        if risky:
                            console.print(
                                f"[red]ALERT: {model['model_name']} has "
                                f"unauthorized permissions![/red]"
                            )
                            console.print(
                                f"[dim]Actions: "
                                f"{', '.join(p['action'] for p in risky)}[/dim]"
                            )

                    risk = self.inspector.calculate_risk(parent_model_id=model['id'])
                    if risk.get('level') in ('high', 'critical'):
                        console.print(
                            f"[red]RISK {risk['level'].upper()}: "
                            f"{model['model_name']} score={risk['score']}[/red]"
                        )

                pending = self.inspector.get_alerts(pending_only=True)
                if pending:
                    self.ui.display_alerts(pending[:5])

                time.sleep(10)

        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoring stopped[/yellow]")

    def run(self):
        parser = argparse.ArgumentParser(
            description="Guardian Agent - Shadow AI Security Monitor",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  guardian live                  Which agents work NOW + their sub-agents
  guardian discover              Find running AI models (discovery)
  guardian map                   Map sub-agents under each main agent
  guardian map --model DemoCrewAI
  guardian inspect               Map + track + perms + risk + alerts
  guardian inspect --model gpt-4
  guardian risk                  Calculate risk scores
  guardian alerts                Show unauthorized-action alerts
  guardian scan                  Scan permissions
  guardian monitor               Continuous monitoring
            """,
        )

        parser.add_argument(
            'command',
            choices=[
                'discover', 'scan', 'monitor', 'help',
                'inspect', 'map', 'risk', 'alerts', 'live',
            ],
            help='Command to execute',
        )
        parser.add_argument('--model', type=str, help='Main agent / model name')
        parser.add_argument(
            '--all-alerts',
            action='store_true',
            help='Show acknowledged alerts too',
        )
        parser.add_argument(
            '--no-demo',
            action='store_true',
            help='Skip demo action simulation during inspect',
        )
        parser.add_argument(
            '--watch',
            action='store_true',
            help='Continuous realtime refresh for live command',
        )

        args = parser.parse_args()

        setup_marker = Path.home() / '.guardian_agent' / '.setup_done'
        if not setup_marker.exists():
            self.ui.show_welcome()
            setup_marker.parent.mkdir(parents=True, exist_ok=True)
            setup_marker.touch()

        if args.command == 'discover':
            self.command_discover()
        elif args.command == 'live':
            self.command_live(watch=args.watch)
        elif args.command == 'scan':
            self.command_scan(args.model)
        elif args.command == 'monitor':
            self.command_monitor()
        elif args.command == 'map':
            self.command_map(args.model)
        elif args.command == 'inspect':
            self.command_inspect(args.model, demo=not args.no_demo)
        elif args.command == 'risk':
            self.command_risk(args.model)
        elif args.command == 'alerts':
            self.command_alerts(all_alerts=args.all_alerts)
        elif args.command == 'help':
            self.ui.show_welcome()


def main():
    cli = GuardianCLI()
    cli.run()


if __name__ == "__main__":
    main()
