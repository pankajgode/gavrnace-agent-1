"""
Beautiful UI for displaying discovered models and permissions
Uses Rich library for terminal UI
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from typing import List, Dict
import time

console = Console()

class GuardianUI:
    @staticmethod
    def display_models(models: List[Dict]):
        """Display discovered AI models in a beautiful table"""
        
        console.clear()
        
        # Header
        console.print(Panel.fit(
            "🤖 Guardian Agent - Discovered AI Models",
            style="bold cyan",
            border_style="cyan"
        ))
        console.print()
        
        if not models:
            console.print("[yellow]⚠️ No AI models detected running on your system[/yellow]")
            console.print("[dim]Make sure you're running an AI tool like ChatGPT, Claude, or any local model[/dim]")
            console.print("[dim]Or start the browser extension and open an AI website[/dim]")
            return
        
        # Main table with Source column
        table = Table(
            title="📊 Running AI Models",
            title_style="bold white",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            border_style="blue"
        )
        
        table.add_column("#", style="dim", width=4)
        table.add_column("🤖 Model Name", style="bold cyan", no_wrap=True)
        table.add_column("📋 Type", style="yellow")
        table.add_column("🆔 PID", style="dim", width=8)
        table.add_column("⚙️ Process", style="green")
        table.add_column("📅 Last Seen", style="dim")
        table.add_column("🔒 Status", style="white")
        table.add_column("📌 Source", style="magenta", width=15)  # NEW COLUMN
        
        for idx, model in enumerate(models, 1):
            status = model.get('status', 'active')
            status_style = "green" if status == 'active' else "red"
            status_text = "🟢 Active" if status == 'active' else "🔴 Inactive"
            
            source = model.get('source', 'Unknown')
            source_emoji = {
                'Process': '🖥️',
                'Browser Extension': '🌐',
                'Database': '💾',
                'Browser': '🌐',
                'Desktop App': '🖥️',
                'Unknown': '❓'
            }.get(source, '❓')
            
            # Truncate long names
            model_name = model['model_name'][:25] if len(model['model_name']) > 25 else model['model_name']
            process_name = model.get('process_name', 'Unknown')[:25]
            last_seen = model.get('last_seen', 'N/A')
            if last_seen and len(last_seen) > 19:
                last_seen = last_seen[:19]
            
            table.add_row(
                str(idx),
                model_name,
                model.get('model_type', 'Unknown'),
                str(model.get('pid', 0)),
                process_name,
                last_seen,
                f"[{status_style}]{status_text}[/{status_style}]",
                f"{source_emoji} {source}"
            )
        
        console.print(table)
        console.print()
        
        # Summary
        total = len(models)
        browser_models = len([m for m in models if 'Browser' in m.get('source', '') or m.get('model_type') == 'Browser'])
        process_models = len([m for m in models if 'Process' in m.get('source', '') or m.get('model_type') == 'Desktop App'])
        
        console.print(Text(f"📊 Total: {total} AI models discovered", style="bold white"))
        if browser_models > 0:
            console.print(f"   🌐 Browser-based: {browser_models}")
        if process_models > 0:
            console.print(f"   🖥️  Desktop apps: {process_models}")
        
        console.print("[dim]💡 Tip: Use 'guardian scan' to view permissions for each model[/dim]")
    
    @staticmethod
    def display_model_permissions(model_name: str, permissions: List[Dict]):
        """Display permissions for a specific model"""
        
        console.clear()
        console.print(Panel.fit(
            f"🔍 Permissions for: {model_name}",
            style="bold cyan",
            border_style="cyan"
        ))
        console.print()
        
        if not permissions:
            console.print("[yellow]⚠️ No permissions found for this model[/yellow]")
            return
        
        # Separate authorized and unauthorized
        authorized = [p for p in permissions if p.get('is_authorized', False)]
        unauthorized = [p for p in permissions if not p.get('is_authorized', False)]
        
        # Unauthorized permissions (high priority)
        if unauthorized:
            console.print("[bold red]🚨 UNAUTHORIZED PERMISSIONS DETECTED![/bold red]")
            console.print("[red]The following permissions are not authorized:[/red]")
            console.print()
            
            table = Table(
                box=box.HEAVY,
                show_header=True,
                header_style="bold red",
                border_style="red"
            )
            table.add_column("⚠️ Action", style="bold red")
            table.add_column("🔧 Type", style="yellow")
            table.add_column("💾 Resource", style="cyan")
            table.add_column("📅 Detected", style="dim")
            
            for perm in unauthorized:
                table.add_row(
                    perm.get('action', 'Unknown'),
                    perm.get('type', 'Unknown'),
                    perm.get('resource', 'Unknown'),
                    perm.get('detected_at', 'N/A')[:19]
                )
            
            console.print(table)
            console.print()
        
        # Authorized permissions
        if authorized:
            console.print("[bold green]✅ Authorized Permissions[/bold green]")
            console.print()
            
            table = Table(
                box=box.SIMPLE,
                show_header=True,
                header_style="bold green",
                border_style="green"
            )
            table.add_column("Action", style="white")
            table.add_column("Type", style="dim")
            table.add_column("Resource", style="dim")
            table.add_column("Detected", style="dim")
            
            for perm in authorized:
                table.add_row(
                    perm.get('action', 'Unknown'),
                    perm.get('type', 'Unknown'),
                    perm.get('resource', 'Unknown'),
                    perm.get('detected_at', 'N/A')[:19]
                )
            
            console.print(table)
        
        console.print()
        
        # Risk summary
        if unauthorized:
            risk_levels = [p.get('risk_level', 'unknown') for p in unauthorized if 'risk_level' in p]
            if 'critical' in risk_levels:
                console.print("[bold red]🔴 CRITICAL RISK: Model has critical unauthorized permissions![/bold red]")
            elif 'high' in risk_levels:
                console.print("[bold orange]🟠 HIGH RISK: Model has dangerous unauthorized permissions[/bold orange]")
            else:
                console.print("[bold yellow]🟡 MEDIUM RISK: Model has some unauthorized permissions[/bold yellow]")
        else:
            console.print("[bold green]🟢 All permissions are authorized[/bold green]")
    
    @staticmethod
    def show_discover_animation():
        """Show animation while discovering"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]🔍 Discovering AI models on your system...", total=None)
            time.sleep(1.5)  # Simulate scanning
            progress.update(task, completed=True)
    
    @staticmethod
    def show_welcome():
        """Show welcome message"""
        console.clear()
        console.print(Panel.fit(
            """
        🛡️  Guardian Agent - AI Security Monitor
        ─────────────────────────────────────────────
        [dim]Your AI security guardian, running in the background[/dim]
        
        [bold green]Commands:[/bold green]
        • guardian discover   - Find all running AI models
        • guardian map        - Map sub-agents under each main agent
        • guardian inspect    - Track actions, perms, risk, alerts
        • guardian risk       - Calculate risk scores
        • guardian alerts     - Show unauthorized-action alerts
        • guardian scan       - Scan permissions for a model
        • guardian monitor    - Start continuous monitoring
        • guardian help       - Show this help message
        
        [bold cyan]Shadow AI focus:[/bold cyan]
        • Sub-agent mapping under each main agent
        • Action + target tracking
        • Permission checks
        • Risk scoring (0-100)
        • Alerts on unauthorized actions
            """,
            title="🤖 Guardian Agent",
            border_style="cyan",
            style="bold white"
        ))
    
    @staticmethod
    def show_scan_progress():
        """Show scanning progress animation"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]🔐 Scanning permissions...", total=None)
            time.sleep(1.5)
            progress.update(task, completed=True)

    @staticmethod
    def display_subagent_map(trees: List[Dict]):
        """Show main agent → sub-agent hierarchy."""
        console.print(Panel.fit(
            "Shadow AI — Sub-Agent Map",
            style="bold cyan",
            border_style="cyan",
        ))
        if not trees:
            console.print("[yellow]No agents mapped yet[/yellow]")
            return

        for tree in trees:
            parent = tree.get('parent') or {}
            subs = tree.get('sub_agents') or []
            console.print(
                f"\n[bold]{parent.get('model_name', '?')}[/bold] "
                f"[dim](id={parent.get('id')}, type={parent.get('model_type')})[/dim]"
            )
            if not subs:
                console.print("  [dim](no sub-agents)[/dim]")
                continue
            table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
            table.add_column("Sub-Agent")
            table.add_column("Role")
            table.add_column("Framework")
            table.add_column("Granted Permissions")
            for s in subs:
                perms = ', '.join(s.get('granted_permissions') or []) or '-'
                table.add_row(
                    s.get('name', '?'),
                    s.get('role', ''),
                    s.get('framework', ''),
                    perms,
                )
            console.print(table)

    @staticmethod
    def display_actions(actions: List[Dict], title: str = "Tracked Actions"):
        console.print(Panel.fit(title, style="bold cyan", border_style="cyan"))
        if not actions:
            console.print("[yellow]No actions tracked[/yellow]")
            return
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
        table.add_column("Action")
        table.add_column("Target")
        table.add_column("Auth?")
        table.add_column("Risk pts")
        table.add_column("When")
        for a in actions:
            auth = a.get('is_authorized', False)
            auth_txt = "[green]yes[/green]" if auth else "[red]NO[/red]"
            table.add_row(
                str(a.get('action', '')),
                str(a.get('target', ''))[:40],
                auth_txt,
                str(a.get('risk_points', 0)),
                str(a.get('detected_at', ''))[:19],
            )
        console.print(table)

    @staticmethod
    def display_risk(risk: Dict):
        console.print(Panel.fit("Risk Score", style="bold cyan", border_style="cyan"))
        if risk.get('all'):
            for item in risk['all']:
                GuardianUI._print_one_risk(item)
            return
        if risk.get('error'):
            console.print(f"[red]{risk['error']}[/red]")
            return
        GuardianUI._print_one_risk(risk)

    @staticmethod
    def _print_one_risk(risk: Dict):
        level = (risk.get('level') or 'low').lower()
        style = {
            'critical': 'bold red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green',
        }.get(level, 'white')
        console.print(
            f"[{style}]Score: {risk.get('score', 0)}  |  Level: {level.upper()}[/{style}]"
        )
        factors = risk.get('factors') or {}
        if factors:
            console.print(f"[dim]factors: {factors}[/dim]")
        for sub in risk.get('sub_agent_risks') or []:
            console.print(
                f"  sub#{sub.get('sub_agent_id')}: "
                f"{sub.get('score')} ({sub.get('level')}) "
                f"— {sub.get('factors', {}).get('label', '')}"
            )

    @staticmethod
    def display_alerts(alerts: List[Dict]):
        console.print(Panel.fit("Unauthorized Action Alerts", style="bold red", border_style="red"))
        if not alerts:
            console.print("[green]No pending alerts[/green]")
            return
        for a in alerts:
            sev = (a.get('severity') or 'medium').upper()
            console.print(
                f"[red]#{a.get('id')} [{sev}][/red] {a.get('message')}\n"
                f"  [dim]{a.get('created_at', '')}[/dim]"
            )

    @staticmethod
    def display_live_agents(trees: List[Dict]):
        """Show currently working main agents and their sub-agents."""
        console.print(Panel.fit(
            "LIVE — Agents working on your system (Desktop + Browser)",
            style="bold green",
            border_style="green",
        ))
        if not trees:
            console.print(
                "[yellow]No AI agents currently detected as working.[/yellow]\n"
                "[dim]Desktop: run ChatGPT/Claude app or Ollama\n"
                "Browser: start python extension_server.py + open ChatGPT/Claude/Gemini "
                "with the Chrome extension[/dim]"
            )
            return

        desktop_n = len([t for t in trees if (t.get('parent') or {}).get('channel') == 'Desktop'])
        browser_n = len([t for t in trees if (t.get('parent') or {}).get('channel') == 'Browser'])
        console.print(
            f"[bold]{len(trees)} main agent(s) working[/bold]  "
            f"[dim]Desktop: {desktop_n} | Browser: {browser_n}[/dim]\n"
        )

        for tree in trees:
            parent = tree.get('parent') or {}
            subs = tree.get('sub_agents') or []
            working = tree.get('working_sub_agents') or []
            idle = tree.get('idle_sub_agents') or []
            channel = parent.get('channel') or 'Unknown'
            channel_style = 'magenta' if channel == 'Browser' else 'cyan'

            console.print(
                f"[bold {channel_style}]MAIN [{channel}]:[/bold {channel_style}] "
                f"{parent.get('model_name')}  "
                f"[green]WORKING[/green]  "
                f"[dim]pid={parent.get('pid')} source={parent.get('source')}[/dim]"
            )
            if parent.get('url'):
                console.print(f"  [dim]url: {parent.get('url')}[/dim]")
            console.print(
                f"  Sub-agents: {len(subs)} total | "
                f"[green]{len(working)} working[/green] | "
                f"[dim]{len(idle)} idle[/dim]"
            )
            console.print()

        # One consolidated SUB-AGENT TABLE for all live mains
        from src.realtime_monitor import build_subagent_table, build_suspicious_table
        console.print(build_subagent_table(trees, title='SUB-AGENT TABLE (live)'))
        console.print()
        console.print(build_suspicious_table(trees, title='SUSPICIOUS ACTIVITIES (by Agent + Sub-Agent)'))
        console.print()
