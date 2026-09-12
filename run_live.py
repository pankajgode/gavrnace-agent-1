"""Run the full Guardian Agent platform with all integrated components."""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

marker = Path.home() / '.guardian_agent' / '.setup_done'
marker.parent.mkdir(parents=True, exist_ok=True)
marker.touch()

from rich.console import Console

from src.core.database import Database
from src.core.subagent_discovery import SubAgentDiscovery
from src.main import GuardianCLI

console = Console()


def start_platform():
    """Initialize all platform components and run live monitor."""
    db = Database()
    db.seed_unauthorized_permissions()

    # RAG knowledge base (lazy init on first use)
    kb = None
    try:
        from src.rag.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        kb.ingest_threat_intelligence()
        kb.ingest_compliance_policies()
        console.print('[green]RAG knowledge base ready[/green]')
    except Exception as exc:
        console.print(f'[yellow]RAG init skipped: {exc}[/yellow]')

    # WebSocket server in background
    ws_thread = None
    try:
        from src.web.websocket import WebSocketServer
        ws = WebSocketServer(db=db, port=5001)
        ws_thread = ws.run_background()
        console.print('[green]WebSocket server on ws://localhost:5001[/green]')
    except Exception as exc:
        console.print(f'[yellow]WebSocket skipped: {exc}[/yellow]')

    # Sub-agent discovery
    discovery = SubAgentDiscovery(db)
    for agent in db.get_all_agents():
        subs = discovery.discover_for_agent(agent['id'], parent_pid=agent.get('pid'))
        if subs:
            console.print(
                f"[cyan]Discovered {len(subs)} sub-agents for {agent['name']} "
                f"(sources: {', '.join(set(s.get('discovery_source','?') for s in subs))})[/cyan]"
            )

    # Run live snapshot
    cli = GuardianCLI()
    cli.command_live(watch=False)

    console.print('\n[dim]Platform components:[/dim]')
    console.print('[dim]  Database: src/core/database.py[/dim]')
    console.print('[dim]  Discovery: src/core/subagent_discovery.py[/dim]')
    console.print('[dim]  RAG: src/rag/knowledge_base.py[/dim]')
    console.print('[dim]  LLM Risk: src/llm/risk_analyzer.py[/dim]')
    console.print('[dim]  NL Interface: src/llm/natural_language.py[/dim]')
    console.print('[dim]  PDF Reports: src/reporting/compliance_reporter.py[/dim]')
    console.print('[dim]  WebSocket: src/web/websocket.py (port 5001)[/dim]')


if __name__ == '__main__':
    start_platform()
