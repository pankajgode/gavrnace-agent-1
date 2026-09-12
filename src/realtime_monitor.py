"""
Real-time agent scanner — Desktop processes + Browser windows ONLY.

Never shows stale DB history. Output is only what is active right now.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import psutil
import requests

from src.agent_inspector import AgentInspector
from src.database import Database


# Browser tab / window title patterns → display name
BROWSER_AI_PATTERNS: List[Tuple[str, str]] = [
    (r'chatgpt|chat\.openai', 'ChatGPT'),
    (r'claude\.ai|\bclaude\b', 'Claude'),
    (r'gemini\.google|\bgemini\b|\bbard\b', 'Gemini'),
    (r'deepseek', 'DeepSeek'),
    (r'perplexity', 'Perplexity'),
    (r'copilot\.microsoft|\bcopilot\b', 'Copilot'),
    (r'chat\.mistral|mistral\.ai', 'Mistral'),
    (r'poe\.com|\bpoe\b', 'Poe'),
    (r'character\.ai', 'Character AI'),
    (r'you\.com', 'You.com'),
]

BROWSER_PROCESS_NAMES = {
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe',
    'opera.exe', 'vivaldi.exe', 'chromium.exe',
}

# Desktop AI process patterns (NOT browsers — those use window titles)
DESKTOP_AI_PATTERNS: List[Tuple[str, str]] = [
    (r'chatgpt', 'ChatGPT Desktop'),
    (r'claude', 'Claude Desktop'),
    (r'ollama', 'Ollama'),
    (r'lm studio|lmstudio', 'LM Studio'),
    (r'gpt4all', 'GPT4All'),
    (r'langchain', 'LangChain'),
    (r'autogen', 'AutoGen'),
    (r'crewai', 'CrewAI'),
]


class RealtimeScanner:
    """Snapshot of agents that are actually running right now."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.inspector = AgentInspector(self.db)

    def snapshot(self) -> Dict:
        """
        Return only live agents:
          - desktop: matching processes
          - browser: open window titles and/or extension server tabs
        """
        desktop = self._scan_desktop_processes()
        browser_windows = self._scan_browser_windows()
        browser_ext = self._scan_extension_server()

        # Merge browser sources by name (prefer URL from extension)
        browser_by_name: Dict[str, Dict] = {}
        for b in browser_windows + browser_ext:
            key = b['model_name'].lower()
            if key not in browser_by_name:
                browser_by_name[key] = b
            else:
                # Keep URL if we just got one
                if b.get('url') and not browser_by_name[key].get('url'):
                    browser_by_name[key]['url'] = b['url']
                if b.get('source') == 'Browser Extension':
                    browser_by_name[key]['source'] = 'Browser Extension'
                    if b.get('url'):
                        browser_by_name[key]['url'] = b['url']

        browser = list(browser_by_name.values())
        live_browser_names = {b['model_name'].lower() for b in browser}

        # Persist ONLY live agents; deactivate other browser rows
        for agent in desktop + browser:
            # Browser always pid=0 so the same DB row is reused (actions/suspicious stick)
            pid = 0 if agent.get('channel') == 'Browser' or agent.get('model_type') == 'Browser' else (agent.get('pid') or 0)
            model_id = self.db.save_model(
                agent['model_name'],
                agent.get('model_type', 'Unknown'),
                pid,
                agent.get('process_name') or agent['model_name'],
            )
            agent['id'] = model_id
            agent['pid'] = pid if agent.get('channel') == 'Browser' else agent.get('pid') or pid
        self.db.deactivate_browser_models_except(live_browser_names)

        trees = self.inspector.live_status(desktop + browser)

        return {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'desktop_count': len(desktop),
            'browser_count': len(browser),
            'desktop': desktop,
            'browser': browser,
            'trees': trees,
            'extension_server': bool(browser_ext is not None and len(browser_ext) >= 0)
            and self._extension_reachable(),
        }

    def _extension_reachable(self) -> bool:
        try:
            r = requests.get('http://localhost:5000/api/status', timeout=1)
            return r.status_code == 200
        except Exception:
            return False

    def _scan_desktop_processes(self) -> List[Dict]:
        found: List[Dict] = []
        seen: Set[str] = set()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                info = proc.info
                name = (info.get('name') or '').lower()
                # Skip browsers — handled via window titles
                if name in BROWSER_PROCESS_NAMES:
                    continue
                cmdline = ' '.join(info.get('cmdline') or []).lower()
                hay = f'{name} {cmdline}'

                for pattern, label in DESKTOP_AI_PATTERNS:
                    if re.search(pattern, hay, re.I):
                        key = label.lower()
                        if key in seen:
                            break
                        seen.add(key)
                        found.append(
                            {
                                'model_name': label,
                                'model_type': 'Desktop App',
                                'pid': info.get('pid') or 0,
                                'process_name': info.get('name') or label,
                                'status': 'active',
                                'source': 'Process',
                                'channel': 'Desktop',
                            }
                        )
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return found

    def _scan_browser_windows(self) -> List[Dict]:
        """Detect AI sites from open browser window titles (Windows)."""
        if sys.platform != 'win32':
            return []

        try:
            import win32gui
            import win32process
        except ImportError:
            return []

        found: Dict[str, Dict] = {}

        def _callback(hwnd, _):
            if not win32gui.IsWindowVisible(hwnd):
                return
            title = win32gui.GetWindowText(hwnd) or ''
            if not title or len(title) < 3:
                return
            title_l = title.lower()

            # Must look like a browser window
            is_browser_title = any(
                x in title_l
                for x in (
                    'chrome', 'edge', 'firefox', 'brave', 'opera',
                    'mozilla', 'chromium',
                )
            )
            # Many Chrome tabs are "Page Title - Google Chrome"
            if not is_browser_title and ' - ' not in title:
                # Still check AI patterns; some Electron apps differ
                pass

            matched_label = None
            for pattern, label in BROWSER_AI_PATTERNS:
                if re.search(pattern, title_l, re.I):
                    matched_label = label
                    break
            if not matched_label:
                return

            # Confirm process is a browser when possible
            pid = 0
            proc_name = 'Browser'
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                proc_name = psutil.Process(pid).name()
                if proc_name.lower() not in BROWSER_PROCESS_NAMES:
                    # Allow if title clearly has browser suffix
                    if not is_browser_title:
                        return
            except Exception:
                if not is_browser_title:
                    return

            key = matched_label.lower()
            if key not in found:
                found[key] = {
                    'model_name': matched_label,
                    'model_type': 'Browser',
                    'pid': pid,
                    'process_name': f'Browser ({matched_label})',
                    'status': 'active',
                    'source': 'Browser Window',
                    'channel': 'Browser',
                    'url': '',
                    'window_title': title[:120],
                }

        try:
            win32gui.EnumWindows(_callback, None)
        except Exception:
            return []

        return list(found.values())

    def _scan_extension_server(self) -> List[Dict]:
        try:
            resp = requests.get('http://localhost:5000/api/models', timeout=1.5)
            if resp.status_code != 200:
                return []
            out = []
            for m in resp.json().get('models', []):
                name = m.get('model_name')
                if not name:
                    continue
                out.append(
                    {
                        'model_name': name,
                        'model_type': 'Browser',
                        'pid': 0,
                        'process_name': f'Browser ({name})',
                        'status': 'active',
                        'source': 'Browser Extension',
                        'channel': 'Browser',
                        'url': m.get('url', ''),
                    }
                )
            return out
        except Exception:
            return []


def build_subagent_table(trees: List[Dict], title: str = 'SUB-AGENT TABLE') -> 'Table':
    """One consolidated table: Main → Sub-Agent → actions → risk → suspicious."""
    from rich.table import Table
    from rich import box

    table = Table(
        title=title,
        title_style='bold white',
        box=box.ROUNDED,
        show_header=True,
        header_style='bold magenta',
        border_style='blue',
        pad_edge=False,
        collapse_padding=True,
    )
    table.add_column('Main Agent', style='bold cyan', no_wrap=True)
    table.add_column('Channel', style='magenta', no_wrap=True)
    table.add_column('Sub-Agent', style='bold yellow', no_wrap=True)
    table.add_column('Status', no_wrap=True)
    table.add_column('Last Action', no_wrap=True)
    table.add_column('Target', no_wrap=True)
    table.add_column('Score', justify='right', no_wrap=True)
    table.add_column('Level', no_wrap=True)
    table.add_column('Suspicious Activities', style='red')

    for tree in trees:
        parent = tree.get('parent') or {}
        main_name = parent.get('model_name') or '?'
        channel = parent.get('channel') or 'Unknown'
        parent_sus = parent.get('suspicious_activities') or []
        subs = tree.get('sub_agents') or []
        if not subs:
            sus_txt = '; '.join(parent_sus[:3]) if parent_sus else '-'
            table.add_row(
                main_name, channel, '-', '[dim]none[/dim]', '-', '-', '-', '-', sus_txt
            )
            continue
        for s in subs:
            level = (s.get('risk_level') or 'low').lower()
            level_style = {
                'critical': 'bold red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'green',
            }.get(level, 'white')
            last = s.get('last_action') or {}
            status = (
                '[green]WORKING[/green]'
                if s.get('working', True)
                else '[dim]idle[/dim]'
            )
            sus = s.get('suspicious_activities') or []
            # Include parent-level suspicious once on first sub row note if needed
            sus_txt = '; '.join(sus[:4]) if sus else '-'
            if sus:
                sus_txt = f'[red]{sus_txt}[/red]'
            table.add_row(
                main_name,
                channel,
                s.get('name', '?'),
                status,
                str(last.get('action', '-')),
                str(last.get('target', '-'))[:20],
                str(s.get('risk_score', 0)),
                f'[{level_style}]{level.upper()}[/{level_style}]',
                sus_txt,
            )
        # Extra row for main-agent-only suspicious (not tied to a sub)
        if parent_sus:
            table.add_row(
                main_name,
                channel,
                '[dim](main agent)[/dim]',
                '[green]WORKING[/green]',
                '-',
                '-',
                '-',
                '-',
                f'[red]{"; ".join(parent_sus[:4])}[/red]',
            )
    return table


def build_suspicious_table(trees: List[Dict], title: str = 'SUSPICIOUS ACTIVITIES') -> 'Table':
    """Detailed suspicious activities for live main + sub-agents."""
    from rich.table import Table
    from rich import box

    table = Table(
        title=title,
        title_style='bold red',
        box=box.ROUNDED,
        show_header=True,
        header_style='bold red',
        border_style='red',
        pad_edge=False,
        collapse_padding=True,
    )
    table.add_column('Main Agent', style='cyan', no_wrap=True)
    table.add_column('Sub-Agent', style='yellow', no_wrap=True)
    table.add_column('Suspicious Activity', style='red')
    table.add_column('Risk', no_wrap=True)

    any_rows = False
    for tree in trees:
        parent = tree.get('parent') or {}
        main_name = parent.get('model_name') or '?'
        for s in tree.get('sub_agents') or []:
            details = s.get('suspicious_details') or []
            labels = s.get('suspicious_activities') or []
            if details:
                for d in details[:5]:
                    any_rows = True
                    lvl = (d.get('risk_level') or 'medium').upper()
                    table.add_row(
                        main_name,
                        s.get('name', '?'),
                        (d.get('description') or d.get('permission') or '')[:80],
                        lvl,
                    )
            elif labels:
                for lab in labels[:5]:
                    any_rows = True
                    table.add_row(
                        main_name,
                        s.get('name', '?'),
                        str(lab)[:80],
                        (s.get('risk_level') or 'medium').upper(),
                    )
        for lab in parent.get('suspicious_activities') or []:
            any_rows = True
            table.add_row(main_name, '(main)', str(lab)[:80], 'MEDIUM')

    if not any_rows:
        table.add_row('-', '-', '[green]No suspicious activities detected[/green]', '-')
    return table


def render_realtime_panel(snap: Dict):
    """Build a Rich renderable for one realtime snapshot."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.text import Text

    trees = snap.get('trees') or []
    header = Text()
    header.append('REALTIME AGENT MONITOR', style='bold green')
    header.append(
        f"  |  {snap.get('timestamp')}  |  "
        f"Desktop: {snap.get('desktop_count', 0)}  "
        f"Browser: {snap.get('browser_count', 0)}",
        style='dim',
    )
    ext = 'ON' if snap.get('extension_server') else 'OFF'
    header.append(f'  |  extension_server: {ext}', style='dim')

    if not trees:
        body = Text(
            'No AI agents active right now on Desktop or Browser.\n'
            'Open DeepSeek/Claude in Chrome, or start a desktop AI app.',
            style='yellow',
        )
        return Panel(Group(header, Text(), body), border_style='green', title='Shadow AI Realtime')

    # Main agents summary
    main_blocks = [header, Text()]
    for tree in trees:
        parent = tree.get('parent') or {}
        channel = parent.get('channel') or 'Unknown'
        ch_style = 'magenta' if channel == 'Browser' else 'cyan'
        line = Text()
        line.append(f'MAIN [{channel}] ', style=f'bold {ch_style}')
        line.append(str(parent.get('model_name')), style='bold white')
        line.append('  WORKING', style='bold green')
        line.append(
            f"  pid={parent.get('pid')}  src={parent.get('source')}",
            style='dim',
        )
        main_blocks.append(line)
        if parent.get('url'):
            main_blocks.append(Text(f"  url: {parent.get('url')}", style='dim'))
        wt = parent.get('window_title') or ''
        if wt:
            main_blocks.append(Text(f'  window: {wt}', style='dim'))

    footer = Text(
        'Press Ctrl+C to stop  |  refresh ~2s  |  live only (no history)',
        style='dim',
    )

    # Table OUTSIDE inner panel width so columns stay readable
    return Group(
        Panel(Group(*main_blocks), border_style='green', title='Shadow AI Realtime'),
        Text(),
        build_subagent_table(trees, title='SUB-AGENT TABLE (live)'),
        Text(),
        build_suspicious_table(trees, title='SUSPICIOUS ACTIVITIES (by Agent + Sub-Agent)'),
        Text(),
        footer,
    )


def run_realtime_loop(interval: float = 2.0):
    """Continuous realtime display."""
    from rich.live import Live
    from rich.console import Console

    console = Console(force_terminal=True)
    scanner = RealtimeScanner()

    console.print(
        '[bold green]Starting REALTIME monitor '
        '(Desktop processes + Browser windows)…[/bold green]'
    )
    console.print('[dim]Only agents active RIGHT NOW are shown. Ctrl+C to stop.[/dim]\n')

    with Live(console=console, refresh_per_second=4, screen=False) as live:
        try:
            while True:
                snap = scanner.snapshot()
                # Attach window titles onto parent for display
                by_name = {
                    a['model_name'].lower(): a
                    for a in (snap.get('desktop') or []) + (snap.get('browser') or [])
                }
                for tree in snap.get('trees') or []:
                    p = tree.get('parent') or {}
                    raw = by_name.get((p.get('model_name') or '').lower(), {})
                    if raw.get('window_title'):
                        p['window_title'] = raw['window_title']
                    if raw.get('url'):
                        p['url'] = raw['url']
                    if raw.get('channel'):
                        p['channel'] = raw['channel']
                    if raw.get('source'):
                        p['source'] = raw['source']
                live.update(render_realtime_panel(snap))
                import time
                time.sleep(interval)
        except KeyboardInterrupt:
            console.print('\n[yellow]Realtime monitor stopped[/yellow]')
