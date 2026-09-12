"""Run real-time Desktop + Browser agent monitor (live only)."""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

marker = Path.home() / '.guardian_agent' / '.setup_done'
marker.parent.mkdir(parents=True, exist_ok=True)
marker.touch()

from src.realtime_monitor import run_realtime_loop

if __name__ == '__main__':
    run_realtime_loop(interval=2.0)
