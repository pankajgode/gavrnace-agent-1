"""Silent background scanner to detect and log active AI agents every 60 seconds."""
import time
import sys
from pathlib import Path

# Setup encoding for Windows
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Seed welcome marker
marker = Path.home() / '.guardian_agent' / '.setup_done'
marker.parent.mkdir(parents=True, exist_ok=True)
marker.touch()

from src.realtime_monitor import RealtimeScanner

def main():
    print("🛡️ Silent background agent scanner started (polling every 60 seconds)...")
    scanner = RealtimeScanner()
    while True:
        try:
            snap = scanner.snapshot()
            # Log number of agents detected to console quietly
            dt = snap.get('timestamp', '')
            dc = snap.get('desktop_count', 0)
            bc = snap.get('browser_count', 0)
            print(f"[{dt}] Scan complete. Active agents: Desktop={dc}, Browser={bc}")
        except Exception as e:
            print(f"⚠️ Error during background scan: {e}")
        time.sleep(60)

if __name__ == '__main__':
    main()
