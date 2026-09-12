"""One-shot runner for Shadow AI inspect (Windows-safe UTF-8)."""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Skip welcome banner on first run
marker = Path.home() / ".guardian_agent" / ".setup_done"
marker.parent.mkdir(parents=True, exist_ok=True)
marker.touch()

from src.agent_inspector import AgentInspector
from src.ui import GuardianUI

insp = AgentInspector()
models = insp.db.get_all_models()
print(f"Main agents in DB: {len(models)}")

demo = insp.db.get_model_by_name("DemoCrewAI")
if not demo:
    mid = insp.db.save_model("DemoCrewAI", "crewai", 0, "demo-crew")
    print(f"Seeded DemoCrewAI id={mid}")
    demo = insp.db.get_model_by_name("DemoCrewAI")

report = insp.inspect(parent_model_id=demo["id"], run_demo_actions=True)
ui = GuardianUI()

mapped = report.get("map") or {}
trees = [
    {
        "parent": mapped.get("parent") or demo,
        "sub_agents": mapped.get("sub_agents") or [],
    }
]
ui.display_subagent_map(trees)

activity = report.get("activity") or {}
results = activity.get("results") or []
title = (
    f"Tracked Actions "
    f"({activity.get('unauthorized', 0)} unauthorized / "
    f"{activity.get('tracked', 0)} total)"
)
ui.display_actions(results, title=title)
ui.display_risk(report.get("risk") or {})
ui.display_alerts(report.get("alerts") or [])
print("\nDONE")
