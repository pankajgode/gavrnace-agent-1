"""
Compliance report generator using reportlab.

Maps actions to GDPR / SOC2 / HIPAA requirements and exports PDF reports.
"""

from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from src.core.database import Database


COMPLIANCE_MAP = {
    'read:database': [
        {'framework': 'GDPR', 'control': 'Art.32', 'requirement': 'Secure processing of personal data'},
        {'framework': 'HIPAA', 'control': '§164.312(a)', 'requirement': 'Access control for PHI systems'},
        {'framework': 'SOC2', 'control': 'CC6.1', 'requirement': 'Logical access restrictions'},
    ],
    'write:database': [
        {'framework': 'GDPR', 'control': 'Art.25', 'requirement': 'Data protection by design'},
        {'framework': 'HIPAA', 'control': '§164.312(b)', 'requirement': 'Audit controls'},
        {'framework': 'SOC2', 'control': 'CC6.6', 'requirement': 'Restrict unauthorized changes'},
    ],
    'send:email': [
        {'framework': 'GDPR', 'control': 'Art.5', 'requirement': 'Lawful processing and confidentiality'},
        {'framework': 'SOC2', 'control': 'CC6.7', 'requirement': 'Restrict data transmission'},
    ],
    'execute:code': [
        {'framework': 'SOC2', 'control': 'CC6.1', 'requirement': 'Prevent unauthorized code execution'},
        {'framework': 'HIPAA', 'control': '§164.308(a)(5)', 'requirement': 'Security awareness — code injection risk'},
    ],
    'tool:shell': [
        {'framework': 'SOC2', 'control': 'CC6.1', 'requirement': 'Restrict shell access'},
        {'framework': 'GDPR', 'control': 'Art.32', 'requirement': 'Integrity and confidentiality measures'},
    ],
    'write:files': [
        {'framework': 'SOC2', 'control': 'CC6.6', 'requirement': 'Protect against unauthorized file changes'},
        {'framework': 'HIPAA', 'control': '§164.312(c)', 'requirement': 'Integrity controls'},
    ],
    'network:exfil': [
        {'framework': 'GDPR', 'control': 'Art.33', 'requirement': 'Breach notification if data exfiltrated'},
        {'framework': 'SOC2', 'control': 'CC7.2', 'requirement': 'Anomaly detection for data transfer'},
        {'framework': 'HIPAA', 'control': '§164.308(a)(6)', 'requirement': 'Security incident procedures'},
    ],
}


class ComplianceReporter:
    """Generate PDF compliance reports from agent action logs."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def map_action_to_compliance(self, action: str) -> List[Dict]:
        action_l = action.lower().strip()
        for key, controls in COMPLIANCE_MAP.items():
            if key in action_l or action_l in key:
                return controls
        # Partial match
        for key, controls in COMPLIANCE_MAP.items():
            prefix = key.split(':')[0]
            if prefix in action_l:
                return controls
        return [{'framework': 'SOC2', 'control': 'CC7.2', 'requirement': 'Monitor anomalous agent behavior'}]

    def build_report_data(
        self,
        agent_id: Optional[int] = None,
        limit: int = 100,
    ) -> Dict:
        agents = (
            [self.db.get_agent_by_id(agent_id)]
            if agent_id
            else self.db.get_all_agents()
        )
        agents = [a for a in agents if a]

        report_sections = []
        for agent in agents:
            actions = self.db.get_actions(agent_id=agent['id'], limit=limit)
            alerts = [
                a for a in self.db.get_alerts(limit=limit)
                if a.get('agent_id') == agent['id']
            ]
            violations = []
            for act in actions:
                if act.get('is_authorized'):
                    continue
                for ctrl in self.map_action_to_compliance(act['action']):
                    violations.append({
                        'action': act['action'],
                        'target': act.get('target', ''),
                        'detected_at': act.get('detected_at', ''),
                        **ctrl,
                    })

            report_sections.append({
                'agent': agent,
                'actions': actions,
                'alerts': alerts,
                'violations': violations,
                'subagents': self.db.get_subagents(agent['id']),
            })

        return {
            'generated_at': datetime.now().isoformat(),
            'sections': report_sections,
            'frameworks': ['GDPR', 'SOC2', 'HIPAA'],
        }

    def generate_pdf(
        self,
        output_path: Optional[Path] = None,
        agent_id: Optional[int] = None,
    ) -> Path:
        """Generate PDF compliance report and return output path."""
        data = self.build_report_data(agent_id=agent_id)
        output_path = output_path or (
            Path.home() / '.guardian_agent' / 'reports' / f'compliance_{datetime.now():%Y%m%d_%H%M%S}.pdf'
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            textColor=colors.HexColor('#1a1a2e'),
        )
        story = []

        story.append(Paragraph('Guardian Agent — Compliance Report', title_style))
        story.append(Paragraph(
            f"Generated: {data['generated_at'][:19]} | Frameworks: GDPR, SOC2, HIPAA",
            styles['Normal'],
        ))
        story.append(Spacer(1, 0.25 * inch))

        for section in data['sections']:
            agent = section['agent']
            story.append(Paragraph(
                f"Agent: {agent['name']} ({agent.get('agent_type', 'unknown')})",
                styles['Heading2'],
            ))

            # Sub-agents table
            sub_rows = [['Sub-Agent', 'Role', 'Discovery Source']]
            for sub in section['subagents']:
                sub_rows.append([
                    sub['name'],
                    sub.get('role', '')[:40],
                    sub.get('discovery_source', 'unknown'),
                ])
            if len(sub_rows) > 1:
                sub_table = Table(sub_rows, colWidths=[1.5 * inch, 2.5 * inch, 1.5 * inch])
                sub_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                ]))
                story.append(sub_table)
                story.append(Spacer(1, 0.15 * inch))

            # Action log
            action_rows = [['Action', 'Target', 'Authorized', 'Time']]
            for act in section['actions'][:30]:
                action_rows.append([
                    act['action'],
                    (act.get('target') or '')[:30],
                    'Yes' if act.get('is_authorized') else 'NO',
                    str(act.get('detected_at', ''))[:19],
                ])
            act_table = Table(action_rows, colWidths=[1.5 * inch, 2 * inch, 0.8 * inch, 1.2 * inch])
            act_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('TEXTCOLOR', (2, 1), (2, -1), colors.red),
            ]))
            story.append(Paragraph('Action Log', styles['Heading3']))
            story.append(act_table)
            story.append(Spacer(1, 0.15 * inch))

            # Compliance violations
            if section['violations']:
                vio_rows = [['Action', 'Framework', 'Control', 'Requirement']]
                for v in section['violations'][:20]:
                    vio_rows.append([
                        v['action'],
                        v['framework'],
                        v['control'],
                        v['requirement'][:50],
                    ])
                vio_table = Table(vio_rows, colWidths=[1.2 * inch, 0.8 * inch, 0.8 * inch, 2.7 * inch])
                vio_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#533483')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                ]))
                story.append(Paragraph('Compliance Violations', styles['Heading3']))
                story.append(vio_table)

            story.append(Spacer(1, 0.3 * inch))

        doc.build(story)
        return output_path

    def export_action_log_csv(self, agent_id: Optional[int] = None) -> str:
        """Export action log as CSV string."""
        agents = (
            [self.db.get_agent_by_id(agent_id)]
            if agent_id
            else self.db.get_all_agents()
        )
        lines = ['agent_id,agent_name,subagent_id,action,target,authorized,detected_at']
        for agent in agents:
            if not agent:
                continue
            for act in self.db.get_actions(agent_id=agent['id'], limit=500):
                lines.append(
                    f"{agent['id']},{agent['name']},{act.get('subagent_id','')},"
                    f"{act['action']},{act.get('target','')},{act.get('is_authorized')},"
                    f"{act.get('detected_at','')}"
                )
        return '\n'.join(lines)
