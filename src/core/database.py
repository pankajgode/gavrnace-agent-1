# src/core/database.py
# FIXES: UNIQUE constraint error, proper connection management

import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional, Any
import os

class Database:
    """Production-grade database manager with proper error handling"""
    
    def __init__(self, db_path: str = "guardian.db"):
        self.db_path = db_path
        self.init_tables()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections - AUTO COMMIT/ROLLBACK"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_tables(self):
        """Initialize all tables with proper schema and indexes"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # ===== AGENTS TABLE =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    pid INTEGER,
                    url TEXT,
                    framework TEXT DEFAULT 'default',
                    confidence REAL DEFAULT 0.0,
                    status TEXT DEFAULT 'WORKING',
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # ===== SUB-AGENTS TABLE (REAL DISCOVERY) =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subagents (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    permissions TEXT,
                    confidence REAL DEFAULT 0.0,
                    discovered_by TEXT NOT NULL,
                    status TEXT DEFAULT 'WORKING',
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE
                )
            """)
            
            # ===== ACTIONS TABLE =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    subagent_id TEXT,
                    action_type TEXT NOT NULL,
                    target TEXT,
                    risk_score INTEGER DEFAULT 0,
                    blocked BOOLEAN DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT,
                    FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE,
                    FOREIGN KEY (subagent_id) REFERENCES subagents (id) ON DELETE SET NULL
                )
            """)
            
            # ===== TOOL EVENTS (FROM CHROME EXTENSION) =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    sub_agent_name TEXT,
                    tool_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE
                )
            """)
            
            # ===== ALERTS TABLE =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    subagent_id TEXT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    message TEXT,
                    status TEXT DEFAULT 'NEW',
                    acknowledged_by TEXT,
                    acknowledged_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE,
                    FOREIGN KEY (subagent_id) REFERENCES subagents (id) ON DELETE SET NULL
                )
            """)
            
            # ===== DISCOVERY LOGS =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS discovery_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    subagent_count INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE
                )
            """)
            
            # ===== FIX: AI MODELS TABLE WITH INSERT OR IGNORE =====
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ai_models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_name TEXT NOT NULL,
                    pid INTEGER,
                    url TEXT,
                    framework TEXT DEFAULT 'default',
                    status TEXT DEFAULT 'WORKING',
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(model_name, pid, url)
                )
            """)
            
            # ===== CREATE INDEXES =====
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_actions_agent ON actions(agent_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON actions(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_events_agent ON tool_events(agent_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_events_timestamp ON tool_events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_subagents_agent ON subagents(agent_id)")
            
            print("✅ Database initialized with all tables and indexes")
    
    # ===== AGENT METHODS =====
    def save_agent(self, agent_data: Dict) -> str:
        """Save or update agent"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO agents 
                (id, name, type, pid, url, framework, confidence, status, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent_data['id'],
                agent_data['name'],
                agent_data['type'],
                agent_data.get('pid'),
                agent_data.get('url'),
                agent_data.get('framework', 'default'),
                agent_data.get('confidence', 0.0),
                agent_data.get('status', 'WORKING'),
                agent_data.get('discovered_at', datetime.now())
            ))
            return agent_data['id']
    
    def get_agents(self, status: Optional[str] = None) -> List[Dict]:
        """Get all agents"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("SELECT * FROM agents WHERE status = ?", (status,))
            else:
                cursor.execute("SELECT * FROM agents ORDER BY discovered_at DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    # ===== SUB-AGENT METHODS =====
    def save_subagent(self, subagent_data: Dict) -> str:
        """Save sub-agent with proper error handling"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO subagents 
                (id, agent_id, name, role, permissions, confidence, discovered_by, status, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                subagent_data['id'],
                subagent_data['agent_id'],
                subagent_data['name'],
                subagent_data['role'],
                json.dumps(subagent_data.get('permissions', [])),
                subagent_data.get('confidence', 0.0),
                subagent_data['discovered_by'],
                subagent_data.get('status', 'WORKING'),
                datetime.now()
            ))
            return subagent_data['id']
    
    def get_subagents(self, agent_id: str) -> List[Dict]:
        """Get all sub-agents for an agent"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM subagents 
                WHERE agent_id = ? AND status = 'WORKING'
                ORDER BY confidence DESC
            """, (agent_id,))
            results = cursor.fetchall()
            subagents = []
            for row in results:
                row_dict = dict(row)
                if row_dict.get('permissions'):
                    row_dict['permissions'] = json.loads(row_dict['permissions'])
                subagents.append(row_dict)
            return subagents
    
    # ===== ACTION METHODS =====
    def save_action(self, action_data: Dict) -> int:
        """Save action"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO actions 
                (agent_id, subagent_id, action_type, target, risk_score, blocked, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                action_data['agent_id'],
                action_data.get('subagent_id'),
                action_data['action_type'],
                action_data.get('target'),
                action_data.get('risk_score', 0),
                action_data.get('blocked', 0),
                json.dumps(action_data.get('details', {}))
            ))
            return cursor.lastrowid
    
    def get_actions(self, agent_id: str, limit: int = 100) -> List[Dict]:
        """Get recent actions for an agent"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT a.*, s.name as subagent_name
                FROM actions a
                LEFT JOIN subagents s ON a.subagent_id = s.id
                WHERE a.agent_id = ?
                ORDER BY a.timestamp DESC
                LIMIT ?
            """, (agent_id, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    # ===== TOOL EVENT METHODS (FIXED - INSERT OR IGNORE) =====
    def save_tool_event(self, event_data: Dict) -> int:
        """Save tool event with INSERT OR IGNORE to prevent duplicates"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # FIX: Use INSERT OR IGNORE
            cursor.execute("""
                INSERT OR IGNORE INTO tool_events 
                (agent_id, sub_agent_name, tool_name, action_type, target)
                VALUES (?, ?, ?, ?, ?)
            """, (
                event_data['agent_id'],
                event_data.get('sub_agent_name'),
                event_data['tool_name'],
                event_data['action_type'],
                event_data.get('target')
            ))
            return cursor.lastrowid
    
    def get_recent_tool_events(self, agent_id: str, seconds: int = 60) -> List[Dict]:
        """Get recent tool events for an agent"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM tool_events
                WHERE agent_id = ?
                AND timestamp > datetime('now', '-' || ? || ' seconds')
                ORDER BY timestamp DESC
            """, (agent_id, seconds))
            return [dict(row) for row in cursor.fetchall()]
    
    # ===== ALERT METHODS =====
    def save_alert(self, alert_data: Dict) -> int:
        """Save alert"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts 
                (agent_id, subagent_id, alert_type, severity, risk_score, message, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_data['agent_id'],
                alert_data.get('subagent_id'),
                alert_data['alert_type'],
                alert_data['severity'],
                alert_data['risk_score'],
                alert_data.get('message'),
                alert_data.get('status', 'NEW')
            ))
            return cursor.lastrowid
    
    def get_alerts(self, status: Optional[str] = None) -> List[Dict]:
        """Get alerts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC", (status,))
            else:
                cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def acknowledge_alert(self, alert_id: int, user: str) -> bool:
        """Acknowledge an alert"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE alerts 
                SET status = 'ACKNOWLEDGED', acknowledged_by = ?, acknowledged_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (user, alert_id))
            return cursor.rowcount > 0
    
    # ===== DISCOVERY LOG METHODS =====
    def log_discovery(self, agent_id: str, method: str, count: int):
        """Log discovery event"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO discovery_log (agent_id, method, subagent_count)
                VALUES (?, ?, ?)
            """, (agent_id, method, count))
    
    # ===== STATS METHODS =====
    def get_stats(self) -> Dict:
        """Get database statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) as count FROM agents")
            agents = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM subagents")
            subagents = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM actions")
            actions = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE status = 'NEW'")
            pending_alerts = cursor.fetchone()['count']
            
            return {
                'agents': agents,
                'subagents': subagents,
                'actions': actions,
                'pending_alerts': pending_alerts
            }