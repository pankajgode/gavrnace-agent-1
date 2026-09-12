"""
Simple Flask server to receive AI detections from Chrome extension
and integrate with Guardian Agent database
"""

import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import json
import sqlite3
from pathlib import Path

app = Flask(__name__)
CORS(app)  # Allow Chrome extension to connect

# Store detected models in memory (also saved to DB)
detected_models = []

# Database path
DB_PATH = Path.home() / '.guardian_agent' / 'guardian.db'

def get_db_connection():
    """Get database connection"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def save_model_to_db(model_name, model_type, pid=0, process_name='Browser'):
    """Save detected model to database via core Database (duplicate-safe)."""
    try:
        from src.core.database import Database as CoreDB
        db = CoreDB()
        return db.save_agent(model_name, model_type, pid, process_name)
    except Exception as e:
        print(f"⚠️ DB Error: {e}")
        return None

def add_suspicious_activity(model_id, description, permission, risk_level):
    """Add suspicious activity to database."""
    try:
        from src.core.database import Database as CoreDB
        db = CoreDB()
        db.add_suspicious_activity(model_id, description, permission, risk_level)
        return True
    except Exception as e:
        print(f"⚠️ DB Error: {e}")
        return False

def save_permissions_for_model(model_id, model_name, permissions):
    """Save permission rows using core Database."""
    try:
        from src.core.database import Database as CoreDB
        db = CoreDB()
        for perm_type, resource, action, is_auth in permissions:
            db.save_permission(model_id, perm_type, resource, action, is_auth)
            if not is_auth:
                add_suspicious_activity(
                    model_id,
                    f"Unauthorized: {action} attempted by {model_name}",
                    action,
                    'high',
                )
        return True
    except Exception as e:
        print(f"⚠️ DB Error: {e}")
        return False

@app.route('/api/detect', methods=['POST'])
def detect_ai():
    """Receive AI detection from browser extension"""
    try:
        data = request.json
        action = data.get('action', 'add')
        model_name = data.get('model_name')
        url = data.get('url')
        title = data.get('title', '')
        tab_id = data.get('tab_id')
        
        if not model_name:
            return jsonify({'status': 'error', 'message': 'No model name provided'}), 400
            
        global detected_models
        if action == 'remove':
            detected_models = [
                m for m in detected_models 
                if not (m.get('tab_id') == tab_id or (m.get('model_name') == model_name and m.get('url') == url))
            ]
            print(f"❌ AI Removed: {model_name} (tab {tab_id})")
            return jsonify({
                'status': 'success', 
                'message': f'AI removed: {model_name}',
                'total': len(detected_models)
            })
        
        # Check if already detected (avoid duplicates)
        if not any(m.get('url') == url for m in detected_models):
            model_info = {
                'model_name': model_name,
                'type': 'Browser',
                'url': url,
                'title': title,
                'timestamp': datetime.now().isoformat(),
                'tab_id': tab_id
            }
            detected_models.append(model_info)
            
            # Save to database
            model_id = save_model_to_db(model_name, 'Browser', 0, 'Browser')

            if model_id:
                # Log tool event for sub-agent discovery
                try:
                    from src.core.database import Database as CoreDB
                    core_db = CoreDB()
                    core_db.save_tool_event(
                        event_type='browser_detect',
                        tool_name=model_name.lower(),
                        subagent_hint='',
                        payload={'url': url, 'title': title, 'tab_id': tab_id},
                        source='chrome_extension',
                        agent_id=model_id,
                    )
                except Exception:
                    pass

                # Add sample permissions for demo
                if 'chatgpt' in model_name.lower() or 'gpt' in model_name.lower():
                    permissions = [
                        ('read', 'database', 'read:database', False),
                        ('read', 'files', 'read:files', True),
                        ('write', 'email', 'send:email', False),
                    ]
                elif 'claude' in model_name.lower():
                    permissions = [
                        ('read', 'database', 'read:database', True),
                        ('write', 'files', 'write:files', False),
                        ('execute', 'code', 'execute:code', False),
                    ]
                elif 'gemini' in model_name.lower() or 'bard' in model_name.lower():
                    permissions = [
                        ('read', 'database', 'read:database', True),
                        ('read', 'cloud', 'read:cloud', True),
                    ]
                else:
                    permissions = [
                        ('read', 'database', 'read:database', True),
                        ('write', 'email', 'send:email', False),
                    ]

                save_permissions_for_model(model_id, model_name, permissions)

            print(f"\n✅ AI Detected: {model_name}")
            print(f"   URL: {url}")
            print(f"   Total detected: {len(detected_models)}")
            print(f"   Saved to database: {'Yes' if model_id else 'No'}")
        
        return jsonify({
            'status': 'success', 
            'message': f'AI detected: {model_name}',
            'total': len(detected_models)
        })
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/models', methods=['GET'])
def get_models():
    """Get all detected models from memory"""
    return jsonify({
        'models': detected_models,
        'total': len(detected_models)
    })

@app.route('/api/models/db', methods=['GET'])
def get_models_from_db():
    """Get all models from database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, model_name, model_type, pid, process_name, 
                   first_detected, last_seen, status
            FROM ai_models
            WHERE status = 'active'
            ORDER BY last_seen DESC
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        models = []
        for row in results:
            models.append({
                'id': row['id'],
                'model_name': row['model_name'],
                'model_type': row['model_type'],
                'pid': row['pid'],
                'process_name': row['process_name'],
                'first_detected': row['first_detected'],
                'last_seen': row['last_seen'],
                'status': row['status']
            })
        
        return jsonify({'models': models, 'total': len(models)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/clear', methods=['POST'])
def clear_models():
    """Clear detected models from memory (not database)"""
    detected_models.clear()
    return jsonify({
        'status': 'success', 
        'message': 'Cleared all models from memory',
        'total': 0
    })

@app.route('/api/status', methods=['GET'])
def status():
    """Server status"""
    return jsonify({
        'status': 'running',
        'detected_models': len(detected_models),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/')
def home():
    """Home page"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }}
            h1 {{ color: #58a6ff; }}
            .container {{ max-width: 800px; margin: 0 auto; }}
            .card {{ background: #161b22; padding: 20px; border-radius: 8px; margin: 10px 0; }}
            .model {{ border-left: 3px solid #58a6ff; padding: 10px; margin: 5px 0; background: #0d1117; }}
            .model-name {{ color: #58a6ff; font-weight: bold; }}
            .model-url {{ color: #8b949e; font-size: 12px; }}
            .count {{ background: #238636; padding: 2px 10px; border-radius: 10px; }}
            .btn {{ background: #238636; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }}
            .btn:hover {{ background: #2ea043; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Guardian AI Detector Server</h1>
            <div class="card">
                <h3>📊 Status <span class="count">{len(detected_models)}</span></h3>
                <p>Server running at: <code>http://localhost:5000</code></p>
                <p>Detected models: <strong>{len(detected_models)}</strong></p>
                <button class="btn" onclick="clearModels()">🗑️ Clear Memory</button>
            </div>
            
            <div class="card">
                <h3>🤖 Detected AI Models</h3>
                {'<p style="color: #8b949e;">No models detected yet. Open ChatGPT, Claude, or Gemini in your browser.</p>' if not detected_models else ''}
                {''.join(f'''
                <div class="model">
                    <div class="model-name">🤖 {m['model_name']}</div>
                    <div class="model-url">📍 {m['url']}</div>
                    <div style="font-size: 11px; color: #8b949e;">🕐 {m['timestamp'][:19]}</div>
                </div>
                ''' for m in detected_models)}
            </div>
            
            <div class="card">
                <h3>🔗 Endpoints</h3>
                <ul>
                    <li><code>GET /</code> - This page</li>
                    <li><code>POST /api/detect</code> - Send AI detection</li>
                    <li><code>GET /api/models</code> - Get detected models (JSON)</li>
                    <li><code>GET /api/models/db</code> - Get models from database</li>
                    <li><code>POST /api/clear</code> - Clear memory</li>
                    <li><code>GET /api/status</code> - Server status</li>
                </ul>
            </div>
        </div>
        
        <script>
            function clearModels() {{
                fetch('/api/clear', {{ method: 'POST' }})
                    .then(() => location.reload());
            }}
            
            // Auto-refresh every 5 seconds
            setInterval(() => location.reload(), 5000);
        </script>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║  🛡️ Guardian AI Detector Server                                 ║
║                                                                   ║
║  🌐 Running on: http://localhost:5000                            ║
║  📡 Waiting for Chrome extension to send detections...           ║
║                                                                   ║
║  🔗 Endpoints:                                                   ║
║     GET  /               - Web interface                         ║
║     POST /api/detect     - Receive AI detection                  ║
║     GET  /api/models     - Get detected models (JSON)            ║
║     GET  /api/models/db  - Get models from database              ║
║     POST /api/clear      - Clear memory                         ║
║                                                                   ║
║  💡 Open your browser and go to: http://localhost:5000           ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    app.run(host='localhost', port=5000, debug=True, use_reloader=False)