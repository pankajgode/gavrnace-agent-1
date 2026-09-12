"""
Discovers running AI models - Now reads from server database too!
"""

import psutil
import re
import requests
from typing import List, Dict
from src.database import Database

class DiscoveryEngine:
    def __init__(self):
        self.db = Database()
        
        # ⚠️ ONLY EXACT AI PATTERNS - No false positives!
        self.ai_patterns = [
            # OpenAI / ChatGPT
            (r'chatgpt', 'ChatGPT'),
            (r'openai', 'OpenAI API'),
            (r'gpt-4', 'GPT-4'),
            (r'gpt-3', 'GPT-3.5'),
            
            # Google
            (r'gemini', 'Google Gemini'),
            (r'bard', 'Google Bard'),
            
            # Anthropic
            (r'claude', 'Anthropic Claude'),
            
            # DeepSeek
            (r'deepseek', 'DeepSeek'),
            
            # Local Models
            (r'ollama', 'Ollama'),
            (r'llama', 'Llama'),
            (r'mistral', 'Mistral'),
            (r'falcon', 'Falcon'),
            (r'phi', 'Phi'),
            
            # AI Frameworks
            (r'langchain', 'LangChain'),
            (r'autogen', 'AutoGen'),
            (r'crewai', 'CrewAI'),
        ]
        
        # 🚫 EXCLUDE these - they're NOT AI models!
        self.exclude_patterns = [
            'spotify', 'spot', 'chrome_crashpad', 'code', 'vscode', 
            'cursor', 'chrome', 'firefox', 'edge', 'brave',
            'slack', 'discord', 'telegram', 'whatsapp',
            'zoom', 'teams', 'outlook', 'thunderbird',
            'terminal', 'gnome', 'kde', 'xfce',
            'docker', 'kubectl', 'node', 'npm', 'yarn',
            'git', 'java', 'javac', 'gradle', 'maven',
            'pip', 'conda', 'jupyter', 'mysql', 'postgres',
            'redis', 'mongodb', 'apache', 'nginx'
        ]
    
    def discover_running_models(self) -> List[Dict]:
        """Discover AI models from: processes + server database"""
        discovered = []
        seen_names = set()
        seen_pids = set()
        
        # ============================================
        # METHOD 1: Check local processes (Desktop Apps)
        # ============================================
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                pid = proc_info['pid']
                process_name = proc_info['name'].lower() if proc_info['name'] else ''
                cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                
                # 🚫 EXCLUDE known non-AI processes
                should_exclude = False
                for exclude in self.exclude_patterns:
                    if exclude in process_name or exclude in cmdline:
                        should_exclude = True
                        break
                
                if should_exclude:
                    continue
                
                # ✅ Check if it matches AI patterns
                for pattern, model_type in self.ai_patterns:
                    if re.search(pattern, cmdline) or re.search(pattern, process_name):
                        model_name = self._extract_model_name(cmdline, process_name)
                        
                        if pid not in seen_pids:
                            discovered.append({
                                'model_name': model_name,
                                'model_type': model_type,
                                'pid': pid,
                                'process_name': proc_info['name'] or 'Unknown',
                                'last_seen': 'N/A',
                                'source': 'Process',
                                'status': 'active'
                            })
                            seen_pids.add(pid)
                            seen_names.add(model_name)
                            
                            # Save to database
                            self.db.save_model(model_name, model_type, pid, proc_info['name'] or 'Unknown')
                        break
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # ============================================
        # METHOD 2: Get browser AI from server (REAL-TIME)
        # ============================================
        server_models = []
        try:
            response = requests.get('http://localhost:5000/api/models', timeout=2)
            if response.status_code == 200:
                data = response.json()
                server_models = data.get('models', [])
                
                for model in server_models:
                    model_name = model.get('model_name')
                    if model_name and model_name not in seen_names:
                        # Save to database immediately!
                        model_id = self.db.save_model(
                            model_name, 
                            'Browser', 
                            0, 
                            f'Browser ({model_name})'
                        )
                        
                        # Add some default permissions for demo
                        if model_id:
                            self._add_demo_permissions(model_id, model_name)
                        
                        discovered.append({
                            'model_name': model_name,
                            'model_type': 'Browser',
                            'pid': 0,
                            'process_name': f'Browser ({model_name})',
                            'last_seen': model.get('timestamp', 'N/A')[:19],
                            'source': 'Browser Extension',
                            'url': model.get('url', ''),
                            'status': 'active'
                        })
                        seen_names.add(model_name)
                        
                if server_models:
                    print(f"📡 Loaded {len(server_models)} models from server and saved to database")
        except requests.exceptions.ConnectionError:
            print("⚠️ Server not running (start with: python extension_server.py)")
        except Exception as e:
            print(f"⚠️ Error connecting to server: {e}")
        
        # ============================================
        # METHOD 3: Get models from local database
        # ============================================
        db_models = self.db.get_all_models()
        for model in db_models:
            model_name = model.get('model_name')
            if model_name and model_name not in seen_names:
                # Check if this model is still active on server
                is_active = any(sm.get('model_name') == model_name for sm in server_models)
                
                discovered.append({
                    'model_name': model_name,
                    'model_type': model.get('model_type', 'Unknown'),
                    'pid': model.get('pid', 0),
                    'process_name': model.get('process_name', 'Unknown'),
                    'last_seen': model.get('last_seen', 'N/A'),
                    'source': 'Database',
                    'status': 'active' if is_active else 'inactive'
                })
                seen_names.add(model_name)
        
        return discovered
    
    def _add_demo_permissions(self, model_id: int, model_name: str):
        """Add demo permissions for browser-detected models"""
        model_name_lower = model_name.lower()
        
        if 'deepseek' in model_name_lower:
            permissions = [
                ('read', 'database', 'read:database', True),
                ('read', 'files', 'read:files', True),
                ('write', 'email', 'send:email', False),  # Unauthorized!
            ]
        elif 'chatgpt' in model_name_lower or 'gpt' in model_name_lower:
            permissions = [
                ('read', 'database', 'read:database', False),  # Unauthorized!
                ('read', 'files', 'read:files', True),
                ('write', 'email', 'send:email', False),  # Unauthorized!
            ]
        elif 'claude' in model_name_lower:
            permissions = [
                ('read', 'database', 'read:database', True),
                ('write', 'files', 'write:files', False),  # Unauthorized!
                ('execute', 'code', 'execute:code', False),  # Unauthorized!
            ]
        elif 'gemini' in model_name_lower or 'bard' in model_name_lower:
            permissions = [
                ('read', 'database', 'read:database', True),
                ('read', 'cloud', 'read:cloud', True),
            ]
        else:
            permissions = [
                ('read', 'database', 'read:database', True),
                ('write', 'email', 'send:email', False),  # Unauthorized!
            ]
        
        for perm_type, resource, action, is_auth in permissions:
            self.db.save_permission(model_id, perm_type, resource, action, is_auth)
            if not is_auth:
                self.db.add_suspicious_activity(
                    model_id,
                    f"Unauthorized: {action} attempted by {model_name}",
                    action,
                    'high'
                )
    
    def _extract_model_name(self, cmdline: str, process_name: str) -> str:
        """Extract model name from command line"""
        known_models = [
            'gpt-4', 'gpt-4o', 'gpt-3.5', 'gpt-4-turbo',
            'claude-3', 'claude-2', 'claude-instant',
            'gemini-pro', 'gemini-ultra',
            'llama2', 'llama3', 'llama-3',
            'mistral', 'mixtral',
            'falcon-7b', 'falcon-40b',
            'phi-2', 'phi-3',
            'codellama', 'deepseek'
        ]
        
        for model in known_models:
            if model in cmdline.lower():
                return model
        
        clean_name = process_name.replace('.exe', '').replace('-', ' ').title()
        return clean_name
    
    def scan_permissions_for_model(self, model_id: int, process_info: Dict) -> List[Dict]:
        """Scan permissions for a model"""
        model_name = process_info.get('model_name', '').lower()
        permissions = []
        
        # Generate permissions based on model type
        if 'gpt' in model_name or 'openai' in model_name or 'chatgpt' in model_name:
            permissions = [
                {'type': 'read', 'resource': 'database', 'action': 'read:database'},
                {'type': 'read', 'resource': 'files', 'action': 'read:files'},
                {'type': 'write', 'resource': 'email', 'action': 'send:email'},
            ]
        elif 'claude' in model_name:
            permissions = [
                {'type': 'read', 'resource': 'database', 'action': 'read:database'},
                {'type': 'write', 'resource': 'files', 'action': 'write:files'},
                {'type': 'execute', 'resource': 'code', 'action': 'execute:code'},
            ]
        elif 'gemini' in model_name or 'bard' in model_name:
            permissions = [
                {'type': 'read', 'resource': 'database', 'action': 'read:database'},
                {'type': 'read', 'resource': 'cloud', 'action': 'read:cloud'},
            ]
        elif 'deepseek' in model_name:
            permissions = [
                {'type': 'read', 'resource': 'database', 'action': 'read:database'},
                {'type': 'read', 'resource': 'files', 'action': 'read:files'},
                {'type': 'write', 'resource': 'email', 'action': 'send:email'},
            ]
        else:
            permissions = [
                {'type': 'read', 'resource': 'database', 'action': 'read:database'},
                {'type': 'write', 'resource': 'email', 'action': 'send:email'},
            ]
        
        for perm in permissions:
            action = perm['action']
            unauthorized = self.db.check_unauthorized(action)
            is_authorized = unauthorized is None
            
            self.db.save_permission(model_id, perm['type'], perm['resource'], action, is_authorized)
            
            if not is_authorized and unauthorized:
                self.db.add_suspicious_activity(
                    model_id,
                    f"Model attempted {action} - {unauthorized['description']}",
                    action,
                    unauthorized['risk_level']
                )
        
        return permissions