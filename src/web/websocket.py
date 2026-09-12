"""
Flask-SocketIO WebSocket server for real-time event broadcasting.

Broadcasts agent discoveries, actions, alerts, and sub-agent updates to subscribed clients.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room

from src.core.database import Database

_socketio: Optional[SocketIO] = None
_app: Optional[Flask] = None


def get_socketio() -> Optional[SocketIO]:
    return _socketio


class WebSocketServer:
    """Real-time event broadcaster with client subscription management."""

    def __init__(
        self,
        db: Optional[Database] = None,
        host: str = '0.0.0.0',
        port: int = 5001,
    ):
        global _socketio, _app
        self.db = db or Database()
        self.host = host
        self.port = port
        self._subscriptions: Dict[str, Set[str]] = {}  # sid -> rooms
        self._callbacks: List[Callable[[Dict], None]] = []

        _app = Flask(__name__)
        _app.config['SECRET_KEY'] = 'guardian-agent-ws'
        CORS(_app, resources={r'/*': {'origins': '*'}})
        _socketio = SocketIO(_app, cors_allowed_origins='*', async_mode='threading')

        self.app = _app
        self.socketio = _socketio
        self._register_routes()
        self._register_events()

    def _register_routes(self) -> None:
        @self.app.route('/api/ws/status')
        def ws_status():
            return jsonify({
                'status': 'running',
                'subscriptions': sum(len(v) for v in self._subscriptions.values()),
                'timestamp': datetime.now().isoformat(),
            })

        @self.app.route('/api/ws/broadcast', methods=['POST'])
        def manual_broadcast():
            data = request.json or {}
            event = data.get('event', 'platform_event')
            payload = data.get('payload', {})
            self.broadcast(event, payload, room=data.get('room'))
            return jsonify({'status': 'broadcast', 'event': event})

    def _register_events(self) -> None:
        @self.socketio.on('connect')
        def on_connect():
            emit('connected', {'message': 'Guardian Agent WebSocket connected'})

        @self.socketio.on('disconnect')
        def on_disconnect():
            sid = request.sid
            self._subscriptions.pop(sid, None)

        @self.socketio.on('subscribe')
        def on_subscribe(data):
            sid = request.sid
            room = (data or {}).get('room', 'all')
            join_room(room)
            self._subscriptions.setdefault(sid, set()).add(room)
            emit('subscribed', {'room': room})

        @self.socketio.on('subscribe_agent')
        def on_subscribe_agent(data):
            sid = request.sid
            agent_id = (data or {}).get('agent_id')
            room = f'agent_{agent_id}'
            join_room(room)
            self._subscriptions.setdefault(sid, set()).add(room)
            emit('subscribed', {'room': room, 'agent_id': agent_id})

        @self.socketio.on('unsubscribe')
        def on_unsubscribe(data):
            sid = request.sid
            room = (data or {}).get('room', 'all')
            leave_room(room)
            if sid in self._subscriptions:
                self._subscriptions[sid].discard(room)

        @self.socketio.on('get_snapshot')
        def on_get_snapshot():
            emit('snapshot', self._build_snapshot())

    def _build_snapshot(self) -> Dict:
        agents = self.db.get_all_agents()
        trees = []
        for agent in agents:
            subs = self.db.get_subagents(agent['id'])
            trees.append({
                'agent': agent,
                'subagents': subs,
                'recent_actions': self.db.get_actions(agent_id=agent['id'], limit=5),
            })
        return {
            'timestamp': datetime.now().isoformat(),
            'agents': agents,
            'trees': trees,
            'alerts': self.db.get_alerts(unacknowledged_only=True, limit=10),
        }

    def broadcast(
        self,
        event: str,
        payload: Dict,
        room: Optional[str] = None,
    ) -> None:
        """Broadcast event to all clients or a specific room."""
        data = {
            **payload,
            'timestamp': datetime.now().isoformat(),
        }
        if room:
            self.socketio.emit(event, data, room=room)
        else:
            self.socketio.emit(event, data, broadcast=True)
        for cb in self._callbacks:
            try:
                cb({'event': event, 'payload': data})
            except Exception:
                pass

    def broadcast_agent_discovered(self, agent: Dict) -> None:
        self.broadcast('agent_discovered', {'agent': agent})

    def broadcast_subagent_discovered(self, agent_id: int, subagent: Dict) -> None:
        self.broadcast(
            'subagent_discovered',
            {'agent_id': agent_id, 'subagent': subagent},
            room=f'agent_{agent_id}',
        )

    def broadcast_action(self, action: Dict) -> None:
        agent_id = action.get('agent_id') or action.get('parent_model_id')
        self.broadcast('action_tracked', {'action': action}, room=f'agent_{agent_id}' if agent_id else None)

    def broadcast_alert(self, alert: Dict) -> None:
        self.broadcast('alert_created', {'alert': alert})

    def on_event(self, callback: Callable[[Dict], None]) -> None:
        self._callbacks.append(callback)

    def run(self, debug: bool = False) -> None:
        """Start the WebSocket server (blocking)."""
        print(f"""
╔═══════════════════════════════════════════════════════════════════╗
║  Guardian Agent WebSocket Server                                  ║
║  ws://{self.host}:{self.port}                                      ║
║  Events: agent_discovered, subagent_discovered, action_tracked    ║
╚═══════════════════════════════════════════════════════════════════╝
        """)
        self.socketio.run(self.app, host=self.host, port=self.port, debug=debug, allow_unsafe_werkzeug=True)

    def run_background(self, debug: bool = False) -> threading.Thread:
        """Start server in a background thread."""
        t = threading.Thread(
            target=lambda: self.run(debug=debug),
            daemon=True,
            name='guardian-ws',
        )
        t.start()
        return t
