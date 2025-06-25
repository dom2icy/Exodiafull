import os
import re
import json
import base64
import time
import asyncio
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List
from flask import Flask, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from exodia_sdk.security import FernetEncryption
from exodia_sdk.auth import authenticate_token
from solana.keypair import Keypair
from solana.rpc.async_api import AsyncClient
from solana.transaction import Transaction
from telethon import TelegramClient, events
import jwt

# Set environment
os.environ['FERNET_KEY'] = "otPo66UgjPf9Iv9w1F0ndhi7HRhfXVO0cWhjKBwWlx8="
os.environ['JWT_SECRET'] = "sniper_jwt_secret_key"

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize SocketIO for real-time sniper events
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Your exact encryption pattern
encryption = FernetEncryption(key=os.environ.get('FERNET_KEY'))

DATABASE = "sniper_ws.db"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"
JUPITER_API_BASE = "https://quote-api.jup.ag/v6"

# Retry configuration
MAX_ATTEMPTS = 3
BASE_DELAY = 1.0

def init_sniper_db():
    """Initialize sniper database with your exact schema"""
    with sqlite3.connect(DATABASE) as conn:
        # Your exact per-group snipe configuration
        conn.execute('''
        CREATE TABLE IF NOT EXISTS snipe_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            slippage REAL DEFAULT 0.5,
            min_liquidity REAL DEFAULT 1000.0,
            auto_snipe BOOLEAN DEFAULT 1,
            max_amount_sol REAL DEFAULT 0.1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, group_id)
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS user_credentials (
            user_id TEXT PRIMARY KEY,
            private_key_encrypted TEXT NOT NULL,
            telegram_api_id TEXT,
            telegram_api_hash TEXT,
            session_active BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS snipe_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            token_address TEXT NOT NULL,
            group_id TEXT NOT NULL,
            amount_sol REAL,
            slippage REAL,
            status TEXT DEFAULT 'pending',
            tx_hash TEXT,
            attempts INTEGER DEFAULT 1,
            error_message TEXT,
            execution_time REAL,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS snipe_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            token_address TEXT NOT NULL,
            tx_hash TEXT,
            status TEXT,
            profit_loss REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

init_sniper_db()

def validate_token(token):
    """Validate JWT token and return user_id"""
    try:
        payload = jwt.decode(token, os.environ.get('JWT_SECRET'), algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.InvalidTokenError:
        return None

def emit_snipe_event(user_id, data):
    """Your exact snipe event emission pattern"""
    socketio.emit('snipe_event', data, room=user_id)
    print(f"Emitted snipe event to user {user_id}: {data['type']}")

def retry_snipe(user_id, token_address, group_id, tx_data, attempts=1, delay=BASE_DELAY):
    """Your exact retry mechanism with exponential backoff"""
    try:
        # Execute snipe transaction
        result = send_transaction(tx_data)
        
        # Log successful execution
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT INTO snipe_executions 
                (user_id, token_address, group_id, amount_sol, status, tx_hash, attempts)
                VALUES (?, ?, ?, ?, 'success', ?, ?)
            ''', (user_id, token_address, group_id, tx_data['amount_sol'], result['tx_hash'], attempts))
            conn.commit()
        
        # Emit success event
        emit_snipe_event(user_id, {
            'type': 'snipe_success',
            'token': token_address,
            'tx_hash': result['tx_hash'],
            'amount_sol': tx_data['amount_sol'],
            'attempts': attempts,
            'timestamp': datetime.now().isoformat()
        })
        
        return result
        
    except Exception as e:
        if attempts < MAX_ATTEMPTS:
            print(f"Snipe attempt {attempts} failed for {token_address}, retrying in {delay}s")
            
            # Emit retry event
            emit_snipe_event(user_id, {
                'type': 'snipe_retry',
                'token': token_address,
                'attempt': attempts,
                'max_attempts': MAX_ATTEMPTS,
                'retry_delay': delay,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            
            time.sleep(delay)
            return retry_snipe(user_id, token_address, group_id, tx_data, attempts + 1, delay * 2)
        else:
            # Log failure after max attempts
            log_failure(user_id, token_address, group_id, str(e), attempts)
            
            # Emit failure event
            emit_snipe_event(user_id, {
                'type': 'snipe_failed',
                'token': token_address,
                'error': str(e),
                'attempts': attempts,
                'timestamp': datetime.now().isoformat()
            })
            
            raise e

def log_failure(user_id, token, group_id, error_message, attempts):
    """Log failed snipe execution"""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT INTO snipe_executions 
            (user_id, token_address, group_id, status, error_message, attempts)
            VALUES (?, ?, ?, 'failed', ?, ?)
        ''', (user_id, token, group_id, error_message, attempts))
        conn.commit()

def send_transaction(tx_data):
    """Execute Solana transaction (simplified for demo)"""
    # Simulate transaction execution
    import random
    
    # 80% success rate for testing
    if random.random() < 0.8:
        return {
            'tx_hash': f"mock_tx_{int(time.time())}_{tx_data['token_address'][:8]}",
            'status': 'confirmed',
            'amount': tx_data['amount_sol']
        }
    else:
        raise Exception("Network congestion - transaction failed")

def get_snipe_config(user_id, group_id):
    """Get per-group snipe configuration"""
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT * FROM snipe_configs 
            WHERE user_id = ? AND group_id = ?
        ''', (user_id, group_id))
        row = cursor.fetchone()
        return dict(row) if row else None

def should_auto_snipe(user_id, group_id):
    """Check if auto-snipe is enabled for group"""
    config = get_snipe_config(user_id, group_id)
    return config and config['auto_snipe']

class TelegramSniperWithWS:
    """Enhanced Telegram sniper with WebSocket integration"""
    
    def __init__(self, user_id, api_id, api_hash):
        self.user_id = user_id
        self.api_id = api_id
        self.api_hash = api_hash
        self.client = None
        self.is_running = False

    async def start_monitoring(self):
        """Start monitoring with WebSocket integration"""
        try:
            session_name = f"sessions/sniper_ws_{self.user_id}"
            self.client = TelegramClient(session_name, self.api_id, self.api_hash)
            await self.client.start()
            
            # Emit monitoring started event
            emit_snipe_event(self.user_id, {
                'type': 'monitoring_started',
                'timestamp': datetime.now().isoformat()
            })
            
            # Your exact contract detection pattern
            @self.client.on(events.NewMessage)
            async def handler(event):
                try:
                    text = event.raw_text or event.message.message
                    chat_id = str(event.chat_id)
                    group_name = getattr(event.chat, 'title', None) or getattr(event.chat, 'username', 'Unknown')
                    
                    # Detect Solana contracts
                    contract_regex = re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}')
                    contracts = contract_regex.findall(text)
                    
                    for contract in contracts:
                        print(f"[User {self.user_id}] Contract detected: {contract} in {group_name}")
                        
                        # Emit contract detection event
                        emit_snipe_event(self.user_id, {
                            'type': 'contract_detected',
                            'token': contract,
                            'group_id': chat_id,
                            'group_name': group_name,
                            'message_preview': text[:100] + '...' if len(text) > 100 else text,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Check auto-snipe configuration
                        if should_auto_snipe(self.user_id, chat_id):
                            await self.execute_auto_snipe(contract, chat_id)
                        else:
                            # Manual snipe fallback - emit manual snipe prompt
                            emit_snipe_event(self.user_id, {
                                'type': 'manual_snipe_prompt',
                                'token': contract,
                                'group_id': chat_id,
                                'group_name': group_name,
                                'auto_snipe': False,
                                'timestamp': datetime.now().isoformat()
                            })
                
                except Exception as e:
                    print(f"Handler error for user {self.user_id}: {e}")
                    emit_snipe_event(self.user_id, {
                        'type': 'monitoring_error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
            
            self.is_running = True
            await self.client.run_until_disconnected()
            
        except Exception as e:
            print(f"Monitoring error for user {self.user_id}: {e}")
            emit_snipe_event(self.user_id, {
                'type': 'monitoring_failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })

    async def execute_auto_snipe(self, token_address, group_id):
        """Execute automatic snipe with retry mechanism"""
        try:
            config = get_snipe_config(self.user_id, group_id)
            if not config:
                return
            
            # Prepare transaction data
            tx_data = {
                'user_id': self.user_id,
                'token_address': token_address,
                'amount_sol': config['max_amount_sol'],
                'slippage': config['slippage'],
                'min_liquidity': config['min_liquidity']
            }
            
            # Emit snipe started event
            emit_snipe_event(self.user_id, {
                'type': 'snipe_started',
                'token': token_address,
                'amount_sol': config['max_amount_sol'],
                'auto_snipe': True,
                'timestamp': datetime.now().isoformat()
            })
            
            # Execute with retry mechanism
            result = retry_snipe(self.user_id, token_address, group_id, tx_data)
            
        except Exception as e:
            print(f"Auto-snipe error for user {self.user_id}: {e}")

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")

@socketio.on('connect_sniper')
def handle_sniper_connect(data):
    """Your exact sniper connection pattern"""
    user_id = validate_token(data['token'])
    if user_id:
        join_room(user_id)
        emit('sniper_status', {'status': 'connected', 'user_id': user_id})
        print(f"Sniper connected for user: {user_id}")
    else:
        emit('sniper_error', {'error': 'Invalid token'})
        disconnect()

@socketio.on('disconnect_sniper')
def handle_sniper_disconnect(data):
    """Disconnect from sniper room"""
    user_id = validate_token(data['token'])
    if user_id:
        leave_room(user_id)
        emit('sniper_status', {'status': 'disconnected'})

# Flask routes
@app.route('/login', methods=['POST'])
def login():
    """JWT login for WebSocket authentication"""
    data = request.get_json()
    username = data.get('username', 'sniper_user')
    
    # Create JWT token
    token = jwt.encode({
        'user_id': username,
        'exp': datetime.now().timestamp() + 3600  # 1 hour
    }, os.environ.get('JWT_SECRET'), algorithm='HS256')
    
    session['user_id'] = username
    
    return jsonify({
        'access_token': token,
        'user_id': username,
        'expires_in': 3600
    })

@app.route('/snipe_config', methods=['POST'])
@authenticate_token('sniper_access')
def save_snipe_config():
    """Your exact auto-snipe config route - Per-group setup"""
    user_id = request.user['user_id']
    data = request.json
    
    group_id = data.get('group_id')
    slippage = float(data.get('slippage', 0.5))
    min_liquidity = float(data.get('min_liquidity', 1000.0))
    auto_snipe = bool(data.get('auto_snipe', True))
    max_amount_sol = float(data.get('max_amount_sol', 0.1))
    
    if not group_id:
        return jsonify({'error': 'group_id required'}), 400
    
    # Save per-group configuration
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT OR REPLACE INTO snipe_configs 
            (user_id, group_id, slippage, min_liquidity, auto_snipe, max_amount_sol)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, group_id, slippage, min_liquidity, auto_snipe, max_amount_sol))
        conn.commit()
    
    return jsonify({
        'status': 'config_saved',
        'group_id': group_id,
        'slippage': slippage,
        'min_liquidity': min_liquidity,
        'auto_snipe': auto_snipe,
        'max_amount_sol': max_amount_sol
    })

@app.route('/snipe_config/<group_id>', methods=['GET'])
@authenticate_token('sniper_access')
def get_snipe_config_endpoint(group_id):
    """Get snipe configuration for specific group"""
    user_id = request.user['user_id']
    
    config = get_snipe_config(user_id, group_id)
    if config:
        return jsonify(config)
    else:
        # Return default configuration
        return jsonify({
            'user_id': user_id,
            'group_id': group_id,
            'slippage': 0.5,
            'min_liquidity': 1000.0,
            'auto_snipe': True,
            'max_amount_sol': 0.1
        })

@app.route('/snipe', methods=['POST'])
@authenticate_token('sniper_access')
def snipe_token():
    """Your exact manual snipe route - Only if auto_snipe=False"""
    user_id = request.user['user_id']
    data = request.json
    
    token_address = data.get('token_address')
    group_id = data.get('group_id')
    amount_sol = float(data.get('amount_sol', 0.1))
    
    if not token_address:
        return jsonify({'error': 'token_address required'}), 400
    
    # Get user's encrypted private key
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute('SELECT private_key_encrypted FROM user_credentials WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'Private key not configured'}), 400
        
        # Decrypt key
        private_key_b64 = encryption.decrypt(row[0].encode()).decode()
    
    try:
        # Prepare transaction data
        tx_data = {
            'user_id': user_id,
            'token_address': token_address,
            'amount_sol': amount_sol,
            'private_key': private_key_b64
        }
        
        # Emit manual snipe started
        emit_snipe_event(user_id, {
            'type': 'snipe_started',
            'token': token_address,
            'amount_sol': amount_sol,
            'auto_snipe': False,
            'timestamp': datetime.now().isoformat()
        })
        
        # Execute with retry mechanism
        result = retry_snipe(user_id, token_address, group_id or 'manual', tx_data)
        
        return jsonify({
            'success': True,
            'tx_hash': result['tx_hash'],
            'amount_sol': amount_sol,
            'token_address': token_address
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'token_address': token_address
        }), 500

@app.route('/configure_credentials', methods=['POST'])
@authenticate_token('sniper_access')
def configure_credentials():
    """Configure user credentials for sniping"""
    user_id = request.user['user_id']
    data = request.json
    
    private_key = data.get('private_key')
    telegram_api_id = data.get('telegram_api_id')
    telegram_api_hash = data.get('telegram_api_hash')
    
    if not private_key:
        return jsonify({'error': 'private_key required'}), 400
    
    # Encrypt private key
    private_key_encrypted = encryption.encrypt(private_key.encode()).decode()
    
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT OR REPLACE INTO user_credentials 
            (user_id, private_key_encrypted, telegram_api_id, telegram_api_hash)
            VALUES (?, ?, ?, ?)
        ''', (user_id, private_key_encrypted, telegram_api_id, telegram_api_hash))
        conn.commit()
    
    return jsonify({
        'status': 'credentials_configured',
        'has_private_key': True,
        'has_telegram_api': bool(telegram_api_id and telegram_api_hash)
    })

@app.route('/snipe_history', methods=['GET'])
@authenticate_token('sniper_access')
def get_snipe_history():
    """Get snipe execution history with live feed"""
    user_id = request.user['user_id']
    limit = int(request.args.get('limit', 50))
    
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT * FROM snipe_executions 
            WHERE user_id = ? 
            ORDER BY executed_at DESC 
            LIMIT ?
        ''', (user_id, limit))
        
        executions = []
        for row in cursor.fetchall():
            execution = dict(row)
            if execution['tx_hash']:
                execution['solscan_url'] = f"https://solscan.io/tx/{execution['tx_hash']}"
            executions.append(execution)
    
    return jsonify({'executions': executions})

@app.route('/snipe_analytics', methods=['GET'])
@authenticate_token('sniper_access')
def get_snipe_analytics():
    """Get snipe analytics and statistics"""
    user_id = request.user['user_id']
    
    with sqlite3.connect(DATABASE) as conn:
        # Success/failure stats
        cursor = conn.execute('''
            SELECT 
                status,
                COUNT(*) as count,
                AVG(execution_time) as avg_time,
                SUM(amount_sol) as total_volume
            FROM snipe_executions 
            WHERE user_id = ? 
            GROUP BY status
        ''', (user_id,))
        
        stats = {}
        for row in cursor.fetchall():
            stats[row[0]] = {
                'count': row[1],
                'avg_time': round(row[2] or 0, 3),
                'total_volume': round(row[3] or 0, 3)
            }
        
        # Recent activity (last 24 hours)
        cursor = conn.execute('''
            SELECT COUNT(*) FROM snipe_executions 
            WHERE user_id = ? AND executed_at > datetime('now', '-1 day')
        ''', (user_id,))
        recent_activity = cursor.fetchone()[0]
        
        # Group configurations
        cursor = conn.execute('''
            SELECT COUNT(*) FROM snipe_configs 
            WHERE user_id = ? AND auto_snipe = 1
        ''', (user_id,))
        auto_snipe_groups = cursor.fetchone()[0]
    
    return jsonify({
        'statistics': stats,
        'recent_activity_24h': recent_activity,
        'auto_snipe_groups': auto_snipe_groups,
        'success_rate': round((stats.get('success', {}).get('count', 0) / 
                              (stats.get('success', {}).get('count', 0) + 
                               stats.get('failed', {}).get('count', 1)) * 100), 2)
    })

@app.route('/system_status', methods=['GET'])
def system_status():
    """Get system status"""
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM user_credentials')
            total_users = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_configs WHERE auto_snipe = 1')
            auto_snipe_configs = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_executions')
            total_executions = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_executions WHERE status = "success"')
            successful_snipes = cursor.fetchone()[0]
        
        return jsonify({
            'database_working': True,
            'total_configured_users': total_users,
            'auto_snipe_configurations': auto_snipe_configs,
            'total_snipe_executions': total_executions,
            'successful_snipes': successful_snipes,
            'websocket_active': True,
            'capabilities': {
                'real_time_events': True,
                'auto_snipe_per_group': True,
                'manual_snipe_fallback': True,
                'retry_mechanism': True,
                'live_analytics': True
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'System status error: {str(e)}'}), 500

if __name__ == '__main__':
    print("WebSocket Sniper System - Real-Time Automated Trading")
    print("Server: http://localhost:4444")
    print()
    print("Features:")
    print("  ✓ Real-time WebSocket sniper events")
    print("  ✓ Per-group auto-snipe configuration")
    print("  ✓ Manual snipe fallback system")
    print("  ✓ Retry mechanism with exponential backoff")
    print("  ✓ Live feed and analytics")
    print()
    print("WebSocket Events:")
    print("  connect_sniper - Connect to sniper room")
    print("  snipe_event - Real-time snipe notifications")
    print("  sniper_status - Connection status updates")
    print()
    print("Frontend Usage:")
    print("  const socket = io.connect(SOCKET_URL);")
    print("  socket.emit('connect_sniper', { token: jwt });")
    print("  socket.on('snipe_event', handleSnipeEvent);")
    print()
    print("Endpoints:")
    print("  POST /login - JWT authentication")
    print("  POST /configure_credentials - Setup keys")
    print("  POST /snipe_config - Per-group auto-snipe setup")
    print("  GET  /snipe_config/<group_id> - Get group config")
    print("  POST /snipe - Manual snipe execution")
    print("  GET  /snipe_history - Execution history")
    print("  GET  /snipe_analytics - Statistics and analytics")
    print("  GET  /system_status - System status")
    
    socketio.run(app, host='0.0.0.0', port=4444, debug=False)