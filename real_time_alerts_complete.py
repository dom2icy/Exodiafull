import os
import re
import json
import base64
import asyncio
import aiohttp
import sqlite3
import threading
from datetime import datetime
from typing import List, Dict, Set
from flask import Flask, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from telethon import TelegramClient, events
from solana.keypair import Keypair
from solana.rpc.async_api import AsyncClient
from solana.transaction import Transaction
from solana.system_program import TransferParams, transfer
from exodia_sdk.security import FernetEncryption
from exodia_sdk.auth import authenticate_token

# Set environment
os.environ['FERNET_KEY'] = "otPo66UgjPf9Iv9w1F0ndhi7HRhfXVO0cWhjKBwWlx8="

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize SocketIO for real-time alerts
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Your exact encryption pattern
encryption = FernetEncryption(key=os.environ.get('FERNET_KEY'))

DATABASE = "real_time_alerts.db"
JUPITER_API_BASE = "https://quote-api.jup.ag/v6"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"

# Real-time connection management
class AlertConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[str]] = {}  # user_id -> set of session_ids
        self.user_preferences: Dict[str, Dict] = {}  # user_id -> alert preferences

    def connect_user(self, user_id: str, session_id: str):
        """Connect user to real-time alerts"""
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(session_id)
        
        # Join user-specific room
        join_room(f"user_{user_id}", sid=session_id)
        
        print(f"User {user_id} connected for real-time alerts (session: {session_id})")

    def disconnect_user(self, user_id: str, session_id: str):
        """Disconnect user from real-time alerts"""
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(session_id)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        
        leave_room(f"user_{user_id}", sid=session_id)
        print(f"User {user_id} disconnected from alerts (session: {session_id})")

    def is_user_connected(self, user_id: str) -> bool:
        """Check if user has active connections"""
        return user_id in self.active_connections and bool(self.active_connections[user_id])

    async def send_alert_to_user(self, user_id: str, alert_data: Dict):
        """Send alert to specific user"""
        if self.is_user_connected(user_id):
            socketio.emit('alert', alert_data, room=f"user_{user_id}")
            print(f"Alert sent to user {user_id}: {alert_data['type']}")

    async def broadcast_alert(self, alert_data: Dict):
        """Broadcast alert to all connected users"""
        socketio.emit('global_alert', alert_data)
        print(f"Global alert broadcasted: {alert_data['type']}")

# Global connection manager
alert_manager = AlertConnectionManager()

def init_alerts_db():
    """Initialize alerts database"""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS user_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            data JSON NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read_status BOOLEAN DEFAULT 0
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id TEXT PRIMARY KEY,
            private_key_encrypted TEXT,
            auto_snipe_enabled BOOLEAN DEFAULT 1,
            snipe_amount_sol REAL DEFAULT 0.1,
            slippage_pct REAL DEFAULT 0.5,
            alert_preferences JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS snipe_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            contract_address TEXT NOT NULL,
            amount_sol REAL,
            slippage_pct REAL,
            status TEXT DEFAULT 'pending',
            tx_signature TEXT,
            error_message TEXT,
            execution_time REAL,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

init_alerts_db()

async def snipe_token_with_alerts(user_id: str, encrypted_private_key_b64: str, recipient: str, 
                                  amount_lamports: int, slippage_pct: float):
    """Your exact sniping pattern with real-time alerts"""
    start_time = asyncio.get_event_loop().time()
    
    # Send start alert
    await alert_manager.send_alert_to_user(user_id, {
        'type': 'snipe_started',
        'contract': recipient,
        'amount_sol': amount_lamports / 1_000_000_000,
        'timestamp': datetime.now().isoformat()
    })
    
    try:
        # Decrypt private key using your exact pattern
        decrypted_bytes = encryption.decrypt(encrypted_private_key_b64.encode())
        key_bytes = base64.b64decode(decrypted_bytes)
        keypair = Keypair.from_secret_key(key_bytes)

        async with AsyncClient(SOLANA_RPC) as client:
            # Build transaction with slippage buffer
            adjusted_amount = int(amount_lamports * (1 - slippage_pct / 100))

            transaction = Transaction()
            transaction.add(
                transfer(
                    TransferParams(
                        from_pubkey=keypair.public_key,
                        to_pubkey=recipient,
                        lamports=adjusted_amount
                    )
                )
            )

            # Send transaction
            response = await client.send_transaction(transaction, keypair)
            signature = response['result']
            
            # Send progress alert
            await alert_manager.send_alert_to_user(user_id, {
                'type': 'transaction_sent',
                'tx_signature': signature,
                'contract': recipient,
                'timestamp': datetime.now().isoformat()
            })
            
            # Confirm transaction status
            confirmation = await client.confirm_transaction(signature)
            execution_time = asyncio.get_event_loop().time() - start_time
            
            if confirmation['result']['value']['err'] is None:
                # Success alert
                await alert_manager.send_alert_to_user(user_id, {
                    'type': 'snipe_success',
                    'tx_signature': signature,
                    'contract': recipient,
                    'amount_sol': amount_lamports / 1_000_000_000,
                    'execution_time': round(execution_time, 2),
                    'solscan_url': f"https://solscan.io/tx/{signature}",
                    'timestamp': datetime.now().isoformat()
                })
                
                print(f"Snipe success! Signature: {signature}")
                return {'success': True, 'signature': signature, 'execution_time': execution_time}
            else:
                error_msg = str(confirmation['result']['value']['err'])
                
                # Error alert
                await alert_manager.send_alert_to_user(user_id, {
                    'type': 'snipe_failed',
                    'contract': recipient,
                    'error': error_msg,
                    'execution_time': round(execution_time, 2),
                    'timestamp': datetime.now().isoformat()
                })
                
                print(f"Transaction error: {error_msg}")
                return {'success': False, 'error': error_msg, 'execution_time': execution_time}
                
    except Exception as e:
        execution_time = asyncio.get_event_loop().time() - start_time
        error_msg = str(e)
        
        # Exception alert
        await alert_manager.send_alert_to_user(user_id, {
            'type': 'snipe_error',
            'contract': recipient,
            'error': error_msg,
            'execution_time': round(execution_time, 2),
            'timestamp': datetime.now().isoformat()
        })
        
        print(f"Exception during sniping: {e}")
        return {'success': False, 'error': error_msg, 'execution_time': execution_time}

async def push_contract_detection_alert(user_id: str, contract_address: str, group_name: str, message_content: str):
    """Push new contract detection alert"""
    alert_data = {
        'type': 'contract_detected',
        'contract_address': contract_address,
        'detected_in_group': group_name,
        'message_preview': message_content[:100] + '...' if len(message_content) > 100 else message_content,
        'timestamp': datetime.now().isoformat(),
        'auto_snipe_pending': True
    }
    
    # Send to specific user
    await alert_manager.send_alert_to_user(user_id, alert_data)
    
    # Store alert in database
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT INTO user_alerts (user_id, alert_type, data)
            VALUES (?, ?, ?)
        ''', (user_id, 'contract_detected', json.dumps(alert_data)))
        conn.commit()

class TelegramSniperWithAlerts:
    """Enhanced Telegram sniper with real-time alerts"""
    
    def __init__(self, user_id: str, api_id: int, api_hash: str, target_groups: List[str]):
        self.user_id = user_id
        self.api_id = api_id
        self.api_hash = api_hash
        self.target_groups = target_groups
        self.client = None
        self.is_running = False

    async def start_monitoring(self):
        """Start monitoring with real-time alerts"""
        try:
            session_name = f"sessions/sniper_{self.user_id}"
            self.client = TelegramClient(session_name, self.api_id, self.api_hash)
            await self.client.start()
            
            # Send connection alert
            await alert_manager.send_alert_to_user(self.user_id, {
                'type': 'monitoring_started',
                'target_groups': self.target_groups,
                'timestamp': datetime.now().isoformat()
            })
            
            # Your exact contract detection pattern
            @self.client.on(events.NewMessage(chats=self.target_groups))
            async def handler(event):
                try:
                    text = event.raw_text or event.message.message
                    group_name = getattr(event.chat, 'title', None) or getattr(event.chat, 'username', 'Unknown')
                    
                    # Detect contracts
                    contract_regex = re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}')
                    contracts = contract_regex.findall(text)
                    
                    for contract in contracts:
                        print(f"[User {self.user_id}] Contract detected: {contract} in {group_name}")
                        
                        # Send detection alert
                        await push_contract_detection_alert(self.user_id, contract, group_name, text)
                        
                        # Auto-snipe if enabled
                        user_settings = self.get_user_settings()
                        if user_settings and user_settings['auto_snipe_enabled']:
                            await self.execute_auto_snipe(contract, user_settings)
                
                except Exception as e:
                    print(f"Handler error for user {self.user_id}: {e}")
                    await alert_manager.send_alert_to_user(self.user_id, {
                        'type': 'monitoring_error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
            
            self.is_running = True
            await self.client.run_until_disconnected()
            
        except Exception as e:
            print(f"Monitoring error for user {self.user_id}: {e}")
            await alert_manager.send_alert_to_user(self.user_id, {
                'type': 'monitoring_failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })

    def get_user_settings(self):
        """Get user settings from database"""
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM user_settings WHERE user_id = ?', (self.user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    async def execute_auto_snipe(self, contract_address: str, user_settings: Dict):
        """Execute automatic snipe with alerts"""
        try:
            if not user_settings['private_key_encrypted']:
                await alert_manager.send_alert_to_user(self.user_id, {
                    'type': 'snipe_skipped',
                    'contract': contract_address,
                    'reason': 'Private key not configured',
                    'timestamp': datetime.now().isoformat()
                })
                return

            amount_lamports = int(user_settings['snipe_amount_sol'] * 1_000_000_000)
            slippage_pct = user_settings['slippage_pct']
            
            # Execute snipe with real-time alerts
            result = await snipe_token_with_alerts(
                self.user_id,
                user_settings['private_key_encrypted'],
                contract_address,
                amount_lamports,
                slippage_pct
            )
            
            # Log execution
            status = 'success' if result['success'] else 'failed'
            with sqlite3.connect(DATABASE) as conn:
                conn.execute('''
                    INSERT INTO snipe_executions 
                    (user_id, contract_address, amount_sol, slippage_pct, status, 
                     tx_signature, error_message, execution_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (self.user_id, contract_address, user_settings['snipe_amount_sol'],
                      slippage_pct, status, result.get('signature'), 
                      result.get('error'), result.get('execution_time', 0)))
                conn.commit()
                
        except Exception as e:
            print(f"Auto-snipe error for user {self.user_id}: {e}")
            await alert_manager.send_alert_to_user(self.user_id, {
                'type': 'auto_snipe_error',
                'contract': contract_address,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")

@socketio.on('join_alerts')
def handle_join_alerts(data):
    """Join user-specific alert room"""
    user_id = data.get('user_id')
    if user_id:
        alert_manager.connect_user(user_id, request.sid)
        emit('alert_status', {'status': 'connected', 'user_id': user_id})

@socketio.on('leave_alerts')
def handle_leave_alerts(data):
    """Leave user-specific alert room"""
    user_id = data.get('user_id')
    if user_id:
        alert_manager.disconnect_user(user_id, request.sid)
        emit('alert_status', {'status': 'disconnected', 'user_id': user_id})

# Flask routes
@app.route('/login', methods=['POST'])
def login():
    """Simple login for testing"""
    data = request.get_json()
    username = data.get('username', 'alert_user')
    session['user_id'] = username
    return jsonify({'status': 'logged_in', 'user_id': username})

@app.route('/alerts/configure', methods=['POST'])
@authenticate_token('alerts_access')
def configure_alerts():
    """Configure user alert settings"""
    user_id = request.user['user_id']
    data = request.json
    
    private_key = data.get('private_key')
    auto_snipe_enabled = data.get('auto_snipe_enabled', True)
    snipe_amount_sol = float(data.get('snipe_amount_sol', 0.1))
    slippage_pct = float(data.get('slippage_pct', 0.5))
    alert_preferences = data.get('alert_preferences', {
        'contract_detection': True,
        'snipe_execution': True,
        'monitoring_status': True,
        'errors': True
    })
    
    # Encrypt private key if provided
    private_key_encrypted = None
    if private_key:
        private_key_encrypted = encryption.encrypt(private_key.encode()).decode()
    
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT OR REPLACE INTO user_settings 
            (user_id, private_key_encrypted, auto_snipe_enabled, snipe_amount_sol, 
             slippage_pct, alert_preferences)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, private_key_encrypted, auto_snipe_enabled, snipe_amount_sol,
              slippage_pct, json.dumps(alert_preferences)))
        conn.commit()
    
    return jsonify({
        'status': 'configured',
        'auto_snipe_enabled': auto_snipe_enabled,
        'snipe_amount_sol': snipe_amount_sol,
        'alert_preferences': alert_preferences
    })

@app.route('/alerts/test', methods=['POST'])
@authenticate_token('alerts_access')
def test_alert():
    """Send test alert to user"""
    user_id = request.user['user_id']
    data = request.json
    
    alert_type = data.get('type', 'test_alert')
    message = data.get('message', 'This is a test alert')
    
    # Send test alert
    test_alert_data = {
        'type': alert_type,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'test': True
    }
    
    # Use asyncio to send alert
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(alert_manager.send_alert_to_user(user_id, test_alert_data))
    loop.close()
    
    return jsonify({'status': 'test_alert_sent', 'alert_data': test_alert_data})

@app.route('/alerts/history', methods=['GET'])
@authenticate_token('alerts_access')
def get_alert_history():
    """Get user alert history"""
    user_id = request.user['user_id']
    limit = int(request.args.get('limit', 50))
    alert_type = request.args.get('type')
    
    query = 'SELECT * FROM user_alerts WHERE user_id = ?'
    params = [user_id]
    
    if alert_type:
        query += ' AND alert_type = ?'
        params.append(alert_type)
    
    query += ' ORDER BY created_at DESC LIMIT ?'
    params.append(limit)
    
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(query, params)
        
        alerts = []
        for row in cursor.fetchall():
            alert = dict(row)
            alert['data'] = json.loads(alert['data'])
            alerts.append(alert)
    
    return jsonify({'alerts': alerts})

@app.route('/alerts/manual_snipe', methods=['POST'])
@authenticate_token('alerts_access')
def manual_snipe_with_alerts():
    """Execute manual snipe with real-time alerts"""
    user_id = request.user['user_id']
    data = request.json
    
    contract_address = data.get('contract_address')
    amount_sol = float(data.get('amount_sol', 0.1))
    slippage_pct = float(data.get('slippage_pct', 0.5))
    
    if not contract_address:
        return jsonify({'error': 'contract_address required'}), 400
    
    # Get user settings
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute('SELECT private_key_encrypted FROM user_settings WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        
        if not row or not row[0]:
            return jsonify({'error': 'Private key not configured'}), 400
        
        private_key_encrypted = row[0]
    
    # Execute snipe with alerts
    amount_lamports = int(amount_sol * 1_000_000_000)
    
    def execute_snipe():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            snipe_token_with_alerts(user_id, private_key_encrypted, contract_address, 
                                   amount_lamports, slippage_pct)
        )
        loop.close()
        return result
    
    result = execute_snipe()
    
    # Log execution
    status = 'success' if result['success'] else 'failed'
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT INTO snipe_executions 
            (user_id, contract_address, amount_sol, slippage_pct, status, 
             tx_signature, error_message, execution_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, contract_address, amount_sol, slippage_pct, status,
              result.get('signature'), result.get('error'), result.get('execution_time', 0)))
        conn.commit()
    
    return jsonify(result)

@app.route('/alerts/connection_status', methods=['GET'])
@authenticate_token('alerts_access')
def get_connection_status():
    """Get user's real-time connection status"""
    user_id = request.user['user_id']
    
    is_connected = alert_manager.is_user_connected(user_id)
    connection_count = len(alert_manager.active_connections.get(user_id, set()))
    
    return jsonify({
        'user_id': user_id,
        'is_connected': is_connected,
        'active_connections': connection_count,
        'total_connected_users': len(alert_manager.active_connections)
    })

@app.route('/system_status', methods=['GET'])
def system_status():
    """Get complete system status"""
    try:
        # Database stats
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM user_settings')
            total_users = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM user_settings WHERE auto_snipe_enabled = 1')
            auto_snipe_users = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM user_alerts')
            total_alerts = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_executions WHERE status = "success"')
            successful_snipes = cursor.fetchone()[0]
        
        # Connection stats
        total_connected_users = len(alert_manager.active_connections)
        total_connections = sum(len(sessions) for sessions in alert_manager.active_connections.values())
        
        return jsonify({
            'database_working': True,
            'total_configured_users': total_users,
            'auto_snipe_enabled_users': auto_snipe_users,
            'total_alerts_sent': total_alerts,
            'successful_snipes': successful_snipes,
            'real_time_connections': {
                'connected_users': total_connected_users,
                'total_connections': total_connections
            },
            'capabilities': {
                'real_time_alerts': True,
                'websocket_connections': True,
                'auto_sniping_with_alerts': True,
                'manual_sniping_with_alerts': True,
                'alert_history': True,
                'connection_management': True
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'System status error: {str(e)}'}), 500

if __name__ == '__main__':
    print("Real-Time Alerts System for Telegram Sniper")
    print("Server: http://localhost:5555")
    print()
    print("Features:")
    print("  ✓ Real-time WebSocket alerts for contract detection")
    print("  ✓ Live snipe execution progress with instant feedback")
    print("  ✓ Monitoring status alerts and error notifications")
    print("  ✓ Alert history and connection management")
    print("  ✓ Manual and automatic sniping with real-time updates")
    print()
    print("WebSocket Events:")
    print("  connect/disconnect - Connection management")
    print("  join_alerts/leave_alerts - Subscribe to user alerts")
    print("  alert - Real-time alert delivery")
    print("  global_alert - System-wide notifications")
    print()
    print("Endpoints:")
    print("  POST /login - Login")
    print("  POST /alerts/configure - Configure alert settings")
    print("  POST /alerts/test - Send test alert")
    print("  GET  /alerts/history - Alert history")
    print("  POST /alerts/manual_snipe - Manual snipe with alerts")
    print("  GET  /alerts/connection_status - Connection status")
    print("  GET  /system_status - System status")
    
    socketio.run(app, host='0.0.0.0', port=5555, debug=False)