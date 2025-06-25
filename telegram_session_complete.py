import os
import re
import asyncio
import sqlite3
import threading
from datetime import datetime
from flask import Flask, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from exodia_sdk.security import FernetEncryption

# Set environment
os.environ['FERNET_KEY'] = "otPo66UgjPf9Iv9w1F0ndhi7HRhfXVO0cWhjKBwWlx8="
os.environ['JWT_SECRET_KEY'] = "telegram_session_jwt_secret"

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.secret_key = os.urandom(24)

# Initialize extensions
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Your exact encryption pattern
encryption = FernetEncryption(key=os.environ.get('FERNET_KEY'))

DATABASE = "telegram_sessions.db"
API_ID = 21724048  # Use your actual API_ID
API_HASH = "82c3e0c51d4c6f46bce0e38b7dc3c9b8"  # Use your actual API_HASH

def init_session_db():
    """Initialize Telegram session database"""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS telegram_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            session_encrypted TEXT NOT NULL,
            phone_number TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id)
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS user_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            group_title TEXT,
            is_monitored BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS token_detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            token_address TEXT NOT NULL,
            message_content TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

init_session_db()

def encrypt_data(data):
    """Your exact encryption pattern"""
    return encryption.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Your exact decryption pattern"""
    return encryption.decrypt(encrypted_data.encode()).decode()

def generate_session(phone_number):
    """Your exact session generation pattern"""
    try:
        client = TelegramClient(StringSession(), API_ID, API_HASH)
        
        async def get_session():
            await client.start(phone_number)
            session_str = client.session.save()
            await client.disconnect()
            return session_str
        
        # Run the async function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        session_str = loop.run_until_complete(get_session())
        loop.close()
        
        # Your exact encryption pattern
        return encrypt_data(session_str)
        
    except Exception as e:
        print(f"Session generation error: {e}")
        raise e

def get_groups(session_str_encrypted):
    """Your exact group fetching pattern"""
    try:
        session_str = decrypt_data(session_str_encrypted)
        client = TelegramClient(StringSession(session_str), API_ID, API_HASH)
        
        async def inner():
            await client.start()
            dialogs = await client.get_dialogs()
            groups = [(str(d.id), d.title) for d in dialogs if d.is_group or d.is_channel]
            await client.disconnect()
            return groups
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(inner())
        loop.close()
        
        return result
        
    except Exception as e:
        print(f"Group fetching error: {e}")
        return []

class TelegramMonitor:
    """Real-time Telegram monitor with WebSocket integration"""
    
    def __init__(self, user_id, session_str_encrypted, monitored_groups):
        self.user_id = user_id
        self.session_str = decrypt_data(session_str_encrypted)
        self.monitored_groups = monitored_groups
        self.client = None
        self.is_running = False

    async def start_monitoring(self):
        """Start monitoring with WebSocket notifications"""
        try:
            self.client = TelegramClient(StringSession(self.session_str), API_ID, API_HASH)
            await self.client.start()
            
            # Emit connection status
            socketio.emit('telegram_connected', {
                'user_id': self.user_id,
                'groups_count': len(self.monitored_groups),
                'timestamp': datetime.now().isoformat()
            }, room=self.user_id)
            
            # Your exact contract detection pattern
            @self.client.on(events.NewMessage(chats=self.monitored_groups))
            async def handler(event):
                try:
                    message = event.raw_text or event.message.message
                    group_id = str(event.chat_id)
                    group_title = getattr(event.chat, 'title', 'Unknown')
                    
                    # Detect Solana token addresses
                    token_regex = re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}')
                    tokens = token_regex.findall(message)
                    
                    for token in tokens:
                        print(f"[User {self.user_id}] Token detected: {token} in {group_title}")
                        
                        # Store detection
                        with sqlite3.connect(DATABASE) as conn:
                            conn.execute('''
                                INSERT INTO token_detections 
                                (user_id, group_id, token_address, message_content)
                                VALUES (?, ?, ?, ?)
                            ''', (self.user_id, group_id, token, message[:500]))
                            conn.commit()
                        
                        # Your exact WebSocket notification pattern
                        socketio.emit('new_token_detected', {
                            'symbol': token[:8] + '...',
                            'token_address': token,
                            'group_id': group_id,
                            'group_title': group_title,
                            'message_preview': message[:100] + '...' if len(message) > 100 else message,
                            'timestamp': datetime.now().isoformat()
                        }, room=self.user_id)
                        
                        # Simulate swap execution for demo
                        await self.simulate_swap(token, group_title)
                
                except Exception as e:
                    print(f"Handler error: {e}")
                    socketio.emit('monitoring_error', {
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }, room=self.user_id)
            
            self.is_running = True
            await self.client.run_until_disconnected()
            
        except Exception as e:
            print(f"Monitoring error: {e}")
            socketio.emit('monitoring_failed', {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }, room=self.user_id)

    async def simulate_swap(self, token_address, group_title):
        """Simulate swap execution with WebSocket notifications"""
        try:
            # Simulate processing delay
            await asyncio.sleep(1)
            
            # 75% success rate for demo
            import random
            if random.random() < 0.75:
                # Success
                tx_hash = f"mock_tx_{int(datetime.now().timestamp())}_{token_address[:8]}"
                
                socketio.emit('swap_executed', {
                    'token_address': token_address,
                    'tx_hash': tx_hash,
                    'amount_sol': 0.1,
                    'group_title': group_title,
                    'solscan_url': f"https://solscan.io/tx/{tx_hash}",
                    'timestamp': datetime.now().isoformat()
                }, room=self.user_id)
            else:
                # Failure
                socketio.emit('swap_failed', {
                    'token_address': token_address,
                    'reason': 'Insufficient liquidity',
                    'group_title': group_title,
                    'timestamp': datetime.now().isoformat()
                }, room=self.user_id)
                
        except Exception as e:
            print(f"Swap simulation error: {e}")

# Active monitors
active_monitors = {}

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    print(f"Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected")

@socketio.on('join')
def handle_join(data):
    """Your exact join pattern"""
    user_id = data.get('user_id')
    if user_id:
        join_room(user_id)
        emit('joined', {'user_id': user_id, 'status': 'connected'})
        print(f"User {user_id} joined room")

@socketio.on('leave')
def handle_leave(data):
    """Leave user room"""
    user_id = data.get('user_id')
    if user_id:
        leave_room(user_id)
        emit('left', {'user_id': user_id, 'status': 'disconnected'})

# Flask routes
@app.route('/login', methods=['POST'])
def login():
    """JWT login"""
    data = request.get_json()
    username = data.get('username', 'telegram_user')
    
    access_token = create_access_token(identity=username)
    
    return jsonify({
        'access_token': access_token,
        'user_id': username
    })

@app.route('/connect_telegram', methods=['POST'])
@jwt_required()
def connect_telegram():
    """Your exact Telegram connection pattern"""
    user_id = get_jwt_identity()
    phone = request.json.get('phone')
    
    if not phone:
        return jsonify({'error': 'Phone number required'}), 400
    
    try:
        # Generate session with your exact pattern
        encrypted_session = generate_session(phone)
        
        # Store in database
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO telegram_sessions 
                (user_id, session_encrypted, phone_number)
                VALUES (?, ?, ?)
            ''', (user_id, encrypted_session, phone))
            conn.commit()
        
        return jsonify({'message': 'Telegram connected successfully'})
        
    except Exception as e:
        return jsonify({'error': f'Connection failed: {str(e)}'}), 500

@app.route('/get_telegram_groups', methods=['GET'])
@jwt_required()
def get_telegram_groups():
    """Your exact group fetching pattern"""
    user_id = get_jwt_identity()
    
    # Get session from database
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute('SELECT session_encrypted FROM telegram_sessions WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'No session found'}), 404
        
        session_encrypted = row[0]
    
    try:
        # Get groups with your exact pattern
        groups = get_groups(session_encrypted)
        
        # Store groups in database
        with sqlite3.connect(DATABASE) as conn:
            # Clear existing groups
            conn.execute('DELETE FROM user_groups WHERE user_id = ?', (user_id,))
            
            # Insert new groups
            for group_id, group_title in groups:
                conn.execute('''
                    INSERT INTO user_groups (user_id, group_id, group_title)
                    VALUES (?, ?, ?)
                ''', (user_id, group_id, group_title))
            conn.commit()
        
        return jsonify([{'id': gid, 'title': title} for gid, title in groups])
        
    except Exception as e:
        return jsonify({'error': f'Failed to fetch groups: {str(e)}'}), 500

@app.route('/start_monitoring', methods=['POST'])
@jwt_required()
def start_monitoring():
    """Start Telegram monitoring"""
    user_id = get_jwt_identity()
    data = request.json
    monitored_group_ids = data.get('group_ids', [])
    
    if user_id in active_monitors:
        return jsonify({'status': 'already_running'})
    
    # Get session
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute('SELECT session_encrypted FROM telegram_sessions WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'No session found'}), 404
        
        session_encrypted = row[0]
        
        # Update monitored status
        conn.execute('UPDATE user_groups SET is_monitored = 0 WHERE user_id = ?', (user_id,))
        for group_id in monitored_group_ids:
            conn.execute('UPDATE user_groups SET is_monitored = 1 WHERE user_id = ? AND group_id = ?', 
                        (user_id, group_id))
        conn.commit()
    
    # Start monitoring
    monitor = TelegramMonitor(user_id, session_encrypted, monitored_group_ids)
    
    def run_monitor():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(monitor.start_monitoring())
        loop.close()
    
    thread = threading.Thread(target=run_monitor, daemon=True)
    thread.start()
    
    active_monitors[user_id] = monitor
    
    return jsonify({
        'status': 'monitoring_started',
        'groups_count': len(monitored_group_ids)
    })

@app.route('/stop_monitoring', methods=['POST'])
@jwt_required()
def stop_monitoring():
    """Stop Telegram monitoring"""
    user_id = get_jwt_identity()
    
    if user_id in active_monitors:
        monitor = active_monitors[user_id]
        monitor.is_running = False
        if monitor.client:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(monitor.client.disconnect())
                loop.close()
            except:
                pass
        del active_monitors[user_id]
        
        return jsonify({'status': 'monitoring_stopped'})
    else:
        return jsonify({'status': 'not_running'})

@app.route('/monitoring_status', methods=['GET'])
@jwt_required()
def get_monitoring_status():
    """Get monitoring status"""
    user_id = get_jwt_identity()
    
    is_running = user_id in active_monitors
    
    # Get monitored groups
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT group_id, group_title FROM user_groups 
            WHERE user_id = ? AND is_monitored = 1
        ''', (user_id,))
        monitored_groups = [dict(row) for row in cursor.fetchall()]
        
        # Get detection count
        cursor = conn.execute('SELECT COUNT(*) FROM token_detections WHERE user_id = ?', (user_id,))
        total_detections = cursor.fetchone()[0]
    
    return jsonify({
        'is_running': is_running,
        'monitored_groups': monitored_groups,
        'total_detections': total_detections
    })

@app.route('/token_detections', methods=['GET'])
@jwt_required()
def get_token_detections():
    """Get token detection history"""
    user_id = get_jwt_identity()
    limit = int(request.args.get('limit', 50))
    
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT td.*, ug.group_title 
            FROM token_detections td
            LEFT JOIN user_groups ug ON td.group_id = ug.group_id AND td.user_id = ug.user_id
            WHERE td.user_id = ? 
            ORDER BY td.detected_at DESC 
            LIMIT ?
        ''', (user_id, limit))
        
        detections = []
        for row in cursor.fetchall():
            detection = dict(row)
            detection['detected_at'] = detection['detected_at']
            detections.append(detection)
    
    return jsonify({'detections': detections})

@app.route('/system_status', methods=['GET'])
def system_status():
    """Get system status"""
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM telegram_sessions')
            total_sessions = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM user_groups WHERE is_monitored = 1')
            monitored_groups = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM token_detections')
            total_detections = cursor.fetchone()[0]
        
        return jsonify({
            'database_working': True,
            'total_sessions': total_sessions,
            'active_monitors': len(active_monitors),
            'monitored_groups': monitored_groups,
            'total_detections': total_detections,
            'websocket_active': True,
            'capabilities': {
                'telegram_sessions': True,
                'group_fetching': True,
                'real_time_monitoring': True,
                'websocket_notifications': True,
                'token_detection': True
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'System status error: {str(e)}'}), 500

if __name__ == '__main__':
    print("Complete Telegram Session Management System")
    print("Server: http://localhost:3333")
    print()
    print("Features:")
    print("  ✓ Telegram StringSession generation with encryption")
    print("  ✓ Group fetching and management")
    print("  ✓ Real-time token detection with WebSocket notifications")
    print("  ✓ Session persistence and monitoring")
    print()
    print("WebSocket Events:")
    print("  join - Join user room for notifications")
    print("  new_token_detected - Real-time token alerts")
    print("  swap_executed - Successful swap notifications")
    print("  swap_failed - Failed swap alerts")
    print()
    print("Frontend Usage:")
    print("  const socket = io('http://localhost:3333');")
    print("  socket.emit('join', { user_id: currentUserId });")
    print("  socket.on('new_token_detected', showNotification);")
    print("  socket.on('swap_executed', updateTxFeed);")
    print("  socket.on('swap_failed', showAlert);")
    print()
    print("Endpoints:")
    print("  POST /login - JWT authentication")
    print("  POST /connect_telegram - Connect Telegram with phone")
    print("  GET  /get_telegram_groups - Fetch user groups")
    print("  POST /start_monitoring - Start token monitoring")
    print("  POST /stop_monitoring - Stop monitoring")
    print("  GET  /monitoring_status - Get monitoring status")
    print("  GET  /token_detections - Get detection history")
    print("  GET  /system_status - System status")
    
    socketio.run(app, host='0.0.0.0', port=3333, debug=False)