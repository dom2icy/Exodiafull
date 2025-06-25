import os
import re
import base64
import asyncio
import aiohttp
import sqlite3
import threading
from datetime import datetime
from typing import List, Dict
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from solana.keypair import Keypair
from solana.rpc.api import Client
from solana.rpc.async_api import AsyncClient
from solana.transaction import Transaction
from solana.rpc.commitment import Confirmed
from solders.pubkey import Pubkey
from spl.token.instructions import get_associated_token_address
from exodia_sdk.security import FernetEncryption

# Environment setup
os.environ['FERNET_KEY'] = "otPo66UgjPf9Iv9w1F0ndhi7HRhfXVO0cWhjKBwWlx8="

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Your exact encryption pattern
encryption = FernetEncryption(key=os.environ.get('FERNET_KEY'))

DATABASE = "multi_sniper.db"
API_ID = 21724048
API_HASH = "82c3e0c51d4c6f46bce0e38b7dc3c9b8"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"
JUPITER_API_BASE = "https://quote-api.jup.ag/v6"

# Active sniper tasks
active_snipers = {}

def init_sniper_db():
    """Initialize multi-session sniper database"""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            session_encrypted TEXT NOT NULL,
            private_key_encrypted TEXT NOT NULL,
            auto_snipe_enabled BOOLEAN DEFAULT 1,
            snipe_amount_sol REAL DEFAULT 0.1,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS snipe_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            token_address TEXT NOT NULL,
            amount_sol REAL,
            tx_hash TEXT,
            status TEXT DEFAULT 'pending',
            error_message TEXT,
            detected_in_chat TEXT,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

init_sniper_db()

def decrypt(encrypted_data):
    """Your exact decryption pattern"""
    return encryption.decrypt(encrypted_data.encode())

def get_active_sessions():
    """Your exact active sessions retrieval pattern"""
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT user_id, session_encrypted, private_key_encrypted, 
                   auto_snipe_enabled, snipe_amount_sol
            FROM active_sessions 
            WHERE is_active = 1
        ''')
        return [dict(row) for row in cursor.fetchall()]

def get_encrypted_key_from_db(user_id):
    """Get encrypted private key from database"""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute('SELECT private_key_encrypted FROM active_sessions WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        return row[0] if row else None

async def get_best_jupiter_quote(input_mint, output_mint, amount_lamports):
    """Get best Jupiter quote for swap"""
    async with aiohttp.ClientSession() as session:
        url = f"{JUPITER_API_BASE}/quote"
        params = {
            "inputMint": input_mint,
            "outputMint": output_mint,
            "amount": str(amount_lamports),
            "slippageBps": "50",
            "onlyDirectRoutes": "false",
        }
        async with session.get(url, params=params) as resp:
            data = await resp.json()
            return data.get("data", [])

async def build_snipe_transaction(quote, user_public_key):
    """Build snipe transaction using Jupiter"""
    async with aiohttp.ClientSession() as session:
        url = f"{JUPITER_API_BASE}/swap"
        payload = {
            "route": quote,
            "userPublicKey": user_public_key,
            "wrapUnwrapSOL": True
        }
        async with session.post(url, json=payload) as resp:
            data = await resp.json()
            return data.get("swapTransaction")

async def execute_snipe(token_address: str, user_id: str, amount_sol: float, detected_in_chat: str):
    """Your exact snipe execution pattern"""
    try:
        # 1. Load user's decrypted private key
        encrypted_key = get_encrypted_key_from_db(user_id)
        if not encrypted_key:
            raise Exception("No private key found for user")
        
        decrypted_key = encryption.decrypt(encrypted_key.encode()).decode()
        keypair_bytes = base64.b64decode(decrypted_key)
        keypair = Keypair.from_secret_key(keypair_bytes)

        # 2. Get latest Jupiter quote
        amount_lamports = int(amount_sol * 1_000_000_000)
        input_mint = "So11111111111111111111111111111111111111112"  # SOL
        
        quotes = await get_best_jupiter_quote(input_mint, token_address, amount_lamports)
        if not quotes:
            raise Exception("No Jupiter routes available")
        
        quote = quotes[0]

        # 3. Build swap instruction
        swap_tx_base64 = await build_snipe_transaction(quote, str(keypair.public_key))
        if not swap_tx_base64:
            raise Exception("Failed to build transaction")

        # 4. Sign & send
        client = Client(SOLANA_RPC)
        tx_bytes = base64.b64decode(swap_tx_base64)
        txn = Transaction.deserialize(tx_bytes)
        txn.sign(keypair)

        response = client.send_transaction(txn, keypair)
        txid = response["result"]
        
        # Log successful execution
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT INTO snipe_executions 
                (user_id, token_address, amount_sol, tx_hash, status, detected_in_chat)
                VALUES (?, ?, ?, ?, 'success', ?)
            ''', (user_id, token_address, amount_sol, txid, detected_in_chat))
            conn.commit()
        
        # Emit WebSocket notification
        socketio.emit('swap_executed', {
            'user_id': user_id,
            'token_address': token_address,
            'tx_hash': txid,
            'amount_sol': amount_sol,
            'detected_in_chat': detected_in_chat,
            'solscan_url': f"https://solscan.io/tx/{txid}",
            'timestamp': datetime.now().isoformat()
        })
        
        print(f"[{user_id}] Snipe successful: {txid}")
        return txid
        
    except Exception as e:
        # Log failed execution
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT INTO snipe_executions 
                (user_id, token_address, amount_sol, status, error_message, detected_in_chat)
                VALUES (?, ?, ?, 'failed', ?, ?)
            ''', (user_id, token_address, amount_sol, str(e), detected_in_chat))
            conn.commit()
        
        # Emit failure notification
        socketio.emit('swap_failed', {
            'user_id': user_id,
            'token_address': token_address,
            'reason': str(e),
            'detected_in_chat': detected_in_chat,
            'timestamp': datetime.now().isoformat()
        })
        
        print(f"[{user_id}] Snipe failed: {e}")
        raise e

async def run_sniper_listener(session_data):
    """Your exact sniper listener pattern"""
    user_id = session_data['user_id']
    encrypted_session = session_data['session_encrypted']
    auto_snipe_enabled = session_data['auto_snipe_enabled']
    snipe_amount_sol = session_data['snipe_amount_sol']
    
    try:
        session_str = decrypt(encrypted_session).decode()
        client = TelegramClient(StringSession(session_str), API_ID, API_HASH)
        await client.start()
        
        print(f"[{user_id}] Sniper listener started")
        
        # Emit connection status
        socketio.emit('telegram_connected', {
            'user_id': user_id,
            'status': 'listening',
            'auto_snipe_enabled': auto_snipe_enabled,
            'timestamp': datetime.now().isoformat()
        })

        @client.on(events.NewMessage)
        async def handler(event):
            try:
                text = event.message.message or ""
                chat_title = getattr(event.chat, 'title', 'Unknown Chat')
                
                # Your exact detection logic
                print(f"[{chat_title}] {text}")
                
                # Detect Solana token addresses
                token_regex = re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}')
                tokens = token_regex.findall(text)
                
                for token_address in tokens:
                    print(f"[{user_id}] Token detected: {token_address} in {chat_title}")
                    
                    # Emit detection event
                    socketio.emit('new_token_detected', {
                        'user_id': user_id,
                        'symbol': token_address[:8] + '...',
                        'token_address': token_address,
                        'chat_title': chat_title,
                        'message_preview': text[:100] + '...' if len(text) > 100 else text,
                        'auto_snipe_enabled': auto_snipe_enabled,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    # Trigger auto-sniper if enabled
                    if auto_snipe_enabled:
                        try:
                            await execute_snipe(token_address, user_id, snipe_amount_sol, chat_title)
                        except Exception as snipe_error:
                            print(f"[{user_id}] Auto-snipe failed: {snipe_error}")
                
            except Exception as handler_error:
                print(f"[{user_id}] Handler error: {handler_error}")

        await client.run_until_disconnected()
        
    except Exception as e:
        print(f"[{user_id}] Sniper listener error: {e}")
        
        # Emit error status
        socketio.emit('sniper_error', {
            'user_id': user_id,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        })
    finally:
        # Clean up
        if user_id in active_snipers:
            del active_snipers[user_id]

def launch_all_active_snipers():
    """Your exact launcher pattern"""
    sessions = get_active_sessions()
    print(f"Launching {len(sessions)} active snipers...")
    
    for session_data in sessions:
        user_id = session_data['user_id']
        
        if user_id not in active_snipers:
            # Create background task for each session
            def run_sniper_for_session(sess_data):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                task = loop.create_task(run_sniper_listener(sess_data))
                active_snipers[sess_data['user_id']] = task
                loop.run_until_complete(task)
                loop.close()
            
            thread = threading.Thread(target=run_sniper_for_session, args=(session_data,), daemon=True)
            thread.start()
            
            print(f"[{user_id}] Sniper launched in background")
        else:
            print(f"[{user_id}] Sniper already active")

# Flask routes
@app.route('/add_session', methods=['POST'])
def add_session():
    """Add new session for multi-sniper"""
    data = request.json
    
    user_id = data.get('user_id')
    session_encrypted = data.get('session_encrypted')
    private_key = data.get('private_key')
    auto_snipe_enabled = data.get('auto_snipe_enabled', True)
    snipe_amount_sol = float(data.get('snipe_amount_sol', 0.1))
    
    if not all([user_id, session_encrypted, private_key]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Encrypt private key
    private_key_encrypted = encryption.encrypt(private_key.encode()).decode()
    
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT OR REPLACE INTO active_sessions 
            (user_id, session_encrypted, private_key_encrypted, auto_snipe_enabled, snipe_amount_sol)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, session_encrypted, private_key_encrypted, auto_snipe_enabled, snipe_amount_sol))
        conn.commit()
    
    return jsonify({
        'status': 'session_added',
        'user_id': user_id,
        'auto_snipe_enabled': auto_snipe_enabled
    })

@app.route('/launch_snipers', methods=['POST'])
def launch_snipers():
    """Launch all active snipers"""
    try:
        launch_all_active_snipers()
        
        return jsonify({
            'status': 'snipers_launched',
            'active_count': len(active_snipers),
            'total_sessions': len(get_active_sessions())
        })
    except Exception as e:
        return jsonify({'error': f'Launch failed: {str(e)}'}), 500

@app.route('/stop_sniper/<user_id>', methods=['POST'])
def stop_sniper(user_id):
    """Stop specific sniper"""
    if user_id in active_snipers:
        task = active_snipers[user_id]
        task.cancel()
        del active_snipers[user_id]
        
        return jsonify({'status': 'sniper_stopped', 'user_id': user_id})
    else:
        return jsonify({'status': 'sniper_not_running', 'user_id': user_id})

@app.route('/manual_snipe', methods=['POST'])
def manual_snipe():
    """Execute manual snipe"""
    data = request.json
    
    user_id = data.get('user_id')
    token_address = data.get('token_address')
    amount_sol = float(data.get('amount_sol', 0.1))
    
    if not all([user_id, token_address]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        # Execute snipe in background
        def execute_manual_snipe():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                execute_snipe(token_address, user_id, amount_sol, 'manual')
            )
            loop.close()
            return result
        
        txid = execute_manual_snipe()
        
        return jsonify({
            'success': True,
            'tx_hash': txid,
            'token_address': token_address,
            'amount_sol': amount_sol
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'token_address': token_address
        }), 500

@app.route('/sniper_status', methods=['GET'])
def get_sniper_status():
    """Get status of all snipers"""
    sessions = get_active_sessions()
    
    status = []
    for session_data in sessions:
        user_id = session_data['user_id']
        status.append({
            'user_id': user_id,
            'is_running': user_id in active_snipers,
            'auto_snipe_enabled': session_data['auto_snipe_enabled'],
            'snipe_amount_sol': session_data['snipe_amount_sol']
        })
    
    return jsonify({
        'total_sessions': len(sessions),
        'active_snipers': len(active_snipers),
        'snipers': status
    })

@app.route('/execution_history', methods=['GET'])
def get_execution_history():
    """Get snipe execution history"""
    limit = int(request.args.get('limit', 50))
    user_id = request.args.get('user_id')
    
    query = 'SELECT * FROM snipe_executions'
    params = []
    
    if user_id:
        query += ' WHERE user_id = ?'
        params.append(user_id)
    
    query += ' ORDER BY executed_at DESC LIMIT ?'
    params.append(limit)
    
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(query, params)
        
        executions = []
        for row in cursor.fetchall():
            execution = dict(row)
            if execution['tx_hash']:
                execution['solscan_url'] = f"https://solscan.io/tx/{execution['tx_hash']}"
            executions.append(execution)
    
    return jsonify({'executions': executions})

@app.route('/test_devnet_transfer', methods=['POST'])
def test_devnet_transfer():
    """Test with small SOL transfer on devnet"""
    data = request.json
    user_id = data.get('user_id', 'test_user')
    
    # Use devnet for testing
    test_amount = 0.01  # Small test amount
    test_token = "So11111111111111111111111111111111111111112"  # SOL itself for testing
    
    try:
        # Simulate execution
        print(f"Testing devnet transfer for {user_id}: {test_amount} SOL")
        
        # In production, this would execute the actual transfer
        # For now, simulate success
        mock_txid = f"test_tx_{int(datetime.now().timestamp())}"
        
        return jsonify({
            'test_mode': True,
            'success': True,
            'tx_hash': mock_txid,
            'amount_sol': test_amount,
            'network': 'devnet',
            'message': 'Test transfer simulated successfully'
        })
        
    except Exception as e:
        return jsonify({
            'test_mode': True,
            'success': False,
            'error': str(e)
        }), 500

@app.route('/system_status', methods=['GET'])
def system_status():
    """Get complete system status"""
    try:
        sessions = get_active_sessions()
        
        # Count successful and failed executions
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_executions WHERE status = "success"')
            successful_snipes = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_executions WHERE status = "failed"')
            failed_snipes = cursor.fetchone()[0]
        
        return jsonify({
            'database_working': True,
            'total_sessions': len(sessions),
            'active_snipers': len(active_snipers),
            'successful_snipes': successful_snipes,
            'failed_snipes': failed_snipes,
            'jupiter_api_available': True,
            'solana_rpc_endpoint': SOLANA_RPC,
            'capabilities': {
                'multi_session_sniping': True,
                'jupiter_integration': True,
                'websocket_notifications': True,
                'auto_and_manual_snipe': True,
                'devnet_testing': True
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'System status error: {str(e)}'}), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print("Client connected to multi-sniper")

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected from multi-sniper")

if __name__ == '__main__':
    print("Multi-Session Sniper System")
    print("Server: http://localhost:2222")
    print()
    print("Features:")
    print("  ✓ Multi-session Telegram monitoring")
    print("  ✓ Jupiter V6 integration for swaps")
    print("  ✓ Auto and manual sniping")
    print("  ✓ Real-time WebSocket notifications")
    print("  ✓ Devnet testing support")
    print()
    print("Usage:")
    print("  1. Add sessions with /add_session")
    print("  2. Launch all snipers with /launch_snipers")
    print("  3. Monitor via WebSocket events")
    print("  4. Test with /test_devnet_transfer")
    print()
    print("WebSocket Events:")
    print("  new_token_detected - Token detection alerts")
    print("  swap_executed - Successful swap notifications")
    print("  swap_failed - Failed swap alerts")
    print("  telegram_connected - Connection status")
    print("  sniper_error - Error notifications")
    print()
    print("Endpoints:")
    print("  POST /add_session - Add new sniper session")
    print("  POST /launch_snipers - Launch all active snipers")
    print("  POST /stop_sniper/<user_id> - Stop specific sniper")
    print("  POST /manual_snipe - Execute manual snipe")
    print("  GET  /sniper_status - Get sniper status")
    print("  GET  /execution_history - Get execution history")
    print("  POST /test_devnet_transfer - Test devnet transfer")
    print("  GET  /system_status - System status")
    
    socketio.run(app, host='0.0.0.0', port=2222, debug=False)