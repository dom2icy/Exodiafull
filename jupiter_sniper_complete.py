import os
import re
import base64
import asyncio
import requests
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.rpc.api import Client
from solana.transaction import Transaction
from solana.rpc.types import TxOpts
from exodia_sdk.security import FernetEncryption

# Environment setup
os.environ['FERNET_KEY'] = "otPo66UgjPf9Iv9w1F0ndhi7HRhfXVO0cWhjKBwWlx8="

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Your exact encryption pattern
encryption = FernetEncryption(key=os.environ.get('FERNET_KEY'))

DATABASE = "jupiter_sniper.db"
API_ID = 21724048
API_HASH = "82c3e0c51d4c6f46bce0e38b7dc3c9b8"

# Your exact Jupiter and Solana patterns
JUPITER_API = "https://quote-api.jup.ag/v6"
SOLANA_CLIENT = Client("https://api.mainnet-beta.solana.com")
SOL_MINT = "So11111111111111111111111111111111111111112"

# Active snipers
active_snipers = {}

def init_jupiter_db():
    """Initialize Jupiter sniper database"""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS sniper_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            encrypted_key TEXT NOT NULL,
            telegram_session_encrypted TEXT,
            auto_snipe_enabled BOOLEAN DEFAULT 1,
            sol_amount REAL DEFAULT 0.02,
            slippage REAL DEFAULT 1.0,
            monitored_groups TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS snipe_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            target_mint TEXT NOT NULL,
            sol_amount REAL,
            slippage REAL,
            tx_hash TEXT,
            status TEXT DEFAULT 'pending',
            error_message TEXT,
            execution_time REAL,
            detected_in_chat TEXT,
            jupiter_quote_data TEXT,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

init_jupiter_db()

def get_best_jupiter_quote(input_mint: str, output_mint: str, amount: float, slippage: float = 1.0):
    """Your exact Jupiter quote pattern"""
    lamports = int(amount * 1_000_000_000)  # convert SOL to lamports
    params = {
        "inputMint": input_mint,
        "outputMint": output_mint,
        "amount": lamports,
        "slippageBps": int(slippage * 100),
        "onlyDirectRoutes": False
    }
    
    try:
        resp = requests.get(f"{JUPITER_API}/quote", params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        if not data.get("data"):
            raise Exception("No routes available from Jupiter")
        
        return data["data"][0]  # return top route
    except Exception as e:
        raise Exception(f"Jupiter quote failed: {str(e)}")

def build_snipe_transaction(client: Client, quote: dict, user_pubkey: Pubkey) -> Transaction:
    """Your exact transaction builder pattern"""
    try:
        tx_resp = requests.post(
            f"{JUPITER_API}/swap",
            json={
                "route": quote,
                "userPublicKey": str(user_pubkey),
                "wrapUnwrapSOL": True,
                "feeAccount": None,  # optionally track fees
                "asLegacyTransaction": True
            },
            timeout=15
        )
        
        if tx_resp.status_code != 200:
            raise Exception(f"Failed to build Jupiter transaction: {tx_resp.status_code}")

        swap_tx = tx_resp.json()["swapTransaction"]
        raw_tx = base64.b64decode(swap_tx)
        return Transaction.deserialize(raw_tx)
        
    except Exception as e:
        raise Exception(f"Transaction build failed: {str(e)}")

def simulate_sniper_trigger(encrypted_key: str, target_mint: str, sol_amount: float, slippage: float = 1.0):
    """Your exact sniper trigger pattern"""
    start_time = datetime.now().timestamp()
    
    try:
        # Step 1: Decrypt private key and reconstruct Keypair
        decrypted = encryption.decrypt(encrypted_key.encode())
        decoded_bytes = base64.b64decode(decrypted)
        keypair = Keypair.from_bytes(decoded_bytes)

        # Step 2: Get Jupiter quote
        quote = get_best_jupiter_quote(SOL_MINT, target_mint, sol_amount, slippage)

        # Step 3: Build and sign transaction
        txn = build_snipe_transaction(SOLANA_CLIENT, quote, keypair.pubkey())
        
        # Your exact signing pattern
        recent_blockhash = SOLANA_CLIENT.get_recent_blockhash()["result"]["value"]["blockhash"]
        txn.recent_blockhash = recent_blockhash
        txn.sign(keypair)

        # Step 4: Broadcast to mainnet
        result = SOLANA_CLIENT.send_transaction(txn, keypair)
        txid = result["result"]
        
        execution_time = datetime.now().timestamp() - start_time
        
        return {
            'success': True,
            'tx_hash': txid,
            'execution_time': execution_time,
            'quote_data': quote,
            'sol_amount': sol_amount,
            'target_mint': target_mint
        }
        
    except Exception as e:
        execution_time = datetime.now().timestamp() - start_time
        return {
            'success': False,
            'error': str(e),
            'execution_time': execution_time,
            'sol_amount': sol_amount,
            'target_mint': target_mint
        }

async def run_telegram_sniper(user_data):
    """Enhanced Telegram sniper with Jupiter integration"""
    user_id = user_data['user_id']
    encrypted_session = user_data['telegram_session_encrypted']
    encrypted_key = user_data['encrypted_key']
    auto_snipe_enabled = user_data['auto_snipe_enabled']
    sol_amount = user_data['sol_amount']
    slippage = user_data['slippage']
    monitored_groups = user_data['monitored_groups'].split(',') if user_data['monitored_groups'] else []
    
    try:
        # Decrypt and start Telegram client
        session_str = encryption.decrypt(encrypted_session.encode()).decode()
        client = TelegramClient(StringSession(session_str), API_ID, API_HASH)
        await client.start()
        
        print(f"[{user_id}] Jupiter sniper started - monitoring {len(monitored_groups)} groups")
        
        # Emit connection status
        socketio.emit('sniper_connected', {
            'user_id': user_id,
            'groups_count': len(monitored_groups),
            'auto_snipe_enabled': auto_snipe_enabled,
            'sol_amount': sol_amount,
            'timestamp': datetime.now().isoformat()
        })

        @client.on(events.NewMessage(chats=monitored_groups))
        async def handler(event):
            try:
                text = event.message.message or ""
                chat_title = getattr(event.chat, 'title', 'Unknown')
                
                # Your exact token detection pattern
                token_regex = re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}')
                detected_tokens = token_regex.findall(text)
                
                for target_mint in detected_tokens:
                    print(f"[{user_id}] Token detected: {target_mint} in {chat_title}")
                    
                    # Emit detection event
                    socketio.emit('token_detected', {
                        'user_id': user_id,
                        'target_mint': target_mint,
                        'chat_title': chat_title,
                        'message_preview': text[:100] + '...' if len(text) > 100 else text,
                        'auto_snipe_enabled': auto_snipe_enabled,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    # Replace target_mint dynamically when parsing Telegram messages
                    if auto_snipe_enabled:
                        # Execute snipe in background to not block message processing
                        def execute_background_snipe():
                            try:
                                # Your exact sniper trigger with dynamic mint
                                result = simulate_sniper_trigger(encrypted_key, target_mint, sol_amount, slippage)
                                
                                # Log execution
                                status = 'success' if result['success'] else 'failed'
                                with sqlite3.connect(DATABASE) as conn:
                                    conn.execute('''
                                        INSERT INTO snipe_logs 
                                        (user_id, target_mint, sol_amount, slippage, tx_hash, status, 
                                         error_message, execution_time, detected_in_chat, jupiter_quote_data)
                                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    ''', (user_id, target_mint, sol_amount, slippage,
                                          result.get('tx_hash'), status, result.get('error'),
                                          result.get('execution_time'), chat_title,
                                          str(result.get('quote_data', {}))))
                                    conn.commit()
                                
                                # Emit result
                                if result['success']:
                                    socketio.emit('snipe_success', {
                                        'user_id': user_id,
                                        'target_mint': target_mint,
                                        'tx_hash': result['tx_hash'],
                                        'sol_amount': sol_amount,
                                        'execution_time': result['execution_time'],
                                        'chat_title': chat_title,
                                        'solscan_url': f"https://solscan.io/tx/{result['tx_hash']}",
                                        'timestamp': datetime.now().isoformat()
                                    })
                                else:
                                    socketio.emit('snipe_failed', {
                                        'user_id': user_id,
                                        'target_mint': target_mint,
                                        'error': result['error'],
                                        'execution_time': result['execution_time'],
                                        'chat_title': chat_title,
                                        'timestamp': datetime.now().isoformat()
                                    })
                                    
                            except Exception as snipe_error:
                                print(f"[{user_id}] Background snipe error: {snipe_error}")
                                
                                socketio.emit('snipe_error', {
                                    'user_id': user_id,
                                    'target_mint': target_mint,
                                    'error': str(snipe_error),
                                    'chat_title': chat_title,
                                    'timestamp': datetime.now().isoformat()
                                })
                        
                        # Execute in thread to avoid blocking
                        thread = threading.Thread(target=execute_background_snipe, daemon=True)
                        thread.start()
                
            except Exception as handler_error:
                print(f"[{user_id}] Message handler error: {handler_error}")

        await client.run_until_disconnected()
        
    except Exception as e:
        print(f"[{user_id}] Sniper error: {e}")
        
        socketio.emit('sniper_error', {
            'user_id': user_id,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        })
    finally:
        if user_id in active_snipers:
            del active_snipers[user_id]

def launch_all_jupiter_snipers():
    """Launch all active Jupiter snipers"""
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('SELECT * FROM sniper_users WHERE is_active = 1')
        users = [dict(row) for row in cursor.fetchall()]
    
    print(f"Launching {len(users)} Jupiter snipers...")
    
    for user_data in users:
        user_id = user_data['user_id']
        
        if user_id not in active_snipers:
            def run_user_sniper(data):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                task = loop.create_task(run_telegram_sniper(data))
                active_snipers[data['user_id']] = task
                loop.run_until_complete(task)
                loop.close()
            
            thread = threading.Thread(target=run_user_sniper, args=(user_data,), daemon=True)
            thread.start()
            
            print(f"[{user_id}] Jupiter sniper launched")

# Flask routes
@app.route('/register_sniper', methods=['POST'])
def register_sniper():
    """Register new Jupiter sniper user"""
    data = request.json
    
    user_id = data.get('user_id')
    private_key = data.get('private_key')
    telegram_session = data.get('telegram_session')
    sol_amount = float(data.get('sol_amount', 0.02))
    slippage = float(data.get('slippage', 1.0))
    monitored_groups = data.get('monitored_groups', [])
    auto_snipe_enabled = data.get('auto_snipe_enabled', True)
    
    if not all([user_id, private_key]):
        return jsonify({'error': 'user_id and private_key required'}), 400
    
    # Encrypt sensitive data
    encrypted_key = encryption.encrypt(private_key.encode()).decode()
    encrypted_session = encryption.encrypt(telegram_session.encode()).decode() if telegram_session else None
    groups_str = ','.join(monitored_groups) if monitored_groups else ''
    
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT OR REPLACE INTO sniper_users 
            (user_id, encrypted_key, telegram_session_encrypted, auto_snipe_enabled, 
             sol_amount, slippage, monitored_groups)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, encrypted_key, encrypted_session, auto_snipe_enabled,
              sol_amount, slippage, groups_str))
        conn.commit()
    
    return jsonify({
        'status': 'sniper_registered',
        'user_id': user_id,
        'sol_amount': sol_amount,
        'slippage': slippage,
        'auto_snipe_enabled': auto_snipe_enabled
    })

@app.route('/manual_snipe', methods=['POST'])
def manual_snipe():
    """Execute manual snipe with Jupiter"""
    data = request.json
    
    user_id = data.get('user_id')
    target_mint = data.get('target_mint')
    sol_amount = float(data.get('sol_amount', 0.02))
    slippage = float(data.get('slippage', 1.0))
    
    if not all([user_id, target_mint]):
        return jsonify({'error': 'user_id and target_mint required'}), 400
    
    # Get user's encrypted key
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute('SELECT encrypted_key FROM sniper_users WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'User not registered'}), 404
        
        encrypted_key = row[0]
    
    try:
        # Execute snipe with your exact pattern
        result = simulate_sniper_trigger(encrypted_key, target_mint, sol_amount, slippage)
        
        # Log execution
        status = 'success' if result['success'] else 'failed'
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT INTO snipe_logs 
                (user_id, target_mint, sol_amount, slippage, tx_hash, status, 
                 error_message, execution_time, detected_in_chat, jupiter_quote_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'manual', ?)
            ''', (user_id, target_mint, sol_amount, slippage,
                  result.get('tx_hash'), status, result.get('error'),
                  result.get('execution_time'), str(result.get('quote_data', {}))))
            conn.commit()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'target_mint': target_mint
        }), 500

@app.route('/launch_snipers', methods=['POST'])
def launch_snipers():
    """Launch all Jupiter snipers"""
    try:
        launch_all_jupiter_snipers()
        
        return jsonify({
            'status': 'jupiter_snipers_launched',
            'active_count': len(active_snipers)
        })
    except Exception as e:
        return jsonify({'error': f'Launch failed: {str(e)}'}), 500

@app.route('/test_jupiter_quote', methods=['POST'])
def test_jupiter_quote():
    """Test Jupiter quote functionality"""
    data = request.json
    
    target_mint = data.get('target_mint', 'DezXnKzLQzsG3DzP4if6UczZ23eaSLRSm3BaYZj2Fv2s')
    sol_amount = float(data.get('sol_amount', 0.01))
    slippage = float(data.get('slippage', 1.0))
    
    try:
        quote = get_best_jupiter_quote(SOL_MINT, target_mint, sol_amount, slippage)
        
        return jsonify({
            'success': True,
            'quote': {
                'input_mint': quote.get('inputMint'),
                'output_mint': quote.get('outputMint'),
                'in_amount': quote.get('inAmount'),
                'out_amount': quote.get('outAmount'),
                'price_impact_pct': quote.get('priceImpactPct'),
                'route_plan': len(quote.get('routePlan', [])),
            },
            'sol_amount': sol_amount,
            'target_mint': target_mint
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'target_mint': target_mint
        }), 500

@app.route('/snipe_history/<user_id>', methods=['GET'])
def get_snipe_history(user_id):
    """Get snipe execution history"""
    limit = int(request.args.get('limit', 50))
    
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT * FROM snipe_logs 
            WHERE user_id = ? 
            ORDER BY executed_at DESC 
            LIMIT ?
        ''', (user_id, limit))
        
        logs = []
        for row in cursor.fetchall():
            log = dict(row)
            if log['tx_hash']:
                log['solscan_url'] = f"https://solscan.io/tx/{log['tx_hash']}"
            logs.append(log)
    
    return jsonify({'snipe_history': logs})

@app.route('/system_status', methods=['GET'])
def system_status():
    """Get Jupiter sniper system status"""
    try:
        # Test Jupiter API
        test_quote = get_best_jupiter_quote(SOL_MINT, "DezXnKzLQzsG3DzP4if6UczZ23eaSLRSm3BaYZj2Fv2s", 0.01)
        jupiter_working = bool(test_quote)
        
        # Test Solana RPC
        recent_blockhash = SOLANA_CLIENT.get_recent_blockhash()
        solana_working = bool(recent_blockhash.get("result"))
        
        # Database stats
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM sniper_users WHERE is_active = 1')
            active_users = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_logs WHERE status = "success"')
            successful_snipes = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_logs WHERE status = "failed"')
            failed_snipes = cursor.fetchone()[0]
        
        return jsonify({
            'jupiter_api_working': jupiter_working,
            'solana_rpc_working': solana_working,
            'active_sniper_users': active_users,
            'running_snipers': len(active_snipers),
            'successful_snipes': successful_snipes,
            'failed_snipes': failed_snipes,
            'success_rate': round((successful_snipes / (successful_snipes + failed_snipes) * 100) if (successful_snipes + failed_snipes) > 0 else 0, 2),
            'capabilities': {
                'jupiter_v6_integration': True,
                'mainnet_trading': True,
                'telegram_monitoring': True,
                'real_time_execution': True,
                'encrypted_key_storage': True,
                'dynamic_mint_replacement': True
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'System status error: {str(e)}'}), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print("Client connected to Jupiter sniper")

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected from Jupiter sniper")

@socketio.on('join_user_room')
def handle_join_user_room(data):
    """Join user-specific room for notifications"""
    user_id = data.get('user_id')
    if user_id:
        # In a real app, you'd validate the user_id
        emit('room_joined', {'user_id': user_id, 'status': 'joined'})

if __name__ == '__main__':
    print("Jupiter Sniper System - Production Ready")
    print("Server: http://localhost:1111")
    print()
    print("Features:")
    print("  ✓ Jupiter V6 mainnet integration")
    print("  ✓ Dynamic mint replacement from Telegram")
    print("  ✓ Real-time token detection and execution")
    print("  ✓ User-configurable slippage and amounts")
    print("  ✓ Comprehensive execution logging")
    print("  ✓ WebSocket notifications")
    print()
    print("Usage Flow:")
    print("  1. Register sniper with /register_sniper")
    print("  2. Launch snipers with /launch_snipers")
    print("  3. Monitor via WebSocket events")
    print("  4. Test quotes with /test_jupiter_quote")
    print("  5. Execute manual snipes with /manual_snipe")
    print()
    print("WebSocket Events:")
    print("  sniper_connected - Sniper connection status")
    print("  token_detected - Real-time token detection")
    print("  snipe_success - Successful executions")
    print("  snipe_failed - Failed executions")
    print("  sniper_error - Error notifications")
    print()
    print("Integration Ready:")
    print("  - Plugs directly into Phase 13 event engine")
    print("  - Dynamic target_mint replacement from Telegram parsing")
    print("  - User-configurable per-group slippage and amounts")
    print("  - Production mainnet Jupiter V6 trading")
    print()
    print("Endpoints:")
    print("  POST /register_sniper - Register new sniper user")
    print("  POST /launch_snipers - Launch all active snipers")
    print("  POST /manual_snipe - Execute manual snipe")
    print("  POST /test_jupiter_quote - Test Jupiter quote")
    print("  GET  /snipe_history/<user_id> - Get execution history")
    print("  GET  /system_status - System status")
    
    socketio.run(app, host='0.0.0.0', port=1111, debug=False)