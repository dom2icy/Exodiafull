import os
import re
import base64
import asyncio
import aiohttp
import sqlite3
import threading
from collections import deque
from datetime import datetime
from flask import Flask, request, jsonify, session
from telethon import TelegramClient, events
from solana.keypair import Keypair
from solana.rpc.async_api import AsyncClient
from solana.transaction import Transaction
from exodia_sdk.security import FernetEncryption
from exodia_sdk.auth import authenticate_token

# Set environment
os.environ['FERNET_KEY'] = "otPo66UgjPf9Iv9w1F0ndhi7HRhfXVO0cWhjKBwWlx8="

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Your exact encryption pattern
encryption = FernetEncryption(key=os.environ.get('FERNET_KEY'))

JUPITER_API_BASE = "https://quote-api.jup.ag/v6"
DATABASE = "complete_sniper.db"

# Contract detection patterns - Solana addresses
CONTRACT_REGEX = r'[1-9A-HJ-NP-Za-km-z]{32,44}'  # Solana base58 pattern
SOLANA_RPC = "https://api.mainnet-beta.solana.com"

# Active sniper bots and user sessions
active_bots = {}
user_sessions = {}

def init_complete_db():
    """Initialize complete sniper database"""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS user_configs (
            user_id TEXT PRIMARY KEY,
            encrypted_session TEXT NOT NULL,
            api_id TEXT NOT NULL,
            api_hash TEXT NOT NULL,
            sol_amount REAL DEFAULT 0.1,
            private_key_encrypted TEXT,
            target_groups TEXT,
            auto_snipe_enabled BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS contract_detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            contract_address TEXT NOT NULL,
            detected_in_group TEXT,
            message_content TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sniped BOOLEAN DEFAULT 0
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS snipe_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            contract_address TEXT NOT NULL,
            sol_amount REAL,
            status TEXT DEFAULT 'pending',
            tx_signature TEXT,
            error_message TEXT,
            execution_time REAL,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

init_complete_db()

async def get_best_route(input_mint, output_mint, amount, slippage_bps=50):
    """Your exact Jupiter route pattern"""
    async with aiohttp.ClientSession() as session:
        url = f"{JUPITER_API_BASE}/quote"
        params = {
            "inputMint": input_mint,
            "outputMint": output_mint,
            "amount": str(amount),
            "slippageBps": str(slippage_bps),
            "onlyDirectRoutes": "false",
        }
        async with session.get(url, params=params) as resp:
            data = await resp.json()
            return data.get("data", [])

async def build_swap_transaction(route, user_public_key):
    """Your exact Jupiter transaction builder pattern"""
    async with aiohttp.ClientSession() as session:
        url = f"{JUPITER_API_BASE}/swap"
        payload = {
            "route": route,
            "userPublicKey": user_public_key,
            "wrapUnwrapSOL": True
        }
        async with session.post(url, json=payload) as resp:
            data = await resp.json()
            return data.get("swapTransaction")

async def snipe_contract(user_id, contract_address, sol_amount):
    """Your exact sniping function with Jupiter V6"""
    start_time = asyncio.get_event_loop().time()
    
    try:
        # Get user's private key
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute('SELECT private_key_encrypted FROM user_configs WHERE user_id = ?', (user_id,))
            row = cursor.fetchone()
            if not row:
                return {'success': False, 'error': 'Private key not found'}
        
        private_key_b64 = encryption.decrypt(row[0].encode()).decode()
        keypair_bytes = base64.b64decode(private_key_b64)
        keypair = Keypair.from_secret_key(keypair_bytes)
        
        client = AsyncClient(SOLANA_RPC)
        lamports = int(sol_amount * 1_000_000_000)
        input_mint = "So11111111111111111111111111111111111111112"  # Wrapped SOL

        print(f"[User {user_id}] Sniping {contract_address} with {sol_amount} SOL")
        
        # Get Jupiter route
        routes = await get_best_route(input_mint, contract_address, lamports)
        if not routes:
            await client.close()
            return {'success': False, 'error': 'No Jupiter routes found'}

        best_route = routes[0]

        # Build transaction
        swap_tx_base64 = await build_swap_transaction(best_route, str(keypair.public_key))
        if not swap_tx_base64:
            await client.close()
            return {'success': False, 'error': 'Failed to build transaction'}

        # Execute transaction
        tx_bytes = base64.b64decode(swap_tx_base64)
        transaction = Transaction.deserialize(tx_bytes)
        transaction.sign(keypair)

        resp = await client.send_raw_transaction(transaction.serialize())
        await client.close()
        
        execution_time = asyncio.get_event_loop().time() - start_time

        if resp.get("result"):
            print(f"[User {user_id}] ✅ Sniped {contract_address} successfully! TxSig: {resp['result']}")
            return {
                'success': True, 
                'tx_signature': resp['result'],
                'execution_time': execution_time,
                'amount': sol_amount,
                'contract': contract_address
            }
        else:
            return {'success': False, 'error': str(resp), 'execution_time': execution_time}
            
    except Exception as e:
        execution_time = asyncio.get_event_loop().time() - start_time
        print(f"[User {user_id}] ❌ Snipe error: {e}")
        return {'success': False, 'error': str(e), 'execution_time': execution_time}

class UserSniperBot:
    """Your exact multi-user sniper bot pattern"""
    
    def __init__(self, user_config):
        self.user_id = user_config['user_id']
        self.session_name = user_config['session_name']
        self.api_id = user_config['api_id']
        self.api_hash = user_config['api_hash']
        self.sol_amount = user_config['sol_amount']
        self.target_groups = user_config['target_groups']
        self.auto_snipe_enabled = user_config['auto_snipe_enabled']
        
        self.client = None
        self.sniping_queue = deque()
        self.is_sniping = False
        self.is_running = False

    async def start(self):
        """Start Telegram client with your exact pattern"""
        try:
            self.client = TelegramClient(f"sessions/{self.session_name}", self.api_id, self.api_hash)
            await self.client.start()
            self.is_running = True
            
            print(f"[User {self.user_id}] Telegram client started, monitoring: {self.target_groups}")

            # Your exact message handler pattern
            @self.client.on(events.NewMessage(chats=self.target_groups))
            async def handler(event):
                try:
                    text = event.message.message
                    group_name = getattr(event.chat, 'title', None) or getattr(event.chat, 'username', 'Unknown')
                    
                    # Your exact contract detection pattern
                    matches = re.findall(CONTRACT_REGEX, text)
                    for contract in matches:
                        print(f"[User {self.user_id}] Detected contract: {contract} in {group_name}")
                        
                        # Store detection
                        with sqlite3.connect(DATABASE) as conn:
                            conn.execute('''
                                INSERT INTO contract_detections 
                                (user_id, contract_address, detected_in_group, message_content)
                                VALUES (?, ?, ?, ?)
                            ''', (self.user_id, contract, group_name, text))
                            conn.commit()
                        
                        # Add to sniping queue
                        self.sniping_queue.append(contract)
                        
                        # Process queue if not already processing
                        if not self.is_sniping and self.auto_snipe_enabled:
                            asyncio.create_task(self.process_queue())
                
                except Exception as e:
                    print(f"[User {self.user_id}] Handler error: {e}")

            await self.client.run_until_disconnected()
            
        except Exception as e:
            print(f"[User {self.user_id}] Client start error: {e}")
            self.is_running = False

    async def process_queue(self):
        """Your exact queue processing pattern"""
        self.is_sniping = True
        
        while self.sniping_queue:
            contract = self.sniping_queue.popleft()
            
            try:
                # Execute snipe
                result = await snipe_contract(self.user_id, contract, self.sol_amount)
                
                # Log execution
                status = 'success' if result['success'] else 'failed'
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute('''
                        INSERT INTO snipe_executions 
                        (user_id, contract_address, sol_amount, status, tx_signature, 
                         error_message, execution_time)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (self.user_id, contract, self.sol_amount, status,
                          result.get('tx_signature'), result.get('error'),
                          result.get('execution_time', 0)))
                    
                    # Mark contract as sniped if successful
                    if result['success']:
                        conn.execute('''
                            UPDATE contract_detections 
                            SET sniped = 1 
                            WHERE user_id = ? AND contract_address = ?
                        ''', (self.user_id, contract))
                    
                    conn.commit()
                
            except Exception as e:
                print(f"[User {self.user_id}] Error sniping {contract}: {e}")
                
                # Log error
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute('''
                        INSERT INTO snipe_executions 
                        (user_id, contract_address, sol_amount, status, error_message)
                        VALUES (?, ?, ?, 'failed', ?)
                    ''', (self.user_id, contract, self.sol_amount, str(e)))
                    conn.commit()
        
        self.is_sniping = False

@app.route('/login', methods=['POST'])
def login():
    """Simple login for testing"""
    data = request.get_json()
    username = data.get('username', 'sniper_user')
    session['user_id'] = username
    return jsonify({'status': 'logged_in', 'user_id': username})

@app.route('/register_telegram', methods=['POST'])
@authenticate_token('sniper_access')
def register_telegram():
    """Your exact Telegram registration pattern"""
    user_id = request.user['user_id']
    data = request.json
    
    session_data = data.get('session_data')  # base64 encoded session file content
    api_id = data.get('api_id')
    api_hash = data.get('api_hash')
    sol_amount = float(data.get('sol_amount', 0.1))
    private_key = data.get('private_key')
    target_groups = data.get('target_groups', ['@freshdrops', '@solana_signals'])
    auto_snipe_enabled = data.get('auto_snipe_enabled', True)
    
    if not all([session_data, api_id, api_hash, private_key]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Encrypt sensitive data
    encrypted_session = encryption.encrypt(session_data.encode()).decode()
    encrypted_private_key = encryption.encrypt(private_key.encode()).decode()
    target_groups_str = ','.join(target_groups)
    
    # Store in database
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT OR REPLACE INTO user_configs 
            (user_id, encrypted_session, api_id, api_hash, sol_amount, 
             private_key_encrypted, target_groups, auto_snipe_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, encrypted_session, api_id, api_hash, sol_amount,
              encrypted_private_key, target_groups_str, auto_snipe_enabled))
        conn.commit()
    
    return jsonify({'status': 'Telegram session registered successfully'})

@app.route('/get_sniper_params/<user_id>', methods=['GET'])
@authenticate_token('sniper_access')
def get_sniper_params(user_id):
    """Get decrypted sniper parameters"""
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('SELECT * FROM user_configs WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'User not found'}), 404
        
        user_data = dict(row)
        
        # Decrypt sensitive data
        decrypted_session = encryption.decrypt(user_data['encrypted_session'].encode()).decode()
        target_groups = user_data['target_groups'].split(',') if user_data['target_groups'] else []
        
        return jsonify({
            'session_data': decrypted_session,
            'api_id': user_data['api_id'],
            'api_hash': user_data['api_hash'],
            'sol_amount': user_data['sol_amount'],
            'target_groups': target_groups,
            'auto_snipe_enabled': user_data['auto_snipe_enabled']
        })

@app.route('/start_sniper_bot', methods=['POST'])
@authenticate_token('sniper_access')
def start_sniper_bot():
    """Start multi-user sniper bot"""
    data = request.json
    user_ids = data.get('user_ids', [])
    
    if not user_ids:
        # Start for current user only
        user_ids = [request.user['user_id']]
    
    started_bots = []
    
    for user_id in user_ids:
        if user_id in active_bots:
            continue  # Already running
        
        # Get user config
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM user_configs WHERE user_id = ?', (user_id,))
            row = cursor.fetchone()
            
            if not row:
                continue
            
            config = dict(row)
            config['session_name'] = f"sniper_{user_id}"
            config['target_groups'] = config['target_groups'].split(',') if config['target_groups'] else []
        
        # Create and start bot
        bot = UserSniperBot(config)
        
        def run_bot(bot_instance):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(bot_instance.start())
            loop.close()
        
        thread = threading.Thread(target=run_bot, args=(bot,), daemon=True)
        thread.start()
        
        active_bots[user_id] = bot
        started_bots.append(user_id)
    
    return jsonify({
        'status': 'Sniper bots started',
        'started_bots': started_bots,
        'total_active_bots': len(active_bots)
    })

@app.route('/stop_sniper_bot', methods=['POST'])
@authenticate_token('sniper_access')
def stop_sniper_bot():
    """Stop sniper bot"""
    user_id = request.user['user_id']
    
    if user_id in active_bots:
        active_bots[user_id].is_running = False
        del active_bots[user_id]
        return jsonify({'status': 'Sniper bot stopped'})
    else:
        return jsonify({'status': 'Bot not running'})

@app.route('/manual_snipe', methods=['POST'])
@authenticate_token('sniper_access')
def manual_snipe():
    """Execute manual snipe"""
    user_id = request.user['user_id']
    data = request.json
    
    contract_address = data.get('contract_address')
    sol_amount = float(data.get('sol_amount', 0.1))
    
    if not contract_address:
        return jsonify({'error': 'contract_address required'}), 400
    
    # Execute snipe
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(snipe_contract(user_id, contract_address, sol_amount))
    loop.close()
    
    # Log execution
    status = 'success' if result['success'] else 'failed'
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT INTO snipe_executions 
            (user_id, contract_address, sol_amount, status, tx_signature, 
             error_message, execution_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, contract_address, sol_amount, status,
              result.get('tx_signature'), result.get('error'),
              result.get('execution_time', 0)))
        conn.commit()
    
    return jsonify(result)

@app.route('/bot_status', methods=['GET'])
@authenticate_token('sniper_access')
def get_bot_status():
    """Get bot status for user"""
    user_id = request.user['user_id']
    
    is_running = user_id in active_bots
    bot_info = None
    
    if is_running:
        bot = active_bots[user_id]
        bot_info = {
            'queue_size': len(bot.sniping_queue),
            'is_sniping': bot.is_sniping,
            'target_groups': bot.target_groups,
            'auto_snipe_enabled': bot.auto_snipe_enabled
        }
    
    # Get statistics
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.execute('''
            SELECT 
                COUNT(*) as total_detections,
                SUM(CASE WHEN sniped = 1 THEN 1 ELSE 0 END) as successful_snipes
            FROM contract_detections 
            WHERE user_id = ?
        ''', (user_id,))
        stats = dict(cursor.fetchone())
        
        cursor = conn.execute('''
            SELECT COUNT(*) as total_executions
            FROM snipe_executions 
            WHERE user_id = ?
        ''', (user_id,))
        stats['total_executions'] = cursor.fetchone()[0]
    
    return jsonify({
        'is_running': is_running,
        'bot_info': bot_info,
        'statistics': stats
    })

@app.route('/detected_contracts', methods=['GET'])
@authenticate_token('sniper_access')
def get_detected_contracts():
    """Get detected contracts for user"""
    user_id = request.user['user_id']
    limit = int(request.args.get('limit', 50))
    
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT * FROM contract_detections 
            WHERE user_id = ? 
            ORDER BY detected_at DESC 
            LIMIT ?
        ''', (user_id, limit))
        
        detections = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({'detections': detections})

@app.route('/execution_history', methods=['GET'])
@authenticate_token('sniper_access')
def get_execution_history():
    """Get snipe execution history"""
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
            if execution['tx_signature']:
                execution['solscan_url'] = f"https://solscan.io/tx/{execution['tx_signature']}"
            executions.append(execution)
    
    return jsonify({'executions': executions})

@app.route('/system_status', methods=['GET'])
def system_status():
    """Get complete system status"""
    try:
        # Test Jupiter API
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        test_routes = loop.run_until_complete(get_best_route(
            "So11111111111111111111111111111111111111112",
            "DezXnKzLQzsG3DzP4if6UczZ23eaSLRSm3BaYZj2Fv2s",
            100000000
        ))
        jupiter_working = bool(test_routes)
        loop.close()
        
        # Database stats
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM user_configs')
            total_users = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM user_configs WHERE auto_snipe_enabled = 1')
            auto_snipe_users = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM contract_detections')
            total_detections = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_executions WHERE status = "success"')
            successful_snipes = cursor.fetchone()[0]
        
        # Active bots info
        active_bot_info = {}
        for user_id, bot in active_bots.items():
            active_bot_info[user_id] = {
                'queue_size': len(bot.sniping_queue),
                'is_sniping': bot.is_sniping,
                'target_groups': len(bot.target_groups)
            }
        
        return jsonify({
            'jupiter_api_working': jupiter_working,
            'total_configured_users': total_users,
            'auto_snipe_enabled_users': auto_snipe_users,
            'active_bots': len(active_bots),
            'active_bot_details': active_bot_info,
            'total_contract_detections': total_detections,
            'successful_snipes': successful_snipes,
            'capabilities': {
                'multi_user_support': True,
                'automatic_detection': True,
                'queue_processing': True,
                'jupiter_integration': jupiter_working,
                'encrypted_storage': True
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'System status error: {str(e)}'}), 500

if __name__ == '__main__':
    print("Complete Telegram Sniper System - Multi-User Automated Trading")
    print("Server: http://localhost:7777")
    print()
    print("Features:")
    print("  ✓ Multi-user support with encrypted session storage")
    print("  ✓ Real-time contract detection from Telegram groups")
    print("  ✓ Automatic queue-based sniping with Jupiter V6")
    print("  ✓ Manual snipe execution with full logging")
    print("  ✓ Contract detection history and execution analytics")
    print()
    print("Endpoints:")
    print("  POST /login - Login")
    print("  POST /register_telegram - Register Telegram session")
    print("  GET  /get_sniper_params/<user_id> - Get user config")
    print("  POST /start_sniper_bot - Start multi-user bots")
    print("  POST /stop_sniper_bot - Stop bot")
    print("  POST /manual_snipe - Execute manual snipe")
    print("  GET  /bot_status - Get bot status")
    print("  GET  /detected_contracts - Get detection history")
    print("  GET  /execution_history - Get execution history")
    print("  GET  /system_status - System status")
    
    app.run(host='0.0.0.0', port=7777, debug=False)