import os
import re
import base64
import asyncio
import aiohttp
import requests
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.rpc.api import Client
from solana.rpc.async_api import AsyncClient
from solders.transaction import VersionedTransaction
from solders.message import MessageV0
from solders.hash import Hash
from exodia_sdk.security import FernetEncryption

# Environment setup
os.environ['FERNET_KEY'] = "otPo66UgjPf9Iv9w1F0ndhi7HRhfXVO0cWhjKBwWlx8="

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Your exact encryption pattern
encryption = FernetEncryption(key=os.environ.get('FERNET_KEY'))

DATABASE = "autonomous_sniper.db"
API_ID = 21724048
API_HASH = "82c3e0c51d4c6f46bce0e38b7dc3c9b8"

# Jupiter and Solana configuration
JUPITER_API = "https://quote-api.jup.ag/v6"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"
SOL_MINT = "So11111111111111111111111111111111111111112"

# Active autonomous engines
active_engines = {}

def init_autonomous_db():
    """Initialize autonomous sniper database"""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS autonomous_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            telegram_session_encrypted TEXT,
            sol_amount REAL DEFAULT 0.02,
            max_slippage REAL DEFAULT 1.0,
            monitored_groups TEXT,
            auto_snipe_enabled BOOLEAN DEFAULT 1,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS snipe_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            mint_address TEXT NOT NULL,
            sol_amount REAL,
            slippage REAL,
            tx_signature TEXT,
            status TEXT DEFAULT 'pending',
            error_message TEXT,
            execution_time_ms REAL,
            detected_in_group TEXT,
            quote_info TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

init_autonomous_db()

class JupiterClient:
    """Enhanced Jupiter V6 client with proper error handling"""
    
    @staticmethod
    async def get_quote(input_mint: str, output_mint: str, amount_lamports: int, slippage_bps: int = 50):
        """Get Jupiter quote with async handling"""
        async with aiohttp.ClientSession() as session:
            try:
                params = {
                    "inputMint": input_mint,
                    "outputMint": output_mint,
                    "amount": str(amount_lamports),
                    "slippageBps": str(slippage_bps),
                    "onlyDirectRoutes": "false",
                }
                
                async with session.get(f"{JUPITER_API}/quote", params=params, timeout=10) as resp:
                    if resp.status != 200:
                        raise Exception(f"Jupiter quote failed: {resp.status}")
                    
                    data = await resp.json()
                    routes = data.get("data", [])
                    
                    if not routes:
                        raise Exception("No routes available")
                    
                    return routes[0]  # Best route
                    
            except Exception as e:
                raise Exception(f"Quote request failed: {str(e)}")
    
    @staticmethod
    async def get_swap_transaction(quote: dict, user_pubkey: str):
        """Get swap transaction from Jupiter"""
        async with aiohttp.ClientSession() as session:
            try:
                payload = {
                    "route": quote,
                    "userPublicKey": user_pubkey,
                    "wrapUnwrapSOL": True,
                    "asLegacyTransaction": False  # Use versioned transactions
                }
                
                async with session.post(f"{JUPITER_API}/swap", json=payload, timeout=15) as resp:
                    if resp.status != 200:
                        raise Exception(f"Swap transaction failed: {resp.status}")
                    
                    data = await resp.json()
                    return data.get("swapTransaction")
                    
            except Exception as e:
                raise Exception(f"Swap transaction failed: {str(e)}")

class AutonomousSniper:
    """Autonomous sniper engine for each user"""
    
    def __init__(self, user_config: dict):
        self.user_id = user_config['user_id']
        self.encrypted_key = user_config['encrypted_private_key']
        self.encrypted_session = user_config['telegram_session_encrypted']
        self.sol_amount = user_config['sol_amount']
        self.max_slippage = user_config['max_slippage']
        self.monitored_groups = user_config['monitored_groups'].split(',') if user_config['monitored_groups'] else []
        self.auto_snipe_enabled = user_config['auto_snipe_enabled']
        
        # Token detection regex
        self.address_pattern = re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b')
        
        # Initialize client
        self.client = None
        self.keypair = None
        
    async def initialize(self):
        """Initialize Telegram client and keypair"""
        try:
            # Decrypt and setup private key
            decrypted_key = encryption.decrypt(self.encrypted_key.encode()).decode()
            key_bytes = base64.b64decode(decrypted_key)
            self.keypair = Keypair.from_bytes(key_bytes)
            
            # Setup Telegram client
            if self.encrypted_session:
                session_str = encryption.decrypt(self.encrypted_session.encode()).decode()
                self.client = TelegramClient(StringSession(session_str), API_ID, API_HASH)
                await self.client.start()
                
                print(f"[{self.user_id}] Autonomous sniper initialized")
                return True
            else:
                print(f"[{self.user_id}] No Telegram session configured")
                return False
                
        except Exception as e:
            print(f"[{self.user_id}] Initialization failed: {e}")
            return False
    
    async def execute_snipe(self, mint_address: str, detected_in_group: str) -> dict:
        """Execute autonomous snipe with Jupiter V6"""
        start_time = datetime.now().timestamp()
        
        try:
            # Convert SOL to lamports
            amount_lamports = int(self.sol_amount * 1_000_000_000)
            slippage_bps = int(self.max_slippage * 100)
            
            # Get Jupiter quote
            quote = await JupiterClient.get_quote(
                SOL_MINT, 
                mint_address, 
                amount_lamports, 
                slippage_bps
            )
            
            # Check slippage tolerance
            price_impact = float(quote.get('priceImpactPct', 0))
            if price_impact > self.max_slippage:
                raise Exception(f"Price impact {price_impact}% exceeds max slippage {self.max_slippage}%")
            
            # Get swap transaction
            swap_tx_b64 = await JupiterClient.get_swap_transaction(quote, str(self.keypair.pubkey()))
            
            if not swap_tx_b64:
                raise Exception("Failed to build swap transaction")
            
            # Decode and sign transaction
            tx_bytes = base64.b64decode(swap_tx_b64)
            versioned_tx = VersionedTransaction.from_bytes(tx_bytes)
            versioned_tx.sign([self.keypair])
            
            # Send transaction
            async_client = AsyncClient(SOLANA_RPC)
            try:
                response = await async_client.send_transaction(versioned_tx)
                tx_signature = str(response.value)
                
                execution_time = (datetime.now().timestamp() - start_time) * 1000
                
                result = {
                    'success': True,
                    'tx_signature': tx_signature,
                    'execution_time_ms': execution_time,
                    'quote_info': quote,
                    'price_impact': price_impact,
                    'detected_in_group': detected_in_group
                }
                
                # Log successful execution
                self.log_snipe_result(mint_address, result, 'success')
                
                # Emit WebSocket notification
                socketio.emit('snipe_executed', {
                    'user_id': self.user_id,
                    'mint_address': mint_address,
                    'tx_signature': tx_signature,
                    'sol_amount': self.sol_amount,
                    'execution_time_ms': execution_time,
                    'detected_in_group': detected_in_group,
                    'solscan_url': f"https://solscan.io/tx/{tx_signature}",
                    'timestamp': datetime.now().isoformat()
                })
                
                return result
                
            finally:
                await async_client.close()
                
        except Exception as e:
            execution_time = (datetime.now().timestamp() - start_time) * 1000
            
            result = {
                'success': False,
                'error': str(e),
                'execution_time_ms': execution_time,
                'detected_in_group': detected_in_group
            }
            
            # Log failed execution
            self.log_snipe_result(mint_address, result, 'failed')
            
            # Emit failure notification
            socketio.emit('snipe_failed', {
                'user_id': self.user_id,
                'mint_address': mint_address,
                'error': str(e),
                'execution_time_ms': execution_time,
                'detected_in_group': detected_in_group,
                'timestamp': datetime.now().isoformat()
            })
            
            return result
    
    def log_snipe_result(self, mint_address: str, result: dict, status: str):
        """Log snipe execution to database"""
        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.execute('''
                    INSERT INTO snipe_history 
                    (user_id, mint_address, sol_amount, slippage, tx_signature, 
                     status, error_message, execution_time_ms, detected_in_group, quote_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    self.user_id,
                    mint_address,
                    self.sol_amount,
                    self.max_slippage,
                    result.get('tx_signature'),
                    status,
                    result.get('error'),
                    result.get('execution_time_ms'),
                    result.get('detected_in_group'),
                    str(result.get('quote_info', {}))
                ))
                conn.commit()
        except Exception as e:
            print(f"[{self.user_id}] Logging error: {e}")
    
    async def start_monitoring(self):
        """Start autonomous monitoring with full automation"""
        if not self.client:
            print(f"[{self.user_id}] No Telegram client available")
            return
        
        try:
            # Emit connection status
            socketio.emit('sniper_started', {
                'user_id': self.user_id,
                'monitored_groups': len(self.monitored_groups),
                'auto_snipe_enabled': self.auto_snipe_enabled,
                'sol_amount': self.sol_amount,
                'max_slippage': self.max_slippage,
                'timestamp': datetime.now().isoformat()
            })
            
            @self.client.on(events.NewMessage(chats=self.monitored_groups))
            async def handle_message(event):
                try:
                    message_text = event.message.message or ""
                    group_title = getattr(event.chat, 'title', 'Unknown Group')
                    
                    # Scan every message for mint addresses using regex
                    detected_mints = self.address_pattern.findall(message_text)
                    
                    for mint_address in detected_mints:
                        print(f"[{self.user_id}] Detected mint: {mint_address} in {group_title}")
                        
                        # Emit detection event
                        socketio.emit('mint_detected', {
                            'user_id': self.user_id,
                            'mint_address': mint_address,
                            'group_title': group_title,
                            'message_preview': message_text[:150] + '...' if len(message_text) > 150 else message_text,
                            'auto_snipe_enabled': self.auto_snipe_enabled,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Execute autonomous snipe if enabled
                        if self.auto_snipe_enabled:
                            # Execute in background to not block message processing
                            asyncio.create_task(self.execute_snipe(mint_address, group_title))
                
                except Exception as e:
                    print(f"[{self.user_id}] Message handler error: {e}")
            
            print(f"[{self.user_id}] Autonomous monitoring started for {len(self.monitored_groups)} groups")
            await self.client.run_until_disconnected()
            
        except Exception as e:
            print(f"[{self.user_id}] Monitoring error: {e}")
            
            socketio.emit('sniper_error', {
                'user_id': self.user_id,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })

async def launch_autonomous_engine(user_config: dict):
    """Launch autonomous sniper engine for user"""
    sniper = AutonomousSniper(user_config)
    
    if await sniper.initialize():
        active_engines[user_config['user_id']] = sniper
        await sniper.start_monitoring()
    else:
        print(f"[{user_config['user_id']}] Failed to initialize autonomous engine")

def launch_all_autonomous_engines():
    """Launch all active autonomous engines"""
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('SELECT * FROM autonomous_users WHERE is_active = 1')
        users = [dict(row) for row in cursor.fetchall()]
    
    print(f"Launching {len(users)} autonomous sniper engines...")
    
    for user_config in users:
        user_id = user_config['user_id']
        
        if user_id not in active_engines:
            def run_engine(config):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                task = loop.create_task(launch_autonomous_engine(config))
                loop.run_until_complete(task)
                loop.close()
            
            thread = threading.Thread(target=run_engine, args=(user_config,), daemon=True)
            thread.start()
            
            print(f"[{user_id}] Autonomous engine launched")

# Flask API Routes
@app.route('/register_autonomous_user', methods=['POST'])
def register_autonomous_user():
    """Register new autonomous sniper user"""
    data = request.json
    
    user_id = data.get('user_id')
    private_key = data.get('private_key')
    telegram_session = data.get('telegram_session')
    sol_amount = float(data.get('sol_amount', 0.02))
    max_slippage = float(data.get('max_slippage', 1.0))
    monitored_groups = data.get('monitored_groups', [])
    
    if not all([user_id, private_key]):
        return jsonify({'error': 'user_id and private_key required'}), 400
    
    # Encrypt sensitive data
    encrypted_key = encryption.encrypt(private_key.encode()).decode()
    encrypted_session = encryption.encrypt(telegram_session.encode()).decode() if telegram_session else None
    groups_str = ','.join(monitored_groups) if monitored_groups else ''
    
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            INSERT OR REPLACE INTO autonomous_users 
            (user_id, encrypted_private_key, telegram_session_encrypted, 
             sol_amount, max_slippage, monitored_groups)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, encrypted_key, encrypted_session, sol_amount, max_slippage, groups_str))
        conn.commit()
    
    return jsonify({
        'status': 'autonomous_user_registered',
        'user_id': user_id,
        'sol_amount': sol_amount,
        'max_slippage': max_slippage,
        'monitored_groups': len(monitored_groups)
    })

@app.route('/launch_autonomous_engines', methods=['POST'])
def launch_engines():
    """Launch all autonomous engines"""
    try:
        launch_all_autonomous_engines()
        
        return jsonify({
            'status': 'autonomous_engines_launched',
            'active_engines': len(active_engines)
        })
    except Exception as e:
        return jsonify({'error': f'Launch failed: {str(e)}'}), 500

@app.route('/manual_snipe', methods=['POST'])
def manual_snipe():
    """Execute manual snipe"""
    data = request.json
    
    user_id = data.get('user_id')
    mint_address = data.get('mint_address')
    
    if not all([user_id, mint_address]):
        return jsonify({'error': 'user_id and mint_address required'}), 400
    
    # Get user engine
    engine = active_engines.get(user_id)
    if not engine:
        return jsonify({'error': 'User engine not active'}), 404
    
    try:
        # Execute snipe manually
        async def execute_manual():
            return await engine.execute_snipe(mint_address, 'manual')
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(execute_manual())
        loop.close()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'mint_address': mint_address
        }), 500

@app.route('/autonomous_status', methods=['GET'])
def autonomous_status():
    """Get autonomous system status"""
    try:
        # Test Jupiter API
        test_response = requests.get(f"{JUPITER_API}/quote", params={
            "inputMint": SOL_MINT,
            "outputMint": "DezXnKzLQzsG3DzP4if6UczZ23eaSLRSm3BaYZj2Fv2s",
            "amount": "10000000",
            "slippageBps": "50"
        }, timeout=5)
        jupiter_working = test_response.status_code == 200
        
        # Database stats
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM autonomous_users WHERE is_active = 1')
            active_users = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_history WHERE status = "success"')
            successful_snipes = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM snipe_history WHERE status = "failed"')
            failed_snipes = cursor.fetchone()[0]
        
        return jsonify({
            'jupiter_api_working': jupiter_working,
            'solana_rpc_endpoint': SOLANA_RPC,
            'active_users': active_users,
            'running_engines': len(active_engines),
            'successful_snipes': successful_snipes,
            'failed_snipes': failed_snipes,
            'success_rate': round((successful_snipes / (successful_snipes + failed_snipes) * 100) if (successful_snipes + failed_snipes) > 0 else 0, 2),
            'capabilities': {
                'autonomous_operation': True,
                'regex_mint_detection': True,
                'jupiter_v6_integration': True,
                'versioned_transactions': True,
                'real_time_execution': True,
                'encrypted_storage': True,
                'websocket_notifications': True
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Status check failed: {str(e)}'}), 500

@app.route('/snipe_history/<user_id>', methods=['GET'])
def get_snipe_history(user_id):
    """Get snipe execution history for user"""
    limit = int(request.args.get('limit', 50))
    
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT * FROM snipe_history 
            WHERE user_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (user_id, limit))
        
        history = []
        for row in cursor.fetchall():
            entry = dict(row)
            if entry['tx_signature']:
                entry['solscan_url'] = f"https://solscan.io/tx/{entry['tx_signature']}"
            history.append(entry)
    
    return jsonify({'snipe_history': history})

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print("Client connected to autonomous sniper")

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected from autonomous sniper")

if __name__ == '__main__':
    print("🧠 AUTONOMOUS SNIPER ENGINE - Production Ready")
    print("Server: http://localhost:3333")
    print()
    print("Engine Behavior:")
    print("  ✓ Scans every message in every joined group")
    print("  ✓ Filters valid mint addresses using regex")
    print("  ✓ If quote is available and slippage is within range, executes immediately")
    print("  ✓ Built for full autonomous operation — no need to manually click")
    print()
    print("Features:")
    print("  ✓ Jupiter V6 mainnet integration with versioned transactions")
    print("  ✓ Regex-based mint detection from Telegram messages")
    print("  ✓ Autonomous execution with slippage validation")
    print("  ✓ Real-time WebSocket notifications")
    print("  ✓ Comprehensive execution logging")
    print("  ✓ Multi-user concurrent operation")
    print()
    print("WebSocket Events:")
    print("  sniper_started - Engine initialization")
    print("  mint_detected - Real-time mint detection")
    print("  snipe_executed - Successful autonomous execution")
    print("  snipe_failed - Failed execution alerts")
    print("  sniper_error - System error notifications")
    print()
    print("Endpoints:")
    print("  POST /register_autonomous_user - Register user for autonomous sniping")
    print("  POST /launch_autonomous_engines - Launch all engines")
    print("  POST /manual_snipe - Execute manual snipe")
    print("  GET  /autonomous_status - System status")
    print("  GET  /snipe_history/<user_id> - Execution history")
    
    socketio.run(app, host='0.0.0.0', port=3333, debug=False)