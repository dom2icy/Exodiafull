import os
import re
import base64
import asyncio
import aiohttp
import aiosqlite
import requests
import sqlite3
import threading
import random
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, Blueprint, request, jsonify
from flask_socketio import SocketIO, emit
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.rpc.async_api import AsyncClient
from solders.transaction import VersionedTransaction
from exodia_sdk.security import FernetEncryption

# Production mainnet configuration
os.environ['FERNET_KEY'] = "otPo66UgjPf9Iv9w1F0ndhi7HRhfXVO0cWhjKBwWlx8="

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Production encryption
encryption = FernetEncryption(key=os.environ.get('FERNET_KEY'))

# Database configuration
DB_PATH = 'production_sniper.sqlite3'
API_ID = 21724048
API_HASH = "82c3e0c51d4c6f46bce0e38b7dc3c9b8"

# MAINNET ONLY configuration
JUPITER_API = "https://quote-api.jup.ag/v6"
SOLANA_RPC_MAINNET = "https://api.mainnet-beta.solana.com"
SOL_MINT = "So11111111111111111111111111111111111111112"

# Retry configuration
MAX_RETRIES = 3
BASE_DELAY = 1

# Active sniper sessions
active_snipers = {}

async def init_production_db():
    """Initialize production database with proper schema"""
    async with aiosqlite.connect(DB_PATH) as db:
        # Users table: stores user info + encrypted Solana key
        await db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            encrypted_key BLOB NOT NULL,
            telegram_session BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Telegram groups table: tracks groups users subscribe to
        await db.execute('''
        CREATE TABLE IF NOT EXISTS telegram_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id BIGINT UNIQUE NOT NULL,
            group_name TEXT
        )
        ''')
        
        # User <-> Telegram group join table (many-to-many)
        await db.execute('''
        CREATE TABLE IF NOT EXISTS user_telegram_groups (
            user_id INTEGER NOT NULL,
            telegram_group_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, telegram_group_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (telegram_group_id) REFERENCES telegram_groups(id)
        )
        ''')
        
        # Sniper action logs for auditing
        await db.execute('''
        CREATE TABLE IF NOT EXISTS sniper_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mint TEXT NOT NULL,
            group_id BIGINT NOT NULL,
            status TEXT NOT NULL,
            error_message TEXT,
            tx_signature TEXT,
            execution_time_ms REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        
        await db.commit()

# Initialize database
asyncio.run(init_production_db())

async def get_users_for_group(group_id: int):
    """Get all users subscribed to a Telegram group"""
    async with aiosqlite.connect(DB_PATH) as db:
        query = """
        SELECT u.id, u.username, u.encrypted_key, u.telegram_session
        FROM users u
        JOIN user_telegram_groups utg ON u.id = utg.user_id
        JOIN telegram_groups tg ON tg.id = utg.telegram_group_id
        WHERE tg.group_id = ?
        """
        cursor = await db.execute(query, (group_id,))
        rows = await cursor.fetchall()
        await cursor.close()
        return [{'id': row[0], 'username': row[1], 'encrypted_key': row[2], 'telegram_session': row[3]} for row in rows]

async def get_encrypted_key_by_user(user_id: int):
    """Get encrypted private key for user"""
    async with aiosqlite.connect(DB_PATH) as db:
        query = "SELECT encrypted_key FROM users WHERE id = ?"
        cursor = await db.execute(query, (user_id,))
        row = await cursor.fetchone()
        await cursor.close()
        return row[0] if row else None

async def log_sniper_action(user_id: int, mint: str, group_id: int, status: str, error_msg: str = '', tx_signature: str = '', execution_time_ms: float = 0):
    """Log sniper action for auditing"""
    async with aiosqlite.connect(DB_PATH) as db:
        query = """
        INSERT INTO sniper_logs (user_id, mint, group_id, status, error_message, tx_signature, execution_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        await db.execute(query, (user_id, mint, group_id, status, error_msg, tx_signature, execution_time_ms))
        await db.commit()

async def execute_with_retries(coro, *args, **kwargs):
    """Execute async coroutine with retries and exponential backoff"""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return await coro(*args, **kwargs)
        except Exception as e:
            if attempt == MAX_RETRIES:
                raise
            delay = BASE_DELAY * (2 ** (attempt - 1)) + random.uniform(0, 0.5)
            await asyncio.sleep(delay)

class JupiterMainnetClient:
    """Production Jupiter V6 client for mainnet trading"""
    
    @staticmethod
    async def get_quote(input_mint: str, output_mint: str, amount_lamports: int, slippage_bps: int = 50):
        """Get Jupiter quote for mainnet trading"""
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            params = {
                "inputMint": input_mint,
                "outputMint": output_mint,
                "amount": str(amount_lamports),
                "slippageBps": str(slippage_bps),
                "onlyDirectRoutes": "false",
            }
            
            async with session.get(f"{JUPITER_API}/quote", params=params) as resp:
                if resp.status != 200:
                    raise Exception(f"Jupiter quote failed: {resp.status}")
                
                data = await resp.json()
                routes = data.get("data", [])
                
                if not routes:
                    raise Exception("No routes available")
                
                return routes[0]
    
    @staticmethod
    async def get_swap_transaction(quote: dict, user_pubkey: str):
        """Get swap transaction for mainnet execution"""
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            payload = {
                "route": quote,
                "userPublicKey": user_pubkey,
                "wrapUnwrapSOL": True,
                "asLegacyTransaction": False
            }
            
            async with session.post(f"{JUPITER_API}/swap", json=payload) as resp:
                if resp.status != 200:
                    raise Exception(f"Swap transaction failed: {resp.status}")
                
                data = await resp.json()
                return data.get("swapTransaction")

async def sniper_for_user(user_id: int, mint: str, group_id: int):
    """Execute snipe for individual user with mainnet trading"""
    start_time = datetime.now().timestamp()
    
    try:
        # Get user's encrypted key
        encrypted_key = await get_encrypted_key_by_user(user_id)
        if not encrypted_key:
            raise Exception("No encrypted key found for user")
        
        # Decrypt private key
        decrypted_key = encryption.decrypt(encrypted_key).decode()
        keypair_bytes = base64.b64decode(decrypted_key)
        keypair = Keypair.from_bytes(keypair_bytes)
        
        # Get Jupiter quote for mainnet
        amount_lamports = int(0.02 * 1_000_000_000)  # 0.02 SOL default
        slippage_bps = 50  # 0.5% slippage
        
        quote = await JupiterMainnetClient.get_quote(SOL_MINT, mint, amount_lamports, slippage_bps)
        
        # Check slippage tolerance
        price_impact = float(quote.get('priceImpactPct', 0))
        if price_impact > 1.0:  # Max 1% price impact
            raise Exception(f"Price impact {price_impact}% too high")
        
        # Build swap transaction
        swap_tx_b64 = await JupiterMainnetClient.get_swap_transaction(quote, str(keypair.pubkey()))
        
        if not swap_tx_b64:
            raise Exception("Failed to build swap transaction")
        
        # Execute on mainnet
        tx_bytes = base64.b64decode(swap_tx_b64)
        versioned_tx = VersionedTransaction.from_bytes(tx_bytes)
        versioned_tx.sign([keypair])
        
        # Send to mainnet
        async_client = AsyncClient(SOLANA_RPC_MAINNET)
        try:
            response = await async_client.send_transaction(versioned_tx)
            tx_signature = str(response.value)
            
            execution_time = (datetime.now().timestamp() - start_time) * 1000
            
            # Log successful mainnet execution
            await log_sniper_action(user_id, mint, group_id, 'success', '', tx_signature, execution_time)
            
            # Emit success notification
            socketio.emit('mainnet_snipe_success', {
                'user_id': user_id,
                'mint': mint,
                'tx_signature': tx_signature,
                'execution_time_ms': execution_time,
                'group_id': group_id,
                'solscan_url': f"https://solscan.io/tx/{tx_signature}",
                'network': 'mainnet',
                'timestamp': datetime.now().isoformat()
            })
            
            print(f"[MAINNET] User {user_id} sniped {mint}: {tx_signature}")
            
        finally:
            await async_client.close()
            
    except Exception as e:
        execution_time = (datetime.now().timestamp() - start_time) * 1000
        
        # Log failed execution
        await log_sniper_action(user_id, mint, group_id, 'failed', str(e), '', execution_time)
        
        # Emit failure notification
        socketio.emit('mainnet_snipe_failed', {
            'user_id': user_id,
            'mint': mint,
            'error': str(e),
            'execution_time_ms': execution_time,
            'group_id': group_id,
            'network': 'mainnet',
            'timestamp': datetime.now().isoformat()
        })
        
        print(f"[MAINNET] User {user_id} snipe failed for {mint}: {e}")

async def sniper_for_user_with_retry(user_id: int, mint: str, group_id: int):
    """Execute snipe with retry logic"""
    async def sniper_task():
        return await sniper_for_user(user_id, mint, group_id)
    
    try:
        await execute_with_retries(sniper_task)
    except Exception as e:
        await log_sniper_action(user_id, mint, group_id, 'failed', f"Retries exhausted: {str(e)}")

async def dispatch_sniper(mint: str, group_id: int):
    """Dispatch sniper to all users for detected mint"""
    try:
        # Get all users subscribed to this group
        users = await get_users_for_group(group_id)
        
        if not users:
            print(f"[DISPATCH] No users found for group {group_id}")
            return
        
        print(f"[DISPATCH] Sniping {mint} for {len(users)} users in group {group_id}")
        
        # Execute concurrent sniping for all users
        tasks = [sniper_for_user_with_retry(user['id'], mint, group_id) for user in users]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Emit dispatch completion
        socketio.emit('dispatch_completed', {
            'mint': mint,
            'group_id': group_id,
            'users_count': len(users),
            'network': 'mainnet',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[DISPATCH] Error dispatching sniper for {mint}: {e}")

class UserTelegramSession:
    """Manage individual user Telegram sessions"""
    
    def __init__(self, user_id: int, encrypted_session_bytes: bytes, encryption_module, api_id: int, api_hash: str):
        self.user_id = user_id
        self.encrypted_session_bytes = encrypted_session_bytes
        self.encryption = encryption_module
        self.api_id = api_id
        self.api_hash = api_hash
        self.client = None
        self.address_pattern = re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b')
    
    async def _decrypt_session(self):
        """Decrypt session string"""
        decrypted = self.encryption.decrypt(self.encrypted_session_bytes)
        return decrypted.decode()
    
    async def start_client(self):
        """Start Telegram client with session"""
        try:
            session_str = await self._decrypt_session()
            self.client = TelegramClient(StringSession(session_str), self.api_id, self.api_hash)
            await self.client.start()
            
            # Setup message handler for mint detection
            @self.client.on(events.NewMessage)
            async def handle_message(event):
                try:
                    message_text = event.message.message or ""
                    group_id = event.chat_id
                    
                    # Detect mint addresses using regex
                    detected_mints = self.address_pattern.findall(message_text)
                    
                    for mint in detected_mints:
                        print(f"[USER {self.user_id}] Detected mint: {mint} in group {group_id}")
                        
                        # Emit detection event
                        socketio.emit('mint_detected', {
                            'user_id': self.user_id,
                            'mint': mint,
                            'group_id': group_id,
                            'message_preview': message_text[:100],
                            'network': 'mainnet',
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Dispatch sniper to all users in this group
                        asyncio.create_task(dispatch_sniper(mint, group_id))
                
                except Exception as e:
                    print(f"[USER {self.user_id}] Message handler error: {e}")
            
            print(f"[USER {self.user_id}] Telegram client started for mainnet sniping")
            return self.client
            
        except Exception as e:
            print(f"[USER {self.user_id}] Failed to start client: {e}")
            return None
    
    async def stop_client(self):
        """Stop Telegram client"""
        if self.client:
            await self.client.disconnect()
            print(f"[USER {self.user_id}] Telegram client stopped")

class MainnetSniperManager:
    """Manage all mainnet sniper sessions"""
    
    def __init__(self):
        self.user_sessions = {}
    
    async def start_all_users(self):
        """Start monitoring for all users with Telegram sessions"""
        async with aiosqlite.connect(DB_PATH) as db:
            query = "SELECT id, telegram_session FROM users WHERE telegram_session IS NOT NULL"
            cursor = await db.execute(query)
            rows = await cursor.fetchall()
            await cursor.close()
            
            for user_id, encrypted_session in rows:
                try:
                    session = UserTelegramSession(user_id, encrypted_session, encryption, API_ID, API_HASH)
                    client = await session.start_client()
                    
                    if client:
                        self.user_sessions[user_id] = session
                        print(f"[MANAGER] Started session for user {user_id}")
                    
                except Exception as e:
                    print(f"[MANAGER] Failed to start session for user {user_id}: {e}")
        
        print(f"[MANAGER] Started {len(self.user_sessions)} user sessions for mainnet sniping")
    
    async def stop_all_users(self):
        """Stop all user sessions"""
        for user_id, session in self.user_sessions.items():
            await session.stop_client()
        
        self.user_sessions.clear()
        print("[MANAGER] Stopped all user sessions")

# Global mainnet sniper manager
mainnet_manager = MainnetSniperManager()

# Flask Blueprint for API routes
sniper_bp = Blueprint('sniper', __name__)

@sniper_bp.route('/telegram/link', methods=['POST'])
def link_telegram_session():
    """Link encrypted Telegram session to user"""
    user_id = request.json.get('user_id')
    session_str = request.json.get('session_str')
    
    if not user_id or not session_str:
        return jsonify({'error': 'user_id and session_str required'}), 400
    
    try:
        # Encrypt session string
        encrypted_session = encryption.encrypt(session_str.encode())
        
        # Save to database
        with sqlite3.connect(DB_PATH) as db:
            db.execute('UPDATE users SET telegram_session = ? WHERE id = ?', (encrypted_session, user_id))
            db.commit()
        
        return jsonify({'status': 'linked', 'user_id': user_id})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@sniper_bp.route('/telegram/groups', methods=['GET'])
def list_user_groups():
    """List user's joined Telegram groups"""
    user_id = request.args.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'user_id required'}), 400
    
    try:
        with sqlite3.connect(DB_PATH) as db:
            db.row_factory = sqlite3.Row
            cursor = db.execute('''
                SELECT tg.group_id, tg.group_name
                FROM telegram_groups tg
                JOIN user_telegram_groups utg ON tg.id = utg.telegram_group_id
                WHERE utg.user_id = ?
            ''', (user_id,))
            
            groups = [dict(row) for row in cursor.fetchall()]
        
        return jsonify({'groups': groups, 'user_id': user_id})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@sniper_bp.route('/sniper/start', methods=['POST'])
def start_sniper():
    """Start mainnet sniper for user"""
    try:
        # Start all user sessions
        def run_manager():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(mainnet_manager.start_all_users())
            
            # Keep running until disconnected
            for session in mainnet_manager.user_sessions.values():
                if session.client:
                    loop.run_until_complete(session.client.run_until_disconnected())
            
            loop.close()
        
        thread = threading.Thread(target=run_manager, daemon=True)
        thread.start()
        
        return jsonify({
            'status': 'mainnet_sniper_started',
            'network': 'mainnet',
            'active_sessions': len(mainnet_manager.user_sessions)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@sniper_bp.route('/sniper/status', methods=['GET'])
def sniper_status():
    """Get mainnet sniper status"""
    try:
        # Test mainnet connectivity
        test_response = requests.get(f"{JUPITER_API}/quote", params={
            "inputMint": SOL_MINT,
            "outputMint": "DezXnKzLQzsG3DzP4if6UczZ23eaSLRSm3BaYZj2Fv2s",
            "amount": "10000000",
            "slippageBps": "50"
        }, timeout=5)
        jupiter_working = test_response.status_code == 200
        
        # Database stats
        with sqlite3.connect(DB_PATH) as db:
            cursor = db.execute('SELECT COUNT(*) FROM users WHERE telegram_session IS NOT NULL')
            users_with_sessions = cursor.fetchone()[0]
            
            cursor = db.execute('SELECT COUNT(*) FROM sniper_logs WHERE status = "success"')
            successful_snipes = cursor.fetchone()[0]
            
            cursor = db.execute('SELECT COUNT(*) FROM sniper_logs WHERE status = "failed"')
            failed_snipes = cursor.fetchone()[0]
        
        return jsonify({
            'network': 'mainnet',
            'jupiter_api_working': jupiter_working,
            'solana_rpc': SOLANA_RPC_MAINNET,
            'users_with_sessions': users_with_sessions,
            'active_sessions': len(mainnet_manager.user_sessions),
            'successful_snipes': successful_snipes,
            'failed_snipes': failed_snipes,
            'success_rate': round((successful_snipes / (successful_snipes + failed_snipes) * 100) if (successful_snipes + failed_snipes) > 0 else 0, 2),
            'capabilities': {
                'mainnet_trading': True,
                'multi_user_concurrent': True,
                'regex_mint_detection': True,
                'jupiter_v6_integration': True,
                'retry_with_backoff': True,
                'encrypted_session_storage': True,
                'real_time_notifications': True
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@sniper_bp.route('/manual_snipe', methods=['POST'])
def manual_snipe():
    """Execute manual mainnet snipe"""
    user_id = request.json.get('user_id')
    mint = request.json.get('mint')
    group_id = request.json.get('group_id', 0)
    
    if not all([user_id, mint]):
        return jsonify({'error': 'user_id and mint required'}), 400
    
    try:
        # Execute manual snipe
        def execute_manual():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(sniper_for_user_with_retry(user_id, mint, group_id))
            loop.close()
        
        thread = threading.Thread(target=execute_manual, daemon=True)
        thread.start()
        
        return jsonify({
            'status': 'manual_snipe_initiated',
            'user_id': user_id,
            'mint': mint,
            'network': 'mainnet'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Register blueprint
app.register_blueprint(sniper_bp, url_prefix='/api')

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print("Client connected to mainnet sniper")

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected from mainnet sniper")

if __name__ == '__main__':
    print("🚀 PRODUCTION MAINNET SNIPER - Live Trading")
    print("Server: http://localhost:4444")
    print()
    print("⚠️  MAINNET CONFIGURATION:")
    print(f"  • Solana RPC: {SOLANA_RPC_MAINNET}")
    print(f"  • Jupiter API: {JUPITER_API}")
    print("  • Real money transactions enabled")
    print("  • All trading on Solana mainnet")
    print()
    print("Multi-User Concurrent Features:")
    print("  ✓ dispatch_sniper: Called once per detected mint event")
    print("  ✓ Queries all users linked to that group")
    print("  ✓ Runs sniper_for_user concurrently for each user")
    print("  ✓ Each sniper fetches user's encrypted key, decrypts it")
    print("  ✓ Gets Jupiter quote, executes swap, logs result")
    print("  ✓ Respects slippage limit as quick filter")
    print("  ✓ Logs success/failure for auditing and frontend push")
    print("  ✓ Async ensures it scales to many users simultaneously")
    print()
    print("Database Schema:")
    print("  • users: stores encrypted keys and sessions")
    print("  • telegram_groups: tracks monitored groups")
    print("  • user_telegram_groups: many-to-many subscriptions")
    print("  • sniper_logs: comprehensive audit trail")
    print()
    print("WebSocket Events:")
    print("  mainnet_snipe_success - Successful mainnet executions")
    print("  mainnet_snipe_failed - Failed execution alerts")
    print("  mint_detected - Real-time mint detection")
    print("  dispatch_completed - Multi-user dispatch status")
    print()
    print("API Endpoints:")
    print("  POST /api/telegram/link - Link encrypted Telegram session")
    print("  GET  /api/telegram/groups - List user's joined groups")
    print("  POST /api/sniper/start - Start mainnet sniper")
    print("  GET  /api/sniper/status - System status")
    print("  POST /api/manual_snipe - Execute manual mainnet snipe")
    print()
    print("⚡ Ready for production mainnet trading")
    
    socketio.run(app, host='0.0.0.0', port=4444, debug=False)