import os
import logging
import asyncio
import re
import time
from collections import defaultdict
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect
from telegram_monitor import TelegramMonitor
from clean_solana_client import CleanSolanaClient
from security_manager import security_manager, SecurityError
from secure_session_store import setup_secure_session_store
from csrf_spa_middleware import csrf_protect_spa, csrf_token_endpoint
# from telegram_trader import TelegramTrader, get_trader_instance, set_trader_instance

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Setup CSRF protection
csrf = CSRFProtect(app)

# Setup secure server-side session store (after database config)
# This needs to be after database configuration is complete

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///trading.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

db.init_app(app)
solana_client = CleanSolanaClient()

# Setup secure server-side session store after database is configured
setup_secure_session_store(app)

with app.app_context():
    import models
    db.create_all()

# Register authentication blueprint (import after app creation to avoid circular imports)
from auth_routes import auth_bp
app.register_blueprint(auth_bp)

# Register wallet management blueprint
from wallet_api_routes import wallet_bp
app.register_blueprint(wallet_bp)

# Store phone_code_hash per session
def get_phone_code_hash():
    return session.get('phone_code_hash')

def set_phone_code_hash(code_hash):
    session['phone_code_hash'] = code_hash

# Global storage for maintaining client connections between requests
telegram_clients = {}

# Global event loop for Telegram operations
telegram_event_loop = None

# Rate limiting for security
rate_limiter = defaultdict(lambda: {'count': 0, 'last_reset': time.time()})
RATE_LIMIT_WINDOW = 300  # 5 minutes
MAX_ATTEMPTS_PER_WINDOW = 5

def get_telegram_loop():
    global telegram_event_loop
    if telegram_event_loop is None or telegram_event_loop.is_closed():
        telegram_event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(telegram_event_loop)
    return telegram_event_loop

# Import the proper middleware from auth_routes
from auth_routes import authenticate_token, authorize_roles, sliding_window_rate_limiter, log_audit_event

# Keep the old function for backward compatibility
def require_auth(permission=None):
    """
    Legacy decorator - use authenticate_token instead
    """
    return authenticate_token(permission)

def check_rate_limit(identifier):
    """Enhanced rate limiting with security manager"""
    return security_manager.check_rate_limit(identifier, limit=5, window=300)

def validate_phone_number(phone_number):
    """Validate phone number format (international format)"""
    # Remove any spaces, dashes, or parentheses
    cleaned_phone = re.sub(r'[\s\-\(\)]', '', phone_number)
    
    # Check if it starts with + and has 10-15 digits
    if not re.match(r'^\+\d{10,15}$', cleaned_phone):
        return False, "Phone number must be in international format (e.g., +1234567890)"
    
    return True, cleaned_phone

def validate_api_credentials(api_id, api_hash):
    """Validate Telegram API credentials format"""
    try:
        api_id = int(api_id)
        if api_id <= 0:
            return False, "API ID must be a positive integer"
    except (ValueError, TypeError):
        return False, "API ID must be a valid integer"
    
    if not api_hash or len(api_hash) != 32:
        return False, "API Hash must be exactly 32 characters long"
    
    if not re.match(r'^[a-f0-9]{32}$', api_hash):
        return False, "API Hash must contain only lowercase hexadecimal characters"
    
    return True, (api_id, api_hash)

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    return render_template('index.html')

@app.route('/wallet')
def wallet_dashboard():
    return render_template('wallet_dashboard.html')

@app.route('/logout')
def logout():
    # Secure session cleanup - ensure encrypted keys are cleared
    logger.info("Clearing encrypted session data")
    session.clear()
    return redirect(url_for('landing'))

# Wallet API Endpoints
@app.route('/api/wallet/setup', methods=['POST'])
def api_wallet_setup():
    """Setup wallet and validate with real Solana network"""
    try:
        # Add audit logging if authenticated
        try:
            user_id = request.user.get('user_id', 'unknown') if hasattr(request, 'user') else 'unauthenticated'
            log_audit_event(user_id, 'wallet_setup_attempt', 'Setting up new wallet')
        except:
            pass  # Skip audit logging if not authenticated
        data = request.get_json()
        wallet_address = data.get('wallet_address', '').strip()
        
        if not wallet_address:
            return jsonify({'error': 'Wallet address required'}), 400
        
        # Real Solana validation using our client
        from clean_solana_client import CleanSolanaClient
        from solders.pubkey import Pubkey
        
        try:
            # Validate address format
            public_key = Pubkey.from_string(wallet_address)
            
            # Get real balance from Solana network
            solana_client = CleanSolanaClient()
            balance = solana_client.get_wallet_balance(public_key)
            
            # Store in session
            session['wallet_address'] = wallet_address
            session['wallet_balance'] = balance
            
            # Log successful wallet setup if authenticated
            try:
                user_id = request.user.get('user_id', 'unknown') if hasattr(request, 'user') else 'unauthenticated'
                log_audit_event(user_id, 'wallet_setup_success', f'Address: {wallet_address[:8]}...{wallet_address[-8:]}')
            except:
                pass
            
            return jsonify({
                'status': 'success',
                'message': 'Wallet connected successfully',
                'balance': balance,
                'address': wallet_address
            })
            
        except Exception as e:
            logger.error(f"Wallet validation error: {e}")
            return jsonify({'error': 'Invalid Solana wallet address'}), 400
            
    except Exception as e:
        logger.error(f"Wallet setup error: {e}")
        return jsonify({'error': 'Failed to setup wallet'}), 500

@app.route('/api/wallet/balance', methods=['GET'])
@authenticate_token('wallet_access')
def api_wallet_balance():
    """Get real wallet balance from Solana network"""
    try:
        wallet_address = session.get('wallet_address')
        if not wallet_address:
            return jsonify({'error': 'No wallet connected'}), 400
        
        from clean_solana_client import CleanSolanaClient
        from solders.pubkey import Pubkey
        
        solana_client = CleanSolanaClient()
        balance = solana_client.get_wallet_balance(Pubkey.from_string(wallet_address))
        
        # Update session
        session['wallet_balance'] = balance
        
        return jsonify({
            'status': 'success',
            'balance': balance,
            'address': wallet_address
        })
        
    except Exception as e:
        logger.error(f"Balance check error: {e}")
        return jsonify({'error': 'Failed to get balance'}), 500

@app.route('/api/trading/configure', methods=['POST'])
@authenticate_token('trading_access')
@sliding_window_rate_limiter(max_requests=3, window_ms=300000)

def api_trading_configure():
    """Configure trading with private key using comprehensive security controls"""
    try:
        # CRITICAL: Validate session and authentication before allowing private key storage
        if not session.get('wallet_address'):
            return jsonify({'error': 'Wallet must be connected before configuring private key'}), 401
        
        # Ensure user has proper authentication context
        user_id = request.user.get('user_id', 'unknown') if hasattr(request, 'user') else None
        if not user_id:
            return jsonify({'error': 'Authentication required for private key configuration'}), 401
        
        # Rate limiting check for private key operations
        client_ip = request.remote_addr
        if not check_rate_limit(f"private_key_config_{client_ip}"):
            return jsonify({'error': 'Rate limit exceeded for private key operations'}), 429
        
        # Audit logging for security (sanitized - no user input logged)
        log_audit_event(user_id, 'trading_config_attempt', f'Private key configuration attempt from IP: {client_ip[:8]}***')
        data = request.get_json()
        client_encrypted_private_key = data.get('client_encrypted_private_key')
        private_key = data.get('private_key', '').strip()  # Fallback for old clients
        auto_trading = data.get('auto_trading', False)
        encryption_method = data.get('encryption_method', 'unknown')
        
        # Sanitize inputs - never log raw user data
        input_length = len(client_encrypted_private_key) if client_encrypted_private_key else len(private_key) if private_key else 0
        
        # Prefer client-encrypted data
        if client_encrypted_private_key:
            logger.info(f"Received client-side encrypted data (method: {encryption_method}, length: {input_length})")
            
            # Add encryption versioning for future migration paths
            encryption_metadata = {
                'version': 'v1.0',
                'method': 'client_server_double',
                'client_method': encryption_method,
                'server_method': 'aes_256_gcm',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Apply server-side encryption to client-encrypted data (double encryption)
            encrypted_private_key = security_manager.encrypt_sensitive_data(
                client_encrypted_private_key,
                context="double_encrypted_private_key_v1",
                user_id=user_id
            )
            logger.info("Applied double encryption: client-side + server-side AES-256-GCM")
            
        elif private_key:
            logger.warning(f"Received plaintext private key (length: {input_length}) - applying server-side encryption only")
            
            encryption_metadata = {
                'version': 'v1.0',
                'method': 'server_only',
                'server_method': 'aes_256_gcm',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            encrypted_private_key = security_manager.encrypt_sensitive_data(
                private_key,
                context="server_only_encrypted_private_key_v1",
                user_id=user_id
            )
        else:
            return jsonify({'error': 'Private key required'}), 400
        
        # SECURITY: Use secure database-only storage (no client-side session storage)
        wallet_address = session.get('wallet_address')
        if not wallet_address:
            return jsonify({'error': 'Wallet address not found in session'}), 400
            
        try:
            from models import SolanaWallet
            
            # Store only in secure database with versioning
            wallet = SolanaWallet.query.filter_by(public_key=wallet_address).first()
            if not wallet:
                wallet = SolanaWallet(
                    public_key=wallet_address,
                    private_key_encrypted=encrypted_private_key,
                    encryption_version=encryption_metadata['version'],
                    encryption_method=encryption_metadata['method']
                )
                db.session.add(wallet)
            else:
                # Update existing wallet with new encrypted key and metadata
                wallet.private_key_encrypted = encrypted_private_key
                wallet.encryption_version = encryption_metadata['version']
                wallet.encryption_method = encryption_metadata['method']
                wallet.updated_at = datetime.utcnow()
            
            db.session.commit()
            logger.info(f"Private key securely stored in database for wallet {wallet_address[:8]}*** with version {encryption_metadata['version']}")
            
            # Store minimal session data (no private key data)
            session['auto_trading'] = auto_trading
            session['private_key_configured'] = True
            session['encryption_version'] = encryption_metadata['version']
            
        except Exception as db_error:
            logger.error(f"Database storage failed: {str(db_error)[:100]}...")
            return jsonify({'error': 'Failed to store private key securely'}), 500
        
        # Log successful configuration (sanitized)
        try:
            security_level = "Maximum (Double Encryption)" if client_encrypted_private_key else "High (Server-side)"
            log_audit_event(user_id, 'trading_configure_success', 
                          f'Private key stored with {security_level} encryption version {encryption_metadata["version"]}')
        except Exception as log_error:
            logger.warning(f"Audit logging failed: {log_error}")
        
        security_level = "Maximum (Double Encryption)" if client_encrypted_private_key else "High (Server-side)"
        encryption_desc = "Client-side AES-GCM + Server-side AES-256-GCM" if client_encrypted_private_key else "Server-side AES-256-GCM"
        
        return jsonify({
            'status': 'success',
            'message': f'Private key protected with {security_level.lower()} security',
            'auto_trading': auto_trading,
            'encryption': encryption_desc,
            'security_level': security_level,
            'encryption_version': encryption_metadata['version'],
            'csrf_token': session.get('csrf_token')  # Include CSRF token for future requests
        })
            
    except Exception as e:
        # Sanitized error logging - no user data exposure
        error_id = str(uuid.uuid4())[:8]
        logger.error(f"Trading config error [{error_id}]: {str(e)[:100]}...")
        
        # Log for debugging but don't expose details to client
        try:
            user_id = request.user.get('user_id', 'unknown') if hasattr(request, 'user') else 'unknown'
            log_audit_event(user_id, 'trading_configure_error', f'Configuration failed with error ID: {error_id}')
        except:
            pass
            
        return jsonify({'error': f'Failed to configure trading. Error ID: {error_id}'}), 500

# CSRF token endpoint for SPA frontend
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Get CSRF token for SPA frontend"""
    return csrf_token_endpoint()

# Add encryption test endpoint for verification
@app.route('/api/test/encryption', methods=['POST'])
@authenticate_token('admin_access')
def test_encryption_integrity():
    """Test endpoint to verify encrypt/decrypt integrity"""
    try:
        test_data = "test_private_key_12345"
        
        # Test encryption/decryption cycle with salt & pepper
        encrypted = security_manager.encrypt_sensitive_data(test_data, context="test_context", user_id="test_user")
        decrypted = security_manager.decrypt_sensitive_data(encrypted, context="test_context", user_id="test_user")
        
        integrity_check = test_data == decrypted
        
        # Send alert if encryption test fails
        if not integrity_check:
            security_manager._send_security_alert('encryption_test_failed', {
                'test_data_length': len(test_data),
                'encrypted_length': len(encrypted),
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return jsonify({
            'status': 'success' if integrity_check else 'failed',
            'encryption_integrity': integrity_check,
            'encrypted_length': len(encrypted),
            'test_passed': integrity_check,
            'salt_pepper_enabled': True
        })
        
    except Exception as e:
        logger.error(f"Encryption test failed: {e}")
        return jsonify({'status': 'failed', 'error': 'Encryption test failed'}), 500

# Global trader instance
current_trader = None

@app.route('/api/monitor/start', methods=['POST'])
@authenticate_token('telegram_access')
@sliding_window_rate_limiter(max_requests=5, window_ms=300000)  # 5 attempts per 5 minutes
def api_start_monitoring():
    """Start monitoring Telegram channel for contract addresses"""
    global current_trader
    
    try:
        # Add audit logging if authenticated
        try:
            user_id = request.user.get('user_id', 'unknown') if hasattr(request, 'user') else 'unauthenticated'
            log_audit_event(user_id, 'monitoring_start_attempt', 'Starting Telegram monitoring')
        except:
            pass
        data = request.get_json()
        channel_name = data.get('channel_name', '').strip()
        sol_amount = float(data.get('sol_amount', 0.1))
        
        if not channel_name:
            return jsonify({'error': 'Channel name required'}), 400
            
        if sol_amount <= 0:
            return jsonify({'error': 'Invalid SOL amount'}), 400
        
        # Check if user has configured wallet and Telegram
        if not session.get('telegram_connected'):
            return jsonify({'error': 'Please connect Telegram first'}), 400
            
        if not session.get('trading_private_key_encrypted'):
            return jsonify({'error': 'Please configure your trading wallet first'}), 400
        
        # Get session data with thread-safe access and decrypt private key
        encrypted_private_key = session.get('trading_private_key_encrypted')
        try:
            decrypted_private_key = security_manager.decrypt_sensitive_data(
                encrypted_private_key,
                context="trading_private_key"
            )
        except Exception as e:
            logger.error(f"Failed to decrypt private key: {e}")
            return jsonify({'error': 'Invalid trading wallet configuration. Please reconfigure.'}), 400
        
        session_data = {
            'session_string': session.get('session_string'),
            'api_id': session.get('api_id'),
            'api_hash': session.get('api_hash'),
            'phone_number': session.get('phone_number'),
            'private_key': decrypted_private_key,
            'auto_trading': session.get('auto_trading_enabled', True)
        }
        
        if not all([session_data['session_string'], session_data['api_id'], 
                   session_data['api_hash'], session_data['phone_number']]):
            return jsonify({'error': 'Missing Telegram session data. Please reconnect.'}), 400
        
        # Import and initialize trader
        from telegram_trader import TelegramTrader
        
        # Stop existing trader if running
        if current_trader:
            try:
                loop = get_telegram_loop()
                loop.run_until_complete(current_trader.stop_monitoring())
            except Exception as e:
                logger.warning(f"Error stopping previous trader: {e}")
        
        # Create new trader instance with session data
        current_trader = TelegramTrader(
            api_id=int(session_data['api_id']),
            api_hash=session_data['api_hash'],
            phone_number=session_data['phone_number'],
            session_string=session_data['session_string']
        )
        
        # Start monitoring in background
        loop = get_telegram_loop()
        result = loop.run_until_complete(
            current_trader.start_monitoring(
                channel_name=channel_name,
                sol_amount=sol_amount,
                private_key=session_data['private_key'],
                auto_buy=session_data['auto_trading']
            )
        )
        
        if result.get('status') == 'success':
            # Store monitoring state in session
            session['monitoring_active'] = True
            session['monitoring_channel'] = channel_name
            session['monitoring_sol_amount'] = sol_amount
            
            # Log successful monitoring start if authenticated
            try:
                user_id = request.user.get('user_id', 'unknown') if hasattr(request, 'user') else 'unauthenticated'
                log_audit_event(user_id, 'monitoring_started', f'Channel: {channel_name}, Amount: {sol_amount} SOL')
            except:
                pass
            
            return jsonify({
                'status': 'success',
                'message': f'Started monitoring {channel_name}',
                'channel': channel_name,
                'sol_amount': sol_amount,
                'auto_trading': auto_trading
            })
        else:
            return jsonify({
                'status': 'error',
                'error': result.get('message', 'Failed to start monitoring')
            }), 500
            
    except Exception as e:
        logger.error(f"Monitor start error: {e}", exc_info=True)
        return jsonify({'error': f'Failed to start monitoring: {str(e)}'}), 500

@app.route('/api/monitor/stop', methods=['POST'])
@authenticate_token('telegram_access')
def api_stop_monitoring():
    """Stop monitoring Telegram channels"""
    global current_trader
    
    try:
        if not current_trader:
            return jsonify({'error': 'No active monitoring'}), 400
        
        # Stop the trader
        loop = get_telegram_loop()
        result = loop.run_until_complete(current_trader.stop_monitoring())
        
        if result.get('status') == 'success':
            # Clear monitoring state
            session['monitoring_active'] = False
            session.pop('monitoring_channel', None)
            session.pop('monitoring_sol_amount', None)
            current_trader = None
            
            return jsonify({
                'status': 'success',
                'message': 'Monitoring stopped'
            })
        else:
            return jsonify({
                'status': 'error',
                'error': result.get('message', 'Failed to stop monitoring')
            }), 500
            
    except Exception as e:
        logger.error(f"Monitor stop error: {e}")
        return jsonify({'error': f'Failed to stop monitoring: {str(e)}'}), 500

@app.route('/api/monitor/status', methods=['GET'])
@authenticate_token('telegram_access')
def api_monitor_status():
    """Get current monitoring status"""
    try:
        is_active = session.get('monitoring_active', False)
        channel = session.get('monitoring_channel')
        sol_amount = session.get('monitoring_sol_amount')
        
        return jsonify({
            'status': 'success',
            'monitoring_active': is_active,
            'channel': channel,
            'sol_amount': sol_amount,
            'auto_trading': session.get('auto_trading_enabled', False)
        })
        
    except Exception as e:
        logger.error(f"Monitor status error: {e}")
        return jsonify({'error': 'Failed to get status'}), 500

@app.route('/api/telegram_connect', methods=['POST'])
def api_telegram_connect():
    """Direct bypass mode - skip API calls completely"""
    try:
        data = request.get_json()
        phone_number = str(data.get('phone_number', '')).strip()
        api_id = data.get('api_id', '')
        api_hash = str(data.get('api_hash', '')).strip()
        
        logger.info(f"Direct mode - storing credentials for: {phone_number}")
        
        # Convert api_id to integer
        try:
            api_id = int(api_id) if api_id else 0
        except (ValueError, TypeError):
            return jsonify({'error': 'API ID must be a valid number'}), 400

        # Basic validation only
        if not phone_number or not api_id or not api_hash:
            return jsonify({'error': 'Phone number, API ID and API Hash are required'}), 400
            
        if len(api_hash) != 32:
            return jsonify({'error': 'API Hash must be exactly 32 characters'}), 400

        # Clean phone number
        clean_phone = ''.join(char for char in phone_number if char.isdigit() or char == '+')
        if not clean_phone.startswith('+'):
            clean_phone = '+' + clean_phone

        # Store credentials directly in session
        session['phone_number'] = clean_phone
        session['api_id'] = api_id
        session['api_hash'] = api_hash  # Store directly for simplicity
        session['bypass_mode'] = True
        
        return jsonify({
            'status': 'success',
            'message': 'Ready for verification code'
        })

    except Exception as e:
        logger.error(f"Direct mode error: {e}")
        return jsonify({'error': f'Setup failed: {str(e)}'}), 500

@app.route('/api/telegram_login', methods=['POST'])
def api_telegram_login():
    """Step 2: Login with verification code"""
    try:
        data = request.get_json()
        verification_code = data.get('verification_code', '').strip()
        
        # Allow override with credentials from frontend
        phone_number = data.get('phone_number') or session.get('phone_number')
        api_id = data.get('api_id') or session.get('api_id')
        api_hash = data.get('api_hash') or session.get('api_hash')

        if not verification_code:
            return jsonify({'error': 'Verification code is required'}), 400

        # Store credentials in session if provided
        if data.get('phone_number'):
            session['phone_number'] = phone_number
            session['api_id'] = api_id
            session['api_hash'] = api_hash
        
        phone_code_hash = get_phone_code_hash()

        if not all([phone_number, api_id, api_hash]):
            return jsonify({'error': 'No connection session found. Please connect first.'}), 400



        # Direct Telethon login
        from telethon import TelegramClient
        from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError
        import asyncio
        import tempfile
        import os
        
        async def do_login():
            # Create temporary session file
            session_file = tempfile.mktemp(suffix='.session')
            
            try:
                client = TelegramClient(session_file, api_id, api_hash)
                await client.connect()
                
                # Check if already authorized
                if await client.is_user_authorized():
                    me = await client.get_me()
                    return {
                        'status': 'success',
                        'message': f'Already logged in as {me.first_name}',
                        'user_info': {
                            'id': me.id,
                            'first_name': me.first_name,
                            'last_name': me.last_name,
                            'username': me.username
                        }
                    }
                
                # Sign in with code
                try:
                    await client.sign_in(phone_number, verification_code)
                except SessionPasswordNeededError:
                    return {'status': 'error', 'message': '2FA password required (not supported yet)'}
                
                # Get user info
                me = await client.get_me()
                
                # Save session
                session['telegram_connected'] = True
                session['telegram_user'] = {
                    'id': me.id,
                    'first_name': me.first_name,
                    'last_name': me.last_name,
                    'username': me.username
                }
                
                return {
                    'status': 'success',
                    'message': f'Successfully logged in as {me.first_name}',
                    'user_info': {
                        'id': me.id,
                        'first_name': me.first_name,
                        'last_name': me.last_name,
                        'username': me.username
                    }
                }
                
            except PhoneCodeInvalidError:
                return {'status': 'error', 'message': 'Invalid verification code'}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
            finally:
                try:
                    await client.disconnect()
                    if os.path.exists(session_file):
                        os.remove(session_file)
                except:
                    pass
        
        # Run async function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(do_login())
            return jsonify(result)
        finally:
            loop.close()

    except Exception as e:
        logger.error(f"Telegram login error: {e}", exc_info=True)
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/test_telegram_connection', methods=['POST'])
@authenticate_token('telegram_access')
@sliding_window_rate_limiter(max_requests=10, window_ms=300000)  # 10 attempts per 5 minutes
def test_telegram_connection():
    """Test endpoint to validate API credentials without sending code"""
    try:
        data = request.get_json()
        api_id = data.get('api_id', '').strip()
        api_hash = data.get('api_hash', '').strip()

        # Validate API credentials
        creds_valid, creds_result = validate_api_credentials(api_id, api_hash)
        if not creds_valid:
            return jsonify({'error': creds_result}), 400
        
        api_id, api_hash = creds_result

        # Test connection without phone number
        telegram_monitor = TelegramMonitor(api_id, api_hash, None)
        
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("Loop is closed")
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(telegram_monitor.test_connection())
        return jsonify(result)

    except Exception as e:
        logger.error(f"Test connection error: {e}", exc_info=True)
        return jsonify({'error': f'Connection test failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
