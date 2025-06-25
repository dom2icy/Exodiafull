"""
Flask API Routes for Telegram Sniper Integration
Provides endpoints for session management, authentication, and sniper control
"""
import asyncio
import json
import logging
from functools import wraps
from flask import Blueprint, request, jsonify, session
from telegram_sniper_integration import get_sniper_manager
from models import User, UserSniperFilter, SniperTransactionLog
from app import db

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
telegram_bp = Blueprint('telegram', __name__, url_prefix='/api/telegram')

def async_route(f):
    """Decorator to handle async functions in Flask routes"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        def run_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(f(*args, **kwargs))
            finally:
                loop.close()
        
        return run_async()
    return wrapper

def require_user_session(f):
    """Decorator to require valid user session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401
        return f(user_id, *args, **kwargs)
    return decorated_function

@telegram_bp.route('/connect', methods=['POST'])
@require_user_session
@async_route
async def connect_telegram(user_id):
    """Initialize Telegram connection for user"""
    try:
        data = request.get_json()
        api_id = data.get('api_id')
        api_hash = data.get('api_hash')
        phone_number = data.get('phone_number')
        
        if not all([api_id, api_hash, phone_number]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        sniper = get_sniper_manager()
        client = await sniper.create_telegram_client(user_id, api_id, api_hash, phone_number)
        
        if client:
            is_authorized = await client.is_user_authorized()
            return jsonify({
                'success': True,
                'authorized': is_authorized,
                'message': 'Code sent to phone' if not is_authorized else 'Already authorized'
            })
        else:
            return jsonify({'error': 'Failed to create Telegram client'}), 500
            
    except Exception as e:
        logger.error(f"Telegram connect error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/verify', methods=['POST'])
@require_user_session
@async_route
async def verify_telegram_code(user_id):
    """Verify Telegram authentication code"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number')
        verification_code = data.get('verification_code')
        api_id = data.get('api_id')
        api_hash = data.get('api_hash')
        
        if not all([phone_number, verification_code, api_id, api_hash]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        sniper = get_sniper_manager()
        success = await sniper.verify_phone_code(user_id, phone_number, verification_code, api_id, api_hash)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Telegram authentication successful'
            })
        else:
            return jsonify({'error': 'Verification failed'}), 400
            
    except Exception as e:
        logger.error(f"Telegram verify error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/status', methods=['GET'])
@require_user_session
def get_telegram_status(user_id):
    """Get Telegram connection status for user"""
    try:
        sniper = get_sniper_manager()
        
        # Check if user has stored session
        session_data = sniper.get_telegram_session(user_id)
        has_session = session_data is not None
        
        # Check if client is active
        client = sniper.active_clients.get(user_id)
        is_connected = client and client.is_connected() if client else False
        
        # Check if sniper is active
        sniper_active = sniper.active_snipers.get(user_id, False)
        
        return jsonify({
            'has_session': has_session,
            'is_connected': is_connected,
            'sniper_active': sniper_active,
            'phone_number': session_data[3] if session_data else None
        })
        
    except Exception as e:
        logger.error(f"Telegram status error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/disconnect', methods=['POST'])
@require_user_session
@async_route
async def disconnect_telegram(user_id):
    """Disconnect Telegram client for user"""
    try:
        sniper = get_sniper_manager()
        success = await sniper.disconnect_user_client(user_id)
        
        return jsonify({
            'success': success,
            'message': 'Telegram client disconnected' if success else 'Failed to disconnect'
        })
        
    except Exception as e:
        logger.error(f"Telegram disconnect error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/sniper/start', methods=['POST'])
@require_user_session
@async_route
async def start_sniper(user_id):
    """Start sniper monitoring for user"""
    try:
        sniper = get_sniper_manager()
        success = await sniper.start_sniper_for_user(user_id)
        
        return jsonify({
            'success': success,
            'message': 'Sniper started' if success else 'Failed to start sniper'
        })
        
    except Exception as e:
        logger.error(f"Start sniper error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/sniper/stop', methods=['POST'])
@require_user_session
@async_route
async def stop_sniper(user_id):
    """Stop sniper monitoring for user"""
    try:
        sniper = get_sniper_manager()
        success = await sniper.stop_sniper_for_user(user_id)
        
        return jsonify({
            'success': success,
            'message': 'Sniper stopped' if success else 'Failed to stop sniper'
        })
        
    except Exception as e:
        logger.error(f"Stop sniper error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/sniper/config', methods=['GET', 'POST'])
@require_user_session
def sniper_config(user_id):
    """Get or update sniper configuration"""
    try:
        if request.method == 'GET':
            # Get current configuration
            sniper_filter = UserSniperFilter.query.filter_by(user_id=user_id).first()
            if sniper_filter:
                return jsonify({
                    'slippage_tolerance': sniper_filter.slippage_tolerance,
                    'max_gas_fee': sniper_filter.max_gas_fee,
                    'allowed_telegram_groups': sniper_filter.allowed_telegram_groups or [],
                    'whitelist_tokens': sniper_filter.whitelist_tokens or [],
                    'blacklist_tokens': sniper_filter.blacklist_tokens or [],
                    'auto_snipe_enabled': getattr(sniper_filter, 'auto_snipe_enabled', True)
                })
            else:
                # Return default configuration
                return jsonify({
                    'slippage_tolerance': 1.0,
                    'max_gas_fee': 0.01,
                    'allowed_telegram_groups': [],
                    'whitelist_tokens': [],
                    'blacklist_tokens': [],
                    'auto_snipe_enabled': True
                })
        
        elif request.method == 'POST':
            # Update configuration
            data = request.get_json()
            
            sniper_filter = UserSniperFilter.query.filter_by(user_id=user_id).first()
            if not sniper_filter:
                sniper_filter = UserSniperFilter(user_id=user_id)
                db.session.add(sniper_filter)
            
            # Update fields if provided
            if 'slippage_tolerance' in data:
                sniper_filter.slippage_tolerance = float(data['slippage_tolerance'])
            if 'max_gas_fee' in data:
                sniper_filter.max_gas_fee = float(data['max_gas_fee'])
            if 'allowed_telegram_groups' in data:
                sniper_filter.allowed_telegram_groups = data['allowed_telegram_groups']
            if 'whitelist_tokens' in data:
                sniper_filter.whitelist_tokens = data['whitelist_tokens']
            if 'blacklist_tokens' in data:
                sniper_filter.blacklist_tokens = data['blacklist_tokens']
            if 'auto_snipe_enabled' in data:
                sniper_filter.auto_snipe_enabled = bool(data['auto_snipe_enabled'])
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Configuration updated successfully'
            })
            
    except Exception as e:
        logger.error(f"Sniper config error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/sniper/logs', methods=['GET'])
@require_user_session
def get_sniper_logs(user_id):
    """Get sniper transaction logs for user"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status_filter = request.args.get('status')
        
        # Build query
        query = SniperTransactionLog.query.filter_by(user_id=user_id)
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        
        # Paginate results
        logs = query.order_by(SniperTransactionLog.created_at.desc()).paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        # Format results
        results = []
        for log in logs.items:
            results.append({
                'id': log.id,
                'mint_address': log.mint_address,
                'transaction_signature': log.transaction_signature,
                'status': log.status,
                'amount_sol': log.amount_sol,
                'amount_tokens': log.amount_tokens,
                'gas_fee': log.gas_fee,
                'slippage': log.slippage,
                'telegram_group': log.telegram_group,
                'error_message': log.error_message,
                'created_at': log.created_at.isoformat() if log.created_at else None
            })
        
        return jsonify({
            'logs': results,
            'pagination': {
                'page': logs.page,
                'pages': logs.pages,
                'per_page': logs.per_page,
                'total': logs.total,
                'has_next': logs.has_next,
                'has_prev': logs.has_prev
            }
        })
        
    except Exception as e:
        logger.error(f"Get sniper logs error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/sniper/stats', methods=['GET'])
@require_user_session
def get_sniper_stats(user_id):
    """Get sniper statistics for user"""
    try:
        # Get transaction statistics
        total_transactions = SniperTransactionLog.query.filter_by(user_id=user_id).count()
        successful_transactions = SniperTransactionLog.query.filter_by(user_id=user_id, status='success').count()
        failed_transactions = SniperTransactionLog.query.filter_by(user_id=user_id, status='failed').count()
        pending_transactions = SniperTransactionLog.query.filter_by(user_id=user_id, status='pending').count()
        
        # Calculate success rate
        success_rate = (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0
        
        # Get total volume
        total_volume_result = db.session.query(db.func.sum(SniperTransactionLog.amount_sol)).filter_by(
            user_id=user_id, status='success'
        ).scalar()
        total_volume = float(total_volume_result) if total_volume_result else 0.0
        
        return jsonify({
            'total_transactions': total_transactions,
            'successful_transactions': successful_transactions,
            'failed_transactions': failed_transactions,
            'pending_transactions': pending_transactions,
            'success_rate': round(success_rate, 2),
            'total_volume_sol': round(total_volume, 4)
        })
        
    except Exception as e:
        logger.error(f"Get sniper stats error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/system/status', methods=['GET'])
def get_system_status():
    """Get overall system status"""
    try:
        sniper = get_sniper_manager()
        status = sniper.get_system_status()
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"System status error: {e}")
        return jsonify({'error': str(e)}), 500

@telegram_bp.route('/test/contract-detection', methods=['POST'])
@require_user_session
def test_contract_detection(user_id):
    """Test contract detection with sample message"""
    try:
        data = request.get_json()
        test_message = data.get('message', '')
        
        if not test_message:
            return jsonify({'error': 'Message text required'}), 400
        
        sniper = get_sniper_manager()
        contracts = sniper.extract_contract_from_message(test_message)
        
        # Validate each contract
        results = []
        for contract in contracts:
            is_valid = sniper.is_valid_sol_token(contract)
            results.append({
                'contract': contract,
                'valid': is_valid
            })
        
        return jsonify({
            'message': test_message,
            'detected_contracts': results,
            'total_detected': len(contracts)
        })
        
    except Exception as e:
        logger.error(f"Test contract detection error for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500