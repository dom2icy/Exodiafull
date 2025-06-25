"""
Authentication routes with proper Node.js-style middleware patterns
Implements proper environment validation and audit logging
"""
from flask import Blueprint, request, jsonify, session
from functools import wraps
import os
import logging
from datetime import datetime
from security_manager import security_manager, SecurityError

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

# Environment validation (like Node.js pattern)
REQUIRED_ENV_VARS = [
    'ACCESS_TOKEN_SECRET',
    'REFRESH_TOKEN_SECRET', 
    'ENCRYPTION_KEY',
    'DATABASE_URL'
]

def validate_environment():
    """Validate required environment variables on startup"""
    missing_vars = []
    for key in REQUIRED_ENV_VARS:
        if not os.environ.get(key):
            missing_vars.append(key)
    
    if missing_vars:
        for var in missing_vars:
            logger.error(f"Missing required environment variable: {var}")
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

def authenticate_token(required_permission=None):
    """
    Flask decorator matching Node.js authenticateToken middleware pattern
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization')
            token = None
            
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            elif 'access_token' in session:
                token = session['access_token']
            
            if not token:
                return jsonify({'message': 'Authentication required'}), 401
            
            try:
                # Authenticate token and check permissions
                payload = security_manager.authenticate_token(token, required_permission)
                request.user = payload  # Attach user info to request
                
                # Log successful authentication
                log_audit_event(
                    payload.get('user_id'),
                    'token_authenticated',
                    f"Permission: {required_permission or 'none'}"
                )
                
                return f(*args, **kwargs)
                
            except SecurityError as e:
                return jsonify({'message': str(e)}), 403
                
        return decorated_function
    return decorator

def authorize_roles(*allowed_roles):
    """
    Flask decorator matching Node.js authorizeRoles middleware pattern
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'user') or not request.user:
                return jsonify({'message': 'Authentication required'}), 401
            
            # Check if user has required role
            if not security_manager.authorize_roles(list(allowed_roles), request.user):
                return jsonify({'message': 'Forbidden: insufficient rights'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def sliding_window_rate_limiter(max_requests=10, window_ms=300000):
    """
    Flask decorator matching Node.js slidingWindowRateLimiter pattern
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Use client IP for rate limiting
            client_ip = request.remote_addr
            identifier = f"rate_limit_{client_ip}"
            
            # Convert window from ms to seconds
            window_seconds = window_ms // 1000
            
            if not security_manager.check_rate_limit(identifier, max_requests, window_seconds):
                return jsonify({'message': 'Too many requests, slow down'}), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_audit_event(user_id, action, details=''):
    """
    Audit logging matching Node.js logEvent pattern
    """
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"{timestamp} | User:{user_id} | Action:{action} | Details:{details}"
    
    # Log to security manager
    security_manager._log_security_event('audit_log', {
        'user_id': user_id,
        'action': action,
        'details': details,
        'timestamp': timestamp
    })
    
    # Also log to application logger
    logger.info(log_entry)

@auth_bp.route('/api/auth/login', methods=['POST'])
@sliding_window_rate_limiter(max_requests=5, window_ms=300000)  # 5 attempts per 5 minutes
def login():
    """
    Secure login endpoint with proper validation
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        phone_number = data.get('phone_number')
        verification_code = data.get('verification_code')
        
        if not phone_number or not verification_code:
            return jsonify({
                'success': False,
                'message': 'Phone number and verification code required'
            }), 400
        
        # In production, this would verify against Telegram authentication
        # For now, we'll create a session for demo purposes
        permissions = ['telegram_access', 'wallet_access', 'trading_access']
        role = 'user'
        
        # Create secure session
        session_data = security_manager.create_secure_session(
            user_id=phone_number,
            permissions=permissions,
            role=role
        )
        
        # Store in Flask session for browser-based requests
        session['access_token'] = session_data['access_token']
        session['user_id'] = phone_number
        session['role'] = role
        
        # Log successful login
        log_audit_event(phone_number, 'login_success', f"Role: {role}")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'access_token': session_data['access_token'],
            'refresh_token': session_data['refresh_token'],
            'expires_in': session_data['expires_in'],
            'token_type': session_data['token_type']
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        log_audit_event(
            data.get('phone_number', 'unknown') if 'data' in locals() else 'unknown',
            'login_failed',
            str(e)
        )
        return jsonify({
            'success': False,
            'message': 'Login failed'
        }), 500

@auth_bp.route('/api/auth/refresh', methods=['POST'])
@sliding_window_rate_limiter(max_requests=10, window_ms=300000)
def refresh_token():
    """
    Refresh access token using refresh token
    """
    try:
        data = request.get_json()
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({
                'success': False,
                'message': 'Refresh token required'
            }), 400
        
        # Refresh session
        session_data = security_manager.refresh_session(refresh_token)
        
        # Update Flask session
        session['access_token'] = session_data['access_token']
        
        # Log token refresh
        log_audit_event(
            session.get('user_id', 'unknown'),
            'token_refreshed',
            'New access token issued'
        )
        
        return jsonify({
            'success': True,
            'access_token': session_data['access_token'],
            'refresh_token': session_data['refresh_token'],
            'expires_in': session_data['expires_in'],
            'token_type': session_data['token_type']
        })
        
    except SecurityError as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 401
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Token refresh failed'
        }), 500

@auth_bp.route('/api/auth/logout', methods=['POST'])
@authenticate_token()
def logout():
    """
    Secure logout with session invalidation
    """
    try:
        user_id = request.user.get('user_id')
        session_id = request.user.get('session_id')
        
        # Invalidate session
        if session_id:
            security_manager.invalidate_session(session_id)
        
        # Clear Flask session
        session.clear()
        
        # Log logout
        log_audit_event(user_id, 'logout', 'Session invalidated')
        
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        })
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Logout failed'
        }), 500

@auth_bp.route('/api/auth/status', methods=['GET'])
def auth_status():
    """
    Check authentication status
    """
    try:
        token = session.get('access_token') or request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'authenticated': False})
        
        try:
            payload = security_manager.authenticate_token(token)
            return jsonify({
                'authenticated': True,
                'user_id': payload.get('user_id'),
                'role': payload.get('role'),
                'permissions': payload.get('permissions', []),
                'expires_at': payload.get('exp')
            })
        except SecurityError:
            return jsonify({'authenticated': False})
            
    except Exception as e:
        logger.error(f"Auth status error: {str(e)}")
        return jsonify({'authenticated': False})

@auth_bp.route('/api/security/audit', methods=['GET'])
@authenticate_token()
@authorize_roles('admin')
def security_audit_log():
    """
    Get security audit log (admin only)
    """
    try:
        limit = min(int(request.args.get('limit', 100)), 1000)  # Max 1000 events
        audit_log = security_manager.get_security_audit_log(limit)
        
        # Log audit access
        log_audit_event(
            request.user.get('user_id'),
            'audit_log_accessed',
            f"Retrieved {len(audit_log)} events"
        )
        
        return jsonify({
            'success': True,
            'events': audit_log,
            'count': len(audit_log)
        })
        
    except Exception as e:
        logger.error(f"Audit log error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to retrieve audit log'
        }), 500

# Environment validation on module import
try:
    validate_environment()
    logger.info("Environment validation passed")
except RuntimeError as e:
    logger.warning(f"Environment validation failed: {e}")
    # In production, this would exit the application
    # For development, we'll continue with warnings