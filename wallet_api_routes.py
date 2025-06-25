"""
Streamlined Wallet Management API Routes
Works with existing infrastructure and session management
"""
from flask import Blueprint, request, jsonify, session, render_template
import base64
import json
import os
from datetime import datetime
from app import db
from models import SolanaWallet, SniperTransactionLog, UserSniperFilter
from crypto_utils import encrypt_key, decrypt_key
from csrf_spa_middleware import csrf_protect_spa

wallet_bp = Blueprint('wallet_api', __name__)

@wallet_bp.route('/api/wallets', methods=['GET'])
def get_wallets():
    """Get all wallets for the current user"""
    try:
        user_id = session.get('user_id', 1)  # Default for development
        
        wallets = SolanaWallet.query.filter_by(user_id=user_id, is_active=True).all()
        
        wallet_list = []
        for wallet in wallets:
            wallet_data = {
                "id": wallet.id,
                "name": wallet.name or f"Wallet {wallet.id}",
                "address": wallet.public_key,
                "balance": wallet.balance_sol or 0.0,
                "active": wallet.is_active,
                "created_at": wallet.created_at.isoformat() if wallet.created_at else None,
                "last_updated": wallet.updated_at.isoformat() if wallet.updated_at else None
            }
            wallet_list.append(wallet_data)
        
        return jsonify({
            "success": True,
            "wallets": wallet_list,
            "total_balance": sum(w["balance"] for w in wallet_list),
            "count": len(wallet_list)
        })
        
    except Exception as e:
        print(f"Error fetching wallets: {e}")
        return jsonify({"error": "Failed to fetch wallets"}), 500

@wallet_bp.route('/api/wallet/generate', methods=['POST'])
def generate_wallet():
    """Generate a new Solana wallet"""
    try:
        # Initialize session if needed
        if 'user_id' not in session:
            session['user_id'] = 1  # Default demo user
        
        user_id = session['user_id']
        data = request.get_json() or {}
        wallet_name = data.get('name')

        # Simulate wallet generation
        import secrets
        import string
        
        # Generate a mock public key (44 characters, Base58-like)
        chars = string.ascii_letters + string.digits
        public_key = ''.join(secrets.choice(chars) for _ in range(44))
        
        # Generate a mock private key
        private_key = base64.b64encode(secrets.token_bytes(64)).decode()
        
        # Encrypt private key
        encrypted_private_key = encrypt_key(private_key)
        
        # Create wallet record
        wallet = SolanaWallet(
            user_id=user_id,
            name=wallet_name,
            public_key=public_key,
            private_key_encrypted=encrypted_private_key,
            balance_sol=0.0,
            is_active=True
        )
        
        db.session.add(wallet)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "wallet": {
                "id": wallet.id,
                "name": wallet.name,
                "address": wallet.public_key,
                "balance": 0.0,
                "active": True
            },
            "message": "Wallet generated successfully"
        })
        
    except Exception as e:
        print(f"Error generating wallet: {e}")
        return jsonify({"error": "Failed to generate wallet"}), 500

@wallet_bp.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Get CSRF token for SPA frontend"""
    from csrf_spa_middleware import get_csrf_token
    return jsonify({"csrf_token": get_csrf_token()})

@wallet_bp.route('/api/wallet/import', methods=['POST'])
@csrf_protect_spa
def import_wallet():
    """Import wallet from private key"""
    try:
        user_id = session.get('user_id', 1)  # Default for development
        data = request.get_json()
        
        if not data or 'private_key' not in data:
            return jsonify({"error": "Private key required"}), 400

        private_key_str = data['private_key'].strip()
        wallet_name = data.get('name')

        # Basic validation
        if len(private_key_str) < 32:
            return jsonify({"error": "Invalid private key format"}), 400

        # Generate public key from private key (mock for now)
        import hashlib
        public_key = hashlib.sha256(private_key_str.encode()).hexdigest()[:44]

        # Check if wallet already exists
        existing_wallet = SolanaWallet.query.filter_by(
            user_id=user_id,
            public_key=public_key,
            is_active=True
        ).first()
        
        if existing_wallet:
            return jsonify({"error": "Wallet already exists"}), 400

        # Encrypt private key
        encrypted_private_key = encrypt_key(private_key_str)
        
        # Create wallet record
        wallet = SolanaWallet(
            user_id=user_id,
            name=wallet_name,
            public_key=public_key,
            private_key_encrypted=encrypted_private_key,
            balance_sol=0.0,
            is_active=True
        )
        
        db.session.add(wallet)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "wallet": {
                "id": wallet.id,
                "name": wallet.name,
                "address": wallet.public_key,
                "balance": 0.0,
                "active": True
            },
            "message": "Wallet imported successfully"
        })
        
    except Exception as e:
        print(f"Error importing wallet: {e}")
        return jsonify({"error": "Failed to import wallet"}), 500

@wallet_bp.route('/api/wallet/<int:wallet_id>/balance', methods=['GET'])
def refresh_wallet_balance(wallet_id):
    """Refresh balance for a specific wallet"""
    try:
        user_id = session.get('user_id', 1)
        
        wallet = SolanaWallet.query.filter_by(
            id=wallet_id,
            user_id=user_id,
            is_active=True
        ).first()
        
        if not wallet:
            return jsonify({"error": "Wallet not found"}), 404

        # Mock balance update
        import random
        balance_sol = round(random.uniform(0.1, 10.0), 4)
        
        # Update wallet
        wallet.balance_sol = balance_sol
        wallet.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            "success": True,
            "balance": balance_sol,
            "updated_at": wallet.updated_at.isoformat()
        })
        
    except Exception as e:
        print(f"Error refreshing balance: {e}")
        return jsonify({"error": "Failed to refresh balance"}), 500

@wallet_bp.route('/api/wallet/<int:wallet_id>/export', methods=['GET'])
def export_wallet(wallet_id):
    """Export wallet private key (encrypted)"""
    try:
        user_id = session.get('user_id', 1)
        
        wallet = SolanaWallet.query.filter_by(
            id=wallet_id,
            user_id=user_id,
            is_active=True
        ).first()
        
        if not wallet:
            return jsonify({"error": "Wallet not found"}), 404

        # Decrypt private key for export
        decrypted_key = decrypt_key(wallet.private_key_encrypted)
        
        export_data = {
            "wallet_id": wallet.id,
            "name": wallet.name,
            "public_key": wallet.public_key,
            "private_key": decrypted_key,
            "balance": wallet.balance_sol,
            "created_at": wallet.created_at.isoformat() if wallet.created_at else None,
            "exported_at": datetime.utcnow().isoformat()
        }
        
        return jsonify({
            "success": True,
            "export_data": export_data,
            "format": "exodia_wallet_v1"
        })
        
    except Exception as e:
        print(f"Error exporting wallet: {e}")
        return jsonify({"error": "Failed to export wallet"}), 500

@wallet_bp.route('/api/wallet/<int:wallet_id>/remove', methods=['DELETE'])
def remove_wallet(wallet_id):
    """Remove/deactivate a wallet"""
    try:
        user_id = session.get('user_id', 1)
        
        wallet = SolanaWallet.query.filter_by(
            id=wallet_id,
            user_id=user_id,
            is_active=True
        ).first()
        
        if not wallet:
            return jsonify({"error": "Wallet not found"}), 404

        # Soft delete - mark as inactive
        wallet.is_active = False
        wallet.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Wallet removed successfully"
        })
        
    except Exception as e:
        print(f"Error removing wallet: {e}")
        return jsonify({"error": "Failed to remove wallet"}), 500

@wallet_bp.route('/api/wallets/export-all', methods=['GET'])
def export_all_wallets():
    """Export all user wallets"""
    try:
        user_id = session.get('user_id', 1)
        
        wallets = SolanaWallet.query.filter_by(user_id=user_id, is_active=True).all()
        
        export_data = {
            "user_id": user_id,
            "exported_at": datetime.utcnow().isoformat(),
            "format": "exodia_multi_wallet_v1",
            "wallets": []
        }
        
        for wallet in wallets:
            # Decrypt private key for export
            decrypted_key = decrypt_key(wallet.private_key_encrypted)
            
            wallet_data = {
                "id": wallet.id,
                "name": wallet.name,
                "public_key": wallet.public_key,
                "private_key": decrypted_key,
                "balance": wallet.balance_sol,
                "created_at": wallet.created_at.isoformat() if wallet.created_at else None
            }
            export_data["wallets"].append(wallet_data)
        
        return jsonify({
            "success": True,
            "export_data": export_data,
            "wallet_count": len(wallets)
        })
        
    except Exception as e:
        print(f"Error exporting all wallets: {e}")
        return jsonify({"error": "Failed to export wallets"}), 500

@wallet_bp.route('/api/sniper/logs', methods=['GET'])
def get_sniper_logs():
    """Get sniper transaction logs for user"""
    try:
        user_id = session.get('user_id', 1)
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        logs = SniperTransactionLog.query.filter_by(user_id=user_id)\
            .order_by(SniperTransactionLog.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        log_list = []
        for log in logs.items:
            log_data = {
                "id": log.id,
                "mint_address": log.mint_address,
                "transaction_signature": log.transaction_signature,
                "status": log.status,
                "amount_sol": log.amount_sol,
                "amount_tokens": log.amount_tokens,
                "gas_fee": log.gas_fee,
                "telegram_group": log.telegram_group,
                "error_message": log.error_message,
                "attempt": log.attempt,
                "created_at": log.created_at.isoformat() if log.created_at else None
            }
            log_list.append(log_data)
        
        return jsonify({
            "success": True,
            "logs": log_list,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": logs.total,
                "pages": logs.pages,
                "has_next": logs.has_next,
                "has_prev": logs.has_prev
            }
        })
        
    except Exception as e:
        print(f"Error fetching sniper logs: {e}")
        return jsonify({"error": "Failed to fetch logs"}), 500

@wallet_bp.route('/api/sniper/stats', methods=['GET'])
def get_sniper_stats():
    """Get sniper statistics for user"""
    try:
        user_id = session.get('user_id', 1)
        
        # Get all sniper logs for user
        all_logs = SniperTransactionLog.query.filter_by(user_id=user_id).all()
        
        total_snipes = len(all_logs)
        successful = len([log for log in all_logs if log.status == 'success'])
        failed = len([log for log in all_logs if log.status == 'failed'])
        success_rate = (successful / total_snipes * 100) if total_snipes > 0 else 0
        
        # Calculate total volume
        total_volume = sum(log.amount_sol or 0 for log in all_logs if log.status == 'success')
        
        return jsonify({
            "success": True,
            "stats": {
                "total_snipes": total_snipes,
                "successful": successful,
                "failed": failed,
                "success_rate": round(success_rate, 2),
                "total_volume_sol": round(total_volume, 4)
            }
        })
        
    except Exception as e:
        print(f"Error fetching sniper stats: {e}")
        return jsonify({"error": "Failed to fetch stats"}), 500

@wallet_bp.route('/dashboard')
def wallet_dashboard():
    """Serve the wallet management dashboard"""
    return render_template('wallet_dashboard.html')