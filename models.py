from datetime import datetime
from app import db

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    hashed_password = db.Column(db.String(255), nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)  # Encrypted Solana private key
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    telegram_sessions = db.relationship("TelegramSession", back_populates="user", cascade="all, delete-orphan")
    sniper_filters = db.relationship("UserSniperFilter", back_populates="user", cascade="all, delete-orphan")
    sniper_logs = db.relationship("SniperTransactionLog", back_populates="user", cascade="all, delete-orphan")

    def __init__(self, username=None, email=None, hashed_password=None, encrypted_private_key=None):
        self.username = username
        self.email = email
        self.hashed_password = hashed_password
        self.encrypted_private_key = encrypted_private_key

class TelegramSession(db.Model):
    __tablename__ = "telegram_sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    session_data = db.Column(db.Text, nullable=False)  # encrypted session string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", back_populates="telegram_sessions")

    def __init__(self, user_id=None, session_data=None):
        self.user_id = user_id
        self.session_data = session_data

class UserSniperFilter(db.Model):
    __tablename__ = "user_sniper_filters"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    group_id = db.Column(db.String(100), nullable=False)
    blacklist = db.Column(db.Text)  # JSON string of blacklisted tokens
    whitelist_only = db.Column(db.Boolean, default=False)
    slippage_tolerance = db.Column(db.Float, default=1.0)  # percentage e.g., 1.0 for 1%
    max_gas_fee = db.Column(db.Float, default=0.01)  # in SOL or relevant unit
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", back_populates="sniper_filters")

    def __init__(self, user_id=None, group_id=None, blacklist=None, whitelist_only=None, slippage_tolerance=None, max_gas_fee=None):
        self.user_id = user_id
        self.group_id = group_id
        self.blacklist = blacklist
        self.whitelist_only = whitelist_only if whitelist_only is not None else False
        self.slippage_tolerance = slippage_tolerance or 1.0
        self.max_gas_fee = max_gas_fee or 0.01

class SniperTransactionLog(db.Model):
    __tablename__ = "sniper_transaction_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    mint_address = db.Column(db.String(100), nullable=False)
    transaction_signature = db.Column(db.String(100))
    status = db.Column(db.String(20), nullable=False)  # 'success', 'failed', 'pending'
    amount_sol = db.Column(db.Float)
    amount_tokens = db.Column(db.Float)
    gas_fee = db.Column(db.Float)
    slippage = db.Column(db.Float)
    telegram_group = db.Column(db.String(100))
    error_message = db.Column(db.Text)
    recipient = db.Column(db.String(100))
    amount = db.Column(db.Integer)
    mint = db.Column(db.String(100), nullable=True)
    attempt = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="sniper_logs")

    def __init__(self, user_id=None, mint_address=None, transaction_signature=None, status=None, 
                 amount_sol=None, amount_tokens=None, gas_fee=None, slippage=None, telegram_group=None, 
                 error_message=None, recipient=None, amount=None, mint=None, attempt=None):
        self.user_id = user_id
        self.mint_address = mint_address
        self.transaction_signature = transaction_signature
        self.status = status
        self.amount_sol = amount_sol
        self.amount_tokens = amount_tokens
        self.gas_fee = gas_fee
        self.slippage = slippage
        self.telegram_group = telegram_group
        self.error_message = error_message
        self.recipient = recipient
        self.amount = amount
        self.mint = mint
        self.attempt = attempt or 1


class SolanaWallet(db.Model):
    __tablename__ = 'solana_wallets'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=True)  # Optional wallet name
    public_key = db.Column(db.String(50), nullable=False, unique=True)
    private_key_encrypted = db.Column(db.Text, nullable=False)  # Always encrypted
    encryption_version = db.Column(db.String(10), default='v1.0')  # Versioning for migration
    encryption_method = db.Column(db.String(50), default='aes_256_gcm')  # Track encryption type
    balance_sol = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", backref="wallets")

    def __init__(self, user_id=None, name=None, public_key=None, private_key_encrypted=None, 
                 balance_sol=None, is_active=None):
        self.user_id = user_id
        self.name = name
        self.public_key = public_key
        self.private_key_encrypted = private_key_encrypted
        self.balance_sol = balance_sol or 0.0
        self.is_active = is_active if is_active is not None else True

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'public_key': self.public_key,
            'balance_sol': self.balance_sol,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class TelegramConnection(db.Model):
    __tablename__ = 'telegram_connections'
    
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(20), nullable=False)
    api_id = db.Column(db.Integer, nullable=False)
    api_hash = db.Column(db.String(32), nullable=False)
    session_string = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(100), nullable=True)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'phone_number': self.phone_number,
            'user_id': self.user_id,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }



class TradingSignal(db.Model):
    __tablename__ = 'trading_signals'
    
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, nullable=False)
    channel_name = db.Column(db.String(200), nullable=False)
    message_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)
    signal_type = db.Column(db.String(20), nullable=True)  # buy, sell, alert
    token_symbol = db.Column(db.String(20), nullable=True)
    price = db.Column(db.Float, nullable=True)
    confidence = db.Column(db.Float, nullable=True)
    processed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TradeExecution(db.Model):
    __tablename__ = 'trade_executions'
    
    id = db.Column(db.Integer, primary_key=True)
    signal_id = db.Column(db.Integer, db.ForeignKey('trading_signals.id'), nullable=False)
    wallet_id = db.Column(db.Integer, db.ForeignKey('solana_wallets.id'), nullable=False)
    transaction_signature = db.Column(db.String(100), nullable=True)
    token_symbol = db.Column(db.String(20), nullable=False)
    amount_sol = db.Column(db.Float, nullable=False)
    execution_price = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, executed, failed
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    executed_at = db.Column(db.DateTime, nullable=True)

class SniperJob(db.Model):
    __tablename__ = "sniper_jobs"
    id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    mint = db.Column(db.String(50), nullable=False)
    chat_id = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, executing, retrying, success, failed
    attempt_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    transaction_signature = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)