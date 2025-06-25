"""
Secure private key encryption utilities for Exodia Digital
Never logs plaintext private keys to console - this is our security moat
"""
import os
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)

class SecureKeyManager:
    def __init__(self):
        self.salt = self._get_or_create_salt()
        self.key = self._derive_key()
        self.cipher = Fernet(self.key)
    
    def _get_or_create_salt(self) -> bytes:
        """Get or create encryption salt"""
        salt = os.environ.get('ENCRYPTION_SALT')
        if not salt:
            # Generate new salt if not in environment
            new_salt = os.urandom(16)
            salt_b64 = base64.b64encode(new_salt).decode()
            logger.warning("No ENCRYPTION_SALT found, generated new one. Set this in production!")
            logger.info(f"Generated salt (set as ENCRYPTION_SALT): {salt_b64}")
            return new_salt
        return base64.b64decode(salt.encode())
    
    def _derive_key(self) -> bytes:
        """Derive encryption key from salt and session secret"""
        session_secret = os.environ.get('SESSION_SECRET', 'default-secret-key')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(session_secret.encode()))
        return key
    
    def encrypt_private_key(self, private_key: str) -> str:
        """
        Encrypt private key - NEVER logs plaintext
        Returns base64 encoded encrypted data
        """
        if not private_key or not isinstance(private_key, str):
            raise ValueError("Invalid private key format")
        
        # Encrypt without logging plaintext
        encrypted_data = self.cipher.encrypt(private_key.encode())
        encrypted_b64 = base64.b64encode(encrypted_data).decode()
        
        # Log only that encryption occurred, never the key
        logger.info("Private key encrypted successfully")
        return encrypted_b64
    
    def decrypt_private_key(self, encrypted_key: str) -> str:
        """
        Decrypt private key - NEVER logs plaintext to console
        This is our security moat - no plaintext logging
        """
        if not encrypted_key:
            raise ValueError("No encrypted key provided")
        
        try:
            # Decode and decrypt
            encrypted_data = base64.b64decode(encrypted_key.encode())
            decrypted_bytes = self.cipher.decrypt(encrypted_data)
            private_key = decrypted_bytes.decode()
            
            # CRITICAL: Never log plaintext private key
            # This is what separates us from rookie snipers
            logger.info("Private key decrypted successfully (plaintext not logged)")
            
            return private_key
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Failed to decrypt private key")

    def is_encrypted(self, key_data: str) -> bool:
        """Check if key data appears to be encrypted"""
        # Check if it looks like base64 encrypted data
        try:
            # If it's longer than a raw key and contains base64 chars
            if len(key_data) > 100 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in key_data):
                return True
            return False
        except:
            return False

# Global instance for backward compatibility
key_manager = SecureKeyManager()

def encrypt_key(private_key: str) -> str:
    """Backward compatible encryption function"""
    return key_manager.encrypt_private_key(private_key)

def decrypt_key(encrypted_key: str) -> str:
    """Backward compatible decryption function"""
    return key_manager.decrypt_private_key(encrypted_key)

def encrypt_private_key(private_key: str) -> str:
    """Encrypt private key securely"""
    return key_manager.encrypt_private_key(private_key)

def decrypt_private_key(encrypted_key: str) -> str:
    """Decrypt private key securely"""
    return key_manager.decrypt_private_key(encrypted_key)

def is_encrypted(key_data: str) -> bool:
    """Check if key appears encrypted"""
    return key_manager.is_encrypted(key_data)