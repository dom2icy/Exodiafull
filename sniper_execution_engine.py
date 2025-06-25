"""
Complete Telegram Sniper Execution Engine
Integrates async transaction execution, encrypted session storage, and WebSocket updates
"""
import asyncio
from solana.rpc.async_api import AsyncClient
from solders.transaction import Transaction
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.system_program import transfer, TransferParams
from spl.token.instructions import transfer_checked, get_associated_token_address
from app import db
from models import SniperTransactionLog, User
from crypto_utils import decrypt_key
from flask_socketio import SocketIO

MAX_RETRIES = 5

socketio = SocketIO()

async def broadcast_sniper_update(user_id, tx_signature, status, error=None):
    """Broadcast sniper update to user-specific room"""
    payload = {
        "tx_signature": tx_signature,
        "status": status,
        "error": error
    }
    # Emit to user-specific room
    socketio.emit('sniper_update', payload, to=f"user_{user_id}")

async def send_sol_transaction(client, keypair, recipient, amount_lamports):
    """Send SOL transaction with retry logic"""
    recent_blockhash_resp = await client.get_latest_blockhash()
    recent_blockhash = recent_blockhash_resp.value.blockhash

    txn = Transaction()
    txn.add(
        transfer(
            TransferParams(
                from_pubkey=keypair.pubkey(),
                to_pubkey=Pubkey.from_string(recipient),
                lamports=amount_lamports
            )
        )
    )

    signed_txn = txn.sign([keypair], recent_blockhash)
    send_resp = await client.send_transaction(signed_txn)
    tx_sig = str(send_resp.value)
    
    # Confirm transaction
    confirmation = await client.confirm_transaction(tx_sig, commitment='finalized')
    
    if confirmation.value:
        return tx_sig
    else:
        raise Exception("Transaction not confirmed")

async def send_spl_token_transfer(client, keypair, recipient, mint, amount, decimals):
    """Send SPL token transfer with retry logic"""
    recent_blockhash_resp = await client.get_latest_blockhash()
    recent_blockhash = recent_blockhash_resp.value.blockhash

    from_ata = get_associated_token_address(keypair.pubkey(), Pubkey.from_string(mint))
    to_ata = get_associated_token_address(Pubkey.from_string(recipient), Pubkey.from_string(mint))

    txn = Transaction()
    txn.add(
        transfer_checked(
            program_id=Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            source=from_ata,
            mint=Pubkey.from_string(mint),
            dest=to_ata,
            owner=keypair.pubkey(),
            amount=amount,
            decimals=decimals
        )
    )
    
    signed_txn = txn.sign([keypair], recent_blockhash)
    send_resp = await client.send_transaction(signed_txn)
    tx_sig = str(send_resp.value)
    
    confirmation = await client.confirm_transaction(tx_sig, commitment='finalized')
    
    if confirmation.value:
        return tx_sig
    else:
        raise Exception("Transaction not confirmed")

async def execute_snipe_multiwallet(user_id, recipient, amount_lamports, mint=None, amount_token=None, decimals=None):
    """Execute snipe with multi-wallet support and comprehensive retry logic"""
    # Fetch user wallet from database
    user = db.session.query(User).filter(User.id == user_id).first()
    if not user:
        raise Exception(f"User {user_id} not found")
    
    encrypted_keys = [user.encrypted_private_key]  # Expand this list for multi-wallet support

    client = AsyncClient("https://api.mainnet-beta.solana.com")

    for encrypted_key in encrypted_keys:
        decrypted_key_bytes = decrypt_key(encrypted_key)
        keypair = Keypair.from_bytes(decrypted_key_bytes)

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                if mint and amount_token and decimals is not None:
                    tx_sig = await send_spl_token_transfer(client, keypair, recipient, mint, amount_token, decimals)
                else:
                    tx_sig = await send_sol_transaction(client, keypair, recipient, amount_lamports)

                # Log successful transaction
                log_entry = SniperTransactionLog(
                    user_id=user_id,
                    tx_signature=tx_sig,
                    recipient=recipient,
                    amount=amount_lamports if not mint else amount_token,
                    mint=mint,
                    status='success',
                    attempt=attempt
                )
                db.session.add(log_entry)
                db.session.commit()

                await broadcast_sniper_update(user_id, tx_sig, 'success')
                await client.close()
                return tx_sig

            except Exception as e:
                # Log failed attempt
                log_entry = SniperTransactionLog(
                    user_id=user_id,
                    tx_signature=None,
                    recipient=recipient,
                    amount=amount_lamports if not mint else amount_token,
                    mint=mint,
                    status='failed',
                    error_message=str(e),
                    attempt=attempt
                )
                db.session.add(log_entry)
                db.session.commit()

                await broadcast_sniper_update(user_id, None, 'failed', error=str(e))

                if attempt == MAX_RETRIES:
                    await client.close()
                    raise e

                await asyncio.sleep(attempt * 2)  # Exponential backoff

    await client.close()
    raise Exception("All wallets failed to execute the snipe")

async def execute_snipe(user_id: int, encrypted_private_key: str, recipient: str, amount_lamports: int):
    """Single wallet snipe execution with comprehensive error handling"""
    decrypted_key_bytes = decrypt_key(encrypted_private_key)
    keypair = Keypair.from_bytes(decrypted_key_bytes)

    client = AsyncClient("https://api.mainnet-beta.solana.com")

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            recent_blockhash_resp = await client.get_latest_blockhash()
            recent_blockhash = recent_blockhash_resp.value.blockhash

            txn = Transaction()
            txn.add(
                transfer(
                    TransferParams(
                        from_pubkey=keypair.pubkey(),
                        to_pubkey=Pubkey.from_string(recipient),
                        lamports=amount_lamports
                    )
                )
            )

            signed_txn = txn.sign([keypair], recent_blockhash)
            send_resp = await client.send_transaction(signed_txn)
            tx_sig = str(send_resp.value)

            # Wait for confirmation
            confirmation = await client.confirm_transaction(tx_sig, commitment='finalized')

            if confirmation.value:
                # Log success to DB
                log_entry = SniperTransactionLog(
                    user_id=user_id,
                    tx_signature=tx_sig,
                    recipient=recipient,
                    amount=amount_lamports,
                    status='success'
                )
                db.session.add(log_entry)
                db.session.commit()

                await broadcast_sniper_update(user_id, tx_sig, 'success')
                await client.close()
                return tx_sig
            else:
                raise Exception("Transaction not confirmed")

        except Exception as e:
            # Log failure attempt
            log_entry = SniperTransactionLog(
                user_id=user_id,
                tx_signature=None,
                recipient=recipient,
                amount=amount_lamports,
                status='failed',
                error_message=str(e),
                attempt=attempt
            )
            db.session.add(log_entry)
            db.session.commit()

            await broadcast_sniper_update(user_id, None, 'failed', error=str(e))

            if attempt == MAX_RETRIES:
                await client.close()
                raise e

            await asyncio.sleep(attempt * 2)  # Exponential backoff

    await client.close()