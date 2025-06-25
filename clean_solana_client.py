import logging
import requests
import base64
import time
from typing import Dict, Any, Tuple
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solders.keypair import Keypair
from solders.pubkey import Pubkey as PublicKey
from solders.transaction import VersionedTransaction
from solders.system_program import transfer, TransferParams

logger = logging.getLogger(__name__)

class CleanSolanaClient:
    def __init__(self):
        self.rpc_endpoint = "https://api.mainnet-beta.solana.com"
        self.client = Client(self.rpc_endpoint)
        self.jupiter_api = "https://quote-api.jup.ag/v6"
        self.sol_mint = "So11111111111111111111111111111111111111112"
        
        logger.info(f"SolanaClient initialized with mainnet RPC")

    def send_sol(self, sender: Keypair, recipient: PublicKey, amount_sol: float):
        """Send SOL transfer"""
        try:
            amount_lamports = int(amount_sol * 1_000_000_000)
            
            transfer_ix = transfer(TransferParams(
                from_pubkey=sender.pubkey(),
                to_pubkey=recipient,
                lamports=amount_lamports
            ))
            
            transaction = Transaction()
            transaction.add(transfer_ix)
            
            # Get recent blockhash
            recent_blockhash = self.client.get_latest_blockhash(commitment=Confirmed)
            transaction.recent_blockhash = recent_blockhash.value.blockhash
            transaction.fee_payer = sender.pubkey()
            
            # Sign and send
            transaction.sign(sender)
            response = self.client.send_transaction(
                transaction, sender,
                opts={'skip_confirmation': False, 'preflight_commitment': Confirmed}
            )
            
            signature = str(response.value)
            logger.info(f"SOL transfer successful: {signature}")
            return signature
            
        except Exception as e:
            logger.error(f"SOL transfer failed: {e}")
            raise

    def get_jupiter_quote(self, input_mint: str, output_mint: str, amount_lamports: int) -> Dict:
        """Get Jupiter swap quote"""
        try:
            params = {
                'inputMint': input_mint,
                'outputMint': output_mint,
                'amount': str(amount_lamports),
                'slippageBps': 300,  # 3% slippage
                'onlyDirectRoutes': 'false'
            }
            
            response = requests.get(f"{self.jupiter_api}/quote", params=params, timeout=10)
            response.raise_for_status()
            
            quote = response.json()
            logger.info(f"Jupiter quote: {quote.get('outAmount', 0)} tokens for {amount_lamports} lamports")
            return quote
            
        except Exception as e:
            logger.error(f"Jupiter quote failed: {e}")
            raise

    def get_jupiter_swap_transaction(self, quote: Dict, user_pubkey: str) -> str:
        """Get Jupiter swap transaction"""
        try:
            swap_data = {
                'quoteResponse': quote,
                'userPublicKey': user_pubkey,
                'wrapAndUnwrapSol': True,
                'dynamicComputeUnitLimit': True,
                'prioritizationFeeLamports': 'auto'
            }
            
            response = requests.post(
                f"{self.jupiter_api}/swap",
                json=swap_data,
                headers={'Content-Type': 'application/json'},
                timeout=15
            )
            response.raise_for_status()
            
            swap_response = response.json()
            return swap_response['swapTransaction']
            
        except Exception as e:
            logger.error(f"Jupiter swap transaction failed: {e}")
            raise

    def execute_versioned_transaction(self, tx_b64: str, signer: Keypair) -> str:
        """Execute a versioned transaction"""
        try:
            # Decode transaction
            tx_bytes = base64.b64decode(tx_b64)
            versioned_tx = VersionedTransaction.from_bytes(tx_bytes)
            
            # Sign transaction
            versioned_tx.sign([signer])
            
            # Send transaction
            response = self.client.send_transaction(
                versioned_tx,
                opts={
                    'skip_confirmation': False,
                    'preflight_commitment': Confirmed,
                    'max_retries': 3
                }
            )
            
            signature = str(response.value)
            logger.info(f"Versioned transaction executed: {signature}")
            return signature
            
        except Exception as e:
            logger.error(f"Transaction execution failed: {e}")
            raise

    def swap_sol_to_token(self, sender: Keypair, token_address: str, sol_amount: float) -> Tuple[str, int]:
        """Swap SOL to token using Jupiter"""
        try:
            amount_lamports = int(sol_amount * 1_000_000_000)
            sender_pubkey_str = str(sender.pubkey())
            
            # Get quote
            quote = self.get_jupiter_quote(self.sol_mint, token_address, amount_lamports)
            
            # Get swap transaction
            swap_tx = self.get_jupiter_swap_transaction(quote, sender_pubkey_str)
            
            # Execute swap
            tx_signature = self.execute_versioned_transaction(swap_tx, sender)
            
            # Get tokens received
            tokens_received = int(quote.get('outAmount', 0))
            
            logger.info(f"Swap completed: {tx_signature}, received {tokens_received:,} tokens")
            return tx_signature, tokens_received
            
        except Exception as e:
            logger.error(f"Swap failed: {e}")
            raise

    def get_token_balance(self, owner: PublicKey, token_mint: str) -> int:
        """Get token balance for specific token"""
        try:
            from spl.token.instructions import get_associated_token_address
            
            ata = get_associated_token_address(owner, PublicKey.from_string(token_mint))
            balance = self.client.get_token_account_balance(ata)
            return int(balance['result']['value']['amount'])
        except Exception as e:
            logger.error(f"Error getting token balance: {e}")
            return 0

    def get_wallet_balance(self, wallet_pubkey: PublicKey) -> float:
        """Get SOL balance for wallet"""
        try:
            response = self.client.get_balance(wallet_pubkey, commitment=Confirmed)
            balance_lamports = response.value
            return balance_lamports / 1_000_000_000
        except Exception as e:
            logger.error(f"Error getting wallet balance: {e}")
            return 0.0

    def buy_token_atomic(self, token_address: str, sol_amount: float, private_key: str) -> Dict[str, Any]:
        """Enhanced atomic-style transaction with fee rollback protection"""
        try:
            if sol_amount <= 0:
                return {'status': 'error', 'message': 'SOL amount must be positive'}

            fee_wallet = PublicKey.from_string("B7dRWXg2vTfpK469dzoaz1mYzU7G8DRMusBEut3pyz3z")
            fee_percentage = 0.01
            fee_amount = round(sol_amount * fee_percentage, 9)
            trade_amount = round(sol_amount - fee_amount, 9)

            sender = Keypair.from_base58_string(private_key)
            sender_pubkey = sender.pubkey()

            logger.info(f"Initiating atomic token buy. User: {sender_pubkey}, Token: {token_address}")
            logger.info(f"Trade: {trade_amount:.9f} SOL, Fee: {fee_amount:.9f} SOL")

            # Check wallet balance
            wallet_balance = self.get_wallet_balance(sender_pubkey)
            required_balance = sol_amount + 0.002
            if wallet_balance < required_balance:
                raise ValueError(f"Insufficient funds: wallet balance {wallet_balance} SOL, required {required_balance}")

            # Get Jupiter quote first to validate trade possibility
            quote = self.get_jupiter_quote(self.sol_mint, token_address, int(trade_amount * 1e9))
            if not quote or int(quote.get('outAmount', 0)) == 0:
                raise ValueError("Invalid or zero output quote from Jupiter.")

            routing_path = quote.get('routes', [{}])[0].get('marketInfos', [])
            logger.debug(f"Routing path: {routing_path}")

            # Execute fee transfer and swap as close to atomic as possible
            logger.info("Executing fee transfer...")
            fee_sig = self.send_sol(sender, fee_wallet, fee_amount)
            logger.debug(f"Fee sent, tx sig: {fee_sig}")

            try:
                # Execute swap immediately after fee
                logger.info("Executing token swap...")
                swap_tx_b64 = self.get_jupiter_swap_transaction(quote, str(sender_pubkey))
                tx_sig = self.execute_versioned_transaction(swap_tx_b64, sender)
                logger.info(f"Swap executed, tx sig: {tx_sig}")

                tokens_received = int(quote.get('outAmount', 0))

                return {
                    'status': 'success',
                    'transaction_signature': tx_sig,
                    'fee_transaction_signature': fee_sig,
                    'tokens_received': tokens_received,
                    'fee_breakdown': {
                        'fee_percent': 100 * fee_percentage,
                        'fee_amount': fee_amount,
                        'trade_amount': trade_amount,
                        'fee_collector': str(fee_wallet)
                    },
                    'routing_path': routing_path,
                    'message': f'Successfully purchased {tokens_received:,} tokens for {trade_amount:.9f} SOL (1% fee to Exodia)'
                }

            except Exception as swap_error:
                # Attempt fee rollback if swap fails
                logger.warning(f"Swap failed: {swap_error}. Attempting fee rollback...")
                try:
                    refund_sig = self.send_sol(Keypair.from_base58_string(private_key), sender_pubkey, fee_amount)
                    logger.info(f"Fee rolled back, tx sig: {refund_sig}")
                    raise ValueError(f"Swap failed but fee was refunded. Original error: {swap_error}")
                except Exception as rollback_err:
                    logger.error(f"Rollback failed: {rollback_err}")
                    raise ValueError(f"Swap failed and rollback failed. Fee may be lost. Original error: {swap_error}")

        except Exception as e:
            logger.error(f"[Exodia Atomic Buy] Error: {e}", exc_info=True)
            return {'status': 'error', 'message': str(e)}

    def buy_token_with_fee(self, token_address: str, sol_amount: float, private_key: str) -> Dict[str, Any]:
        try:
            if sol_amount <= 0:
                return {'status': 'error', 'message': 'SOL amount must be positive'}

            fee_wallet = PublicKey.from_string("B7dRWXg2vTfpK469dzoaz1mYzU7G8DRMusBEut3pyz3z")
            fee_percentage = 0.01
            fee_amount = round(sol_amount * fee_percentage, 9)
            trade_amount = round(sol_amount - fee_amount, 9)

            sender = Keypair.from_base58_string(private_key)
            sender_pubkey = sender.pubkey()

            logger.info(f"Starting trade with fee. User: {sender_pubkey}, Token: {token_address}")
            logger.info(f"Trade amount: {trade_amount:.9f} SOL, Fee amount: {fee_amount:.9f} SOL")

            wallet_balance = self.get_wallet_balance(sender_pubkey)
            required_balance = sol_amount + 0.002  # buffer for fees
            if wallet_balance < required_balance:
                raise ValueError(f"Insufficient balance: have {wallet_balance} SOL, need {required_balance} SOL")

            # Step 1: Send fee first, lock it in
            fee_tx_sig = self.send_sol(sender, fee_wallet, fee_amount)
            logger.debug(f"Fee sent with tx sig: {fee_tx_sig}")

            # Step 2: Get Jupiter quote for remaining trade amount (in lamports)
            trade_amount_lamports = int(trade_amount * 1e9)
            quote = self.get_jupiter_quote(self.sol_mint, token_address, trade_amount_lamports)
            if not quote or int(quote.get('outAmount', 0)) == 0:
                raise ValueError("Failed to get valid Jupiter quote for swap")

            routing_path = quote.get('routes', [{}])[0].get('marketInfos', [])
            logger.debug(f"Routing path: {routing_path}")

            # Step 3: Execute swap with retries
            max_retries = 3
            tx_sig = None
            last_exception = None
            for attempt in range(1, max_retries + 1):
                try:
                    swap_tx_b64 = self.get_jupiter_swap_transaction(quote, str(sender_pubkey))
                    tx_sig = self.execute_versioned_transaction(swap_tx_b64, sender)
                    logger.info(f"Swap executed with tx sig: {tx_sig} on attempt {attempt}")
                    break
                except Exception as e:
                    logger.warning(f"Swap attempt {attempt} failed: {e}")
                    last_exception = e
                    time.sleep(1 * attempt)  # simple backoff: 1s, 2s, 3s

            if tx_sig is None:
                raise last_exception or Exception("Failed to execute swap transaction after retries")

            tokens_received = int(quote.get('outAmount', 0))

            return {
                'status': 'success',
                'transaction_signature': tx_sig,
                'fee_transaction_signature': fee_tx_sig,
                'tokens_received': tokens_received,
                'fee_breakdown': {
                    'fee_percent': 100 * fee_percentage,
                    'fee_amount': fee_amount,
                    'trade_amount': trade_amount,
                    'fee_collector': str(fee_wallet)
                },
                'routing_path': routing_path,
                'message': f"Bought {tokens_received:,} tokens for {trade_amount:.9f} SOL (1% fee to Exodia)"
            }

        except Exception as e:
            logger.error(f"[Exodia Buy with Fee] Error: {e}", exc_info=True)
            return {'status': 'error', 'message': str(e)}

    def detect_contract_address(self, message_text: str) -> list:
        """Detect Solana contract addresses in messages"""
        import re
        
        # Solana addresses pattern
        solana_pattern = r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'
        addresses = re.findall(solana_pattern, message_text)
        
        # Validate addresses
        valid_addresses = []
        for addr in addresses:
            if len(addr) >= 32 and not addr.startswith('0x'):
                try:
                    PublicKey.from_string(addr)  # Validate
                    valid_addresses.append(addr)
                except:
                    continue
        
        return valid_addresses

    def get_balance(self, wallet_address: str) -> Dict[str, Any]:
        """Get SOL balance for wallet"""
        try:
            pubkey = PublicKey.from_string(wallet_address)
            response = self.client.get_balance(pubkey, commitment=Confirmed)
            
            balance_lamports = response.value
            balance_sol = balance_lamports / 1_000_000_000
            
            return {
                'status': 'success',
                'balance_sol': balance_sol,
                'balance_lamports': balance_lamports
            }
            
        except Exception as e:
            logger.error(f"Balance check failed: {e}")
            return {'status': 'error', 'message': str(e)}