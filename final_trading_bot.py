"""
Exodia Digital - Real Solana Trading Bot
Enhanced buy logic with Jupiter V6 integration and automatic fee collection
"""

import logging
import requests
import base64
import asyncio
from typing import Dict, Any, Tuple
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solders.keypair import Keypair
from solders.pubkey import Pubkey as PublicKey
from solders.transaction import VersionedTransaction
from solders.system_program import transfer, TransferParams
from solders.transaction import Transaction
from telethon import TelegramClient, events
from telethon.sessions import StringSession

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ExodiaSolanaClient:
    def __init__(self):
        self.rpc_endpoint = "https://api.mainnet-beta.solana.com"
        self.client = Client(self.rpc_endpoint)
        self.jupiter_api = "https://quote-api.jup.ag/v6"
        self.sol_mint = "So11111111111111111111111111111111111111112"
        
        logger.info("Exodia Digital Solana Client initialized with mainnet RPC")

    def send_sol(self, sender: Keypair, recipient: PublicKey, amount_sol: float):
        """Send SOL transfer"""
        amount_lamports = int(amount_sol * 1_000_000_000)
        
        transfer_ix = transfer(TransferParams(
            from_pubkey=sender.pubkey(),
            to_pubkey=recipient,
            lamports=amount_lamports
        ))
        
        transaction = Transaction()
        transaction.add(transfer_ix)
        
        recent_blockhash = self.client.get_latest_blockhash(commitment=Confirmed)
        transaction.recent_blockhash = recent_blockhash.value.blockhash
        transaction.fee_payer = sender.pubkey()
        
        transaction.sign(sender)
        response = self.client.send_transaction(
            transaction, sender,
            opts={'skip_confirmation': False, 'preflight_commitment': Confirmed}
        )
        
        signature = str(response.value)
        logger.info(f"SOL transfer successful: {signature}")
        return signature

    def get_jupiter_quote(self, input_mint: str, output_mint: str, amount_lamports: int) -> Dict:
        """Get Jupiter swap quote"""
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

    def get_jupiter_swap_transaction(self, quote: Dict, user_pubkey: str) -> str:
        """Get Jupiter swap transaction"""
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
        
        return response.json()['swapTransaction']

    def execute_versioned_transaction(self, tx_b64: str, signer: Keypair) -> str:
        """Execute versioned transaction"""
        tx_bytes = base64.b64decode(tx_b64)
        versioned_tx = VersionedTransaction.from_bytes(tx_bytes)
        
        versioned_tx.sign([signer])
        
        response = self.client.send_transaction(
            versioned_tx,
            opts={
                'skip_confirmation': False,
                'preflight_commitment': Confirmed,
                'max_retries': 3
            }
        )
        
        signature = str(response.value)
        logger.info(f"Transaction executed: {signature}")
        return signature

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

    def buy_token_with_fee(self, token_address: str, sol_amount: float, private_key: str) -> Dict[str, Any]:
        """Enhanced buy logic with Jupiter V6 and Exodia fee collection"""
        try:
            if sol_amount <= 0:
                return {'status': 'error', 'message': 'SOL amount must be positive'}

            fee_wallet = PublicKey.from_string("B7dRWXg2vTfpK469dzoaz1mYzU7G8DRMusBEut3pyz3z")
            fee_percentage = 0.01
            fee_amount = round(sol_amount * fee_percentage, 9)
            trade_amount = round(sol_amount - fee_amount, 9)

            sender = Keypair.from_base58_string(private_key)
            sender_pubkey = sender.pubkey()

            logger.info(f"Initiating token buy. User: {sender_pubkey}, Token: {token_address}")
            logger.info(f"Trade: {trade_amount:.9f} SOL, Fee: {fee_amount:.9f} SOL")

            wallet_balance = self.get_wallet_balance(sender_pubkey)
            required_balance = sol_amount + 0.002  # buffer for fee+swap tx fees
            if wallet_balance < required_balance:
                raise ValueError(f"Insufficient funds: wallet balance {wallet_balance} SOL, required {required_balance}")

            # Send fee first
            fee_sig = self.send_sol(sender, fee_wallet, fee_amount)
            logger.debug(f"Fee sent, tx sig: {fee_sig}")

            # Get quote for the trade_amount
            quote = self.get_jupiter_quote(self.sol_mint, token_address, int(trade_amount * 1e9))
            if not quote or int(quote.get('outAmount', 0)) == 0:
                # Attempt rollback fee if swap impossible
                try:
                    refund_sig = self.send_sol(Keypair.from_base58_string(private_key), sender_pubkey, fee_amount)
                    logger.warning(f"Rolled back fee tx, sig: {refund_sig}")
                except Exception as rollback_err:
                    logger.error(f"Rollback failed: {rollback_err}")
                raise ValueError("Invalid or zero output quote from Jupiter.")

            routing_path = quote.get('routes', [{}])[0].get('marketInfos', [])
            logger.debug(f"Routing path: {routing_path}")

            # Prepare swap transaction
            swap_tx = self.get_jupiter_swap_transaction(quote, str(sender_pubkey))

            # Execute swap transaction
            tx_sig = self.execute_versioned_transaction(swap_tx, sender)
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

        except Exception as e:
            logger.error(f"[Exodia Buy] Error: {e}", exc_info=True)
            return {'status': 'error', 'message': str(e)}

    def detect_contract_address(self, message_text: str) -> list:
        """Detect Solana contract addresses in messages"""
        import re
        
        solana_pattern = r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'
        addresses = re.findall(solana_pattern, message_text)
        
        valid_addresses = []
        for addr in addresses:
            if len(addr) >= 32 and not addr.startswith('0x'):
                try:
                    PublicKey.from_string(addr)  # Validate
                    valid_addresses.append(addr)
                except:
                    continue
        
        return valid_addresses

class ExodiaTelegramTrader:
    def __init__(self, api_id: int, api_hash: str, phone_number: str):
        self.api_id = api_id
        self.api_hash = api_hash
        self.phone_number = phone_number
        self.client = None
        self.solana_client = ExodiaSolanaClient()
        self.monitoring_channels = {}

    async def connect(self, verification_code=None):
        """Connect to Telegram"""
        self.client = TelegramClient(StringSession(), self.api_id, self.api_hash)
        await self.client.connect()
        
        if await self.client.is_user_authorized():
            me = await self.client.get_me()
            return {'status': 'success', 'user': me.first_name}
        
        if not verification_code:
            await self.client.send_code_request(self.phone_number)
            return {'status': 'code_required'}
        
        await self.client.sign_in(phone=self.phone_number, code=verification_code)
        me = await self.client.get_me()
        return {'status': 'success', 'user': me.first_name}

    async def start_monitoring(self, channel_name: str, sol_amount: float, private_key: str):
        """Start monitoring channel for contract addresses with auto-trading"""
        entity = await self.client.get_entity(channel_name)
        
        self.monitoring_channels[entity.id] = {
            'sol_amount': sol_amount,
            'private_key': private_key
        }
        
        @self.client.on(events.NewMessage(chats=entity))
        async def handle_message(event):
            message_text = event.message.message
            if not message_text:
                return
            
            # Detect contract addresses
            contracts = self.solana_client.detect_contract_address(message_text)
            
            if contracts:
                logger.info(f"[Exodia] Detected {len(contracts)} contracts: {contracts}")
                
                config = self.monitoring_channels[entity.id]
                
                # Execute trades for each detected contract
                for contract in contracts:
                    logger.info(f"[Exodia] Auto-trading {contract}")
                    
                    result = self.solana_client.buy_token_with_fee(
                        token_address=contract,
                        sol_amount=config['sol_amount'],
                        private_key=config['private_key']
                    )
                    
                    if result['status'] == 'success':
                        logger.info(f"✅ [Exodia] Bought {contract}")
                        logger.info(f"   TX: {result['transaction_signature']}")
                        logger.info(f"   Tokens: {result['tokens_received']:,}")
                        logger.info(f"   Fee TX: {result['fee_transaction_signature']}")
                        logger.info(f"   Fee: {result['fee_breakdown']['fee_amount']:.4f} SOL")
                    else:
                        logger.error(f"❌ [Exodia] Failed {contract}: {result['message']}")
        
        logger.info(f"[Exodia] Started monitoring {channel_name}")
        return {'status': 'success', 'message': f'Monitoring {channel_name}'}

# Usage Example
async def main():
    # Configuration
    API_ID = 12345678  # Your Telegram API ID
    API_HASH = "your_api_hash"  # Your Telegram API Hash
    PHONE_NUMBER = "+1234567890"  # Your phone number
    PRIVATE_KEY = "your_solana_private_key_base58"  # Your Solana wallet private key
    
    # Initialize Exodia trader
    trader = ExodiaTelegramTrader(API_ID, API_HASH, PHONE_NUMBER)
    
    # Connect to Telegram
    result = await trader.connect()
    if result['status'] == 'code_required':
        code = input("Enter verification code: ")
        result = await trader.connect(code)
    
    if result['status'] != 'success':
        print(f"Failed to connect: {result}")
        return
    
    print(f"Connected as: {result['user']}")
    
    # Start monitoring and auto-trading
    await trader.start_monitoring(
        channel_name="@your_trading_channel",  # Channel to monitor
        sol_amount=0.1,  # SOL amount per trade
        private_key=PRIVATE_KEY
    )
    
    print("🚀 Exodia Digital trading bot is active!")
    print("💰 Auto-collecting 1% fees to B7dRWXg2vTfpK469dzoaz1mYzU7G8DRMusBEut3pyz3z")
    print("📡 Monitoring Telegram for contract addresses...")
    
    # Keep the bot running
    try:
        await trader.client.run_until_disconnected()
    except KeyboardInterrupt:
        print("\n🛑 Exodia trading bot stopped")

if __name__ == "__main__":
    # Run the Exodia trading bot
    asyncio.run(main())