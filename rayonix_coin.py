# rayonix_coin.py
import hashlib
import json
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
import ecdsa
from ecdsa import SECP256k1, SigningKey, VerifyingKey
import base58
import bech32
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import plyvel
from merkle import MerkleTree, CompactMerkleTree
from utxo import UTXOSet, Transaction, UTXO
from consensus import ProofOfStake, Validator
from smart_contract import ContractManager, SmartContract
from database import AdvancedDatabase
from wallet import AdvancedWallet, WalletConfig
from p2p_network import AdvancedP2PNetwork, NodeConfig
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RayonixCoin:
    
    def __init__(self, network_type: str = "mainnet", data_dir: str = "./rayonix_data"):
        self.network_type = network_type
        self.data_dir = data_dir
        self.genesis_block = None
        self.blockchain = []
        self.mempool = []
        self.utxo_set = UTXOSet()
        self.consensus = ProofOfStake()
        self.contract_manager = ContractManager()
        self.wallet = None
        self.network = None
        
        # Initialize database with plyvel
        self.database = AdvancedDatabase(f"{data_dir}/blockchain_db")
        
        # Configuration
        self.config = {
            'block_reward': 50,
            'halving_interval': 210000,
            'difficulty_adjustment_blocks': 2016,
            'max_block_size': 4000000,
            'max_transaction_size': 100000,
            'min_transaction_fee': 1,
            'stake_minimum': 1000,
            'block_time_target': 30,
            'max_supply': 21000000,
            'premine_amount': 1000000,
            'foundation_address': 'RXFOUNDATIONXXXXXXXXXXXXXXXXXXXXXX',
            'developer_fee_percent': 0.05,
            'network_id': self._get_network_id(network_type)
        }
        
        # State
        self.current_difficulty = 4
        self.total_supply = 0
        self.circulating_supply = 0
        self.staking_rewards_distributed = 0
        self.foundation_funds = 0
        self.last_block_time = time.time()
        
        # Initialize components
        self._initialize_blockchain()
        self._initialize_wallet()
        self._initialize_network()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _get_network_id(self, network_type: str) -> int:
        """Get network ID based on network type"""
        network_ids = {
            "mainnet": 1,
            "testnet": 2,
            "devnet": 3,
            "regtest": 4
        }
        return network_ids.get(network_type, 1)
    
    def _initialize_blockchain(self):
        """Initialize or load blockchain"""
        # Try to load from database
        if self.database.get('genesis_block'):
            self._load_blockchain()
        else:
            self._create_genesis_block()
    
    def _create_genesis_block(self):
        """Create genesis block with premine"""
        genesis_transactions = []
        
        # Premine transaction
        premine_tx = Transaction(
            inputs=[],
            outputs=[{
                'address': self.config['foundation_address'],
                'amount': self.config['premine_amount'],
                'locktime': 0
            }],
            locktime=0
        )
        genesis_transactions.append(premine_tx)
        
        # Create genesis block
        self.genesis_block = {
            'height': 0,
            'hash': '0' * 64,
            'previous_hash': '0' * 64,
            'merkle_root': self._calculate_merkle_root(genesis_transactions),
            'timestamp': int(time.time()),
            'difficulty': 1,
            'nonce': 0,
            'validator': 'genesis',
            'transactions': genesis_transactions,
            'version': 1,
            'chainwork': 1
        }
        
        # Calculate actual hash
        self.genesis_block['hash'] = self._calculate_block_hash(self.genesis_block)
        
        # Add to blockchain
        self.blockchain.append(self.genesis_block)
        
        # Update UTXO set
        self._update_utxo_set(self.genesis_block)
        
        # Update supply
        self.total_supply += self.config['premine_amount']
        self.circulating_supply += self.config['premine_amount']
        self.foundation_funds += self.config['premine_amount']
        
        # Save to database
        self._save_blockchain()
    
    def _load_blockchain(self):
        """Load blockchain from database"""
        try:
            self.genesis_block = self.database.get('genesis_block')
            chain_data = self.database.get('blockchain')
            
            if chain_data:
                self.blockchain = chain_data
                # Rebuild UTXO set by processing all blocks
                for block in self.blockchain:
                    self._update_utxo_set(block)
                
                # Calculate current supply
                self._calculate_supply()
                
            logger.info(f"Blockchain loaded with {len(self.blockchain)} blocks")
            
        except Exception as e:
            logger.error(f"Failed to load blockchain: {e}")
            self._create_genesis_block()
    
    def _save_blockchain(self):
        """Save blockchain to database"""
        try:
            self.database.put('genesis_block', self.genesis_block)
            self.database.put('blockchain', self.blockchain)
            self.database.put('utxo_set', self.utxo_set.to_dict())
            self.database.put('supply_info', {
                'total_supply': self.total_supply,
                'circulating_supply': self.circulating_supply,
                'staking_rewards': self.staking_rewards_distributed,
                'foundation_funds': self.foundation_funds
            })
        except Exception as e:
            logger.error(f"Failed to save blockchain: {e}")
    
    def _initialize_wallet(self):
        """Initialize wallet system"""
        wallet_config = WalletConfig(
            network=self.network_type,
            address_type='RAYONIX',
            encryption=True
        )
        self.wallet = AdvancedWallet(wallet_config)
    
    def _initialize_network(self):
        """Initialize P2P network"""
        network_config = NodeConfig(
            network_type=self.network_type.upper(),
            listen_port=30303,
            max_connections=50,
            bootstrap_nodes=self._get_bootstrap_nodes()
        )
        self.network = AdvancedP2PNetwork(network_config)
        
        # Register message handlers
        self.network.register_message_handler('block', self._handle_block_message)
        self.network.register_message_handler('transaction', self._handle_transaction_message)
        self.network.register_message_handler('consensus', self._handle_consensus_message)
    
    def _get_bootstrap_nodes(self) -> List[str]:
        """Get bootstrap nodes for network"""
        if self.network_type == "mainnet":
            return [
                "node1.rayonix.org:30303",
                "node2.rayonix.org:30303",
                "node3.rayonix.org:30303"
            ]
        elif self.network_type == "testnet":
            return [
                "testnet-node1.rayonix.org:30304",
                "testnet-node2.rayonix.org:30304"
            ]
        else:
            return []
    
    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        # Mining/staking thread
        self.mining_thread = threading.Thread(target=self._mining_loop, daemon=True)
        self.mining_thread.start()
        
        # Network sync thread
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()
        
        # Mempool management thread
        self.mempool_thread = threading.Thread(target=self._mempool_loop, daemon=True)
        self.mempool_thread.start()
    
    def _mining_loop(self):
        """Proof-of-Stake mining loop"""
        while True:
            try:
                if self._should_mine_block():
                    new_block = self._create_new_block()
                    if new_block:
                        self._add_block(new_block)
                        self._broadcast_block(new_block)
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Mining error: {e}")
                time.sleep(5)
    
    def _should_mine_block(self) -> bool:
        """Check if we should mine a new block"""
        # Check if we're a validator with sufficient stake
        if self.wallet and self.consensus.is_validator(self.wallet.get_address()):
            current_time = time.time()
            # Check if it's our turn to validate
            return self.consensus.should_validate(self.wallet.get_address(), current_time)
        return False
    
    def _create_new_block(self) -> Optional[Dict]:
        """Create a new block"""
        try:
            # Select transactions from mempool
            transactions = self._select_transactions_for_block()
            
            # Get current validator
            validator_address = self.wallet.get_address()
            
            # Create block header
            previous_block = self.blockchain[-1]
            new_block = {
                'height': previous_block['height'] + 1,
                'previous_hash': previous_block['hash'],
                'timestamp': int(time.time()),
                'difficulty': self.current_difficulty,
                'validator': validator_address,
                'transactions': transactions,
                'version': 2,
                'nonce': 0
            }
            
            # Calculate merkle root
            new_block['merkle_root'] = self._calculate_merkle_root(transactions)
            
            # Sign the block (Proof-of-Stake)
            block_hash = self._calculate_block_hash(new_block)
            signature = self.wallet.sign_data(block_hash.encode())
            new_block['signature'] = signature
            new_block['hash'] = block_hash
            
            # Add block reward transaction
            reward_tx = self._create_block_reward_transaction(validator_address)
            new_block['transactions'].insert(0, reward_tx)
            
            return new_block
            
        except Exception as e:
            logger.error(f"Block creation failed: {e}")
            return None
    
    def _select_transactions_for_block(self) -> List[Dict]:
        """Select transactions for new block"""
        # Sort by fee rate (higher fees first)
        sorted_txs = sorted(self.mempool, key=lambda tx: tx.get('fee_rate', 0), reverse=True)
        
        selected_txs = []
        current_size = 0
        
        for tx in sorted_txs:
            tx_size = self._calculate_transaction_size(tx)
            if current_size + tx_size <= self.config['max_block_size']:
                if self._validate_transaction(tx):
                    selected_txs.append(tx)
                    current_size += tx_size
            
            if current_size >= self.config['max_block_size']:
                break
        
        return selected_txs
    
    def _create_block_reward_transaction(self, validator_address: str) -> Dict:
        """Create block reward transaction"""
        block_reward = self._get_block_reward()
        
        # Calculate foundation fee
        foundation_fee = int(block_reward * self.config['developer_fee_percent'])
        validator_reward = block_reward - foundation_fee
        
        # Create reward transaction
        reward_tx = Transaction(
            inputs=[],
            outputs=[
                {
                    'address': validator_address,
                    'amount': validator_reward,
                    'locktime': 0
                },
                {
                    'address': self.config['foundation_address'],
                    'amount': foundation_fee,
                    'locktime': 0
                }
            ],
            locktime=0
        )
        
        # Update supply tracking
        self.total_supply += block_reward
        self.circulating_supply += validator_reward
        self.foundation_funds += foundation_fee
        self.staking_rewards_distributed += validator_reward
        
        return reward_tx.to_dict()
    
    def _get_block_reward(self) -> int:
        """Calculate current block reward with halving"""
        height = len(self.blockchain)
        halvings = height // self.config['halving_interval']
        
        # Base reward divided by 2^halvings
        reward = self.config['block_reward'] >> halvings
        
        # Ensure reward doesn't go below minimum
        return max(reward, 1)
    
    def _add_block(self, block: Dict):
        """Add block to blockchain"""
        # Validate block
        if not self._validate_block(block):
            raise ValueError("Invalid block")
        
        # Add to blockchain
        self.blockchain.append(block)
        
        # Update UTXO set
        self._update_utxo_set(block)
        
        # Remove transactions from mempool
        self._remove_transactions_from_mempool(block['transactions'])
        
        # Adjust difficulty if needed
        self._adjust_difficulty()
        
        # Save to database
        self._save_blockchain()
        
        logger.info(f"New block added: #{block['height']} - {block['hash'][:16]}...")
    
    def _validate_block(self, block: Dict) -> bool:
        """Validate block"""
        try:
            # Check block structure
            required_fields = ['height', 'previous_hash', 'timestamp', 'difficulty', 
                             'validator', 'transactions', 'merkle_root', 'hash', 'signature']
            for field in required_fields:
                if field not in block:
                    return False
            
            # Check block hash
            calculated_hash = self._calculate_block_hash(block)
            if calculated_hash != block['hash']:
                return False
            
            # Check previous block
            if block['previous_hash'] != self.blockchain[-1]['hash']:
                return False
            
            # Check merkle root
            calculated_merkle = self._calculate_merkle_root(block['transactions'])
            if calculated_merkle != block['merkle_root']:
                return False
            
            # Check validator signature
            if not self._validate_block_signature(block):
                return False
            
            # Validate all transactions
            for tx in block['transactions']:
                if not self._validate_transaction(tx):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Block validation failed: {e}")
            return False
    
    def _validate_block_signature(self, block: Dict) -> bool:
        """Validate block signature"""
        try:
            # Get validator public key
            validator_address = block['validator']
            public_key = self.consensus.get_validator_public_key(validator_address)
            
            if not public_key:
                return False
            
            # Verify signature
            block_data = self._get_block_signing_data(block)
            return self.wallet.verify_signature(block_data, block['signature'], public_key)
            
        except Exception as e:
            logger.error(f"Signature validation failed: {e}")
            return False
    
    def _get_block_signing_data(self, block: Dict) -> bytes:
        """Get data used for block signing"""
        # Exclude signature from signing data
        signing_block = block.copy()
        if 'signature' in signing_block:
            del signing_block['signature']
        
        return json.dumps(signing_block, sort_keys=True).encode()
    
    def _calculate_block_hash(self, block: Dict) -> str:
        """Calculate block hash"""
        block_data = self._get_block_signing_data(block)
        return hashlib.sha256(block_data).hexdigest()
    
    def _calculate_merkle_root(self, transactions: List[Dict]) -> str:
        """Calculate merkle root of transactions"""
        if not transactions:
            return '0' * 64
        
        tx_hashes = [self._calculate_transaction_hash(tx) for tx in transactions]
        merkle_tree = MerkleTree(tx_hashes)
        return merkle_tree.get_root_hash()
    
    def _calculate_transaction_hash(self, transaction: Dict) -> str:
        """Calculate transaction hash"""
        tx_data = json.dumps(transaction, sort_keys=True).encode()
        return hashlib.sha256(tx_data).hexdigest()
    
    def _calculate_transaction_size(self, transaction: Dict) -> int:
        """Calculate transaction size in bytes"""
        return len(json.dumps(transaction).encode())
    
    def _update_utxo_set(self, block: Dict):
        """Update UTXO set with block transactions"""
        for tx in block['transactions']:
            transaction = Transaction.from_dict(tx)
            self.utxo_set.process_transaction(transaction)
    
    def _remove_transactions_from_mempool(self, transactions: List[Dict]):
        """Remove transactions from mempool"""
        tx_hashes = [self._calculate_transaction_hash(tx) for tx in transactions]
        self.mempool = [tx for tx in self.mempool 
                       if self._calculate_transaction_hash(tx) not in tx_hashes]
    
    def _adjust_difficulty(self):
        """Adjust mining difficulty"""
        if len(self.blockchain) % self.config['difficulty_adjustment_blocks'] == 0:
            self._recalculate_difficulty()
    
    def _recalculate_difficulty(self):
        """Recalculate current difficulty"""
        # Get blocks from previous difficulty period
        start_height = max(0, len(self.blockchain) - self.config['difficulty_adjustment_blocks'])
        adjustment_blocks = self.blockchain[start_height:]
        
        if len(adjustment_blocks) < 2:
            return
        
        # Calculate actual time taken
        actual_time = adjustment_blocks[-1]['timestamp'] - adjustment_blocks[0]['timestamp']
        target_time = self.config['block_time_target'] * len(adjustment_blocks)
        
        # Adjust difficulty
        ratio = actual_time / target_time
        if ratio < 0.5:
            ratio = 0.5
        elif ratio > 2.0:
            ratio = 2.0
        
        new_difficulty = self.current_difficulty * ratio
        self.current_difficulty = max(1, int(new_difficulty))
        
        logger.info(f"Difficulty adjusted: {self.current_difficulty}")
    
    def _validate_transaction(self, transaction: Dict) -> bool:
        """Validate transaction"""
        try:
            tx = Transaction.from_dict(transaction)
            
            # Check basic structure
            if not tx.inputs or not tx.outputs:
                return False
            
            # Check transaction size
            if self._calculate_transaction_size(transaction) > self.config['max_transaction_size']:
                return False
            
            # Check fees
            total_input = 0
            total_output = 0
            
            # Validate inputs
            for tx_input in tx.inputs:
                # Check if UTXO exists and is unspent
                utxo = self.utxo_set.get_utxo(tx_input['tx_hash'], tx_input['output_index'])
                if not utxo or utxo.spent:
                    return False
                
                # Check input signature
                if not self._validate_input_signature(tx_input, utxo):
                    return False
                
                total_input += utxo.amount
            
            # Calculate outputs
            for output in tx.outputs:
                total_output += output['amount']
            
            # Check if outputs don't exceed inputs
            if total_output > total_input:
                return False
            
            # Check minimum fee
            fee = total_input - total_output
            if fee < self.config['min_transaction_fee']:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Transaction validation failed: {e}")
            return False
    
    def _validate_input_signature(self, tx_input: Dict, utxo: UTXO) -> bool:
        """Validate transaction input signature"""
        # This would verify the cryptographic signature
        # For now, we'll simulate validation
        return True
    
    def _sync_loop(self):
        """Blockchain synchronization loop"""
        while True:
            try:
                if self.network and self.network.is_connected():
                    self._synchronize_with_network()
                
                time.sleep(30)  # Sync every 30 seconds
                
            except Exception as e:
                logger.error(f"Sync error: {e}")
                time.sleep(60)
    
    def _synchronize_with_network(self):
        """Synchronize with network peers"""
        # Get best block from peers
        best_block = self._get_best_block_from_peers()
        
        if best_block and best_block['height'] > len(self.blockchain) - 1:
            # We need to sync
            self._download_missing_blocks(best_block['height'])
    
    def _get_best_block_from_peers(self) -> Optional[Dict]:
        """Get best block information from network peers"""
        # This would query multiple peers and return consensus best block
        # For now, return None (simulation)
        return None
    
    def _download_missing_blocks(self, target_height: int):
        """Download missing blocks from network"""
        current_height = len(self.blockchain) - 1
        
        while current_height < target_height:
            try:
                next_height = current_height + 1
                block = self._request_block_from_peers(next_height)
                
                if block and self._validate_block(block):
                    self._add_block(block)
                    current_height += 1
                else:
                    break
                    
            except Exception as e:
                logger.error(f"Failed to download block {next_height}: {e}")
                break
    
    def _request_block_from_peers(self, height: int) -> Optional[Dict]:
        """Request block from network peers"""
        # This would send network requests for specific block
        # For now, return None (simulation)
        return None
    
    def _mempool_loop(self):
        """Mempool management loop"""
        while True:
            try:
                # Clean old transactions
                self._clean_mempool()
                
                # Validate all transactions
                self._validate_mempool()
                
                # Broadcast transactions
                self._broadcast_mempool()
                
                time.sleep(60)  # Run every minute
                
            except Exception as e:
                logger.error(f"Mempool error: {e}")
                time.sleep(30)
    
    def _clean_mempool(self):
        """Clean old transactions from mempool"""
        current_time = time.time()
        self.mempool = [tx for tx in self.mempool 
                       if current_time - tx.get('timestamp', 0) < 3600]  # 1 hour
    
    def _validate_mempool(self):
        """Validate all transactions in mempool"""
        valid_transactions = []
        
        for tx in self.mempool:
            if self._validate_transaction(tx):
                valid_transactions.append(tx)
        
        self.mempool = valid_transactions
    
    def _broadcast_mempool(self):
        """Broadcast mempool transactions to network"""
        if self.network and self.mempool:
            for tx in self.mempool[:10]:  # Broadcast first 10
                self._broadcast_transaction(tx)
    
    def _broadcast_block(self, block: Dict):
        """Broadcast block to network"""
        if self.network:
            self.network.broadcast_message('block', block)
    
    def _broadcast_transaction(self, transaction: Dict):
        """Broadcast transaction to network"""
        if self.network:
            self.network.broadcast_message('transaction', transaction)
    
    def _handle_block_message(self, message: Dict):
        """Handle incoming block message"""
        try:
            block = message['data']
            if self._validate_block(block):
                self._add_block(block)
        except Exception as e:
            logger.error(f"Block message handling failed: {e}")
    
    def _handle_transaction_message(self, message: Dict):
        """Handle incoming transaction message"""
        try:
            transaction = message['data']
            if self._validate_transaction(transaction):
                self._add_to_mempool(transaction)
        except Exception as e:
            logger.error(f"Transaction message handling failed: {e}")
    
    def _handle_consensus_message(self, message: Dict):
        """Handle consensus message"""
        try:
            # Process consensus messages (votes, proposals, etc.)
            # This would be implemented based on specific consensus protocol
            pass
        except Exception as e:
            logger.error(f"Consensus message handling failed: {e}")
    
    def _add_to_mempool(self, transaction: Dict):
        """Add transaction to mempool"""
        # Check if already in mempool
        tx_hash = self._calculate_transaction_hash(transaction)
        existing_tx = next((tx for tx in self.mempool 
                          if self._calculate_transaction_hash(tx) == tx_hash), None)
        
        if not existing_tx:
            transaction['timestamp'] = time.time()
            transaction['fee_rate'] = self._calculate_fee_rate(transaction)
            self.mempool.append(transaction)
    
    def _calculate_fee_rate(self, transaction: Dict) -> float:
        """Calculate fee rate (fee per byte)"""
        tx_size = self._calculate_transaction_size(transaction)
        
        # Calculate total fee
        total_input = sum(inp.get('amount', 0) for inp in transaction.get('inputs', []))
        total_output = sum(out.get('amount', 0) for out in transaction.get('outputs', []))
        fee = total_input - total_output
        
        return fee / tx_size if tx_size > 0 else 0
    
    def _calculate_supply(self):
        """Calculate current supply from blockchain"""
        self.total_supply = 0
        self.circulating_supply = 0
        self.staking_rewards_distributed = 0
        self.foundation_funds = 0
        
        for block in self.blockchain:
            for tx in block['transactions']:
                # Skip coinbase transactions for input calculation
                if not tx.get('inputs'):
                    # This is a coinbase transaction
                    total_output = sum(out.get('amount', 0) for out in tx.get('outputs', []))
                    self.total_supply += total_output
                    
                    # Track foundation funds
                    for output in tx.get('outputs', []):
                        if output.get('address') == self.config['foundation_address']:
                            self.foundation_funds += output.get('amount', 0)
                        else:
                            self.circulating_supply += output.get('amount', 0)
                            self.staking_rewards_distributed += output.get('amount', 0)
    
    def create_transaction(self, from_address: str, to_address: str, amount: int, 
                          fee: Optional[int] = None, memo: Optional[str] = None) -> Optional[Dict]:
        """Create and sign a transaction"""
        try:
            # Get UTXOs for sender
            utxos = self.utxo_set.get_utxos_for_address(from_address)
            if not utxos:
                raise ValueError("No spendable funds")
            
            # Calculate total available
            total_available = sum(utxo.amount for utxo in utxos)
            
            # Set default fee if not provided
            if fee is None:
                fee = self.config['min_transaction_fee']
            
            # Check if sufficient funds
            if total_available < amount + fee:
                raise ValueError("Insufficient funds")
            
            # Select UTXOs to spend
            selected_utxos = []
            selected_amount = 0
            
            for utxo in sorted(utxos, key=lambda x: x.amount, reverse=True):
                if selected_amount >= amount + fee:
                    break
                selected_utxos.append(utxo)
                selected_amount += utxo.amount
            
            # Create transaction inputs
            inputs = []
            for utxo in selected_utxos:
                inputs.append({
                    'tx_hash': utxo.tx_hash,
                    'output_index': utxo.output_index,
                    'address': from_address,
                    'amount': utxo.amount
                })
            
            # Create transaction outputs
            outputs = [
                {
                    'address': to_address,
                    'amount': amount,
                    'locktime': 0
                }
            ]
            
            # Add change output if needed
            change_amount = selected_amount - amount - fee
            if change_amount > 0:
                change_address = self.wallet.get_new_address()  # Get new change address
                outputs.append({
                    'address': change_address,
                    'amount': change_amount,
                    'locktime': 0
                })
            
            # Create transaction
            transaction = Transaction(
                inputs=inputs,
                outputs=outputs,
                locktime=0
            )
            
            # Sign transaction
            signed_tx = self.wallet.sign_transaction(transaction.to_dict())
            
            # Add to mempool
            self._add_to_mempool(signed_tx)
            
            return signed_tx
            
        except Exception as e:
            logger.error(f"Transaction creation failed: {e}")
            return None
    
    def get_balance(self, address: str) -> int:
        """Get balance for address"""
        utxos = self.utxo_set.get_utxos_for_address(address)
        return sum(utxo.amount for utxo in utxos)
    
    def get_blockchain_info(self) -> Dict:
        """Get blockchain information"""
        return {
            'height': len(self.blockchain) - 1,
            'difficulty': self.current_difficulty,
            'total_supply': self.total_supply,
            'circulating_supply': self.circulating_supply,
            'block_reward': self._get_block_reward(),
            'mempool_size': len(self.mempool),
            'foundation_funds': self.foundation_funds,
            'staking_rewards': self.staking_rewards_distributed,
            'network': self.network_type,
            'version': 1
        }
    
    def get_block(self, height: int) -> Optional[Dict]:
        """Get block by height"""
        if 0 <= height < len(self.blockchain):
            return self.blockchain[height]
        return None
    
    def get_transaction(self, tx_hash: str) -> Optional[Dict]:
        """Get transaction by hash"""
        # Check mempool first
        for tx in self.mempool:
            if self._calculate_transaction_hash(tx) == tx_hash:
                return tx
        
        # Check blockchain
        for block in self.blockchain:
            for tx in block['transactions']:
                if self._calculate_transaction_hash(tx) == tx_hash:
                    return tx
        
        return None
    
    def start_mining(self):
        """Start mining/staking"""
        if not self.mining_thread.is_alive():
            self.mining_thread = threading.Thread(target=self._mining_loop, daemon=True)
            self.mining_thread.start()
            logger.info("Mining started")
    
    def stop_mining(self):
        """Stop mining/staking"""
        # Mining loop checks a flag, so we just need to set it
        # This would be implemented with proper threading control
        logger.info("Mining stopped")
    
    def connect_to_network(self):
        """Connect to P2P network"""
        if self.network:
            self.network.start()
            logger.info("Network connection started")
    
    def disconnect_from_network(self):
        """Disconnect from P2P network"""
        if self.network:
            self.network.stop()
            logger.info("Network connection stopped")
    
    def deploy_contract(self, contract_code: str, initial_balance: int = 0) -> Optional[str]:
        """Deploy smart contract"""
        if not self.wallet:
            raise ValueError("Wallet not available")
        
        return self.contract_manager.deploy_contract(
            self.wallet.get_address(),
            contract_code,
            initial_balance
        )
    
    def call_contract(self, contract_address: str, function_name: str, 
                     args: List[Any], value: int = 0) -> Any:
        """Call smart contract function"""
        if not self.wallet:
            raise ValueError("Wallet not available")
        
        return self.contract_manager.execute_contract(
            contract_address,
            function_name,
            args,
            self.wallet.get_address(),
            value
        )
    
    def register_validator(self, stake_amount: int) -> bool:
        """Register as validator"""
        if not self.wallet:
            raise ValueError("Wallet not available")
        
        # Check minimum stake
        if stake_amount < self.config['stake_minimum']:
            raise ValueError(f"Minimum stake is {self.config['stake_minimum']} RXY")
        
        # Check balance
        balance = self.get_balance(self.wallet.get_address())
        if balance < stake_amount:
            raise ValueError("Insufficient balance")
        
        # Create staking transaction
        staking_tx = self.create_transaction(
            self.wallet.get_address(),
            self.config['foundation_address'],  # Staking contract address
            stake_amount,
            fee=self.config['min_transaction_fee'],
            memo="Validator registration"
        )
        
        if staking_tx:
            # Register with consensus
            return self.consensus.register_validator(
                self.wallet.get_address(),
                self.wallet.get_public_key(),
                stake_amount
            )
        
        return False

    def close(self):
        """Cleanup resources"""
        if hasattr(self, 'database'):
            self.database.close()
        if hasattr(self, 'network'):
            self.network.stop()

    def __del__(self):
        """Destructor"""
        self.close()

# Utility functions
def create_rayonix_network(network_type: str = "mainnet") -> RayonixCoin:
    """Create RAYONIX network instance"""
    return RayonixCoin(network_type)

def generate_genesis_block(config: Dict) -> Dict:
    """Generate genesis block with custom configuration"""
    # This would create a custom genesis block for private networks
    pass

def validate_rayonix_address(address: str) -> bool:
    """Validate RAYONIX address"""
    # RAYONIX uses Bech32 addresses starting with 'rx'
    if address.startswith('rx1'):
        try:
            hrp, data = bech32.decode(address)
            return hrp == 'rx' and data is not None
        except:
            return False
    return False

def calculate_mining_reward(height: int, base_reward: int = 50, halving_interval: int = 210000) -> int:
    """Calculate mining reward at given height"""
    halvings = height // halving_interval
    reward = base_reward >> halvings
    return max(reward, 1)

# Example usage
if __name__ == "__main__":
    # Create mainnet instance
    rayonix = RayonixCoin("mainnet")
    
    try:
        # Start network and mining
        rayonix.connect_to_network()
        rayonix.start_mining()
        
        # Display blockchain info
        info = rayonix.get_blockchain_info()
        print(f"RAYONIX Blockchain Info:")
        print(f"  Height: {info['height']}")
        print(f"  Total Supply: {info['total_supply']} RXY")
        print(f"  Circulating Supply: {info['circulating_supply']} RXY")
        print(f"  Current Reward: {info['block_reward']} RXY")
        print(f"  Difficulty: {info['difficulty']}")
        
        # Create a transaction (example)
        if rayonix.wallet:
            address = rayonix.wallet.get_address()
            balance = rayonix.get_balance(address)
            print(f"Wallet Balance: {balance} RXY")
            
            # Send transaction if we have funds
            if balance > 10:
                tx = rayonix.create_transaction(
                    address,
                    "rx1recipientaddressxxxxxxxxxxxxxx",
                    10,
                    fee=1
                )
                if tx:
                    print(f"Transaction created: {rayonix._calculate_transaction_hash(tx)[:16]}...")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            
    finally:
        rayonix.stop_mining()
        rayonix.disconnect_from_network()
        rayonix.close()