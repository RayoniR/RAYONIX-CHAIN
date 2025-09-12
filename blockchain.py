# blockchain.py
import hashlib
import json
import time
#import leveldb
import pickle
from typing import List, Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from merkle import MerkleTree
from utxo import UTXOSet, Transaction, UTXO
from consensus import ProofOfStake, Validator
from database import AdvancedDatabase
from smart_contract import ContractManager, SmartContract
from config import get_config
from index_manager import IndexManager, IndexConfig

#self.config_manager = get_config()
#port = self.config_manager.get('network.listen_port')

class Block:
    def __init__(self, index: int, previous_hash: str, transactions: List[Transaction], 
                 validator: str, timestamp: float = None, nonce: int = 0, 
                 validator_signature: str = None):
        self.version = 1
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.validator = validator
        self.timestamp = timestamp or time.time()
        self.nonce = nonce
        self.validator_signature = validator_signature
        self.merkle_root = self.calculate_merkle_root()
        self.hash = self.calculate_hash()

    def calculate_merkle_root(self) -> str:
        tx_hashes = [tx.hash for tx in self.transactions]
        return MerkleTree(tx_hashes).root

    def calculate_hash(self) -> str:
        block_data = json.dumps({
            'version': self.version,
            'index': self.index,
            'previous_hash': self.previous_hash,
            'validator': self.validator,
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'merkle_root': self.merkle_root,
            'transaction_count': len(self.transactions)
        }, sort_keys=True)
        return hashlib.sha256(block_data.encode()).hexdigest()

    def to_dict(self) -> Dict:
        return {
            'version': self.version,
            'index': self.index,
            'hash': self.hash,
            'previous_hash': self.previous_hash,
            'validator': self.validator,
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'validator_signature': self.validator_signature,
            'merkle_root': self.merkle_root,
            'transactions': [tx.to_dict() for tx in self.transactions]
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Block':
        transactions = [Transaction.from_dict(tx) for tx in data['transactions']]
        block = cls(
            data['index'],
            data['previous_hash'],
            transactions,
            data['validator'],
            data['timestamp'],
            data['nonce'],
            data['validator_signature']
        )
        block.hash = data['hash']
        return block

class Blockchain:
    def __init__(self, db_path: str = './blockchain_db'):
        self.db = AdvancedDatabase(db_path)
        self.index_manager = IndexManager(db_path) 
        self.utxo_set = UTXOSet()
        self.consensus = ProofOfStake(min_stake=1000)
        self.contract_manager = ContractManager()
        self.difficulty = 4
        self.block_time_target = 30
        self.transaction_fee = 1
        self.mempool: List[Transaction] = []
        
        self._setup_indices()
        self._load_chain()

    def _setup_indices(self):
        self.index_manager.create_index('blocks_by_height', lambda b: b['index'])

self.index_manager.create_index('blocks_by_hash', lambda b: b['hash'])

self.index_manager.create_index('blocks_by_timestamp', lambda b: b['timestamp'])

self.index_manager.create_index('transactions_by_hash', lambda tx: tx['hash'])
self.index_manager.create_index('blocks_by_validator', lambda b: b.validator)
self.index_manager.create_index('transactions_by_address', lambda tx: tx['from'])

self.index_manager.create_index('transactions_by_address', lambda tx: tx['to'])

    def _load_chain(self):
        genesis_data = self.db.get('genesis_block')
        if genesis_data:
            self.chain = [Block.from_dict(b) for b in self.db.get('chain', [])]
            self.utxo_set = self.db.get('utxo_set', UTXOSet())
            self.consensus = self.db.get('consensus_state', ProofOfStake())
            self.contract_manager = self.db.get('contracts_state', ContractManager())
        else:
            self._create_genesis_block()

    def _create_genesis_block(self):
        genesis_tx = Transaction(
            inputs=[],
            outputs=[{'address': 'genesis', 'amount': 1000000}],
            locktime=0
        )
        
        genesis_block = Block(
            index=0,
            previous_hash="0" * 64,
            transactions=[genesis_tx],
            validator="genesis",
            timestamp=1630000000,
            nonce=0
        )
        
        self.chain = [genesis_block]
        self._update_utxo_set(genesis_block)
        self._save_state()

    def _save_state(self):
        chain_data = [block.to_dict() for block in self.chain]
        self.db.put('chain', chain_data)
        self.db.put('utxo_set', self.utxo_set)
        self.db.put('consensus_state', self.consensus)
        self.db.put('contracts_state', self.contract_manager)
        self.db.put('mempool', self.mempool)

    def _update_utxo_set(self, block: Block):
        for tx in block.transactions:
            # Mark inputs as spent
            for tx_input in tx.inputs:
                utxo_id = f"{tx_input['tx_hash']}:{tx_input['output_index']}"
                self.utxo_set.spend_utxo(utxo_id)
            
            # Add new UTXOs from outputs
            for i, output in enumerate(tx.outputs):
                utxo = UTXO(tx.hash, i, output['address'], output['amount'])
                self.utxo_set.add_utxo(utxo)

    def add_transaction(self, transaction: Transaction) -> bool:
        if not self._validate_transaction(transaction):
            return False
        
        self.mempool.append(transaction)
        self._broadcast_transaction(transaction)
        self._save_state()
        return True

    def _validate_transaction(self, transaction: Transaction) -> bool:
        # Check basic structure
        if not transaction.inputs or not transaction.outputs:
            return False
        
        total_input = 0
        total_output = sum(output['amount'] for output in transaction.outputs)
        
        # Validate each input
        for tx_input in transaction.inputs:
            utxo_id = f"{tx_input['tx_hash']}:{tx_input['output_index']}"
            utxo = self.utxo_set.utxos.get(utxo_id)
            
            if not utxo or utxo.spent:
                return False
            
            if utxo.address != tx_input['address']:
                return False
            
            # Verify signature
            if not transaction.verify_input_signature(tx_input):
                return False
            
            total_input += utxo.amount
        
        # Check if outputs don't exceed inputs + fees
        if total_input < total_output + self.transaction_fee:
            return False
        
        return True

    def mine_block(self, validator_address: str) -> Optional[Block]:
        if not self.consensus.validate_validator(validator_address):
            return None
        
        validator = self.consensus.validators[validator_address]
        
        # Select transactions from mempool
        selected_txs = self._select_transactions_for_block()
        
        # Create block
        new_block = Block(
            index=len(self.chain),
            previous_hash=self.chain[-1].hash,
            transactions=selected_txs,
            validator=validator_address,
            timestamp=time.time()
        )
        
        # Validator signs the block
        new_block.validator_signature = self._sign_block(new_block, validator)
        
        # Validate and add block
        if self._validate_block(new_block):
            self.chain.append(new_block)
            self._update_utxo_set(new_block)
            self._update_mempool(selected_txs)
            self._distribute_rewards(new_block)
            self._save_state()
            
            self._broadcast_block(new_block)
            return new_block
        
        return None

    def _select_transactions_for_block(self) -> List[Transaction]:
        # Prioritize transactions by fee (simplified)
        sorted_txs = sorted(self.mempool, key=lambda tx: self._calculate_transaction_fee(tx), reverse=True)
        return sorted_txs[:1000]  # Limit block size

    def _calculate_transaction_fee(self, transaction: Transaction) -> int:
        total_input = sum(self.utxo_set.utxos[f"{inp['tx_hash']}:{inp['output_index']}"].amount 
                         for inp in transaction.inputs)
        total_output = sum(output['amount'] for output in transaction.outputs)
        return total_input - total_output

    def _validate_block(self, block: Block) -> bool:
        # Basic validation
        if block.index != len(self.chain):
            return False
        
        if block.previous_hash != self.chain[-1].hash:
            return False
        
        if not self.consensus.validate_block(block):
            return False
        
        # Validate transactions
        for tx in block.transactions:
            if not self._validate_transaction(tx):
                return False
        
        # Validate merkle root
        if block.merkle_root != block.calculate_merkle_root():
            return False
        
        return True

    def _distribute_rewards(self, block: Block):
        # Block reward + transaction fees
        total_reward = 50 + sum(self._calculate_transaction_fee(tx) for tx in block.transactions)
        
        reward_tx = Transaction(
            inputs=[],
            outputs=[{'address': block.validator, 'amount': total_reward}],
            locktime=0
        )
        
        # Add reward transaction to next block's mempool
        self.mempool.append(reward_tx)

    def _update_mempool(self, included_txs: List[Transaction]):
        included_hashes = {tx.hash for tx in included_txs}
        self.mempool = [tx for tx in self.mempool if tx.hash not in included_hashes]

    def _sign_block(self, block: Block, validator: Validator) -> str:
        # Implement actual signing with validator's private key
        signing_data = f"{block.previous_hash}{block.timestamp}{block.merkle_root}"
        return f"signed_{signing_data}"  # Placeholder

    def _broadcast_transaction(self, transaction: Transaction):
        # Implement network broadcast
        pass

    def _broadcast_block(self, block: Block):
        # Implement network broadcast
        pass

    def get_balance(self, address: str) -> int:
        return self.utxo_set.get_balance(address) + self.contract_manager.get_contract_balance(address)

    def deploy_contract(self, creator: str, code: Dict, initial_balance: int = 0) -> str:
        # Check balance for deployment fee
        if self.get_balance(creator) < 10:  # Deployment fee
            raise Exception("Insufficient balance for contract deployment")
        
        contract_address = self.contract_manager.deploy_contract(creator, code, initial_balance)
        self._save_state()
        return contract_address

    def execute_contract(self, contract_address: str, function_name: str, 
                        args: List, caller: str, value: int = 0) -> Any:
        result = self.contract_manager.execute_contract(contract_address, function_name, args, caller, value)
        self._save_state()
        return result

    def validate_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            if current_block.previous_hash != previous_block.hash:
                return False
            
            if current_block.hash != current_block.calculate_hash():
                return False
            
            if not self.consensus.validate_block(current_block):
                return False
        
        return True

    def find_fork(self, other_chain: List[Block]) -> int:
        """Find where this chain forks from another chain"""
        min_length = min(len(self.chain), len(other_chain))
        for i in range(min_length):
            if self.chain[i].hash != other_chain[i].hash:
                return i
        return min_length

    def reorganize_chain(self, new_chain: List[Block]):
        """Reorganize to a longer valid chain"""
        fork_point = self.find_fork(new_chain)
        
        # Revert blocks from fork point
        for i in range(len(self.chain) - 1, fork_point - 1, -1):
            self._revert_block(self.chain[i])
        
        # Add new blocks
        for i in range(fork_point, len(new_chain)):
            self.chain.append(new_chain[i])
            self._update_utxo_set(new_chain[i])
        
        self._save_state()

    def _revert_block(self, block: Block):
        """Revert a block's effects"""
        # Revert UTXO changes
        for tx in reversed(block.transactions):
            # Re-add spent UTXOs
            for tx_input in tx.inputs:
                utxo_id = f"{tx_input['tx_hash']}:{tx_input['output_index']}"
                if utxo_id in self.utxo_set.utxos:
                    self.utxo_set.utxos[utxo_id].spent = False
            
            # Remove created UTXOs
            for i in range(len(tx.outputs)):
                utxo_id = f"{tx.hash}:{i}"
                if utxo_id in self.utxo_set.utxos:
                    del self.utxo_set.utxos[utxo_id]
        
        # Re-add transactions to mempool
        self.mempool.extend(block.transactions)

    def get_transaction_proof(self, tx_hash: str) -> Optional[Dict]:
        """Get Merkle proof for a transaction"""
        for block in self.chain:
            for tx in block.transactions:
                if tx.hash == tx_hash:
                    merkle_tree = MerkleTree([tx.hash for tx in block.transactions])
                    return {
                        'block_hash': block.hash,
                        'merkle_root': block.merkle_root,
                        'proof': merkle_tree.get_proof(tx_hash),
                        'transaction_index': block.transactions.index(tx)
                    }
        return None

    def verify_transaction_proof(self, proof: Dict, tx_hash: str) -> bool:
        """Verify Merkle proof for a transaction"""
        return MerkleTree.verify_proof(
            tx_hash, 
            proof['merkle_root'], 
            proof['proof']
        )