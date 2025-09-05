# utxo.py
import hashlib
import json
from typing import List, Dict, Set, Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class UTXO:
    def __init__(self, tx_hash: str, output_index: int, address: str, amount: int):
        self.tx_hash = tx_hash
        self.output_index = output_index
        self.address = address
        self.amount = amount
        self.spent = False
        self.locktime = 0  # Block height or timestamp when spendable
        
    def to_dict(self) -> Dict:
        return {
            'tx_hash': self.tx_hash,
            'output_index': self.output_index,
            'address': self.address,
            'amount': self.amount,
            'spent': self.spent,
            'locktime': self.locktime
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'UTXO':
        utxo = cls(
            data['tx_hash'],
            data['output_index'],
            data['address'],
            data['amount']
        )
        utxo.spent = data['spent']
        utxo.locktime = data.get('locktime', 0)
        return utxo
    
    @property
    def id(self) -> str:
        return f"{self.tx_hash}:{self.output_index}"
    
    def is_spendable(self, current_block_height: int, current_time: int) -> bool:
        if self.spent:
            return False
        
        if self.locktime > 0:
            if self.locktime < 500000000:  # Block height
                return current_block_height >= self.locktime
            else:  # Timestamp
                return current_time >= self.locktime
        
        return True

class UTXOSet:
    def __init__(self):
        self.utxos: Dict[str, UTXO] = {}
        self.address_utxos: Dict[str, Set[str]] = {}
        self.spent_utxos: Dict[str, UTXO] = {}
        
    def add_utxo(self, utxo: UTXO):
        utxo_id = utxo.id
        self.utxos[utxo_id] = utxo
        
        if utxo.address not in self.address_utxos:
            self.address_utxos[utxo.address] = set()
        self.address_utxos[utxo.address].add(utxo_id)
    
    def spend_utxo(self, utxo_id: str):
        if utxo_id in self.utxos:
            utxo = self.utxos[utxo_id]
            utxo.spent = True
            
            # Move to spent UTXOs
            self.spent_utxos[utxo_id] = utxo
            del self.utxos[utxo_id]
            
            # Remove from address index
            if utxo.address in self.address_utxos:
                self.address_utxos[utxo.address].discard(utxo_id)
                if not self.address_utxos[utxo.address]:
                    del self.address_utxos[utxo.address]
    
    def get_utxos_for_address(self, address: str, current_block_height: int = 0, 
                             current_time: int = 0) -> List[UTXO]:
        utxo_ids = self.address_utxos.get(address, set())
        return [
            self.utxos[uid] for uid in utxo_ids 
            if self.utxos[uid].is_spendable(current_block_height, current_time)
        ]
    
    def get_balance(self, address: str, current_block_height: int = 0, 
                   current_time: int = 0) -> int:
        utxos = self.get_utxos_for_address(address, current_block_height, current_time)
        return sum(utxo.amount for utxo in utxos)
    
    def find_spendable_utxos(self, address: str, amount: int, 
                            current_block_height: int = 0, current_time: int = 0) -> Tuple[List[UTXO], int]:
        utxos = self.get_utxos_for_address(address, current_block_height, current_time)
        utxos.sort(key=lambda x: x.amount, reverse=True)
        
        total = 0
        selected = []
        
        for utxo in utxos:
            if total >= amount:
                break
            selected.append(utxo)
            total += utxo.amount
        
        return selected, total
    
    def get_utxo(self, utxo_id: str) -> Optional[UTXO]:
        return self.utxos.get(utxo_id) or self.spent_utxos.get(utxo_id)
    
    def to_dict(self) -> Dict:
        return {
            'utxos': {uid: utxo.to_dict() for uid, utxo in self.utxos.items()},
            'spent_utxos': {uid: utxo.to_dict() for uid, utxo in self.spent_utxos.items()},
            'address_utxos': {addr: list(utxo_set) for addr, utxo_set in self.address_utxos.items()}
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'UTXOSet':
        utxo_set = cls()
        
        # Load UTXOs
        for uid, utxo_data in data.get('utxos', {}).items():
            utxo_set.utxos[uid] = UTXO.from_dict(utxo_data)
        
        # Load spent UTXOs
        for uid, utxo_data in data.get('spent_utxos', {}).items():
            utxo_set.spent_utxos[uid] = UTXO.from_dict(utxo_data)
        
        # Load address index
        for addr, utxo_ids in data.get('address_utxos', {}).items():
            utxo_set.address_utxos[addr] = set(utxo_ids)
        
        return utxo_set

class Transaction:
    def __init__(self, inputs: List[Dict], outputs: List[Dict], locktime: int = 0, version: int = 1):
        self.version = version
        self.inputs = inputs  # [{ 'tx_hash', 'output_index', 'signature', 'public_key', 'address' }]
        self.outputs = outputs  # [{ 'address', 'amount', 'locktime' }]
        self.locktime = locktime
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        tx_data = json.dumps({
            'version': self.version,
            'inputs': self.inputs,
            'outputs': self.outputs,
            'locktime': self.locktime
        }, sort_keys=True)
        return hashlib.sha256(tx_data.encode()).hexdigest()
    
    def sign_input(self, input_index: int, private_key: ec.EllipticCurvePrivateKey, 
                  utxo: UTXO, sighash_type: int = 1):
        if input_index >= len(self.inputs):
            raise ValueError("Invalid input index")
        
        # Create signing data
        signing_data = self._get_signing_data(input_index, utxo, sighash_type)
        
        # Sign the data
        signature = private_key.sign(
            signing_data.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        
        # Store signature and public key
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        ).hex()
        
        self.inputs[input_index]['signature'] = signature.hex()
        self.inputs[input_index]['public_key'] = public_key
    
    def _get_signing_data(self, input_index: int, utxo: UTXO, sighash_type: int) -> str:
        # Create copy without signatures for this input
        inputs_copy = []
        for i, inp in enumerate(self.inputs):
            if i == input_index:
                inp_copy = {k: v for k, v in inp.items() if k not in ['signature', 'public_key']}
            else:
                inp_copy = {k: v for k, v in inp.items() if k != 'signature'}
            inputs_copy.append(inp_copy)
        
        # Include referenced UTXO in signing data
        signing_data = json.dumps({
            'version': self.version,
            'inputs': inputs_copy,
            'outputs': self.outputs,
            'locktime': self.locktime,
            'referenced_utxo': utxo.to_dict(),
            'sighash_type': sighash_type
        }, sort_keys=True)
        
        return signing_data
    
    def verify_input_signature(self, input_index: int) -> bool:
        if input_index >= len(self.inputs) or 'signature' not in self.inputs[input_index]:
            return False
        
        try:
            signature = bytes.fromhex(self.inputs[input_index]['signature'])
            public_key_bytes = bytes.fromhex(self.inputs[input_index]['public_key'])
            
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), public_key_bytes
            )
            
            # Reconstruct signing data (simplified - need UTXO reference)
            signing_data = self._get_signing_data(input_index, None, 1)
            
            public_key.verify(
                signature,
                signing_data.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except (InvalidSignature, ValueError):
            return False
    
    def get_related_addresses(self) -> List[str]:
        addresses = set()
        
        for inp in self.inputs:
            if 'address' in inp:
                addresses.add(inp['address'])
        
        for output in self.outputs:
            addresses.add(output['address'])
        
        return list(addresses)
    
    def to_dict(self) -> Dict:
        return {
            'version': self.version,
            'hash': self.hash,
            'inputs': self.inputs,
            'outputs': self.outputs,
            'locktime': self.locktime
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Transaction':
        tx = cls(
            data['inputs'],
            data['outputs'],
            data['locktime'],
            data['version']
        )
        tx.hash = data['hash']
        return tx
    
    def calculate_fee(self, utxo_set: UTXOSet) -> int:
        total_input = 0
        total_output = sum(output['amount'] for output in self.outputs)
        
        for tx_input in self.inputs:
            utxo_id = f"{tx_input['tx_hash']}:{tx_input['output_index']}"
            utxo = utxo_set.get_utxo(utxo_id)
            if utxo:
                total_input += utxo.amount
        
        return total_input - total_output