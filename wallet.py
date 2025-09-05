# wallet.py
import json
import os
import hashlib
import base58
import binascii
import secrets
import threading
import time
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidKey
import hmac
import bech32
import ecdsa
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.curves import Curve
from ecdsa.util import randrange_from_seed__trytryagain
#import bip32utils
import mnemonic
from base64 import b64encode, b64decode
import qrcode
import io
import requests
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RayonixWallet")

class WalletType(Enum):
    """Types of wallets"""
    HD = auto()          # Hierarchical Deterministic (BIP32/44)
    NON_HD = auto()      # Single key pair
    MULTISIG = auto()    # Multi-signature
    WATCH_ONLY = auto()  # Watch-only (public keys only)
    HARDWARE = auto()    # Hardware wallet integration
    SMART_CONTRACT = auto()  # Smart contract wallet

class KeyDerivation(Enum):
    """Key derivation standards"""
    BIP32 = auto()       # Hierarchical Deterministic Wallets
    BIP39 = auto()       # Mnemonic code for generating deterministic keys
    BIP44 = auto()       # Multi-Account Hierarchy for Deterministic Wallets
    BIP49 = auto()       # Derivation scheme for P2WPKH-nested-in-P2SH
    BIP84 = auto()       # Derivation scheme for P2WPKH
    ELECTRUM = auto()    # Electrum-style derivation

class AddressType(Enum):
    """Cryptocurrency address types"""
    P2PKH = auto()       # Pay to Public Key Hash (legacy)
    P2SH = auto()        # Pay to Script Hash
    P2WPKH = auto()     # Pay to Witness Public Key Hash (native SegWit)
    P2WSH = auto()       # Pay to Witness Script Hash
    P2TR = auto()        # Pay to Taproot (Taproot)
    BECH32 = auto()      # Bech32 addresses
    ETHEREUM = auto()    # Ethereum-style addresses
    CONTRACT = auto()    # Smart contract addresses

@dataclass
class WalletConfig:
    """Wallet configuration"""
    wallet_type: WalletType = WalletType.HD
    key_derivation: KeyDerivation = KeyDerivation.BIP44
    address_type: AddressType = AddressType.BECH32
    encryption: bool = True
    compression: bool = True
    passphrase: Optional[str] = None
    network: str = "mainnet"
    account_index: int = 0
    change_index: int = 0
    gap_limit: int = 20
    auto_backup: bool = True
    backup_interval: int = 86400  # 24 hours
    price_alerts: bool = False
    transaction_fees: Dict[str, int] = field(default_factory=lambda: {
        "low": 1, "medium": 2, "high": 5
    })

@dataclass
class KeyPair:
    """Cryptographic key pair"""
    private_key: bytes
    public_key: bytes
    chain_code: Optional[bytes] = None
    depth: int = 0
    index: int = 0
    parent_fingerprint: bytes = b'\x00\x00\x00\x00'
    curve: curve = field(default_factory=lambda: SECP256k1)

@dataclass
class Transaction:
    """Wallet transaction"""
    txid: str
    amount: int
    fee: int
    confirmations: int
    timestamp: int
    block_height: Optional[int]
    from_address: str
    to_address: str
    status: str  # pending, confirmed, failed
    direction: str  # sent, received
    memo: Optional[str] = None
    exchange_rate: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AddressInfo:
    """Address information"""
    address: str
    index: int
    derivation_path: str
    balance: int
    received: int
    sent: int
    tx_count: int
    is_used: bool
    is_change: bool
    labels: List[str] = field(default_factory=list)

@dataclass
class WalletBalance:
    """Wallet balance information"""
    total: int
    confirmed: int
    unconfirmed: int
    locked: int
    available: int
    by_address: Dict[str, int] = field(default_factory=dict)
    tokens: Dict[str, int] = field(default_factory=dict)

@dataclass
class WalletState:
    """Wallet state and statistics"""
    sync_height: int
    last_updated: float
    tx_count: int
    addresses_generated: int
    addresses_used: int
    total_received: int
    total_sent: int
    security_score: int

class AdvancedWallet:
    """Advanced cryptographic wallet with enterprise-grade features"""
    
    def __init__(self, config: Optional[WalletConfig] = None, wallet_id: Optional[str] = None):
        self.config = config or WalletConfig()
        self.wallet_id = wallet_id or self._generate_wallet_id()
        self.master_key: Optional[KeyPair] = None
        self.key_pairs: Dict[str, KeyPair] = {}
        self.addresses: Dict[str, AddressInfo] = {}
        self.transactions: Dict[str, Transaction] = {}
        self.balance = WalletBalance(0, 0, 0, 0, 0)
        self.state = WalletState(0, time.time(), 0, 0, 0, 0, 0, 0)
        
        # Security
        self.encryption_key: Optional[bytes] = None
        self.lock_time: Optional[float] = None
        self.failed_attempts = 0
        self.locked = False
        
        # Cache and performance
        self.address_cache: Dict[str, str] = {}
        self.transaction_cache: Dict[str, List[Transaction]] = {}
        self.balance_cache: Dict[str, int] = {}
        
        # Multi-signature
        self.multisig_config: Optional[Dict] = None
        self.cosigners: List[str] = []
        
        # Hardware wallet integration
        self.hardware_wallet: Optional[Any] = None
        
        # Background tasks
        self.background_thread: Optional[threading.Thread] = None
        self.running = False
        
        # Initialize
        self._initialize_wallet()
    
    def _generate_wallet_id(self) -> str:
        """Generate unique wallet ID"""
        return hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]
    
    def _initialize_wallet(self):
        """Initialize wallet components"""
        # Setup encryption if enabled
        if self.config.encryption and self.config.passphrase:
            self.encryption_key = self._derive_encryption_key(self.config.passphrase)
        
        # Initialize hardware wallet if configured
        if self.config.wallet_type == WalletType.HARDWARE:
            self._initialize_hardware_wallet()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _derive_encryption_key(self, passphrase: str, salt: Optional[bytes] = None) -> bytes:
        """Derive encryption key from passphrase"""
        salt = salt or os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode())
    
    def _initialize_hardware_wallet(self):
        """Initialize hardware wallet integration"""
        try:
            # This would integrate with actual hardware wallets like Ledger, Trezor
            # For now, we'll simulate hardware wallet behavior
            self.hardware_wallet = {
                'connected': False,
                'model': 'Simulated',
                'version': '1.0.0'
            }
            logger.info("Hardware wallet simulation initialized")
        except Exception as e:
            logger.error(f"Hardware wallet initialization failed: {e}")
    
    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        self.running = True
        self.background_thread = threading.Thread(target=self._background_worker, daemon=True)
        self.background_thread.start()
    
    def _background_worker(self):
        """Background worker for wallet maintenance"""
        while self.running:
            try:
                # Auto-backup if enabled
                if self.config.auto_backup:
                    self._auto_backup()
                
                # Price alerts if enabled
                if self.config.price_alerts:
                    self._check_price_alerts()
                
                # Cleanup old cache entries
                self._cleanup_cache()
                
                # Check for wallet lock timeout
                self._check_lock_timeout()
                
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                logger.error(f"Background worker error: {e}")
                time.sleep(60)
    
    def _auto_backup(self):
        """Automatically backup wallet"""
        backup_dir = os.path.join(os.path.expanduser("~"), ".rayonix", "backups")
        os.makedirs(backup_dir, exist_ok=True)
        
        backup_file = os.path.join(backup_dir, f"wallet_{self.wallet_id}_{int(time.time())}.backup")
        self.backup(backup_file)
        logger.info(f"Auto-backup created: {backup_file}")
    
    def _check_price_alerts(self):
        """Check cryptocurrency price alerts"""
        # This would integrate with price APIs
        pass
    
    def _cleanup_cache(self):
        """Cleanup old cache entries"""
        current_time = time.time()
        # Remove entries older than 1 hour
        self.transaction_cache = {
            k: v for k, v in self.transaction_cache.items()
            if current_time - self._get_cache_timestamp(k) < 3600
        }
    
    def _check_lock_timeout(self):
        """Check and reset wallet lock timeout"""
        if self.locked and self.lock_time and time.time() - self.lock_time > 3600:  # 1 hour lock
            self.unlock()
    
    def create_from_mnemonic(self, mnemonic_phrase: str, passphrase: str = "") -> bool:
        """Create wallet from BIP39 mnemonic phrase"""
        try:
            # Validate mnemonic
            if not self._validate_mnemonic(mnemonic_phrase):
                raise ValueError("Invalid mnemonic phrase")
            
            # Generate seed from mnemonic
            seed = self._mnemonic_to_seed(mnemonic_phrase, passphrase)
            
            # Generate master key from seed
            self.master_key = self._generate_master_key(seed)
            
            # Generate initial addresses
            self._generate_initial_addresses()
            
            logger.info("Wallet created from mnemonic successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create wallet from mnemonic: {e}")
            return False
    
    def create_from_private_key(self, private_key: str, wallet_type: WalletType = WalletType.NON_HD) -> bool:
        """Create wallet from private key"""
        try:
            # Decode private key
            priv_key_bytes = self._decode_private_key(private_key)
            
            # Create key pair
            key_pair = self._create_key_pair(priv_key_bytes)
            self.key_pairs['m/0/0'] = key_pair
            
            # Generate address
            address = self._derive_address(key_pair.public_key, 0, False)
            self.addresses[address] = AddressInfo(
                address=address,
                index=0,
                derivation_path='m/0/0',
                balance=0,
                received=0,
                sent=0,
                tx_count=0,
                is_used=False,
                is_change=False
            )
            
            self.config.wallet_type = wallet_type
            logger.info("Wallet created from private key successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create wallet from private key: {e}")
            return False
    
    def create_hd_wallet(self) -> Tuple[str, str]:
        """Create new HD wallet with mnemonic"""
        try:
            # Generate mnemonic
            mnemonic_phrase = self._generate_mnemonic()
            
            # Generate seed
            seed = self._mnemonic_to_seed(mnemonic_phrase, "")
            
            # Generate master key
            self.master_key = self._generate_master_key(seed)
            
            # Generate initial addresses
            self._generate_initial_addresses()
            
            logger.info("HD wallet created successfully")
            return mnemonic_phrase, self._get_master_xpub()
            
        except Exception as e:
            logger.error(f"Failed to create HD wallet: {e}")
            raise
    
    def _generate_mnemonic(self, strength: int = 256) -> str:
        """Generate BIP39 mnemonic phrase"""
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError("Strength must be one of: 128, 160, 192, 224, 256")
        
        mnemo = mnemonic.Mnemonic("english")
        return mnemo.generate(strength=strength)
    
    def _validate_mnemonic(self, mnemonic_phrase: str) -> bool:
        """Validate BIP39 mnemonic phrase"""
        mnemo = mnemonic.Mnemonic("english")
        return mnemo.check(mnemonic_phrase)
    
    def _mnemonic_to_seed(self, mnemonic_phrase: str, passphrase: str = "") -> bytes:
        """Convert mnemonic to seed using BIP39"""
        mnemo = mnemonic.Mnemonic("english")
        return mnemo.to_seed(mnemonic_phrase, passphrase)
    
    def _generate_master_key(self, seed: bytes) -> KeyPair:
        """Generate master key from seed using BIP32"""
        # HMAC-SHA512 with "Bitcoin seed" as key
        h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        
        private_key = h[:32]
        chain_code = h[32:]
        
        return KeyPair(
            private_key=private_key,
            public_key=self._private_to_public(private_key),
            chain_code=chain_code,
            depth=0,
            index=0,
            parent_fingerprint=b'\x00\x00\x00\x00'
        )
    
    def _private_to_public(self, private_key: bytes, compressed: bool = True) -> bytes:
        """Convert private key to public key"""
        # Using ECDSA for key conversion
        sk = SigningKey.from_string(private_key, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        if compressed:
            return vk.to_string("compressed")
        else:
            return vk.to_string("uncompressed")
    
    def _generate_initial_addresses(self):
        """Generate initial set of addresses"""
        if not self.master_key:
            raise ValueError("Master key not available")
        
        # Generate receiving addresses
        for i in range(self.config.gap_limit):
            address_info = self.derive_address(i, False)
            self.addresses[address_info.address] = address_info
        
        # Generate change addresses
        for i in range(self.config.gap_limit):
            address_info = self.derive_address(i, True)
            self.addresses[address_info.address] = address_info
    
    def derive_address(self, index: int, is_change: bool = False) -> AddressInfo:
        """Derive address at specific index"""
        if not self.master_key:
            raise ValueError("Master key not available")
        
        # BIP44 derivation path: m/purpose'/coin_type'/account'/change/address_index
        change = 1 if is_change else 0
        derivation_path = f"m/44'/0'/{self.config.account_index}'/{change}/{index}"
        
        # Derive key pair
        key_pair = self._derive_child_key(self.master_key, derivation_path)
        
        # Generate address
        address = self._derive_address(key_pair.public_key, index, is_change)
        
        return AddressInfo(
            address=address,
            index=index,
            derivation_path=derivation_path,
            balance=0,
            received=0,
            sent=0,
            tx_count=0,
            is_used=False,
            is_change=is_change
        )
    
    def _derive_child_key(self, parent_key: KeyPair, path: str) -> KeyPair:
        """Derive child key using BIP32"""
        # Parse derivation path
        indices = self._parse_derivation_path(path)
        
        current_key = parent_key
        for index in indices:
            current_key = self._derive_child_key_at_index(current_key, index)
        
        return current_key
    
    def _parse_derivation_path(self, path: str) -> List[int]:
        """Parse BIP32 derivation path"""
        if not path.startswith('m'):
            raise ValueError("Invalid derivation path")
        
        parts = path.split('/')[1:]  # Remove 'm'
        indices = []
        
        for part in parts:
            if part.endswith("'"):
                # Hardened derivation
                index = int(part[:-1]) + 0x80000000
            else:
                # Normal derivation
                index = int(part)
            indices.append(index)
        
        return indices
    
    def _derive_child_key_at_index(self, parent_key: KeyPair, index: int) -> KeyPair:
        """Derive child key at specific index"""
        if index >= 0x80000000:  # Hardened derivation
            data = b'\x00' + parent_key.private_key + index.to_bytes(4, 'big')
        else:  # Normal derivation
            data = parent_key.public_key + index.to_bytes(4, 'big')
        
        h = hmac.new(parent_key.chain_code, data, hashlib.sha512).digest()
        
        child_private = (int.from_bytes(parent_key.private_key, 'big') + 
                        int.from_bytes(h[:32], 'big')) % SECP256k1.order
        child_private = child_private.to_bytes(32, 'big')
        
        return KeyPair(
            private_key=child_private,
            public_key=self._private_to_public(child_private),
            chain_code=h[32:],
            depth=parent_key.depth + 1,
            index=index,
            parent_fingerprint=self._get_fingerprint(parent_key.public_key)
        )
    
    def _get_fingerprint(self, public_key: bytes) -> bytes:
        """Get key fingerprint"""
        hash160 = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()
        return hash160[:4]
    
    def _derive_address(self, public_key: bytes, index: int, is_change: bool) -> str:
        """Derive address from public key based on address type"""
        if self.config.address_type == AddressType.P2PKH:
            return self._public_key_to_p2pkh(public_key)
        elif self.config.address_type == AddressType.P2WPKH:
            return self._public_key_to_p2wpkh(public_key)
        elif self.config.address_type == AddressType.BECH32:
            return self._public_key_to_bech32(public_key)
        elif self.config.address_type == AddressType.ETHEREUM:
            return self._public_key_to_ethereum(public_key)
        else:
            return self._public_key_to_p2pkh(public_key)  # Default
    
    def _public_key_to_p2pkh(self, public_key: bytes) -> str:
        """Convert public key to P2PKH address"""
        # SHA256 + RIPEMD160
        sha256 = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        
        # Add network prefix
        prefix = b'\x00' if self.config.network == "mainnet" else b'\x6f'
        payload = prefix + ripemd160
        
        # Checksum
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        
        # Base58 encoding
        return base58.b58encode(payload + checksum).decode()
    
    def _public_key_to_p2wpkh(self, public_key: bytes) -> str:
        """Convert public key to P2WPKH address"""
        # Witness program: version 0 + RIPEMD160(SHA256(public_key))
        sha256 = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        witness_program = b'\x00\x14' + ripemd160  # version 0 + 20-byte program
        
        # For nested SegWit (P2SH-P2WPKH)
        script_hash = hashlib.new('ripemd160', hashlib.sha256(witness_program).digest()).digest()
        prefix = b'\x05' if self.config.network == "mainnet" else b'\xc4'
        payload = prefix + script_hash
        
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()
    
    def _public_key_to_bech32(self, public_key: bytes) -> str:
        """Convert public key to Bech32 address"""
        # Witness program: version 0 + RIPEMD160(SHA256(public_key))
        sha256 = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        
        hrp = "bc" if self.config.network == "mainnet" else "tb"
        return bech32.encode(hrp, 0, ripemd160)
    
    def _public_key_to_ethereum(self, public_key: bytes) -> str:
        """Convert public key to Ethereum address"""
        # Remove compression prefix if present
        if len(public_key) == 33:
            public_key = public_key[1:]  # Remove compression byte
        
        # Keccak-256 hash
        keccak_hash = hashlib.sha3_256(public_key).digest()
        
        # Take last 20 bytes and add 0x prefix
        address_bytes = keccak_hash[-20:]
        return "0x" + address_bytes.hex()
    
    def get_balance(self) -> WalletBalance:
        """Get wallet balance"""
        # This would typically query a blockchain node or indexer
        # For now, we'll simulate balance calculation
        total = sum(info.balance for info in self.addresses.values())
        confirmed = total  # Simulate all confirmed
        unconfirmed = 0    # No unconfirmed transactions
        
        return WalletBalance(
            total=total,
            confirmed=confirmed,
            unconfirmed=unconfirmed,
            locked=0,
            available=total,
            by_address={addr: info.balance for addr, info in self.addresses.items()}
        )
    
    def sign_transaction(self, transaction_data: Dict, private_key: Optional[bytes] = None) -> str:
        """Sign transaction data"""
        try:
            if private_key is None:
                if not self.master_key:
                    raise ValueError("No private key available")
                private_key = self.master_key.private_key
            
            # Serialize transaction data for signing
            signing_data = self._serialize_for_signing(transaction_data)
            
            # Sign with ECDSA
            sk = SigningKey.from_string(private_key, curve=SECP256k1)
            signature = sk.sign(signing_data)
            
            # Return DER-encoded signature
            return signature.hex()
            
        except Exception as e:
            logger.error(f"Transaction signing failed: {e}")
            raise
    
    def _serialize_for_signing(self, transaction_data: Dict) -> bytes:
        """Serialize transaction data for signing"""
        # This would create the proper serialization format for the blockchain
        # For Bitcoin-like: version, inputs, outputs, locktime
        # For Ethereum-like: nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0
        
        if self.config.address_type == AddressType.ETHEREUM:
            # Ethereum-style serialization
            return self._serialize_eth_transaction(transaction_data)
        else:
            # Bitcoin-style serialization
            return self._serialize_btc_transaction(transaction_data)
    
    def _serialize_eth_transaction(self, tx_data: Dict) -> bytes:
        """Serialize Ethereum transaction"""
        elements = [
            tx_data.get('nonce', 0),
            tx_data.get('gasPrice', 0),
            tx_data.get('gasLimit', 0),
            tx_data.get('to', ''),
            tx_data.get('value', 0),
            tx_data.get('data', b''),
            tx_data.get('chainId', 1),
            0,  # r
            0   # s
        ]
        
        # RLP encoding would go here
        return json.dumps(elements).encode()
    
    def _serialize_btc_transaction(self, tx_data: Dict) -> bytes:
        """Serialize Bitcoin transaction"""
        elements = [
            tx_data.get('version', 1),
            tx_data.get('inputs', []),
            tx_data.get('outputs', []),
            tx_data.get('locktime', 0)
        ]
        
        return json.dumps(elements).encode()
    
    def verify_signature(self, message: bytes, signature: str, public_key: bytes) -> bool:
        """Verify message signature"""
        try:
            vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
            return vk.verify(bytes.fromhex(signature), message)
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def encrypt_data(self, data: bytes, passphrase: Optional[str] = None) -> bytes:
        """Encrypt data with passphrase"""
        if passphrase:
            key = self._derive_encryption_key(passphrase)
        elif self.encryption_key:
            key = self.encryption_key
        else:
            raise ValueError("No encryption key available")
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    
    def decrypt_data(self, encrypted_data: bytes, passphrase: Optional[str] = None) -> bytes:
        """Decrypt data with passphrase"""
        if passphrase:
            key = self._derive_encryption_key(passphrase)
        elif self.encryption_key:
            key = self.encryption_key
        else:
            raise ValueError("No encryption key available")
        
        iv = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def backup(self, backup_path: str, passphrase: Optional[str] = None) -> bool:
        """Backup wallet to file"""
        try:
            config_dict = asdict(self.config)
            config_dict['wallet_type'] = config_dict['wallet_type'].name
            config_dict['key_derivation'] = config_dict['key_derivation'].name
            config_dict['address_type'] = config_dict['address_type'].name
            wallet_data = {
                'wallet_id': self.wallet_id,
                'config': config_dict,
                'master_key': {
                    'private_key': self.master_key.private_key.hex() if self.master_key else None,
                    'public_key': self.master_key.public_key.hex() if self.master_key else None,
                    'chain_code': self.master_key.chain_code.hex() if self.master_key else None
                } if self.master_key else None,
                'addresses': {addr: asdict(info) for addr, info in self.addresses.items()},
                'transactions': {txid: asdict(tx) for txid, tx in self.transactions.items()},
                'state': asdict(self.state)
            }
            
            # Encrypt backup if passphrase provided
            backup_data = json.dumps(wallet_data).encode()
            if passphrase:
                backup_data = self.encrypt_data(backup_data, passphrase)
            
            with open(backup_path, 'wb') as f:
                f.write(backup_data)
            
            logger.info(f"Wallet backed up to {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
    
    def restore(self, backup_path: str, passphrase: Optional[str] = None) -> bool:
        """Restore wallet from backup"""
        try:
            with open(backup_path, 'rb') as f:
                backup_data = f.read()
            
            # Decrypt if encrypted
            if passphrase:
                backup_data = self.decrypt_data(backup_data, passphrase)
            
            wallet_data = json.loads(backup_data.decode())
            
            config_data = wallet_data['config']
            config_data['wallet_type'] = WalletType[config_data['wallet_type']]
            config_data['key_derivation'] = KeyDerivation[config_data['key_derivation']]
            config_data['address_type'] = AddressType[config_data['address_type']]
            
            # Restore wallet state
            self.wallet_id = wallet_data['wallet_id']
            self.config = WalletConfig(**config_data)
            
            if wallet_data['master_key']:
                self.master_key = KeyPair(
                    private_key=bytes.fromhex(wallet_data['master_key']['private_key']),
                    public_key=bytes.fromhex(wallet_data['master_key']['public_key']),
                    chain_code=bytes.fromhex(wallet_data['master_key']['chain_code'])
                )
            
            self.addresses = {
                addr: AddressInfo(**info) 
                for addr, info in wallet_data['addresses'].items()
            }
            
            self.transactions = {
                txid: Transaction(**tx) 
                for txid, tx in wallet_data['transactions'].items()
            }
            
            self.state = WalletState(**wallet_data['state'])
            
            logger.info("Wallet restored successfully")
            return True
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    def export_private_key(self, address: str, passphrase: Optional[str] = None) -> Optional[str]:
        """Export private key for address"""
        try:
            # Find key pair for address
            key_pair = self._find_key_pair_for_address(address)
            if not key_pair:
                return None
            
            # Encrypt private key if passphrase provided
            private_key_bytes = key_pair.private_key
            if passphrase:
                private_key_bytes = self.encrypt_data(private_key_bytes, passphrase)
            
            # Return in WIF format or hex
            return private_key_bytes.hex()
            
        except Exception as e:
            logger.error(f"Private key export failed: {e}")
            return None
    
    def _find_key_pair_for_address(self, address: str) -> Optional[KeyPair]:
        """Find key pair for given address"""
        for info in self.addresses.values():
            if info.address == address:
                # Derive key pair from path
                return self._derive_child_key(self.master_key, info.derivation_path)
        return None
    
    def generate_qr_code(self, address: str, amount: Optional[float] = None, 
                        message: Optional[str] = None) -> Optional[bytes]:
        """Generate QR code for address"""
        try:
            # Create payment request URI
            uri = self._create_payment_uri(address, amount, message)
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Save to bytes
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            return img_bytes.getvalue()
            
        except Exception as e:
            logger.error(f"QR code generation failed: {e}")
            return None
    
    def _create_payment_uri(self, address: str, amount: Optional[float], 
                           message: Optional[str]) -> str:
        """Create payment request URI"""
        if self.config.address_type == AddressType.ETHEREUM:
            # Ethereum URI scheme
            uri = f"ethereum:{address}"
            params = []
            if amount:
                params.append(f"value={amount}")
            if message:
                params.append(f"message={message}")
            if params:
                uri += "?" + "&".join(params)
        else:
            # Bitcoin URI scheme
            uri = f"bitcoin:{address}"
            params = []
            if amount:
                params.append(f"amount={amount}")
            if message:
                params.append(f"message={message}")
            if params:
                uri += "?" + "&".join(params)
        
        return uri
    
    def lock(self):
        """Lock wallet"""
        self.locked = True
        self.lock_time = time.time()
        # Clear sensitive data from memory
        self.master_key = None
        self.key_pairs.clear()
        logger.info("Wallet locked")
    
    def unlock(self, passphrase: str) -> bool:
        """Unlock wallet with passphrase"""
        if self.failed_attempts >= 3:
            lock_time = self.lock_time or 0
            if time.time() - lock_time < 3600:  # 1 hour lock
                raise ValueError("Wallet locked due to too many failed attempts")
        
        try:
            # Derive encryption key to verify passphrase
            test_key = self._derive_encryption_key(passphrase)
            
            # If we have encrypted data, try to decrypt it
            if hasattr(self, '_encrypted_data'):
                self.decrypt_data(self._encrypted_data, passphrase)
            
            self.encryption_key = test_key
            self.locked = False
            self.failed_attempts = 0
            self.lock_time = None
            
            logger.info("Wallet unlocked successfully")
            return True
            
        except Exception as e:
            self.failed_attempts += 1
            if self.failed_attempts >= 3:
                self.lock()
            logger.warning(f"Unlock failed (attempt {self.failed_attempts}): {e}")
            return False
    
    def _get_master_xpub(self) -> str:
        """Get master extended public key"""
        if not self.master_key:
            raise ValueError("Master key not available")
        
        # BIP32 serialization format
        version = b'\x04\x88\xB2\x1E'  # xpub mainnet
        if self.config.network != "mainnet":
            version = b'\x04\x35\x87\xCF'  # tpub testnet
        
        depth = bytes([self.master_key.depth])
        parent_fp = self.master_key.parent_fingerprint
        index = self.master_key.index.to_bytes(4, 'big')
        chain_code = self.master_key.chain_code
        key_data = b'\x00' + self.master_key.public_key  
        # Serialize extended public key
        extended_key = (
            version +
            depth +
            parent_fp +
            index +
            chain_code +
            key_data
        )
        
        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        return base58.b58encode(extended_key + checksum).decode()
    
    def _get_master_xpriv(self) -> str:
        """Get master extended private key"""
        if not self.master_key:
            raise ValueError("Master key not available")
        
        # BIP32 serialization format
        version = b'\x04\x88\xAD\xE4'  # xprv mainnet
        if self.config.network != "mainnet":
            version = b'\x04\x35\x83\x94'  # tprv testnet
        
        depth = bytes([self.master_key.depth])
        parent_fp = self.master_key.parent_fingerprint
        index = self.master_key.index.to_bytes(4, 'big')
        chain_code = self.master_key.chain_code
        key_data = b'\x00' + self.master_key.private_key  # Prepend 0x00 for private keys
        
        # Serialize extended private key
        extended_key = (
            version +
            depth +
            parent_fp +
            index +
            chain_code +
            key_data
        )
        
        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        return base58.b58encode(extended_key + checksum).decode()
    
    def get_account_xpub(self, account_index: int = 0) -> str:
        """Get extended public key for account"""
        if not self.master_key:
            raise ValueError("Master key not available")
        
        # BIP44 derivation: m/44'/0'/{account_index}'
        derivation_path = f"m/44'/0'/{account_index}'"
        account_key = self._derive_child_key(self.master_key, derivation_path)
        
        # Serialize to xpub format
        version = b'\x04\x88\xB2\x1E'  # xpub mainnet
        if self.config.network != "mainnet":
            version = b'\x04\x35\x87\xCF'  # tpub testnet
        
        depth = bytes([account_key.depth])
        parent_fp = self._get_fingerprint(self.master_key.public_key)
        index = account_key.index.to_bytes(4, 'big')
        chain_code = account_key.chain_code
        key_data = b'\x00' + account_key.public_key
        
        extended_key = (
            version +
            depth +
            parent_fp +
            index +
            chain_code +
            key_data
        )
        
        checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        return base58.b58encode(extended_key + checksum).decode()
    
    def create_multisig_wallet(self, cosigners: List[str], required_signatures: int, 
                              address_type: AddressType = AddressType.P2SH) -> Dict:
        """Create multi-signature wallet"""
        if len(cosigners) < 2:
            raise ValueError("Multisig requires at least 2 cosigners")
        if required_signatures > len(cosigners):
            raise ValueError("Required signatures cannot exceed number of cosigners")
        
        # Generate our public key
        our_pubkey = self.master_key.public_key.hex() if self.master_key else self._generate_key_pair().public_key.hex()
        
        multisig_config = {
            'cosigners': cosigners + [our_pubkey],
            'required_signatures': required_signatures,
            'address_type': address_type.name,
            'derivation_path': f"m/45'/{len(cosigners)}/{required_signatures}"
        }
        
        self.multisig_config = multisig_config
        self.cosigners = cosigners
        
        # Generate multisig address
        multisig_address = self._create_multisig_address()
        multisig_config['address'] = multisig_address
        
        logger.info(f"Multisig wallet created: {multisig_address}")
        return multisig_config
    
    def _create_multisig_address(self) -> str:
        """Create multi-signature address"""
        if not self.multisig_config:
            raise ValueError("Multisig configuration not available")
        
        # Get all public keys
        public_keys = []
        for cosigner in self.multisig_config['cosigners']:
            if cosigner == 'ours':
                public_keys.append(self.master_key.public_key if self.master_key else self._generate_key_pair().public_key)
            else:
                # This would typically be other participants' public keys
                public_keys.append(bytes.fromhex(cosigner))
        
        # Sort public keys (for deterministic address)
        public_keys.sort()
        
        # Create redeem script based on address type
        if self.multisig_config['address_type'] == 'P2SH':
            return self._create_p2sh_multisig(public_keys, self.multisig_config['required_signatures'])
        elif self.multisig_config['address_type'] == 'P2WSH':
            return self._create_p2wsh_multisig(public_keys, self.multisig_config['required_signatures'])
        else:
            raise ValueError(f"Unsupported multisig address type: {self.multisig_config['address_type']}")
    
    def _create_p2sh_multisig(self, public_keys: List[bytes], required: int) -> str:
        """Create P2SH multi-signature address"""
        # Create redeem script: OP_{required} {pubkeys} OP_{total} OP_CHECKMULTISIG
        redeem_script = bytes([80 + required])  # OP_{required}
        
        for pubkey in public_keys:
            redeem_script += bytes([len(pubkey)]) + pubkey
        
        redeem_script += bytes([80 + len(public_keys)])  # OP_{total}
        redeem_script += b'\xae'  # OP_CHECKMULTISIG
        
        # Hash redeem script
        script_hash = hashlib.new('ripemd160', hashlib.sha256(redeem_script).digest()).digest()
        
        # Create P2SH address
        prefix = b'\x05' if self.config.network == "mainnet" else b'\xc4'
        payload = prefix + script_hash
        
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()
    
    def _create_p2wsh_multisig(self, public_keys: List[bytes], required: int) -> str:
        """Create P2WSH multi-signature address"""
        # Create witness script (similar to redeem script but for SegWit)
        witness_script = bytes([80 + required])  # OP_{required}
        
        for pubkey in public_keys:
            witness_script += bytes([len(pubkey)]) + pubkey
        
        witness_script += bytes([80 + len(public_keys)])  # OP_{total}
        witness_script += b'\xae'  # OP_CHECKMULTISIG
        
        # SHA256 of witness script
        script_hash = hashlib.sha256(witness_script).digest()
        
        # Bech32 encoding for native SegWit
        hrp = "bc" if self.config.network == "mainnet" else "tb"
        return bech32.encode(hrp, 0, script_hash)
    
    def sign_multisig_transaction(self, transaction_data: Dict, other_signatures: List[str]) -> Dict:
        """Sign multi-signature transaction"""
        if not self.multisig_config:
            raise ValueError("Multisig configuration not available")
        
        # Our signature
        our_signature = self.sign_transaction(transaction_data)
        
        # Combine signatures
        all_signatures = other_signatures + [our_signature]
        
        # Create signing package
        signing_package = {
            'transaction': transaction_data,
            'signatures': all_signatures,
            'required_signatures': self.multisig_config['required_signatures'],
            'redeem_script': self._get_multisig_redeem_script()
        }
        
        return signing_package
    
    def _get_multisig_redeem_script(self) -> str:
        """Get multisig redeem script"""
        # This would generate the redeem script based on the multisig configuration
        # Implementation similar to _create_p2sh_multisig but returning the script
        return "mock_redeem_script_hex"
    
    def integrate_hardware_wallet(self, device_type: str, connection_params: Dict) -> bool:
        """Integrate with hardware wallet"""
        try:
            # Simulate hardware wallet integration
            self.hardware_wallet = {
                'device_type': device_type,
                'connected': True,
                'model': device_type,
                'version': '2.1.0',
                'connection_params': connection_params
            }
            
            # For hardware wallets, we don't have the private keys locally
            self.master_key = None
            self.key_pairs.clear()
            
            logger.info(f"Hardware wallet {device_type} integrated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Hardware wallet integration failed: {e}")
            return False
    
    def sign_with_hardware(self, transaction_data: Dict, derivation_path: str) -> Optional[str]:
        """Sign transaction using hardware wallet"""
        if not self.hardware_wallet or not self.hardware_wallet['connected']:
            raise ValueError("Hardware wallet not connected")
        
        # This would communicate with the actual hardware wallet
        # For simulation, we'll return a mock signature
        try:
            # Simulate hardware signing delay
            time.sleep(0.5)
            
            # Generate deterministic signature based on transaction data
            signing_hash = hashlib.sha256(json.dumps(transaction_data).encode()).digest()
            return f"hardware_sig_{signing_hash.hex()[:16]}"
            
        except Exception as e:
            logger.error(f"Hardware signing failed: {e}")
            return None
    
    def get_hardware_address(self, derivation_path: str) -> Optional[str]:
        """Get address from hardware wallet"""
        if not self.hardware_wallet or not self.hardware_wallet['connected']:
            raise ValueError("Hardware wallet not connected")
        
        # This would get the public key from hardware wallet and derive address
        try:
            # Simulate hardware communication
            time.sleep(0.2)
            
            # Generate deterministic address based on derivation path
            path_hash = hashlib.sha256(derivation_path.encode()).digest()
            address = base58.b58encode(path_hash[:20]).decode()[:34]
            
            return address
            
        except Exception as e:
            logger.error(f"Failed to get address from hardware wallet: {e}")
            return None
    
    def _decode_private_key(self, private_key_str: str) -> bytes:
        """Decode private key from various formats"""
        try:
            # Try hex format
            if len(private_key_str) == 64:
                return bytes.fromhex(private_key_str)
            
            # Try WIF format
            if private_key_str.startswith('5') or private_key_str.startswith('9') or private_key_str.startswith('c'):
                decoded = base58.b58decode(private_key_str)
                # Remove network byte and checksum
                return decoded[1:-4]  # WIF: version byte + key + checksum
            
            # Try mini private key format
            if private_key_str.startswith('S') and len(private_key_str) <= 30:
                # This is a simplified implementation
                return hashlib.sha256(private_key_str.encode()).digest()
            
            raise ValueError("Unknown private key format")
            
        except Exception as e:
            logger.error(f"Private key decoding failed: {e}")
            raise
    
    def _generate_key_pair(self) -> KeyPair:
        """Generate new key pair"""
        private_key = os.urandom(32)
        public_key = self._private_to_public(private_key)
        
        return KeyPair(
            private_key=private_key,
            public_key=public_key
        )
    
    def sweep_private_key(self, private_key: str, destination_address: str, fee_rate: int = 2) -> Optional[str]:
        """Sweep funds from private key to destination address"""
        try:
            # Decode private key
            priv_key_bytes = self._decode_private_key(private_key)
            
            # Create temporary key pair
            temp_key_pair = KeyPair(
                private_key=priv_key_bytes,
                public_key=self._private_to_public(priv_key_bytes)
            )
            
            # Get address from private key
            source_address = self._derive_address(temp_key_pair.public_key, 0, False)
            
            # Get balance (this would query blockchain)
            balance = 1000000  # Simulated balance
            
            if balance <= 0:
                raise ValueError("No funds to sweep")
            
            # Create sweep transaction
            transaction_data = {
                'inputs': [{'address': source_address, 'amount': balance}],
                'outputs': [{'address': destination_address, 'amount': balance - fee_rate}],
                'fee': fee_rate
            }
            
            # Sign with the private key
            signature = self.sign_transaction(transaction_data, priv_key_bytes)
            
            # Broadcast transaction (simulated)
            txid = f"sweep_{hashlib.sha256(signature.encode()).hexdigest()[:16]}"
            
            logger.info(f"Sweep transaction created: {txid}")
            return txid
            
        except Exception as e:
            logger.error(f"Sweep failed: {e}")
            return None
    
    def estimate_fee(self, tx_size: int, fee_rate: str = "medium") -> int:
        """Estimate transaction fee"""
        rate = self.config.transaction_fees.get(fee_rate, 2)
        return tx_size * rate
    
    def get_transaction_history(self, limit: int = 50, offset: int = 0) -> List[Transaction]:
        """Get transaction history"""
        transactions = list(self.transactions.values())
        transactions.sort(key=lambda x: x.timestamp, reverse=True)
        return transactions[offset:offset + limit]
    
    def add_transaction(self, transaction: Transaction):
        """Add transaction to wallet"""
        self.transactions[transaction.txid] = transaction
        
        # Update address balances
        if transaction.direction == "received":
            if transaction.to_address in self.addresses:
                self.addresses[transaction.to_address].balance += transaction.amount
                self.addresses[transaction.to_address].received += transaction.amount
                self.addresses[transaction.to_address].tx_count += 1
                self.addresses[transaction.to_address].is_used = True
        else:  # sent
            if transaction.from_address in self.addresses:
                self.addresses[transaction.from_address].balance -= transaction.amount
                self.addresses[transaction.from_address].sent += transaction.amount
                self.addresses[transaction.from_address].tx_count += 1
                self.addresses[transaction.from_address].is_used = True
        
        # Update wallet state
        self.state.tx_count += 1
        self.state.last_updated = time.time()
        
        if transaction.direction == "received":
            self.state.total_received += transaction.amount
        else:
            self.state.total_sent += transaction.amount
    
    def rescan_blockchain(self, start_height: int = 0, end_height: Optional[int] = None):
        """Rescan blockchain for transactions"""
        # This would typically connect to a blockchain node and scan blocks
        # For simulation, we'll just log the action
        logger.info(f"Rescanning blockchain from height {start_height} to {end_height}")
        
        # Simulate finding some transactions
        fake_transaction = Transaction(
            txid=f"rescan_tx_{int(time.time())}",
            amount=100000,
            fee=100,
            confirmations=10,
            timestamp=int(time.time()) - 3600,
            block_height=1000,
            from_address="unknown",
            to_address=list(self.addresses.keys())[0] if self.addresses else "new_address",
            status="confirmed",
            direction="received"
        )
        
        self.add_transaction(fake_transaction)
    
    def close(self):
        """Close wallet and cleanup"""
        self.running = False
        if self.background_thread:
            self.background_thread.join(timeout=5)
        
        # Clear sensitive data from memory
        self.master_key = None
        self.key_pairs.clear()
        self.encryption_key = None
        
        logger.info("Wallet closed successfully")

# Utility functions
def create_new_wallet(wallet_type: WalletType = WalletType.HD, **kwargs) -> AdvancedWallet:
    """Create a new wallet"""
    config = WalletConfig(wallet_type=wallet_type, **kwargs)
    wallet = AdvancedWallet(config)
    
    if wallet_type == WalletType.HD:
        mnemonic_phrase, xpub = wallet.create_hd_wallet()
        return wallet, mnemonic_phrase, xpub
    else:
        wallet.create_from_private_key(os.urandom(32).hex(), wallet_type)
        return wallet, None, None

def load_existing_wallet(wallet_file: str, passphrase: Optional[str] = None) -> Optional[AdvancedWallet]:
    """Load existing wallet from file"""
    try:
        wallet = AdvancedWallet()
        if wallet.restore(wallet_file, passphrase):
            return wallet
        return None
    except Exception as e:
        logger.error(f"Failed to load wallet: {e}")
        return None

def validate_address(address: str, address_type: Optional[AddressType] = None) -> bool:
    """Validate cryptocurrency address"""
    try:
        if address.startswith('1') or address.startswith('3') or address.startswith('m') or address.startswith('n'):
            # Bitcoin-style address
            decoded = base58.b58decode(address)
            if len(decoded) < 5:
                return False
            
            # Verify checksum
            payload = decoded[:-4]
            checksum = decoded[-4:]
            computed_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            return checksum == computed_checksum
        
        elif address.startswith('bc1') or address.startswith('tb1'):
            # Bech32 address
            hrp, data = bech32.decode(address)
            return hrp in ['bc', 'tb'] and data is not None
        
        elif address.startswith('0x') and len(address) == 42:
            # Ethereum address
            return all(c in '0123456789abcdefABCDEF' for c in address[2:])
        
        return False
        
    except Exception:
        return False

def generate_mnemonic_phrase(strength: int = 256) -> str:
    """Generate BIP39 mnemonic phrase"""
    wallet = AdvancedWallet()
    return wallet._generate_mnemonic(strength)

def get_address_type(address: str) -> Optional[AddressType]:
    """Detect address type"""
    if address.startswith('1'):
        return AddressType.P2PKH
    elif address.startswith('3'):
        return AddressType.P2SH
    elif address.startswith('bc1') or address.startswith('tb1'):
        return AddressType.BECH32
    elif address.startswith('0x'):
        return AddressType.ETHEREUM
    else:
        return None

# Example usage
if __name__ == "__main__":
    # Create a new HD wallet
    wallet, mnemonic, xpub = create_new_wallet()
    print(f"Mnemonic: {mnemonic}")
    print(f"Master xpub: {xpub}")
    
    # Derive addresses
    for i in range(5):
        address_info = wallet.derive_address(i)
        print(f"Address {i}: {address_info.address}")
    
    # Get balance
    balance = wallet.get_balance()
    print(f"Wallet balance: {balance.total}")
    
    # Create transaction
    tx_data = {
        'to': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        'amount': 10000,
        'fee': 100
    }
    
    signature = wallet.sign_transaction(tx_data)
    print(f"Transaction signature: {signature[:20]}...")
    
    # Backup wallet
    wallet.backup("wallet_backup.dat", "secure_passphrase")
    
    # Close wallet
    wallet.close()        