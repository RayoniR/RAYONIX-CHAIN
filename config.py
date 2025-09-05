# config.py
import os
import json
import yaml
import toml
import inspect
from typing import Dict, List, Optional, Any, Union, Type, Callable
import dataclasses
from dataclasses import dataclass, field, asdict, is_dataclass
from enum import Enum, auto
from pathlib import Path
import logging
import threading
import time
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from dotenv import load_dotenv
import jsonschema
from jsonschema import validate, ValidationError
import watchgod

# Configure logging
logger = logging.getLogger("RayonixConfig")

class ConfigFormat(Enum):
    JSON = auto()
    YAML = auto()
    TOML = auto()
    ENV = auto()
    PYTHON = auto()

class ConfigEncryption(Enum):
    NONE = auto()
    FERNET = auto()
    AES256 = auto()
    CHACHA20 = auto()

class ConfigSource(Enum):
    FILE = auto()
    ENVIRONMENT = auto()
    DATABASE = auto()
    CONSUL = auto()
    ETCD = auto()
    AWS_SM = auto()  # AWS Secrets Manager
    HASHICORP_VAULT = auto()

@dataclass
class ConfigMetadata:
    version: str = "1.0.0"
    created: float = field(default_factory=time.time)
    modified: float = field(default_factory=time.time)
    checksum: Optional[str] = None
    source: ConfigSource = ConfigSource.FILE
    format: ConfigFormat = ConfigFormat.YAML
    encrypted: bool = False
    encryption_method: ConfigEncryption = ConfigEncryption.NONE
    signatures: Dict[str, str] = field(default_factory=dict)

@dataclass
class NetworkConfig:
    network_type: str = "mainnet"  # mainnet, testnet, devnet, regtest
    network_id: int = 1
    listen_ip: str = "0.0.0.0"
    listen_port: int = 30303
    public_ip: Optional[str] = None
    public_port: Optional[int] = None
    max_connections: int = 50
    max_peers: int = 1000
    connection_timeout: int = 30
    message_timeout: int = 10
    ping_interval: int = 60
    enable_nat_traversal: bool = True
    enable_encryption: bool = True
    enable_compression: bool = True
    enable_dht: bool = True
    enable_gossip: bool = True
    bootstrap_nodes: List[str] = field(default_factory=lambda: [
        "node1.rayonix.org:30303",
        "node2.rayonix.org:30303",
        "node3.rayonix.org:30303"
    ])
    allowed_peers: List[str] = field(default_factory=list)
    blocked_peers: List[str] = field(default_factory=list)

@dataclass
class ConsensusConfig:
    consensus_type: str = "pos"  # pos, poa, pow, raft, ibft
    block_time: int = 30  # seconds
    block_reward: int = 50
    halving_interval: int = 210000
    difficulty_adjustment_blocks: int = 2016
    min_stake: int = 1000
    max_stake: int = 10000000
    stake_locktime: int = 86400  # 24 hours
    slash_percentage: float = 0.01  # 1% slashing for misbehavior
    jail_duration: int = 3600  # 1 hour jail
    epoch_blocks: int = 100
    max_validators: int = 100
    validator_commission: float = 0.1 
    unbonding_period: int = 172800  # 2 days
    min_delegation: int = 100
    governance_enabled: bool = True
    proposal_deposit: int = 1000
    voting_period: int = 259200  # 3 days

@dataclass
class DatabaseConfig:
    db_type: str = "leveldb"  # leveldb, rocksdb, sqlite, postgresql
    db_path: str = "./rayonix_data"
    compression: str = "snappy"  # none, snappy, zlib, lz4, zstd
    encryption: str = "fernet"  # none, fernet, aes256, chacha20
    cache_size: int = 134217728  # 128MB
    max_open_files: int = 1000
    write_buffer_size: int = 67108864  # 64MB
    bloom_filter_bits: int = 10
    auto_compaction: bool = True
    compaction_interval: int = 3600  # 1 hour
    backup_enabled: bool = True
    backup_interval: int = 86400  # 24 hours
    backup_retention: int = 7  # days
    stats_enabled: bool = True
    stats_interval: int = 300  # 5 minutes

@dataclass
class WalletConfig:
    wallet_type: str = "hd"  # hd, non_hd, multisig, hardware, watch_only
    key_derivation: str = "bip44"  # bip32, bip39, bip44, bip49, bip84
    address_type: str = "bech32"  # p2pkh, p2sh, bech32, p2wpkh, p2wsh
    encryption: bool = True
    compression: bool = True
    passphrase: Optional[str] = None
    account_index: int = 0
    change_index: int = 0
    gap_limit: int = 20
    auto_backup: bool = True
    backup_interval: int = 86400  # 24 hours
    price_alerts: bool = False
    transaction_fees: Dict[str, int] = field(default_factory=lambda: {
        "low": 1, "medium": 2, "high": 5
    })
    multisig_config: Optional[Dict] = None
    hardware_wallet: Optional[Dict] = None

@dataclass
class SmartContractConfig:
    evm_version: str = "istanbul"  # frontier, homestead, byzantium, constantinople, istanbul
    gas_limit: int = 8000000
    gas_price: int = 1
    max_contract_size: int = 24576  # bytes
    enable_optimizer: bool = True
    optimizer_runs: int = 200
    allow_selfdestruct: bool = False
    allow_delegatecall: bool = True
    allow_create2: bool = True
    max_recursion_depth: int = 1024
    contract_timeout: int = 30  # seconds
    enable_debugging: bool = False
    debug_port: int = 8545
    allowed_opcodes: List[str] = field(default_factory=lambda: [
        "STOP", "ADD", "MUL", "SUB", "DIV", "SDIV", "MOD", "SMOD", "ADDMOD", 
        "MULMOD", "EXP", "SIGNEXTEND", "LT", "GT", "SLT", "SGT", "EQ", "ISZERO",
        "AND", "OR", "XOR", "NOT", "BYTE", "SHL", "SHR", "SAR", "SHA3",
        "ADDRESS", "BALANCE", "ORIGIN", "CALLER", "CALLVALUE", "CALLDATALOAD",
        "CALLDATASIZE", "CALLDATACOPY", "CODESIZE", "CODECOPY", "GASPRICE",
        "EXTCODESIZE", "EXTCODECOPY", "RETURNDATASIZE", "RETURNDATACOPY",
        "BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER", "DIFFICULTY", "GASLIMIT",
        "POP", "MLOAD", "MSTORE", "MSTORE8", "SLOAD", "SSTORE", "JUMP", "JUMPI",
        "PC", "MSIZE", "GAS", "JUMPDEST", "PUSH1", "PUSH2", "PUSH32", "DUP1", 
        "DUP16", "SWAP1", "SWAP16", "LOG0", "LOG4", "CREATE", "CALL", "CALLCODE",
        "RETURN", "DELEGATECALL", "CREATE2", "STATICCALL", "REVERT", "INVALID"
    ])

@dataclass
class APIConfig:
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8545
    cors_domains: List[str] = field(default_factory=lambda: ["*"])
    rate_limiting: bool = True
    rate_limit: int = 100  # requests per second
    authentication: bool = False
    auth_tokens: List[str] = field(default_factory=list)
    ssl_enabled: bool = False
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    enable_websockets: bool = True
    websocket_port: int = 8546
    max_connections: int = 100
    request_timeout: int = 30
    enable_metrics: bool = True
    metrics_port: int = 9090
    enable_profiling: bool = False
    profiling_port: int = 6060

@dataclass
class LoggingConfig:
    level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_enabled: bool = True
    file_path: str = "./logs/rayonix.log"
    file_max_size: int = 104857600  # 100MB
    file_backup_count: int = 10
    console_enabled: bool = True
    syslog_enabled: bool = False
    syslog_address: Optional[str] = None
    syslog_facility: str = "local0"
    enable_rotation: bool = True
    rotation_interval: int = 86400  # 24 hours
    compression: bool = True
    json_format: bool = False
    enable_tracing: bool = False
    trace_sample_rate: float = 0.1  # 10% of requests

@dataclass
class MonitoringConfig:
    enabled: bool = True
    prometheus_enabled: bool = True
    prometheus_port: int = 9090
    health_check_interval: int = 30
    metrics_interval: int = 60
    enable_alerting: bool = True
    alert_manager_url: Optional[str] = None
    enable_tracing: bool = False
    tracing_endpoint: Optional[str] = None
    enable_profiling: bool = False
    profiling_interval: int = 300  # 5 minutes
    resource_monitoring: bool = True
    resource_interval: int = 60
    performance_metrics: bool = True
    performance_interval: int = 30
    log_metrics: bool = True
    log_interval: int = 300  # 5 minutes

@dataclass
class SecurityConfig:
    enable_encryption: bool = True
    encryption_algorithm: str = "aes-256-gcm"
    key_derivation_iterations: int = 100000
    enable_ssl: bool = True
    ssl_min_version: str = "TLSv1.2"
    ssl_ciphers: List[str] = field(default_factory=lambda: [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305"
    ])
    enable_firewall: bool = True
    firewall_rules: List[Dict] = field(default_factory=list)
    rate_limiting: bool = True
    rate_limit: int = 1000  # requests per second
    enable_2fa: bool = False
    session_timeout: int = 3600  # 1 hour
    password_policy: Dict = field(default_factory=lambda: {
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special": True,
        "max_age": 90,  # days
        "history": 5  # remember last 5 passwords
    })
    audit_logging: bool = True
    audit_retention: int = 365  # days

@dataclass
class CacheConfig:
    enabled: bool = True
    type: str = "redis"  # redis, memcached, memory
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    database: int = 0
    max_memory: str = "1gb"
    max_memory_policy: str = "allkeys-lru"
    timeout: int = 300  # seconds
    compression: bool = True
    cluster_mode: bool = False
    sentinel_mode: bool = False
    sentinel_master: Optional[str] = None
    sentinel_nodes: List[str] = field(default_factory=list)

@dataclass
class RateLimitConfig:
    enabled: bool = True
    strategy: str = "fixed_window"  # fixed_window, sliding_window, token_bucket
    requests_per_second: int = 100
    burst_capacity: int = 200
    time_window: int = 60  # seconds
    by_ip: bool = True
    by_user: bool = False
    by_endpoint: bool = True
    exclude_ips: List[str] = field(default_factory=list)
    exclude_endpoints: List[str] = field(default_factory=lambda: ["/health", "/metrics"])

@dataclass
class ClusterConfig:
    enabled: bool = False
    mode: str = "standalone"  # standalone, cluster, distributed
    node_id: str = "node-1"
    cluster_size: int = 3
    discovery_method: str = "static"  # static, dns, etcd, consul
    discovery_config: Dict = field(default_factory=dict)
    replication_factor: int = 3
    quorum_size: int = 2
    enable_auto_healing: bool = True
    healing_timeout: int = 30
    enable_load_balancing: bool = True
    load_balancing_algorithm: str = "round_robin"  # round_robin, least_connections, ip_hash

@dataclass
class BackupConfig:
    enabled: bool = True
    strategy: str = "full"  # full, incremental, differential
    interval: int = 86400  # 24 hours
    retention: int = 7  # days
    compression: bool = True
    encryption: bool = True
    storage_type: str = "local"  # local, s3, gcs, azure, ftp
    storage_config: Dict = field(default_factory=dict)
    verify_backups: bool = True
    backup_verification_interval: int = 3600  # 1 hour
    enable_cloud_storage: bool = False
    cloud_provider: str = "aws"  # aws, gcp, azure
    cloud_config: Dict = field(default_factory=dict)

@dataclass
class RayonixConfig:
    # Core configurations
    network: NetworkConfig = field(default_factory=NetworkConfig)
    consensus: ConsensusConfig = field(default_factory=ConsensusConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    wallet: WalletConfig = field(default_factory=WalletConfig)
    smart_contract: SmartContractConfig = field(default_factory=SmartContractConfig)
    
    # API and interfaces
    api: APIConfig = field(default_factory=APIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    
    # Security and performance
    security: SecurityConfig = field(default_factory=SecurityConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    
    # Advanced features
    cluster: ClusterConfig = field(default_factory=ClusterConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    
    # Metadata
    metadata: ConfigMetadata = field(default_factory=ConfigMetadata)
    
    # Dynamic settings
    _overrides: Dict[str, Any] = field(default_factory=dict)
    _validators: Dict[str, Callable] = field(default_factory=dict)
    _watchers: Dict[str, List[Callable]] = field(default_factory=dict)

class ConfigManager:
    """Advanced configuration management system with validation, encryption, and hot-reloading"""
    
    def __init__(self, config_path: Optional[str] = None, 
                 encryption_key: Optional[str] = None,
                 auto_reload: bool = True):
        self.config_path = config_path
        self.encryption_key = encryption_key
        self.auto_reload = auto_reload
        self.config = RayonixConfig()
        self._lock = threading.RLock()
        self._watcher_thread = None
        self._schema = self._load_schema()
        
        if config_path:
            self.load_config(config_path)
        
        if auto_reload:
            self._start_config_watcher()
    
    def _load_schema(self) -> Dict:
        """Load JSON schema for configuration validation"""
        schema_path = Path(__file__).parent / "schemas" / "config_schema.json"
        if schema_path.exists():
            with open(schema_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _validate_config(self, config_data: Dict) -> bool:
        """Validate configuration against schema"""
        if not self._schema:
            return True
        
        try:
            validate(instance=config_data, schema=self._schema)
            return True
        except ValidationError as e:
            logger.error(f"Configuration validation failed: {e}")
            return False
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt configuration data"""
        if not self.encryption_key:
            return data
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.encryption_key.encode()))
        fernet = Fernet(key)
        
        return salt + fernet.encrypt(data)
    
    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt configuration data"""
        if not self.encryption_key:
            return encrypted_data
        
        salt = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.encryption_key.encode()))
        fernet = Fernet(key)
        
        return fernet.decrypt(ciphertext)
    
    def _dataclass_to_dict(self, obj: Any) -> Dict:
        """Convert dataclass to dictionary"""
        if is_dataclass(obj):
            result = {}
            for field in dataclasses.fields(obj):
                value = getattr(obj, field.name)
                result[field.name] = self._dataclass_to_dict(value)
            return result
        elif isinstance(obj, list):
            return [self._dataclass_to_dict(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: self._dataclass_to_dict(v) for k, v in obj.items()}
        else:
            return obj
    
    def _dict_to_dataclass(self, data: Dict, cls: Type) -> Any:
        """Convert dictionary to dataclass"""
        if is_dataclass(cls):
            field_types = {f.name: f.type for f in dataclasses.fields(cls)}
            kwargs = {}
            for field_name, field_type in field_types.items():
                if field_name in data:
                    kwargs[field_name] = self._dict_to_dataclass(data[field_name], field_type)
                else:
                    kwargs[field_name] = None
            return cls(**kwargs)
        elif hasattr(cls, '__origin__') and cls.__origin__ is list:
            return [self._dict_to_dataclass(item, cls.__args__[0]) for item in data]
        elif hasattr(cls, '__origin__') and cls.__origin__ is dict:
            return {k: self._dict_to_dataclass(v, cls.__args__[1]) for k, v in data.items()}
        else:
            return data
    
    def load_config(self, config_path: str, format: Optional[ConfigFormat] = None) -> bool:
        """Load configuration from file"""
        try:
            path = Path(config_path)
            if not path.exists():
                logger.error(f"Configuration file not found: {config_path}")
                return False
            
            # Determine format from extension if not specified
            if format is None:
                ext = path.suffix.lower()
                if ext == '.json':
                    format = ConfigFormat.JSON
                elif ext in ['.yaml', '.yml']:
                    format = ConfigFormat.YAML
                elif ext == '.toml':
                    format = ConfigFormat.TOML
                elif ext == '.py':
                    format = ConfigFormat.PYTHON
                else:
                    format = ConfigFormat.YAML
            
            # Read and parse configuration
            with open(path, 'rb') as f:
                raw_data = f.read()
            
            # Decrypt if encrypted
            if self.config.metadata.encrypted:
                raw_data = self._decrypt_data(raw_data)
            
            # Parse based on format
            if format == ConfigFormat.JSON:
                config_data = json.loads(raw_data.decode())
            elif format == ConfigFormat.YAML:
                config_data = yaml.safe_load(raw_data.decode())
            elif format == ConfigFormat.TOML:
                config_data = toml.loads(raw_data.decode())
            elif format == ConfigFormat.PYTHON:
                # Execute Python file and extract config
                global_vars = {}
                exec(raw_data.decode(), global_vars)
                config_data = global_vars.get('config', {})
            else:
                raise ValueError(f"Unsupported config format: {format}")
            
            # Validate configuration
            if not self._validate_config(config_data):
                return False
            
            # Convert to dataclass
            with self._lock:
                self.config = self._dict_to_dataclass(config_data, RayonixConfig)
                self.config.metadata.modified = time.time()
                self.config.metadata.checksum = hashlib.sha256(raw_data).hexdigest()
                self.config.metadata.format = format
            
            logger.info(f"Configuration loaded from {config_path}")
            self._notify_watchers("config_loaded", config_path)
            return True
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return False
    
    def save_config(self, config_path: str, format: Optional[ConfigFormat] = None) -> bool:
        """Save configuration to file"""
        try:
            path = Path(config_path)
            
            # Determine format from extension if not specified
            if format is None:
                ext = path.suffix.lower()
                if ext == '.json':
                    format = ConfigFormat.JSON
                elif ext in ['.yaml', '.yml']:
                    format = ConfigFormat.YAML
                elif ext == '.toml':
                    format = ConfigFormat.TOML
                elif ext == '.py':
                    format = ConfigFormat.PYTHON
                else:
                    format = ConfigFormat.YAML
            
            # Convert to dictionary
            config_dict = self._dataclass_to_dict(self.config)
            
            # Serialize based on format
            if format == ConfigFormat.JSON:
                output = json.dumps(config_dict, indent=2, ensure_ascii=False)
            elif format == ConfigFormat.YAML:
                output = yaml.dump(config_dict, default_flow_style=False, allow_unicode=True)
            elif format == ConfigFormat.TOML:
                output = toml.dumps(config_dict)
            elif format == ConfigFormat.PYTHON:
                output = f"# RAYONIX Configuration\n# Generated: {time.ctime()}\n\n"
                output += f"config = {json.dumps(config_dict, indent=2, ensure_ascii=False)}"
            else:
                raise ValueError(f"Unsupported config format: {format}")
            
            # Encrypt if enabled
            output_bytes = output.encode()
            if self.config.metadata.encrypted and self.encryption_key:
                output_bytes = self._encrypt_data(output_bytes)
            
            # Write to file
            with open(path, 'wb') as f:
                f.write(output_bytes)
            
            self.config.metadata.modified = time.time()
            self.config.metadata.checksum = hashlib.sha256(output_bytes).hexdigest()
            self.config.metadata.format = format
            
            logger.info(f"Configuration saved to {config_path}")
            self._notify_watchers("config_saved", config_path)
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation key"""
        try:
            parts = key.split('.')
            value = self.config
            
            for part in parts:
                if hasattr(value, part):
                    value = getattr(value, part)
                elif isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return default
            
            return value
        except (AttributeError, KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """Set configuration value by dot notation key"""
        try:
            parts = key.split('.')
            obj = self.config
            
            # Navigate to the parent object
            for part in parts[:-1]:
                if hasattr(obj, part):
                    obj = getattr(obj, part)
                elif isinstance(obj, dict) and part in obj:
                    obj = obj[part]
                else:
                    return False
            
            # Set the value
            final_part = parts[-1]
            if hasattr(obj, final_part):
                setattr(obj, final_part, value)
            elif isinstance(obj, dict):
                obj[final_part] = value
            else:
                return False
            
            self.config.metadata.modified = time.time()
            self._notify_watchers("config_changed", key, value)
            return True
            
        except (AttributeError, KeyError, TypeError) as e:
            logger.error(f"Failed to set configuration value: {e}")
            return False
    
    def register_validator(self, key: str, validator: Callable) -> None:
        """Register validator for configuration key"""
        with self._lock:
            self.config._validators[key] = validator
    
    def register_watcher(self, key: str, callback: Callable) -> None:
        """Register watcher for configuration key changes"""
        with self._lock:
            if key not in self.config._watchers:
                self.config._watchers[key] = []
            self.config._watchers[key].append(callback)
    
    def _notify_watchers(self, event: str, *args) -> None:
        """Notify registered watchers of configuration changes"""
        with self._lock:
            if event in self.config._watchers:
                for callback in self.config._watchers[event]:
                    try:
                        callback(*args)
                    except Exception as e:
                        logger.error(f"Watcher callback failed: {e}")
    
    def _start_config_watcher(self) -> None:
        """Start configuration file watcher for auto-reload"""
        if not self.config_path:
            return
        
        def watch_config():
            for changes in watchgod.watch(self.config_path):
                for change_type, file_path in changes:
                    if change_type == watchgod.Change.modified:
                        logger.info(f"Configuration file modified, reloading...")
                        self.load_config(self.config_path)
        
        self._watcher_thread = threading.Thread(target=watch_config, daemon=True)
        self._watcher_thread.start()
    
    def validate(self) -> List[str]:
        """Validate entire configuration and return errors"""
        errors = []
        
        # Validate network configuration
        if not 1024 <= self.config.network.listen_port <= 65535:
            errors.append("Network port must be between 1024 and 65535")
        
        # Validate consensus configuration
        if self.config.consensus.block_time < 1:
            errors.append("Block time must be at least 1 second")
        
        # Validate database configuration
        if not Path(self.config.database.db_path).parent.exists():
            errors.append("Database path parent directory must exist")
        
        # Run custom validators
        for key, validator in self.config._validators.items():
            try:
                value = self.get(key)
                if not validator(value):
                    errors.append(f"Validation failed for {key}")
            except Exception as e:
                errors.append(f"Validator error for {key}: {e}")
        
        return errors
    
    def to_dict(self) -> Dict:
        """Convert configuration to dictionary"""
        return self._dataclass_to_dict(self.config)
    
    def from_dict(self, config_dict: Dict) -> bool:
        """Load configuration from dictionary"""
        try:
            with self._lock:
                self.config = self._dict_to_dataclass(config_dict, RayonixConfig)
                self.config.metadata.modified = time.time()
            return True
        except Exception as e:
            logger.error(f"Failed to load configuration from dict: {e}")
            return False
    
    def diff(self, other_config: 'ConfigManager') -> Dict:
        """Compare with another configuration and return differences"""
        current_dict = self.to_dict()
        other_dict = other_config.to_dict()
        
        def find_diff(d1, d2, path=""):
            diff = {}
            for key in set(d1.keys()) | set(d2.keys()):
                new_path = f"{path}.{key}" if path else key
                
                if key not in d1:
                    diff[new_path] = {"old": None, "new": d2[key]}
                elif key not in d2:
                    diff[new_path] = {"old": d1[key], "new": None}
                elif d1[key] != d2[key]:
                    if isinstance(d1[key], dict) and isinstance(d2[key], dict):
                        nested_diff = find_diff(d1[key], d2[key], new_path)
                        diff.update(nested_diff)
                    else:
                        diff[new_path] = {"old": d1[key], "new": d2[key]}
            return diff
        
        return find_diff(current_dict, other_dict)

# Global configuration instance
global_config: Optional[ConfigManager] = None

def init_config(config_path: Optional[str] = None, 
               encryption_key: Optional[str] = None,
               auto_reload: bool = True) -> ConfigManager:
    """Initialize global configuration"""
    global global_config
    global_config = ConfigManager(config_path, encryption_key, auto_reload)
    return global_config

def get_config() -> ConfigManager:
    """Get global configuration instance"""
    if global_config is None:
        raise RuntimeError("Configuration not initialized. Call init_config() first.")
    return global_config

# Example usage
if __name__ == "__main__":
    # Initialize configuration
    config = init_config("rayonix.yaml", "secret-encryption-key")
    
    # Access configuration values
    print(f"Network port: {config.get('network.listen_port')}")
    print(f"Block time: {config.get('consensus.block_time')}")
    
    # Modify configuration
    config.set('network.listen_port', 30304)
    config.set('consensus.block_time', 15)
    
    # Save configuration
    config.save_config("config_modified.yaml")
    
    # Validate configuration
    errors = config.validate()
    if errors:
        print(f"Configuration errors: {errors}")
    else:
        print("Configuration is valid!")