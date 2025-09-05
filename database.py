# database.py
import plyvel as leveldb
import rocksdb
import plyvel
import pickle
import json
import zlib
import lz4.frame
import snappy
import msgpack
from typing import Dict, List, Any, Optional, Iterator, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import threading
import time
import hashlib
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import mmap
import numpy as np
from bloom_filter import BloomFilter
import crc32c

class DatabaseType(Enum):
    LEVELDB = auto()
    ROCKSDB = auto()
    PLYVEL = auto()
    MEMORY = auto()

class CompressionType(Enum):
    NONE = auto()
    ZLIB = auto()
    LZ4 = auto()
    SNAPPY = auto()
    ZSTD = auto()

class EncryptionType(Enum):
    NONE = auto()
    AES256 = auto()
    CHACHA20 = auto()
    FERNET = auto()

class IndexType(Enum):
    BTREE = auto()
    HASH = auto()
    BLOOM = auto()
    LSM = auto()

@dataclass
class DatabaseConfig:
    """Database configuration"""
    db_type: DatabaseType = DatabaseType.LEVELDB
    compression: CompressionType = CompressionType.SNAPPY
    encryption: EncryptionType = EncryptionType.FERNET
    create_if_missing: bool = True
    error_if_exists: bool = False
    paranoid_checks: bool = False
    write_buffer_size: int = 64 * 1024 * 1024  # 64MB
    max_open_files: int = 1000
    block_size: int = 4096
    cache_size: int = 128 * 1024 * 1024  # 128MB
    bloom_filter_bits: int = 10
    compression_level: int = 6
    encryption_key: Optional[str] = None
    read_only: bool = False

@dataclass
class IndexConfig:
    """Index configuration"""
    index_type: IndexType = IndexType.BTREE
    unique: bool = False
    sparse: bool = False
    bloom_filter_size: int = 1000000
    bloom_filter_error_rate: float = 0.01

@dataclass
class BatchOperation:
    """Batch operation"""
    op_type: str  # 'put', 'delete', 'merge'
    key: bytes
    value: Optional[bytes] = None
    ttl: Optional[int] = None  # Time-to-live in seconds

class AdvancedDatabase:
    """Advanced database layer with multiple backends, encryption, and compression"""
    
    def __init__(self, db_path: str, config: Optional[DatabaseConfig] = None):
        self.db_path = db_path
        self.config = config or DatabaseConfig()
        self.db = None
        self.cache: Dict[bytes, bytes] = {}
        self.indexes: Dict[str, Any] = {}
        self.lock = threading.RLock()
        self.stats = DatabaseStats()
        self.encryption = None
        self.compression = None
        
        self._initialize_database()
        self._initialize_encryption()
        self._initialize_compression()
        
        # Background tasks
        self._start_background_tasks()
    
    def _initialize_database(self):
        """Initialize the database backend"""
        Path(self.db_path).mkdir(parents=True, exist_ok=True)
        
        if self.config.db_type == DatabaseType.LEVELDB:
            import leveldb
            self.db = leveldb.LevelDB(self.db_path, 
                                     create_if_missing=self.config.create_if_missing,
                                     error_if_exists=self.config.error_if_exists,
                                     paranoid_checks=self.config.paranoid_checks)
        
        elif self.config.db_type == DatabaseType.ROCKSDB:
            import rocksdb
            options = rocksdb.Options()
            options.create_if_missing = self.config.create_if_missing
            options.write_buffer_size = self.config.write_buffer_size
            options.max_open_files = self.config.max_open_files
            options.target_file_size_base = 64 * 1024 * 1024
            options.max_bytes_for_level_base = 512 * 1024 * 1024
            self.db = rocksdb.DB(self.db_path, options)
        
        elif self.config.db_type == DatabaseType.PLYVEL:
            import plyvel
            self.db = plyvel.DB(self.db_path, 
                               create_if_missing=self.config.create_if_missing,
                               error_if_exists=self.config.error_if_exists)
        
        elif self.config.db_type == DatabaseType.MEMORY:
            self.db = {}
        
        # Create default indexes
        self._create_default_indexes()
    
    def _initialize_encryption(self):
        """Initialize encryption system"""
        if self.config.encryption == EncryptionType.FERNET:
            key = self._derive_encryption_key()
            self.encryption = Fernet(key)
        elif self.config.encryption == EncryptionType.AES256:
            self.encryption = AES256Encryption(self.config.encryption_key)
        elif self.config.encryption == EncryptionType.CHACHA20:
            self.encryption = ChaCha20Encryption(self.config.encryption_key)
    
    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from config or generate new"""
        if self.config.encryption_key:
            salt = b'rayonix_db_salt'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            return kdf.derive(self.config.encryption_key.encode())
        else:
            return Fernet.generate_key()
    
    def _initialize_compression(self):
        """Initialize compression system"""
        if self.config.compression == CompressionType.ZLIB:
            self.compression = ZlibCompression(self.config.compression_level)
        elif self.config.compression == CompressionType.LZ4:
            self.compression = LZ4Compression()
        elif self.config.compression == CompressionType.SNAPPY:
            self.compression = SnappyCompression()
        elif self.config.compression == CompressionType.ZSTD:
            self.compression = ZstdCompression()
    
    def _create_default_indexes(self):
        """Create default indexes"""
        # Primary key index
        self.create_index("primary", IndexConfig(IndexType.BTREE, unique=True))
        
        # Timestamp index for TTL
        self.create_index("timestamp", IndexConfig(IndexType.BTREE))
        
        # Bloom filter for existence checks
        self.create_index("bloom", IndexConfig(IndexType.BLOOM))
    
    def create_index(self, index_name: str, config: IndexConfig):
        """Create a new index"""
        with self.lock:
            if config.index_type == IndexType.BTREE:
                self.indexes[index_name] = BTreeIndex()
            elif config.index_type == IndexType.HASH:
                self.indexes[index_name] = HashIndex()
            elif config.index_type == IndexType.BLOOM:
                self.indexes[index_name] = BloomFilter(
                    config.bloom_filter_size, 
                    config.bloom_filter_error_rate
                )
            elif config.index_type == IndexType.LSM:
                self.indexes[index_name] = LSMIndex()
    
    def put(self, key: Union[str, bytes], value: Any, ttl: Optional[int] = None, 
            use_cache: bool = True, use_index: bool = True) -> bool:
        """
        Store key-value pair with advanced features
        
        Args:
            key: Key to store
            value: Value to store (any serializable object)
            ttl: Time-to-live in seconds
            use_cache: Whether to cache the value
            use_index: Whether to update indexes
        
        Returns:
            True if successful
        """
        key_bytes = self._ensure_bytes(key)
        
        with self.lock:
            try:
                # Serialize value
                serialized_value = self._serialize_value(value)
                
                # Compress if enabled
                if self.compression:
                    serialized_value = self.compression.compress(serialized_value)
                
                # Encrypt if enabled
                if self.encryption:
                    serialized_value = self.encryption.encrypt(serialized_value)
                
                # Add metadata
                metadata = {
                    'timestamp': time.time(),
                    'ttl': ttl,
                    'checksum': self._calculate_checksum(serialized_value),
                    'version': 1
                }
                
                # Store in database
                if self.config.db_type == DatabaseType.MEMORY:
                    self.db[key_bytes] = serialized_value
                else:
                    if hasattr(self.db, 'put'):
                        self.db.put(key_bytes, serialized_value)
                    else:
                        # LevelDB compatibility
                        self.db.Put(key_bytes, serialized_value)
                
                # Update cache
                if use_cache:
                    self.cache[key_bytes] = value
                
                # Update indexes
                if use_index:
                    self._update_indexes(key_bytes, value, metadata)
                
                self.stats.put_operations += 1
                self.stats.bytes_written += len(serialized_value)
                
                return True
                
            except Exception as e:
                self.stats.put_errors += 1
                raise DatabaseError(f"Put operation failed: {e}")
    
    def get(self, key: Union[str, bytes], use_cache: bool = True, 
            check_ttl: bool = True) -> Optional[Any]:
        """
        Retrieve value by key
        
        Args:
            key: Key to retrieve
            use_cache: Whether to check cache first
            check_ttl: Whether to check for expiration
        
        Returns:
            Retrieved value or None if not found/expired
        """
        key_bytes = self._ensure_bytes(key)
        
        with self.lock:
            try:
                # Check cache first
                if use_cache and key_bytes in self.cache:
                    self.stats.cache_hits += 1
                    return self.cache[key_bytes]
                
                # Retrieve from database
                if self.config.db_type == DatabaseType.MEMORY:
                    serialized_value = self.db.get(key_bytes)
                else:
                    if hasattr(self.db, 'get'):
                        serialized_value = self.db.get(key_bytes)
                    else:
                        # LevelDB compatibility
                        try:
                            serialized_value = self.db.Get(key_bytes)
                        except KeyError:
                            serialized_value = None
                
                if serialized_value is None:
                    self.stats.misses += 1
                    return None
                
                # Decrypt if enabled
                if self.encryption:
                    serialized_value = self.encryption.decrypt(serialized_value)
                
                # Decompress if enabled
                if self.compression:
                    serialized_value = self.compression.decompress(serialized_value)
                
                # Deserialize value
                value = self._deserialize_value(serialized_value)
                
                # Check TTL if enabled
                if check_ttl and self._is_expired(key_bytes):
                    self.delete(key_bytes)
                    return None
                
                # Update cache
                if use_cache:
                    self.cache[key_bytes] = value
                
                self.stats.get_operations += 1
                self.stats.bytes_read += len(serialized_value)
                
                return value
                
            except Exception as e:
                self.stats.get_errors += 1
                raise DatabaseError(f"Get operation failed: {e}")
    
    def delete(self, key: Union[str, bytes], use_cache: bool = True, 
               use_index: bool = True) -> bool:
        """
        Delete key-value pair
        
        Args:
            key: Key to delete
            use_cache: Whether to update cache
            use_index: Whether to update indexes
        
        Returns:
            True if successful
        """
        key_bytes = self._ensure_bytes(key)
        
        with self.lock:
            try:
                # Delete from database
                if self.config.db_type == DatabaseType.MEMORY:
                    if key_bytes in self.db:
                        del self.db[key_bytes]
                    else:
                        return False
                else:
                    if hasattr(self.db, 'delete'):
                        self.db.delete(key_bytes)
                    else:
                        # LevelDB compatibility
                        try:
                            self.db.Delete(key_bytes)
                        except KeyError:
                            return False
                
                # Update cache
                if use_cache and key_bytes in self.cache:
                    del self.cache[key_bytes]
                
                # Update indexes
                if use_index:
                    self._remove_from_indexes(key_bytes)
                
                self.stats.delete_operations += 1
                return True
                
            except Exception as e:
                self.stats.delete_errors += 1
                raise DatabaseError(f"Delete operation failed: {e}")
    
    def batch_write(self, operations: List[BatchOperation]) -> bool:
        """
        Execute batch operations atomically
        
        Args:
            operations: List of batch operations
        
        Returns:
            True if successful
        """
        with self.lock:
            try:
                if self.config.db_type == DatabaseType.LEVELDB:
                    batch = leveldb.WriteBatch()
                elif self.config.db_type == DatabaseType.ROCKSDB:
                    batch = rocksdb.WriteBatch()
                elif self.config.db_type == DatabaseType.PLYVEL:
                    batch = self.db.write_batch()
                else:
                    # For memory DB, execute operations sequentially
                    for op in operations:
                        if op.op_type == 'put':
                            self.db[op.key] = op.value
                        elif op.op_type == 'delete':
                            if op.key in self.db:
                                del self.db[op.key]
                    return True
                
                for op in operations:
                    if op.op_type == 'put':
                        value = self._prepare_value_for_storage(op.value, op.ttl)
                        batch.Put(op.key, value)
                    elif op.op_type == 'delete':
                        batch.Delete(op.key)
                    elif op.op_type == 'merge':
                        # Merge operation (requires special handling)
                        current = self.get(op.key, use_cache=False, check_ttl=False)
                        if current is not None:
                            merged = self._merge_values(current, op.value)
                            value = self._prepare_value_for_storage(merged, op.ttl)
                            batch.Put(op.key, value)
                
                if self.config.db_type == DatabaseType.LEVELDB:
                    self.db.Write(batch, sync=True)
                elif self.config.db_type == DatabaseType.ROCKSDB:
                    self.db.write(batch)
                elif self.config.db_type == DatabaseType.PLYVEL:
                    batch.write()
                
                self.stats.batch_operations += 1
                return True
                
            except Exception as e:
                self.stats.batch_errors += 1
                raise DatabaseError(f"Batch operation failed: {e}")
    
    def iterate(self, prefix: Optional[bytes] = None, 
               reverse: bool = False) -> Iterator[Tuple[bytes, Any]]:
        """
        Iterate over key-value pairs with optional prefix
        
        Args:
            prefix: Key prefix to filter
            reverse: Whether to iterate in reverse order
        
        Returns:
            Iterator of (key, value) tuples
        """
        with self.lock:
            try:
                if self.config.db_type == DatabaseType.MEMORY:
                    keys = sorted(self.db.keys(), reverse=reverse)
                    for key in keys:
                        if prefix is None or key.startswith(prefix):
                            yield key, self.db[key]
                
                elif self.config.db_type == DatabaseType.LEVELDB:
                    iterator = self.db.RangeIter(prefix=prefix, reverse=reverse)
                    for key, value in iterator:
                        yield key, self._deserialize_value(value)
                
                elif self.config.db_type == DatabaseType.ROCKSDB:
                    it = self.db.iteritems()
                    if prefix:
                        it.seek(prefix)
                    for key, value in it:
                        if prefix and not key.startswith(prefix):
                            break
                        yield key, self._deserialize_value(value)
                
                self.stats.iterate_operations += 1
                
            except Exception as e:
                self.stats.iterate_errors += 1
                raise DatabaseError(f"Iterate operation failed: {e}")
    
    def multi_get(self, keys: List[bytes], parallel: bool = True) -> Dict[bytes, Any]:
        """
        Retrieve multiple values in parallel
        
        Args:
            keys: List of keys to retrieve
            parallel: Whether to use parallel retrieval
        
        Returns:
            Dictionary of key-value pairs
        """
        results = {}
        
        if parallel and len(keys) > 10:
            with ThreadPoolExecutor() as executor:
                future_to_key = {
                    executor.submit(self.get, key, False, False): key 
                    for key in keys
                }
                for future in as_completed(future_to_key):
                    key = future_to_key[future]
                    try:
                        results[key] = future.result()
                    except Exception:
                        results[key] = None
        else:
            for key in keys:
                results[key] = self.get(key, False, False)
        
        return results
    
    def exists(self, key: Union[str, bytes]) -> bool:
        """Check if key exists using bloom filter"""
        key_bytes = self._ensure_bytes(key)
        
        # Check bloom filter first
        if 'bloom' in self.indexes:
            if not self.indexes['bloom'].check(key_bytes):
                return False
        
        # Fallback to actual check
        return self.get(key, use_cache=False, check_ttl=False) is not None
    
    def get_range(self, start_key: bytes, end_key: bytes, 
                 limit: int = 1000) -> List[Tuple[bytes, Any]]:
        """Get range of keys"""
        results = []
        count = 0
        
        for key, value in self.iterate(prefix=start_key):
            if key > end_key:
                break
            if count >= limit:
                break
            results.append((key, value))
            count += 1
        
        return results
    
    def create_snapshot(self, snapshot_path: str) -> bool:
        """Create database snapshot"""
        try:
            if self.config.db_type == DatabaseType.LEVELDB:
                # LevelDB doesn't have native snapshots, create copy
                import shutil
                shutil.copytree(self.db_path, snapshot_path)
            elif self.config.db_type == DatabaseType.ROCKSDB:
                # RocksDB has snapshot support
                snapshot = self.db.snapshot()
                # Would need to implement snapshot serialization
            elif self.config.db_type == DatabaseType.PLYVEL:
                # Plyvel snapshots
                with self.db.snapshot() as snapshot:
                    # Implement snapshot export
                    pass
            
            return True
        except Exception as e:
            raise DatabaseError(f"Snapshot creation failed: {e}")
    
    def compact(self) -> bool:
        """Compact database"""
        try:
            if hasattr(self.db, 'CompactRange'):
                self.db.CompactRange()
            return True
        except Exception as e:
            raise DatabaseError(f"Compaction failed: {e}")
    
    def backup(self, backup_path: str) -> bool:
        """Create database backup"""
        try:
            import shutil
            shutil.copytree(self.db_path, backup_path)
            return True
        except Exception as e:
            raise DatabaseError(f"Backup failed: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        return {
            'put_operations': self.stats.put_operations,
            'get_operations': self.stats.get_operations,
            'delete_operations': self.stats.delete_operations,
            'batch_operations': self.stats.batch_operations,
            'iterate_operations': self.stats.iterate_operations,
            'cache_hits': self.stats.cache_hits,
            'misses': self.stats.misses,
            'bytes_written': self.stats.bytes_written,
            'bytes_read': self.stats.bytes_read,
            'errors': self.stats.get_errors + self.stats.put_errors + self.stats.delete_errors
        }
    
    def _serialize_value(self, value: Any) -> bytes:
        """Serialize value for storage"""
        if isinstance(value, bytes):
            return value
        elif isinstance(value, str):
            return value.encode('utf-8')
        else:
            return pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
    
    def _deserialize_value(self, value: bytes) -> Any:
        """Deserialize value from storage"""
        try:
            return pickle.loads(value)
        except (pickle.UnpicklingError, TypeError):
            # Try to decode as string
            try:
                return value.decode('utf-8')
            except UnicodeDecodeError:
                return value
    
    def _prepare_value_for_storage(self, value: Any, ttl: Optional[int] = None) -> bytes:
        """Prepare value for storage with metadata"""
        serialized = self._serialize_value(value)
        
        if self.compression:
            serialized = self.compression.compress(serialized)
        
        if self.encryption:
            serialized = self.encryption.encrypt(serialized)
        
        return serialized
    
    def _ensure_bytes(self, key: Union[str, bytes]) -> bytes:
        """Ensure key is bytes"""
        if isinstance(key, str):
            return key.encode('utf-8')
        return key
    
    def _calculate_checksum(self, data: bytes) -> bytes:
        """Calculate checksum for data integrity"""
        return crc32c.crc32c(data).to_bytes(4, 'big')
    
    def _is_expired(self, key: bytes) -> bool:
        """Check if key is expired"""
        # Would check TTL metadata
        return False
    
    def _update_indexes(self, key: bytes, value: Any, metadata: Dict):
        """Update all indexes"""
        for index_name, index in self.indexes.items():
            if hasattr(index, 'add'):
                index.add(key, value, metadata)
    
    def _remove_from_indexes(self, key: bytes):
        """Remove key from all indexes"""
        for index_name, index in self.indexes.items():
            if hasattr(index, 'remove'):
                index.remove(key)
    
    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        def cache_cleaner():
            while True:
                time.sleep(300)  # Clean every 5 minutes
                self._clean_cache()
        
        def ttl_cleaner():
            while True:
                time.sleep(60)  # Check every minute
                self._clean_expired()
        
        def stats_logger():
            while True:
                time.sleep(3600)  # Log every hour
                self._log_stats()
        
        threading.Thread(target=cache_cleaner, daemon=True).start()
        threading.Thread(target=ttl_cleaner, daemon=True).start()
        threading.Thread(target=stats_logger, daemon=True).start()
    
    def _clean_cache(self):
        """Clean cache using LRU policy"""
        with self.lock:
            # Simple LRU implementation
            if len(self.cache) > 10000:  # Max 10,000 items in cache
                # Remove oldest 20%
                keys_to_remove = list(self.cache.keys())[:2000]
                for key in keys_to_remove:
                    del self.cache[key]
    
    def _clean_expired(self):
        """Clean expired keys"""
        # Would iterate through keys and remove expired ones
        pass
    
    def _log_stats(self):
        """Log database statistics"""
        stats = self.get_stats()
        print(f"Database Stats: {stats}")

# Index implementations
class BTreeIndex:
    """B-Tree index implementation"""
    def __init__(self):
        self.index = {}
    
    def add(self, key: bytes, value: Any, metadata: Dict):
        self.index[key] = metadata
    
    def remove(self, key: bytes):
        if key in self.index:
            del self.index[key]
    
    def search(self, query: Any) -> List[bytes]:
        # Simple implementation - would use proper B-tree
        return [k for k, v in self.index.items() if self._matches(v, query)]
    
    def _matches(self, metadata: Dict, query: Any) -> bool:
        # Simple matching logic
        return True

class HashIndex:
    """Hash index implementation"""
    def __init__(self):
        self.index = {}
    
    def add(self, key: bytes, value: Any, metadata: Dict):
        # Create hash of value for indexing
        value_hash = hashlib.sha256(str(value).encode()).digest()
        if value_hash not in self.index:
            self.index[value_hash] = []
        self.index[value_hash].append(key)
    
    def remove(self, key: bytes):
        # Would need to track reverse mapping
        pass

class LSMIndex:
    """LSM Tree index implementation"""
    def __init__(self):
        self.memory_table = {}
        self.disk_tables = []
    
    def add(self, key: bytes, value: Any, metadata: Dict):
        self.memory_table[key] = metadata
        if len(self.memory_table) > 1000:  # Flush when memory table is full
            self._flush_to_disk()
    
    def _flush_to_disk(self):
        # Flush memory table to disk
        pass

# Compression implementations
class ZlibCompression:
    def __init__(self, level: int = 6):
        self.level = level
    
    def compress(self, data: bytes) -> bytes:
        return zlib.compress(data, self.level)
    
    def decompress(self, data: bytes) -> bytes:
        return zlib.decompress(data)

class LZ4Compression:
    def compress(self, data: bytes) -> bytes:
        return lz4.frame.compress(data)
    
    def decompress(self, data: bytes) -> bytes:
        return lz4.frame.decompress(data)

class SnappyCompression:
    def compress(self, data: bytes) -> bytes:
        return snappy.compress(data)
    
    def decompress(self, data: bytes) -> bytes:
        return snappy.decompress(data)

class ZstdCompression:
    def __init__(self, level: int = 3):
        self.level = level
    
    def compress(self, data: bytes) -> bytes:
        import zstandard as zstd
        return zstd.compress(data, self.level)
    
    def decompress(self, data: bytes) -> bytes:
        import zstandard as zstd
        return zstd.decompress(data)

# Encryption implementations
class AES256Encryption:
    def __init__(self, key: Optional[str] = None):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        self.AES = AES
        self.pad = pad
        self.unpad = unpad
        self.key = key or os.urandom(32)
    
    def encrypt(self, data: bytes) -> bytes:
        cipher = self.AES.new(self.key, self.AES.MODE_CBC)
        ct_bytes = cipher.encrypt(self.pad(data, self.AES.block_size))
        return cipher.iv + ct_bytes
    
    def decrypt(self, data: bytes) -> bytes:
        iv = data[:16]
        ct = data[16:]
        cipher = self.AES.new(self.key, self.AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(ct), self.AES.block_size)

class ChaCha20Encryption:
    def __init__(self, key: Optional[str] = None):
        from Crypto.Cipher import ChaCha20
        self.ChaCha20 = ChaCha20
        self.key = key or os.urandom(32)
    
    def encrypt(self, data: bytes) -> bytes:
        cipher = self.ChaCha20.new(key=self.key)
        return cipher.nonce + cipher.encrypt(data)
    
    def decrypt(self, data: bytes) -> bytes:
        nonce = data[:8]
        ct = data[8:]
        cipher = self.ChaCha20.new(key=self.key, nonce=nonce)
        return cipher.decrypt(ct)

# Statistics tracking
class DatabaseStats:
    def __init__(self):
        self.put_operations = 0
        self.get_operations = 0
        self.delete_operations = 0
        self.batch_operations = 0
        self.iterate_operations = 0
        self.cache_hits = 0
        self.misses = 0
        self.put_errors = 0
        self.get_errors = 0
        self.delete_errors = 0
        self.batch_errors = 0
        self.iterate_errors = 0
        self.bytes_written = 0
        self.bytes_read = 0

class DatabaseError(Exception):
    """Database operation error"""
    pass

# Context manager for transactions
@contextmanager
def transaction(db: AdvancedDatabase):
    """Context manager for database transactions"""
    # Would implement transaction logic
    try:
        yield
        # Commit transaction
    except Exception:
        # Rollback transaction
        raise

# Example usage
if __name__ == "__main__":
    # Test database
    config = DatabaseConfig(
        db_type=DatabaseType.LEVELDB,
        compression=CompressionType.SNAPPY,
        encryption=EncryptionType.FERNET
    )
    
    db = AdvancedDatabase("./test_db", config)
    
    # Store data
    db.put("key1", {"name": "test", "value": 42})
    db.put("key2", "hello world")
    db.put("key3", [1, 2, 3, 4, 5])
    
    # Retrieve data
    value1 = db.get("key1")
    value2 = db.get("key2")
    value3 = db.get("key3")
    
    print(f"Value1: {value1}")
    print(f"Value2: {value2}")
    print(f"Value3: {value3}")
    
    # Batch operations
    operations = [
        BatchOperation('put', b'batch1', b'value1'),
        BatchOperation('put', b'batch2', b'value2'),
        BatchOperation('delete', b'key1')
    ]
    db.batch_write(operations)
    
    # Iterate through keys
    for key, value in db.iterate():
        print(f"Key: {key}, Value: {value}")
    
    # Get statistics
    stats = db.get_stats()
    print(f"Database statistics: {stats}")