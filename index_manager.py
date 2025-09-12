# index_manager.py
import plyvel
import pickle
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
import threading

@dataclass
class IndexConfig:
    name: str
    key_extractor: Callable[[Any], Any]
    unique: bool = False

class IndexManager:
    def __init__(self, db: plyvel.DB):
        # Accept an existing database connection instead of creating a new one
        self.db = db
        self.indices: Dict[str, IndexConfig] = {}
        self.lock = threading.RLock()
        
        # Load existing indices
        self._load_indices()
    
    def _load_indices(self):
        """Load existing indices from database"""
        try:
            # Iterate through index configurations
            for key, value in self.db.iterator(prefix=b'index_config_'):
                index_name = key.decode().replace('index_config_', '')
                config_data = pickle.loads(value)
                
                # Recreate the key extractor function
                # Note: This is a simplified approach - in production you'd need
                # a better way to serialize/deserialize functions
                if config_data['key_extractor'] == 'lambda b: b[\'index\']':
                    key_extractor = lambda b: b['index']
                elif config_data['key_extractor'] == 'lambda b: b[\'hash\']':
                    key_extractor = lambda b: b['hash']
                elif config_data['key_extractor'] == 'lambda b: b[\'timestamp\']':
                    key_extractor = lambda b: b['timestamp']
                elif config_data['key_extractor'] == 'lambda tx: tx[\'hash\']':
                    key_extractor = lambda tx: tx['hash']
                elif config_data['key_extractor'] == 'lambda tx: tx[\'from\']':
                    key_extractor = lambda tx: tx['from']
                elif config_data['key_extractor'] == 'lambda tx: tx[\'to\']':
                    key_extractor = lambda tx: tx['to']
                else:
                    # Default fallback
                    key_extractor = lambda x: str(x)
                
                self.indices[index_name] = IndexConfig(
                    index_name, key_extractor, config_data['unique']
                )
        except Exception as e:
            print(f"Warning: Could not load indices: {e}")
    
    def create_index(self, name: str, key_extractor: Callable[[Any], Any], unique: bool = False):
        """Create a new index"""
        with self.lock:
            if name in self.indices:
                return  # Index already exists
            
            self.indices[name] = IndexConfig(name, key_extractor, unique)
            
            # Store index configuration
            config_data = pickle.dumps({
                'key_extractor': str(key_extractor),  # Simplified representation
                'unique': unique
            })
            self.db.put(f'index_config_{name}'.encode(), config_data)
    
    def btree_index(self, name: str, key_extractor: Callable[[Any], Any], unique: bool = False):
        """Create a B-tree index (alias for create_index)"""
        return self.create_index(name, key_extractor, unique)
    
    def add_to_index(self, name: str, value: Any, data: Any):
        """Add data to an index"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            index_config = self.indices[name]
            key = index_config.key_extractor(value)
            
            if not isinstance(key, (str, bytes, int, float)):
                key = str(key)
            
            if isinstance(key, str):
                key = key.encode()
            
            # Use prefixed iterator for this index
            index_prefix = f'index_{name}_'.encode()
            
            # Store the data
            if index_config.unique:
                # For unique indexes, store directly
                self.db.put(index_prefix + key, pickle.dumps(data))
            else:
                # For non-unique indexes, store as a list
                existing = self.db.get(index_prefix + key)
                if existing:
                    items = pickle.loads(existing)
                    items.append(data)
                    self.db.put(index_prefix + key, pickle.dumps(items))
                else:
                    self.db.put(index_prefix + key, pickle.dumps([data]))
    
    def get_from_index(self, name: str, key: Any) -> Optional[Any]:
        """Get data from an index"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            if not isinstance(key, (str, bytes, int, float)):
                key = str(key)
            
            if isinstance(key, str):
                key = key.encode()
            
            index_prefix = f'index_{name}_'.encode()
            data = self.db.get(index_prefix + key)
            
            if data:
                index_config = self.indices[name]
                if index_config.unique:
                    return pickle.loads(data)
                else:
                    return pickle.loads(data)
            return None
    
    def remove_from_index(self, name: str, key: Any, data: Any = None):
        """Remove data from an index"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            if not isinstance(key, (str, bytes, int, float)):
                key = str(key)
            
            if isinstance(key, str):
                key = key.encode()
            
            index_prefix = f'index_{name}_'.encode()
            index_config = self.indices[name]
            
            if index_config.unique:
                self.db.delete(index_prefix + key)
            else:
                existing = self.db.get(index_prefix + key)
                if existing:
                    items = pickle.loads(existing)
                    if data:
                        items = [item for item in items if item != data]
                    else:
                        items = []
                    
                    if items:
                        self.db.put(index_prefix + key, pickle.dumps(items))
                    else:
                        self.db.delete(index_prefix + key)
    
    def query_index(self, name: str, query_func: Optional[Callable[[Any], bool]] = None) -> List[Any]:
        """Query index with optional filter function"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            results = []
            index_prefix = f'index_{name}_'.encode()
            
            for key, value in self.db.iterator(prefix=index_prefix):
                data = pickle.loads(value)
                index_config = self.indices[name]
                
                if index_config.unique:
                    if query_func is None or query_func(data):
                        results.append(data)
                else:
                    for item in data:
                        if query_func is None or query_func(item):
                            results.append(item)
            
            return results
    
    def get_index_keys(self, name: str) -> List[Any]:
        """Get all keys in an index"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            keys = []
            index_prefix = f'index_{name}_'.encode()
            
            for key, _ in self.db.iterator(prefix=index_prefix):
                # Remove the prefix to get the actual key
                actual_key = key[len(index_prefix):].decode()
                keys.append(actual_key)
            
            return keys
    
    def drop_index(self, name: str):
        """Remove an index completely"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            # Delete all index data
            index_prefix = f'index_{name}_'.encode()
            for key, _ in self.db.iterator(prefix=index_prefix):
                self.db.delete(key)
            
            # Remove index configuration
            self.db.delete(f'index_config_{name}'.encode())
            del self.indices[name]
    
    def rebuild_index(self, name: str, data_provider: Callable[[], List[Any]]):
        """Rebuild an index from scratch"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            # Clear existing index data
            index_prefix = f'index_{name}_'.encode()
            for key, _ in self.db.iterator(prefix=index_prefix):
                self.db.delete(key)
            
            # Rebuild index
            index_config = self.indices[name]
            all_data = data_provider()
            
            for item in all_data:
                self.add_to_index(name, item, item)
    
    def close(self):
        """Close the database connection"""
        # Don't close the DB here since it's shared
        pass
    
    def __del__(self):
        """Destructor"""
        self.close()