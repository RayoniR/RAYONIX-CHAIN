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
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.db = plyvel.DB(db_path, create_if_missing=True)
        self.indices: Dict[str, IndexConfig] = {}
        self.lock = threading.RLock()
        
    def create_index(self, name: str, key_extractor: Callable[[Any], Any], unique: bool = False):
        """Create a new index"""
        with self.lock:
            if name in self.indices:
                raise ValueError(f"Index '{name}' already exists")
            
            self.indices[name] = IndexConfig(name, key_extractor, unique)
            
            # Create sub-database for this index
            index_db = self.db.prefixed_db(f'index_{name}_'.encode())
            
            # For now, just store the index configuration
            config_data = pickle.dumps({
                'key_extractor': key_extractor.__name__ if hasattr(key_extractor, '__name__') else str(key_extractor),
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
            
            # Get index database
            index_db = self.db.prefixed_db(f'index_{name}_'.encode())
            
            # Store the data
            if index_config.unique:
                # For unique indexes, store directly
                index_db.put(key, pickle.dumps(data))
            else:
                # For non-unique indexes, store as a list
                existing = index_db.get(key)
                if existing:
                    items = pickle.loads(existing)
                    items.append(data)
                    index_db.put(key, pickle.dumps(items))
                else:
                    index_db.put(key, pickle.dumps([data]))
    
    def get_from_index(self, name: str, key: Any) -> Optional[Any]:
        """Get data from an index"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            if not isinstance(key, (str, bytes, int, float)):
                key = str(key)
            
            if isinstance(key, str):
                key = key.encode()
            
            index_db = self.db.prefixed_db(f'index_{name}_'.encode())
            data = index_db.get(key)
            
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
            
            index_db = self.db.prefixed_db(f'index_{name}_'.encode())
            index_config = self.indices[name]
            
            if index_config.unique:
                index_db.delete(key)
            else:
                existing = index_db.get(key)
                if existing:
                    items = pickle.loads(existing)
                    if data:
                        items = [item for item in items if item != data]
                    else:
                        items = []
                    
                    if items:
                        index_db.put(key, pickle.dumps(items))
                    else:
                        index_db.delete(key)
    
    def query_index(self, name: str, query_func: Optional[Callable[[Any], bool]] = None) -> List[Any]:
        """Query index with optional filter function"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            results = []
            index_db = self.db.prefixed_db(f'index_{name}_'.encode())
            
            for key, value in index_db:
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
            index_db = self.db.prefixed_db(f'index_{name}_'.encode())
            
            for key, _ in index_db:
                keys.append(key.decode())
            
            return keys
    
    def drop_index(self, name: str):
        """Remove an index completely"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            # Delete all index data
            index_db = self.db.prefixed_db(f'index_{name}_'.encode())
            for key, _ in index_db:
                index_db.delete(key)
            
            # Remove index configuration
            self.db.delete(f'index_config_{name}'.encode())
            del self.indices[name]
    
    def rebuild_index(self, name: str, data_provider: Callable[[], List[Any]]):
        """Rebuild an index from scratch"""
        with self.lock:
            if name not in self.indices:
                raise ValueError(f"Index '{name}' does not exist")
            
            # Clear existing index data
            index_db = self.db.prefixed_db(f'index_{name}_'.encode())
            for key, _ in index_db:
                index_db.delete(key)
            
            # Rebuild index
            index_config = self.indices[name]
            all_data = data_provider()
            
            for item in all_data:
                self.add_to_index(name, item, item)
    
    def close(self):
        """Close the database connection"""
        self.db.close()
    
    def __del__(self):
        """Destructor"""
        self.close()