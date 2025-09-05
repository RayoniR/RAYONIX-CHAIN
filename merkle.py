# merkle.py
import hashlib
import json
from typing import List, Dict, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

class MerkleNode:
    """Represents a node in the Merkle tree"""
    def __init__(self, hash_value: str, left: Optional['MerkleNode'] = None, 
                 right: Optional['MerkleNode'] = None, is_leaf: bool = False, index: int = -1):
        self.hash = hash_value
        self.left = left
        self.right = right
        self.is_leaf = is_leaf
        self.depth = 0
        self.index = index
        
        if left and right:
            self.depth = max(left.depth, right.depth) + 1

    def to_dict(self) -> Dict:
        return {
            'hash': self.hash,
            'is_leaf': self.is_leaf,
            'depth': self.depth,
            'index': self.index,
            'left': self.left.to_dict() if self.left else None,
            'right': self.right.to_dict() if self.right else None
        }

class MerkleTree:
    """Complete Merkle tree implementation with advanced features"""
    
    def __init__(self, data_items: List[str], hash_algorithm: str = 'sha256', 
                 double_hash: bool = False, use_encoding: bool = True):
        """
        Initialize Merkle tree with data items
        
        Args:
            data_items: List of data strings to include in the tree
            hash_algorithm: Hash algorithm to use ('sha256', 'sha3_256', 'blake2b')
            double_hash: Whether to apply double hashing for security
            use_encoding: Whether to encode data before hashing
        """
        self.hash_algorithm = hash_algorithm
        self.double_hash = double_hash
        self.use_encoding = use_encoding
        self.leaves: List[MerkleNode] = []
        self.root: Optional[MerkleNode] = None
        self.levels: List[List[MerkleNode]] = []
        self.build_tree(data_items)
        
    def _hash_data(self, data: str) -> str:
        """Hash data using configured algorithm and options"""
        if self.use_encoding:
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        
        if self.hash_algorithm == 'sha256':
            hash_func = hashlib.sha256
        elif self.hash_algorithm == 'sha3_256':
            hash_func = hashlib.sha3_256
        elif self.hash_algorithm == 'blake2b':
            hash_func = hashlib.blake2b
        else:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")
        
        hash_result = hash_func(data_bytes).hexdigest()
        
        if self.double_hash:
            hash_result = hash_func(hash_result.encode('utf-8')).hexdigest()
            
        return hash_result
    
    def _calculate_node_hash(self, left_hash: str, right_hash: str) -> str:
        """Calculate parent node hash from child hashes"""
        combined = left_hash + right_hash
        return self._hash_data(combined)
    
    def build_tree(self, data_items: List[str]):
        """Build the complete Merkle tree from data items"""
        if not data_items:
            self.root = MerkleNode(self._hash_data(""))
            return
            
        # Create leaf nodes
        self.leaves = [
            MerkleNode(self._hash_data(item), is_leaf=True, index=i)
            for i, item in enumerate(data_items)
        ]
        
        current_level = self.leaves.copy()
        self.levels = [current_level]
        
        # Build tree levels until we reach the root
        while len(current_level) > 1:
            next_level = []
            
            # Process nodes in pairs
            for i in range(0, len(current_level), 2):
                left_node = current_level[i]
                right_node = current_level[i + 1] if i + 1 < len(current_level) else left_node
                
                parent_hash = self._calculate_node_hash(left_node.hash, right_node.hash)
                parent_node = MerkleNode(parent_hash, left_node, right_node)
                parent_node.depth = left_node.depth + 1
                parent_node.index = i // 2
                
                next_level.append(parent_node)
            
            self.levels.append(next_level)
            current_level = next_level
        
        self.root = current_level[0] if current_level else None
    
    def get_root_hash(self) -> str:
        """Get the Merkle root hash"""
        return self.root.hash if self.root else ""
    
    def get_proof(self, data_item: str) -> Optional[Dict]:
        """
        Get Merkle proof for a data item
        
        Returns:
            Dictionary containing proof information or None if item not found
        """
        target_hash = self._hash_data(data_item)
        return self.get_proof_by_hash(target_hash)
    
    def get_proof_by_hash(self, target_hash: str) -> Optional[Dict]:
        """Get Merkle proof for a specific hash"""
        # Find the leaf node
        leaf_index = -1
        for i, leaf in enumerate(self.leaves):
            if leaf.hash == target_hash:
                leaf_index = i
                break
        
        if leaf_index == -1:
            return None
        
        proof = {
            'leaf_hash': target_hash,
            'leaf_index': leaf_index,
            'sibling_hashes': [],
            'sibling_positions': [],  # 'left' or 'right'
            'path_indices': [],      # 0 for left, 1 for right at each level
            'tree_depth': len(self.levels) - 1,
            'total_leaves': len(self.leaves),
            'root_hash': self.get_root_hash()
        }
        
        current_index = leaf_index
        current_level = 0
        
        # Traverse up the tree to collect proof
        while current_level < len(self.levels) - 1:
            current_nodes = self.levels[current_level]
            
            # Determine if current node is left or right child
            is_left = current_index % 2 == 0
            sibling_index = current_index + 1 if is_left else current_index - 1
            
            if sibling_index < len(current_nodes):
                sibling_node = current_nodes[sibling_index]
                proof['sibling_hashes'].append(sibling_node.hash)
                proof['sibling_positions'].append('right' if is_left else 'left')
                proof['path_indices'].append(0 if is_left else 1)
            else:
                # Handle odd number of nodes at level
                proof['sibling_hashes'].append(current_nodes[current_index].hash)
                proof['sibling_positions'].append('right' if is_left else 'left')
                proof['path_indices'].append(0 if is_left else 1)
            
            current_index //= 2
            current_level += 1
        
        return proof
    
    def get_proof_by_index(self, leaf_index: int) -> Optional[Dict]:
        """Get Merkle proof for a leaf by its index"""
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            return None
        
        target_hash = self.leaves[leaf_index].hash
        return self.get_proof_by_hash(target_hash)
    
    @staticmethod
    def verify_proof(proof: Dict, target_hash: str, root_hash: str) -> bool:
        """
        Verify a Merkle proof
        
        Args:
            proof: Proof dictionary from get_proof()
            target_hash: Hash of the data item to verify
            root_hash: Expected root hash of the tree
            
        Returns:
            True if proof is valid, False otherwise
        """
        if not proof or 'sibling_hashes' not in proof:
            return False
        
        current_hash = target_hash
        sibling_hashes = proof['sibling_hashes']
        sibling_positions = proof.get('sibling_positions', [])
        path_indices = proof.get('path_indices', [])
        
        # Reconstruct the root hash
        for i, sibling_hash in enumerate(sibling_hashes):
            if i < len(sibling_positions):
                position = sibling_positions[i]
            else:
                # Fallback: assume alternating positions
                position = 'right' if i % 2 == 0 else 'left'
            
            if position == 'right':
                combined = current_hash + sibling_hash
            else:
                combined = sibling_hash + current_hash
            
            # Use same hash algorithm as original tree (simplified - would need to know algorithm)
            current_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        
        return current_hash == root_hash
    
    def verify_leaf(self, data_item: str) -> bool:
        """Verify that a data item is in the tree"""
        proof = self.get_proof(data_item)
        if not proof:
            return False
        return self.verify_proof(proof, self._hash_data(data_item), self.get_root_hash())
    
    def get_leaf_count(self) -> int:
        """Get number of leaf nodes"""
        return len(self.leaves)
    
    def get_tree_depth(self) -> int:
        """Get depth of the tree"""
        return len(self.levels) - 1 if self.levels else 0
    
    def get_level_hashes(self, level: int) -> List[str]:
        """Get all hashes at a specific level"""
        if level < 0 or level >= len(self.levels):
            return []
        return [node.hash for node in self.levels[level]]
    
    def find_leaf_by_hash(self, target_hash: str) -> Optional[int]:
        """Find leaf index by hash, returns index or None if not found"""
        for i, leaf in enumerate(self.leaves):
            if leaf.hash == target_hash:
                return i
        return None
    
    def to_dict(self) -> Dict:
        """Convert tree to dictionary representation"""
        return {
            'root_hash': self.get_root_hash(),
            'hash_algorithm': self.hash_algorithm,
            'double_hash': self.double_hash,
            'use_encoding': self.use_encoding,
            'leaf_count': self.get_leaf_count(),
            'tree_depth': self.get_tree_depth(),
            'levels': [
                [node.hash for node in level]
                for level in self.levels
            ],
            'leaves': [leaf.hash for leaf in self.leaves]
        }
    
    def get_serialized_proof(self, data_item: str) -> Optional[str]:
        """Get proof as serialized JSON string"""
        proof = self.get_proof(data_item)
        if not proof:
            return None
        return json.dumps(proof, indent=2)
    
    @classmethod
    def verify_serialized_proof(cls, serialized_proof: str, target_hash: str, root_hash: str) -> bool:
        """Verify proof from serialized JSON string"""
        try:
            proof = json.loads(serialized_proof)
            return cls.verify_proof(proof, target_hash, root_hash)
        except (json.JSONDecodeError, TypeError):
            return False

class CompactMerkleTree(MerkleTree):
    """Merkle tree with compact representation for storage efficiency"""
    
    def __init__(self, data_items: List[str], **kwargs):
        super().__init__(data_items, **kwargs)
        self._build_compact_representation()
    
    def _build_compact_representation(self):
        """Build compact representation of the tree"""
        self.compact_nodes = {}
        self._traverse_and_store(self.root)
    
    def _traverse_and_store(self, node: MerkleNode, path: str = ""):
        """Recursively traverse tree and store nodes in compact form"""
        if not node:
            return
        
        self.compact_nodes[path] = node.hash
        
        if node.left:
            self._traverse_and_store(node.left, path + "0")
        if node.right:
            self._traverse_and_store(node.right, path + "1")
    
    def get_compact_proof(self, data_item: str) -> Optional[Dict]:
        """Get compact Merkle proof"""
        proof = self.get_proof(data_item)
        if not proof:
            return None
        
        # Convert to compact form
        compact_proof = {
            'leaf_hash': proof['leaf_hash'],
            'leaf_index': proof['leaf_index'],
            'sibling_hashes': proof['sibling_hashes'],
            'bitmask': self._create_bitmask(proof['path_indices']),
            'root_hash': proof['root_hash']
        }
        
        return compact_proof
    
    def _create_bitmask(self, path_indices: List[int]) -> int:
        """Create bitmask from path indices"""
        bitmask = 0
        for i, index in enumerate(path_indices):
            if index == 1:  # right child
                bitmask |= (1 << i)
        return bitmask
    
    @staticmethod
    def verify_compact_proof(compact_proof: Dict, target_hash: str, root_hash: str) -> bool:
        """Verify compact Merkle proof"""
        if not compact_proof or 'sibling_hashes' not in compact_proof:
            return False
        
        sibling_hashes = compact_proof['sibling_hashes']
        bitmask = compact_proof.get('bitmask', 0)
        
        current_hash = target_hash
        for i, sibling_hash in enumerate(sibling_hashes):
            # Determine position from bitmask
            is_right_sibling = (bitmask >> i) & 1 == 0
            
            if is_right_sibling:
                combined = current_hash + sibling_hash
            else:
                combined = sibling_hash + current_hash
            
            current_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        
        return current_hash == root_hash

class SparseMerkleTree:
    """Sparse Merkle tree for efficient updates and proofs"""
    
    def __init__(self, depth: int = 256, default_value: str = "0" * 64):
        """
        Initialize sparse Merkle tree
        
        Args:
            depth: Depth of the tree (determines capacity: 2^depth leaves)
            default_value: Default hash value for empty nodes
        """
        self.depth = depth
        self.default_value = default_value
        self.leaves: Dict[int, str] = {}  # index -> hash
        self.nodes: Dict[str, str] = {}   # path -> hash
        self._initialize_tree()
    
    def _initialize_tree(self):
        """Initialize tree with default values"""
        # Precompute default values for each level
        default_hashes = [self.default_value]
        for i in range(self.depth):
            default_hashes.append(
                hashlib.sha256((default_hashes[-1] + default_hashes[-1]).encode()).hexdigest()
            )
        self.default_hashes = default_hashes
    
    def _get_path(self, index: int) -> str:
        """Get binary path for given index"""
        return bin(index)[2:].zfill(self.depth)
    
    def update_leaf(self, index: int, value: str):
        """Update leaf value and propagate changes"""
        path = self._get_path(index)
        self.leaves[index] = value
        
        # Update the leaf node
        current_hash = value
        self.nodes[path] = current_hash
        
        # Propagate changes up the tree
        for level in range(self.depth - 1, -1, -1):
            sibling_path = path[:level] + ('1' if path[level] == '0' else '0')
            sibling_hash = self.nodes.get(sibling_path, self.default_hashes[self.depth - level - 1])
            
            if path[level] == '0':
                combined = current_hash + sibling_hash
            else:
                combined = sibling_hash + current_hash
            
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
            parent_path = path[:level]
            self.nodes[parent_path] = current_hash
            path = parent_path
    
    def get_root(self) -> str:
        """Get current root hash"""
        return self.nodes.get("", self.default_hashes[-1])
    
    def get_proof(self, index: int) -> Dict:
        """Get inclusion proof for leaf"""
        path = self._get_path(index)
        proof = {
            'leaf_index': index,
            'leaf_hash': self.leaves.get(index, self.default_hashes[0]),
            'sibling_hashes': [],
            'path': path
        }
        
        current_path = path
        for level in range(self.depth - 1, -1, -1):
            sibling_path = current_path[:level] + ('1' if current_path[level] == '0' else '0')
            sibling_hash = self.nodes.get(sibling_path, self.default_hashes[self.depth - level - 1])
            proof['sibling_hashes'].append(sibling_hash)
            current_path = current_path[:level]
        
        proof['root_hash'] = self.get_root()
        return proof
    
    @staticmethod
    def verify_proof(proof: Dict, target_hash: str, root_hash: str) -> bool:
        """Verify sparse Merkle proof"""
        if not proof or 'sibling_hashes' not in proof:
            return False
        
        current_hash = target_hash
        sibling_hashes = proof['sibling_hashes']
        path = proof.get('path', '')
        
        for level, sibling_hash in enumerate(sibling_hashes):
            bit = path[level] if level < len(path) else '0'
            
            if bit == '0':
                combined = current_hash + sibling_hash
            else:
                combined = sibling_hash + current_hash
            
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        return current_hash == root_hash

# Advanced utility functions
def create_merkle_tree_from_file(filename: str, **kwargs) -> MerkleTree:
    """Create Merkle tree from file content"""
    with open(filename, 'r') as f:
        lines = f.readlines()
    data_items = [line.strip() for line in lines if line.strip()]
    return MerkleTree(data_items, **kwargs)

def batch_verify_proofs(proofs: List[Dict], target_hashes: List[str], root_hash: str) -> List[bool]:
    """Batch verify multiple Merkle proofs"""
    results = []
    for proof, target_hash in zip(proofs, target_hashes):
        results.append(MerkleTree.verify_proof(proof, target_hash, root_hash))
    return results

def create_merkle_mountain_range(blocks: List[str], range_size: int = 10) -> List[MerkleTree]:
    """Create Merkle Mountain Range for efficient append operations"""
    trees = []
    current_range = []
    
    for block in blocks:
        current_range.append(block)
        if len(current_range) >= range_size:
            trees.append(MerkleTree(current_range))
            current_range = []
    
    if current_range:
        trees.append(MerkleTree(current_range))
    
    return trees

# Example usage and testing
if __name__ == "__main__":
    # Test basic Merkle tree
    data = ["tx1", "tx2", "tx3", "tx4"]
    tree = MerkleTree(data)
    
    print(f"Root hash: {tree.get_root_hash()}")
    print(f"Tree depth: {tree.get_tree_depth()}")
    print(f"Leaf count: {tree.get_leaf_count()}")
    
    # Test proof generation and verification
    proof = tree.get_proof("tx2")
    if proof:
        print(f"Proof for tx2: {json.dumps(proof, indent=2)}")
        is_valid = tree.verify_proof(proof, tree._hash_data("tx2"), tree.get_root_hash())
        print(f"Proof valid: {is_valid}")
    
    # Test compact tree
    compact_tree = CompactMerkleTree(data)
    compact_proof = compact_tree.get_compact_proof("tx2")
    print(f"Compact proof: {json.dumps(compact_proof, indent=2)}")
    
    # Test sparse tree
    sparse_tree = SparseMerkleTree(depth=8)
    sparse_tree.update_leaf(5, "custom_value_hash")
    sparse_proof = sparse_tree.get_proof(5)
    print(f"Sparse proof: {json.dumps(sparse_proof, indent=2)}")