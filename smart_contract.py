# smart_contract.py
import hashlib
import json
import re
import time
import pickle
import ast
import inspect
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from enum import Enum, auto
from dataclasses import dataclass, field
import leveldb
import threading
from concurrent.futures import ThreadPoolExecutor
import gas
import sys
import traceback
from collections import defaultdict

class ContractType(Enum):
    """Types of smart contracts"""
    ERC20 = auto()
    ERC721 = auto()
    ERC1155 = auto()
    GOVERNANCE = auto()
    DEX = auto()
    LENDING = auto()
    CUSTOM = auto()

class ContractState(Enum):
    """Contract lifecycle states"""
    ACTIVE = auto()
    PAUSED = auto()
    DESTROYED = auto()
    UPGRADING = auto()

class ExecutionResult:
    """Result of contract execution"""
    def __init__(self, success: bool, return_value: Any = None, gas_used: int = 0,
                 error: Optional[str] = None, events: List[Dict] = None):
        self.success = success
        self.return_value = return_value
        self.gas_used = gas_used
        self.error = error
        self.events = events or []
    
    def to_dict(self) -> Dict:
        return {
            'success': self.success,
            'return_value': self.return_value,
            'gas_used': self.gas_used,
            'error': self.error,
            'events': self.events
        }

@dataclass
class ContractStorage:
    """Contract storage with access control"""
    storage: Dict[str, Any] = field(default_factory=dict)
    allowed_writers: Set[str] = field(default_factory=set)  # Addresses that can write
    
    def get(self, key: str) -> Any:
        return self.storage.get(key)
    
    def set(self, key: str, value: Any, caller: str) -> bool:
        if caller in self.allowed_writers:
            self.storage[key] = value
            return True
        return False
    
    def to_dict(self) -> Dict:
        return {
            'storage': self.storage,
            'allowed_writers': list(self.allowed_writers)
        }

class SmartContract:
    """Complete smart contract implementation with advanced features"""
    
    def __init__(self, contract_address: str, creator: str, bytecode: str, 
                 contract_type: ContractType = ContractType.CUSTOM):
        self.contract_address = contract_address
        self.creator = creator
        self.bytecode = bytecode
        self.contract_type = contract_type
        self.balance = 0
        self.state = ContractState.ACTIVE
        self.created_at = time.time()
        self.last_executed = time.time()
        self.execution_count = 0
        self.gas_used_total = 0
        
        # Storage with access control
        self.storage = ContractStorage()
        self.storage.allowed_writers.add(creator)
        
        # Function signatures and implementations
        self.functions: Dict[str, Callable] = {}
        self.function_signatures: Dict[str, List[str]] = {}  # function_name -> param_types
        
        # Events and logging
        self.events: List[Dict] = []
        self.event_signatures: Dict[str, List[str]] = {}  # event_name -> param_types
        
        # Access control
        self.owners: Set[str] = {creator}
        self.admins: Set[str] = {creator}
        self.blacklisted: Set[str] = set()
        
        # Gas tracking
        self.gas_limit = 1000000
        self.gas_price = 1
        
        # Initialize from bytecode
        self._initialize_contract()
    
    def _initialize_contract(self):
        """Initialize contract from bytecode"""
        try:
            # Parse bytecode to extract functions and storage
            contract_data = json.loads(self.bytecode)
            
            if 'functions' in contract_data:
                self._load_functions(contract_data['functions'])
            
            if 'storage' in contract_data:
                self.storage.storage.update(contract_data['storage'])
            
            if 'config' in contract_data:
                self._load_config(contract_data['config'])
                
        except (json.JSONDecodeError, TypeError):
            # Raw bytecode - try to parse as Python-like code
            self._parse_raw_bytecode(self.bytecode)
    
    def _load_functions(self, functions_data: Dict):
        """Load function definitions"""
        for func_name, func_def in functions_data.items():
            if 'code' in func_def:
                # Create function from code
                try:
                    func = self._create_function_from_code(func_name, func_def['code'], 
                                                         func_def.get('params', []))
                    self.functions[func_name] = func
                    self.function_signatures[func_name] = func_def.get('params', [])
                except Exception as e:
                    print(f"Error loading function {func_name}: {e}")
    
    def _create_function_from_code(self, func_name: str, code: str, params: List[str]) -> Callable:
        """Dynamically create function from code string"""
        # Security: Validate and sanitize code
        if not self._validate_code_security(code):
            raise ValueError("Code validation failed")
        
        # Create function dynamically
        func_globals = {'__builtins__': self._get_safe_builtins()}
        func_locals = {}
        
        function_def = f"""
def {func_name}({', '.join(params)}):
    {code}
"""
        exec(function_def, func_globals, func_locals)
        
        return func_locals[func_name]
    
    def _validate_code_security(self, code: str) -> bool:
        """Validate code for security constraints"""
        # Disallowed patterns
        disallowed_patterns = [
            r'import\s+',
            r'__.*__',
            r'exec\s*\(',
            r'eval\s*\(',
            r'open\s*\(',
            r'file\s*\(',
            r'subprocess',
            r'os\.',
            r'sys\.',
            r'importlib'
        ]
        
        for pattern in disallowed_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return False
        
        # Check for attempted access to dangerous attributes
        try:
            ast.parse(code)
        except SyntaxError:
            return False
        
        return True
    
    def _get_safe_builtins(self) -> Dict[str, Any]:
        """Get safe subset of builtins"""
        safe_builtins = {
            'abs': abs, 'all': all, 'any': any, 'bool': bool, 'chr': chr,
            'dict': dict, 'divmod': divmod, 'enumerate': enumerate, 'filter': filter,
            'float': float, 'int': int, 'len': len, 'list': list, 'map': map,
            'max': max, 'min': min, 'ord': ord, 'pow': pow, 'range': range,
            'round': round, 'set': set, 'sorted': sorted, 'str': str, 'sum': sum,
            'tuple': tuple, 'zip': zip, ' isinstance': isinstance, 'type': type
        }
        return safe_builtins
    
    def _load_config(self, config: Dict):
        """Load contract configuration"""
        if 'owners' in config:
            self.owners = set(config['owners'])
        if 'admins' in config:
            self.admins = set(config['admins'])
        if 'gas_limit' in config:
            self.gas_limit = config['gas_limit']
        if 'gas_price' in config:
            self.gas_price = config['gas_price']
    
    def _parse_raw_bytecode(self, bytecode: str):
        """Parse raw bytecode string"""
        # Simple function detection for demonstration
        lines = bytecode.split('\n')
        current_function = None
        current_code = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('function '):
                if current_function:
                    self._add_function(current_function, current_code)
                current_function = line.replace('function ', '').split('(')[0].strip()
                current_code = []
            elif current_function and line and not line.startswith('//'):
                current_code.append(line)
        
        if current_function:
            self._add_function(current_function, current_code)
    
    def _add_function(self, func_decl: str, code_lines: List[str]):
        """Add function from declaration and code"""
        try:
            # Extract function name and parameters
            if '(' in func_decl and ')' in func_decl:
                func_name = func_decl.split('(')[0].strip()
                params_str = func_decl.split('(')[1].split(')')[0].strip()
                params = [p.strip() for p in params_str.split(',')] if params_str else []
                
                code = '\n'.join(code_lines)
                func = self._create_function_from_code(func_name, code, params)
                self.functions[func_name] = func
                self.function_signatures[func_name] = params
        except Exception as e:
            print(f"Error adding function {func_decl}: {e}")
    
    def execute_function(self, function_name: str, args: List[Any], 
                        caller: str, value: int = 0, gas_limit: int = None) -> ExecutionResult:
        """
        Execute a contract function
        
        Args:
            function_name: Name of function to execute
            args: List of arguments
            caller: Address of caller
            value: Value sent with call
            gas_limit: Gas limit for execution
        
        Returns:
            ExecutionResult with outcome
        """
        if self.state != ContractState.ACTIVE:
            return ExecutionResult(False, error="Contract not active")
        
        if caller in self.blacklisted:
            return ExecutionResult(False, error="Caller blacklisted")
        
        if function_name not in self.functions:
            return ExecutionResult(False, error=f"Function {function_name} not found")
        
        # Check function signature
        expected_params = self.function_signatures.get(function_name, [])
        if len(args) != len(expected_params):
            return ExecutionResult(False, error=f"Argument count mismatch")
        
        # Add value to contract balance
        self.balance += value
        
        # Setup execution environment
        gas_limit = gas_limit or self.gas_limit
        gas_meter = gas.GasMeter(gas_limit, self.gas_price)
        
        try:
            # Prepare execution context
            context = {
                'caller': caller,
                'value': value,
                'contract_address': self.contract_address,
                'balance': self.balance,
                'gas_meter': gas_meter,
                'storage': self.storage,
                'emit_event': self._create_emit_function(caller),
                'self': self  # For internal calls
            }
            
            # Bind function to context
            bound_function = self._bind_function_to_context(self.functions[function_name], context)
            
            # Execute function
            start_time = time.time()
            return_value = bound_function(*args)
            execution_time = time.time() - start_time
            
            # Update stats
            self.last_executed = time.time()
            self.execution_count += 1
            self.gas_used_total += gas_meter.gas_used
            
            # Create events from execution
            events = self._capture_events(context)
            
            return ExecutionResult(
                success=True,
                return_value=return_value,
                gas_used=gas_meter.gas_used,
                events=events
            )
            
        except gas.OutOfGasError:
            return ExecutionResult(False, gas_used=gas_limit, error="Out of gas")
        except Exception as e:
            return ExecutionResult(False, gas_used=gas_meter.gas_used, 
                                 error=f"Execution error: {str(e)}")
    
    def _bind_function_to_context(self, func: Callable, context: Dict) -> Callable:
        """Bind function to execution context"""
        def bound_function(*args, **kwargs):
            # Set context variables
            for key, value in context.items():
                setattr(func, key, value)
            
            return func(*args, **kwargs)
        
        return bound_function
    
    def _create_emit_function(self, caller: str) -> Callable:
        """Create event emission function"""
        def emit_event(event_name: str, **kwargs):
            event = {
                'event': event_name,
                'contract': self.contract_address,
                'caller': caller,
                'timestamp': time.time(),
                'data': kwargs
            }
            self.events.append(event)
            return event
        
        return emit_event
    
    def _capture_events(self, context: Dict) -> List[Dict]:
        """Capture events emitted during execution"""
        # Events are already stored in self.events, return recent ones
        return self.events[-10:]  # Return last 10 events
    
    def call_function(self, function_name: str, args: List[Any], 
                     caller: str) -> ExecutionResult:
        """Call function without modifying state (view function)"""
        # Create a copy for safe execution
        contract_copy = self._create_snapshot()
        result = contract_copy.execute_function(function_name, args, caller, 0)
        return result
    
    def _create_snapshot(self) -> 'SmartContract':
        """Create a snapshot of the contract for safe execution"""
        # Simple deep copy for demonstration
        import copy
        return copy.deepcopy(self)
    
    def upgrade_contract(self, new_bytecode: str, upgrador: str) -> bool:
        """Upgrade contract bytecode"""
        if upgrador not in self.owners:
            return False
        
        self.state = ContractState.UPGRADING
        
        try:
            old_functions = self.functions.copy()
            old_storage = self.storage.storage.copy()
            
            self.bytecode = new_bytecode
            self.functions.clear()
            self.function_signatures.clear()
            
            self._initialize_contract()
            
            # Preserve storage and important functions
            self.storage.storage.update(old_storage)
            
            # Keep fallback functions if they exist
            for func_name in ['fallback', 'receive']:
                if func_name in old_functions:
                    self.functions[func_name] = old_functions[func_name]
            
            self.state = ContractState.ACTIVE
            return True
            
        except Exception as e:
            # Revert on error
            self.functions = old_functions
            self.storage.storage = old_storage
            self.state = ContractState.ACTIVE
            return False
    
    def destroy_contract(self, destroyer: str) -> bool:
        """Destroy contract and return remaining balance"""
        if destroyer not in self.owners:
            return False
        
        self.state = ContractState.DESTROYED
        # In real implementation, would transfer balance to destroyer
        return True
    
    def add_owner(self, new_owner: str, adder: str) -> bool:
        """Add new contract owner"""
        if adder not in self.owners:
            return False
        
        self.owners.add(new_owner)
        return True
    
    def add_admin(self, new_admin: str, adder: str) -> bool:
        """Add new contract admin"""
        if adder not in self.owners:
            return False
        
        self.admins.add(new_admin)
        self.storage.allowed_writers.add(new_admin)
        return True
    
    def blacklist_address(self, address: str, blacklister: str) -> bool:
        """Blacklist address from interacting with contract"""
        if blacklister not in self.admins:
            return False
        
        self.blacklisted.add(address)
        return True
    
    def get_storage(self, key: str, reader: str) -> Any:
        """Read from contract storage"""
        # For demonstration, allow anyone to read
        return self.storage.get(key)
    
    def set_storage(self, key: str, value: Any, setter: str) -> bool:
        """Write to contract storage"""
        return self.storage.set(key, value, setter)
    
    def get_events(self, event_name: str = None, limit: int = 100) -> List[Dict]:
        """Get contract events with optional filtering"""
        events = self.events[-limit:] if limit else self.events
        
        if event_name:
            events = [e for e in events if e['event'] == event_name]
        
        return events
    
    def to_dict(self) -> Dict:
        """Convert contract to dictionary for storage"""
        return {
            'contract_address': self.contract_address,
            'creator': self.creator,
            'bytecode': self.bytecode,
            'contract_type': self.contract_type.name,
            'balance': self.balance,
            'state': self.state.name,
            'created_at': self.created_at,
            'last_executed': self.last_executed,
            'execution_count': self.execution_count,
            'gas_used_total': self.gas_used_total,
            'storage': self.storage.to_dict(),
            'owners': list(self.owners),
            'admins': list(self.admins),
            'blacklisted': list(self.blacklisted),
            'gas_limit': self.gas_limit,
            'gas_price': self.gas_price,
            'events': self.events[-1000:]  # Store last 1000 events
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'SmartContract':
        """Create contract from dictionary"""
        contract = cls(
            data['contract_address'],
            data['creator'],
            data['bytecode'],
            ContractType[data['contract_type']]
        )
        
        contract.balance = data['balance']
        contract.state = ContractState[data['state']]
        contract.created_at = data['created_at']
        contract.last_executed = data['last_executed']
        contract.execution_count = data['execution_count']
        contract.gas_used_total = data['gas_used_total']
        
        # Load storage
        storage_data = data['storage']
        contract.storage.storage = storage_data['storage']
        contract.storage.allowed_writers = set(storage_data['allowed_writers'])
        
        # Load access control
        contract.owners = set(data['owners'])
        contract.admins = set(data['admins'])
        contract.blacklisted = set(data['blacklisted'])
        
        contract.gas_limit = data['gas_limit']
        contract.gas_price = data['gas_price']
        contract.events = data['events']
        
        # Reinitialize functions from bytecode
        contract._initialize_contract()
        
        return contract

class ContractManager:
    """Manager for smart contracts with persistence and advanced features"""
    
    def __init__(self, db_path: str = './contract_db'):
        self.contracts: Dict[str, SmartContract] = {}
        self.contract_index: Dict[str, List[str]] = defaultdict(list)  # creator -> contract_addresses
        self.type_index: Dict[ContractType, List[str]] = defaultdict(list)
        
        self.db = leveldb.LevelDB(db_path)
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        self._load_contracts()
    
    def _load_contracts(self):
        """Load contracts from database"""
        try:
            contracts_data = pickle.loads(self.db.Get(b'contracts'))
            self.contracts = {addr: SmartContract.from_dict(data) 
                             for addr, data in contracts_data.items()}
            
            # Rebuild indexes
            for address, contract in self.contracts.items():
                self.contract_index[contract.creator].append(address)
                self.type_index[contract.contract_type].append(address)
                
        except KeyError:
            # Fresh database
            pass
    
    def _save_contracts(self):
        """Save contracts to database"""
        with self.lock:
            contracts_data = {addr: contract.to_dict() 
                             for addr, contract in self.contracts.items()}
            self.db.Put(b'contracts', pickle.dumps(contracts_data))
    
    def deploy_contract(self, creator: str, bytecode: str, 
                       contract_type: ContractType = ContractType.CUSTOM,
                       initial_balance: int = 0) -> str:
        """
        Deploy a new smart contract
        
        Args:
            creator: Address of contract creator
            bytecode: Contract bytecode
            contract_type: Type of contract
            initial_balance: Initial balance to fund contract
        
        Returns:
            Contract address
        """
        with self.lock:
            # Generate contract address
            contract_address = self._generate_contract_address(creator, bytecode)
            
            if contract_address in self.contracts:
                raise ValueError("Contract already deployed")
            
            # Create contract
            contract = SmartContract(contract_address, creator, bytecode, contract_type)
            contract.balance = initial_balance
            
            # Store contract
            self.contracts[contract_address] = contract
            self.contract_index[creator].append(contract_address)
            self.type_index[contract_type].append(contract_address)
            
            self._save_contracts()
            
            return contract_address
    
    def _generate_contract_address(self, creator: str, bytecode: str) -> str:
        """Generate deterministic contract address"""
        unique_data = f"{creator}{bytecode}{len(self.contracts)}"
        hash_result = hashlib.sha256(unique_data.encode()).hexdigest()
        return f"0x{hash_result[:40]}"
    
    def execute_contract(self, contract_address: str, function_name: str,
                        args: List[Any], caller: str, value: int = 0) -> ExecutionResult:
        """
        Execute a contract function
        
        Args:
            contract_address: Address of contract
            function_name: Name of function to execute
            args: Function arguments
            caller: Address of caller
            value: Value to send with call
        
        Returns:
            Execution result
        """
        if contract_address not in self.contracts:
            return ExecutionResult(False, error="Contract not found")
        
        contract = self.contracts[contract_address]
        result = contract.execute_function(function_name, args, caller, value)
        
        if result.success:
            self._save_contracts()
        
        return result
    
    def call_contract(self, contract_address: str, function_name: str,
                     args: List[Any], caller: str) -> ExecutionResult:
        """Call contract function without state changes"""
        if contract_address not in self.contracts:
            return ExecutionResult(False, error="Contract not found")
        
        contract = self.contracts[contract_address]
        return contract.call_function(function_name, args, caller)
    
    def get_contract(self, contract_address: str) -> Optional[SmartContract]:
        """Get contract by address"""
        return self.contracts.get(contract_address)
    
    def get_contracts_by_creator(self, creator: str) -> List[SmartContract]:
        """Get all contracts created by an address"""
        addresses = self.contract_index.get(creator, [])
        return [self.contracts[addr] for addr in addresses if addr in self.contracts]
    
    def get_contracts_by_type(self, contract_type: ContractType) -> List[SmartContract]:
        """Get all contracts of specific type"""
        addresses = self.type_index.get(contract_type, [])
        return [self.contracts[addr] for addr in addresses if addr in self.contracts]
    
    def upgrade_contract(self, contract_address: str, new_bytecode: str, upgrador: str) -> bool:
        """Upgrade a contract"""
        if contract_address not in self.contracts:
            return False
        
        contract = self.contracts[contract_address]
        success = contract.upgrade_contract(new_bytecode, upgrador)
        
        if success:
            self._save_contracts()
        
        return success
    
    def destroy_contract(self, contract_address: str, destroyer: str) -> bool:
        """Destroy a contract"""
        if contract_address not in self.contracts:
            return False
        
        contract = self.contracts[contract_address]
        success = contract.destroy_contract(destroyer)
        
        if success:
            # Remove from indexes
            self.contract_index[contract.creator].remove(contract_address)
            self.type_index[contract.contract_type].remove(contract_address)
            del self.contracts[contract_address]
            
            self._save_contracts()
        
        return success
    
    def get_contract_balance(self, contract_address: str) -> int:
        """Get contract balance"""
        if contract_address not in self.contracts:
            return 0
        return self.contracts[contract_address].balance
    
    def transfer_to_contract(self, contract_address: str, from_address: str, 
                           amount: int) -> bool:
        """Transfer funds to contract"""
        if contract_address not in self.contracts:
            return False
        
        # In real implementation, would check sender balance first
        self.contracts[contract_address].balance += amount
        self._save_contracts()
        return True
    
    def get_contract_events(self, contract_address: str, event_name: str = None, 
                          limit: int = 100) -> List[Dict]:
        """Get events from contract"""
        if contract_address not in self.contracts:
            return []
        
        return self.contracts[contract_address].get_events(event_name, limit)
    
    def batch_execute(self, executions: List[Tuple[str, str, List, str, int]]) -> List[ExecutionResult]:
        """Execute multiple contract calls in batch"""
        results = []
        for contract_address, function_name, args, caller, value in executions:
            result = self.execute_contract(contract_address, function_name, args, caller, value)
            results.append(result)
        return results

# Standard contract templates
class StandardContracts:
    """Standard contract implementations"""
    
    @staticmethod
    def create_erc20_template(name: str, symbol: str, initial_supply: int) -> str:
        """Create ERC20 token contract template"""
        return json.dumps({
            'type': 'ERC20',
            'config': {
                'name': name,
                'symbol': symbol,
                'decimals': 18,
                'total_supply': initial_supply
            },
            'functions': {
                'transfer': {
                    'params': ['to', 'amount'],
                    'code': f"""
    if amount <= self.storage.get('balances', {{}}).get('caller', 0):
        balances = self.storage.get('balances', {{}})
        balances['caller'] = balances.get('caller', 0) - amount
        balances[to] = balances.get(to, 0) + amount
        self.storage.set('balances', balances, 'caller')
        self.emit_event('Transfer', from_addr='caller', to_addr=to, amount=amount)
        return True
    return False
    """
                },
                'balanceOf': {
                    'params': ['owner'],
                    'code': "return self.storage.get('balances', {}).get(owner, 0)"
                }
            },
            'storage': {
                'balances': {'creator': initial_supply},
                'allowed': {}
            }
        })
    
    @staticmethod
    def create_erc721_template(name: str, symbol: str) -> str:
        """Create ERC721 NFT contract template"""
        return json.dumps({
            'type': 'ERC721',
            'config': {
                'name': name,
                'symbol': symbol
            },
            'functions': {
                'mint': {
                    'params': ['to', 'token_id'],
                    'code': f"""
    owners = self.storage.get('owners', {{}})
    if token_id in owners:
        return False
    owners[token_id] = to
    self.storage.set('owners', owners, 'caller')
    self.emit_event('Transfer', from_addr='0x0', to_addr=to, token_id=token_id)
    return True
    """
                },
                'ownerOf': {
                    'params': ['token_id'],
                    'code': "return self.storage.get('owners', {}).get(token_id, '0x0')"
                }
            },
            'storage': {
                'owners': {},
                'approvals': {}
            }
        })

# Gas metering system
class GasMeter:
    """Gas metering for contract execution"""
    
    def __init__(self, gas_limit: int, gas_price: int):
        self.gas_limit = gas_limit
        self.gas_price = gas_price
        self.gas_used = 0
        self.opcode_costs = {
            'STORAGE_READ': 100,
            'STORAGE_WRITE': 500,
            'COMPUTATION': 10,
            'EVENT_EMIT': 100,
            'CONTRACT_CALL': 700
        }
    
    def use_gas(self, amount: int, opcode: str = 'COMPUTATION'):
        """Use gas for operation"""
        self.gas_used += amount
        if self.gas_used > self.gas_limit:
            raise OutOfGasError(f"Out of gas: {self.gas_used}/{self.gas_limit}")
    
    def get_gas_cost(self, opcode: str) -> int:
        """Get gas cost for opcode"""
        return self.opcode_costs.get(opcode, 10)

class OutOfGasError(Exception):
    """Exception for out of gas conditions"""
    pass

# Example usage
if __name__ == "__main__":
    # Test contract system
    manager = ContractManager()
    
    # Deploy ERC20 contract
    erc20_bytecode = StandardContracts.create_erc20_template("TestToken", "TEST", 1000000)
    contract_address = manager.deploy_contract("creator_address", erc20_bytecode, ContractType.ERC20)
    
    print(f"Contract deployed at: {contract_address}")
    
    # Execute contract function
    result = manager.execute_contract(
        contract_address, 
        "transfer", 
        ["recipient_address", 100], 
        "caller_address"
    )
    
    print(f"Transfer result: {result.success}")
    print(f"Gas used: {result.gas_used}")
    
    # Call view function
    balance_result = manager.call_contract(
        contract_address,
        "balanceOf",
        ["creator_address"],
        "caller_address"
    )
    
    print(f"Creator balance: {balance_result.return_value}")