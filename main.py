# main.py
import argparse
import asyncio
import json
import sys
import time
import traceback
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import logging
import signal
import threading
from dataclasses import asdict
import readline  # For better input handling

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rayonix_node.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("RayonixNode")

# Import all components
from blockchain import Blockchain, Block, Transaction
from wallet import (
    AdvancedWallet,
    WalletConfig,
    WalletType,
    KeyDerivation,
    AddressType,
    create_new_wallet,
    load_existing_wallet,
    validate_address,
    KeyPair,
    Transaction,
    AddressInfo
)
from p2p_network import AdvancedP2PNetwork, NodeConfig, NetworkType, ProtocolType
from consensus import ProofOfStake, Validator
from smart_contract import ContractManager, SmartContract, StandardContracts
from database import AdvancedDatabase, DatabaseConfig
from utxo import UTXOSet, UTXO
from merkle import MerkleTree
from consensus import ProofOfStake
from config import get_config
self.config_manager = get_config()
self.config = self.config_manager.config

class RayonixNode:
    """Complete RAYONIX blockchain node with all components integrated"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.running = False
        self.shutdown_event = threading.Event()
        
        # Initialize components
        self.blockchain = None
        self.wallet = None
        self.network = None
        self.consensus = None
        self.contract_manager = None
        self.database = None        
        
        # State management
        self.sync_state = {
            'syncing': False,
            'current_block': 0,
            'target_block': 0,
            'peers_connected': 0
        }
        
        # Command history
        self.command_history = []
        self.history_file = Path('.rayonix_history')
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load node configuration"""
        default_config = {
            'network': 'mainnet',
            'data_dir': './rayonix_data',
            'port': 30303,
            'rpc_port': 8545,
            'max_peers': 50,
            'mining_enabled': False,
            'staking_enabled': True,
            'api_enabled': False,
            'log_level': 'INFO',
            'db_type': 'leveldb',
            'compression': 'snappy',
            'encryption': 'fernet'
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                default_config.update(loaded_config)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return default_config
    
    async def initialize(self):
        """Initialize all node components"""
        try:
            logger.info("Initializing RAYONIX Node...")
            
            # Create data directory
            data_dir = Path(self.config['data_dir'])
            data_dir.mkdir(exist_ok=True)
            
            # Initialize database
            db_config = DatabaseConfig(
                db_type=self.config['db_type'],
                compression=self.config['compression'],
                encryption=self.config['encryption']
            )
            self.database = AdvancedDatabase(str(data_dir / 'blockchain_db'), db_config)
            
            # Initialize blockchain
            self.blockchain = Blockchain(str(data_dir / 'blockchain_db'))
            
            # Initialize wallet
            wallet_file = data_dir / 'wallet.json'
            if wallet_file.exists():
                self.wallet = load_existing_wallet()
            else:
                logger.info("No wallet found. Create one with 'create-wallet' command.")
            
            # Initialize consensus
            self.consensus = ProofOfStake(
                min_stake=1000,
                jail_duration=3600,
                slash_percentage=0.01,
                epoch_blocks=100,
                max_validators=100
            )
            
            # Initialize contract manager
            self.contract_manager = ContractManager(str(data_dir / 'contracts_db'))
            
            # Initialize network if enabled
            if self.config.get('network_enabled', True):
                await self._initialize_network()
            
            logger.info("RAYONIX Node initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize node: {e}")
            traceback.print_exc()
            return False
    
    async def _initialize_network(self):
        """Initialize P2P network"""
        try:
            network_config = NodeConfig(
                network_type=NetworkType[self.config['network'].upper()],
                listen_ip='0.0.0.0',
                listen_port=self.config['port'],
                max_connections=self.config['max_peers'],
                bootstrap_nodes=self.config.get('bootstrap_nodes', [])
            )
            
            self.network = AdvancedP2PNetwork(network_config)
            
            # Register message handlers
            self.network.register_message_handler(
                self.network.MessageType.BLOCK, 
                self._handle_block_message
            )
            self.network.register_message_handler(
                self.network.MessageType.TRANSACTION,
                self._handle_transaction_message
            )
            self.network.register_message_handler(
                self.network.MessageType.CONSENSUS,
                self._handle_consensus_message
            )
            
            logger.info("Network initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize network: {e}")
            raise
    
    async def _handle_block_message(self, connection_id: str, message: Any):
        """Handle incoming block messages"""
        try:
            block_data = message.payload
            block = Block.from_dict(block_data)
            
            # Validate and add to blockchain
            if self.blockchain.validate_block(block):
                self.blockchain.add_block(block)
                logger.info(f"New block received: #{block.index}")
                
                # Broadcast to other peers
                await self._broadcast_block(block)
                
        except Exception as e:
            logger.error(f"Error handling block: {e}")
    
    async def _handle_transaction_message(self, connection_id: str, message: Any):
        """Handle incoming transaction messages"""
        try:
            tx_data = message.payload
            transaction = Transaction.from_dict(tx_data)
            
            # Add to mempool
            if self.blockchain.add_transaction(transaction):
                logger.info(f"New transaction received: {transaction.hash[:16]}...")
                
                # Broadcast to other peers
                await self._broadcast_transaction(transaction)
                
        except Exception as e:
            logger.error(f"Error handling transaction: {e}")
    
    async def _handle_consensus_message(self, connection_id: str, message: Any):
        """Handle consensus messages"""
        try:
            # Process consensus messages (votes, proposals, etc.)
            consensus_data = message.payload
            # Implementation would handle various consensus messages
            
        except Exception as e:
            logger.error(f"Error handling consensus message: {e}")
    
    async def _broadcast_block(self, block: Block):
        """Broadcast block to network"""
        if self.network:
            message = self.network.NetworkMessage(
                message_id=str(time.time()),
                message_type=self.network.MessageType.BLOCK,
                payload=block.to_dict()
            )
            await self.network.broadcast_message(message)
    
    async def _broadcast_transaction(self, transaction: Transaction):
        """Broadcast transaction to network"""
        if self.network:
            message = self.network.NetworkMessage(
                message_id=str(time.time()),
                message_type=self.network.MessageType.TRANSACTION,
                payload=transaction.to_dict()
            )
            await self.network.broadcast_message(message)
    
    async def start(self):
        """Start the node"""
        if self.running:
            logger.warning("Node is already running")
            return False
        
        try:
            logger.info("Starting RAYONIX Node...")
            self.running = True
            
            # Start network if enabled
            if self.network:
                asyncio.create_task(self.network.start())
            
            # Start background tasks
            asyncio.create_task(self._sync_blocks())
            asyncio.create_task(self._monitor_peers())
            asyncio.create_task(self._process_mempool())
            
            # Start staking if enabled
            if self.config['staking_enabled'] and self.wallet:
                asyncio.create_task(self._staking_loop())
            
            logger.info("RAYONIX Node started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start node: {e}")
            traceback.print_exc()
            return False
    
    async def stop(self):
        """Stop the node gracefully"""
        if not self.running:
            return
        
        logger.info("Stopping RAYONIX Node...")
        self.running = False
        self.shutdown_event.set()
        
        # Stop network
        if self.network:
            await self.network.stop()
        
        # Save state
        self._save_state()
        
        logger.info("RAYONIX Node stopped gracefully")
    
    async def _sync_blocks(self):
        """Synchronize blocks with network"""
        while self.running:
            try:
                if self.network and self.network.connections:
                    self.sync_state['syncing'] = True
                    await self._download_blocks()
                else:
                    self.sync_state['syncing'] = False
                
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Block sync error: {e}")
                await asyncio.sleep(30)
    
    async def _download_blocks(self):
        """Download missing blocks from peers"""
        current_height = len(self.blockchain.chain)
        
        # Get highest block from peers
        highest_block = await self._get_highest_block()
        if highest_block > current_height:
            self.sync_state['target_block'] = highest_block
            self.sync_state['current_block'] = current_height
            
            logger.info(f"Syncing blocks {current_height} -> {highest_block}")
            
            # Download blocks in batches
            batch_size = 100
            for start_block in range(current_height, highest_block, batch_size):
                end_block = min(start_block + batch_size, highest_block)
                await self._download_block_batch(start_block, end_block)
                
                self.sync_state['current_block'] = end_block
                
                if not self.running:
                    break
    
    async def _get_highest_block(self) -> int:
        """Get highest block height from peers"""
        # Implementation would query multiple peers and return consensus height
        return len(self.blockchain.chain)  # Placeholder
    
    async def _download_block_batch(self, start: int, end: int):
        """Download batch of blocks"""
        # Implementation would request blocks from peers
        pass
    
    async def _monitor_peers(self):
        """Monitor peer connections and network health"""
        while self.running:
            try:
                if self.network:
                    self.sync_state['peers_connected'] = len(self.network.connections)
                
                # Check network health
                network_health = await self._check_network_health()
                if network_health < 0.5:
                    logger.warning("Network health degraded")
                
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error(f"Peer monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _check_network_health(self) -> float:
        """Check overall network health"""
        # Implementation would check peer connectivity, latency, etc.
        return 1.0  # Placeholder
    
    async def _process_mempool(self):
        """Process transactions in mempool"""
        while self.running:
            try:
                # Check if we should create a block
                if (self.config['mining_enabled'] or 
                    (self.config['staking_enabled'] and self.wallet and 
                     await self._is_validator())):
                    
                    # Create and broadcast new block
                    block = await self._create_new_block()
                    if block:
                        self.blockchain.add_block(block)
                        await self._broadcast_block(block)
                
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Mempool processing error: {e}")
                await asyncio.sleep(10)
    
    async def _is_validator(self) -> bool:
        """Check if current node is a validator"""
        if not self.wallet:
            return False
        
        # Check if wallet has enough stake and is registered
        balance = self.blockchain.get_balance(self.wallet.address)
        return balance >= self.consensus.min_stake
    
    async def _create_new_block(self) -> Optional[Block]:
        """Create new block with transactions from mempool"""
        try:
            # Get validator address
            validator_address = self.wallet.address if self.wallet else "unknown"
            
            # Select transactions for block
            transactions = self.blockchain.mempool[:1000]  # Limit block size
            
            # Create block
            new_block = Block(
                index=len(self.blockchain.chain),
                previous_hash=self.blockchain.get_latest_block().hash,
                transactions=transactions,
                validator=validator_address
            )
            
            # For PoW, would mine here. For PoS, validator signs.
            if self.config['mining_enabled']:
                # Mine block (Proof-of-Work)
                self.blockchain.mine_block(new_block, validator_address)
            else:
                # Sign block (Proof-of-Stake)
                new_block.validator_signature = await self._sign_block(new_block)
            
            return new_block
            
        except Exception as e:
            logger.error(f"Error creating block: {e}")
            return None
    
    async def _sign_block(self, block: Block) -> str:
        """Sign block with validator's private key"""
        # Implementation would use wallet's private key to sign block
        return "signed_signature"  # Placeholder
    
    async def _staking_loop(self):
        """Proof-of-Stake validation loop"""
        while self.running:
            try:
                if await self._is_validator():
                    # Participate in consensus
                    await self._participate_consensus()
                
                await asyncio.sleep(15)
                
            except Exception as e:
                logger.error(f"Staking error: {e}")
                await asyncio.sleep(30)
    
    async def _participate_consensus(self):
        """Participate in consensus protocol"""
        # Implementation would handle block proposal and voting
        pass
    
    def _save_state(self):
        """Save node state to disk"""
        try:
            # Save wallet if exists
            if self.wallet:
                self.wallet.save_to_file()
            
            # Save blockchain state
            self.blockchain._save_state()
            
            # Save contracts state
            self.contract_manager.save_contracts()
            
            logger.info("Node state saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving state: {e}")
    
    async def handle_command(self, command: str, args: List[str]) -> bool:
        """Handle CLI commands"""
        try:
            if command == 'exit':
                await self.stop()
                return False
                
            elif command == 'help':
                self._show_help()
                
            elif command == 'status':
                self._show_status()
                
            elif command == 'create-wallet':
                self._create_wallet()
                
            elif command == 'load-wallet':
                self._load_wallet(args)
                
            elif command == 'get-balance':
                self._get_balance(args)
                
            elif command == 'send':
                self._send_transaction(args)
                
            elif command == 'mine':
                await self._mine_block()
                
            elif command == 'stake':
                await self._stake_tokens(args)
                
            elif command == 'deploy-contract':
                await self._deploy_contract(args)
                
            elif command == 'call-contract':
                await self._call_contract(args)
                
            elif command == 'peers':
                self._show_peers()
                
            elif command == 'network-info':
                self._show_network_info()
                
            elif command == 'blockchain-info':
                self._show_blockchain_info()
                
            elif command == 'transaction':
                self._show_transaction(args)
                
            elif command == 'block':
                self._show_block(args)
                
            elif command == 'mempool':
                self._show_mempool()
                
            elif command == 'contracts':
                self._show_contracts()
                
            elif command == 'validator-info':
                self._show_validator_info()
                
            elif command == 'sync-status':
                self._show_sync_status()
                
            else:
                print(f"Unknown command: {command}. Type 'help' for available commands.")
                
            return True
            
        except Exception as e:
            logger.error(f"Error executing command {command}: {e}")
            traceback.print_exc()
            return True
    
    def _show_help(self):
        """Show help information"""
        help_text = """
Available Commands:
  help                 - Show this help message
  exit                 - Stop the node and exit
  status               - Show node status
  create-wallet        - Create a new wallet
  load-wallet <file>   - Load wallet from file
  get-balance [addr]   - Get wallet or address balance
  send <to> <amount>   - Send coins to address
  mine                 - Mine a block (if mining enabled)
  stake <amount>       - Stake tokens for validation
  deploy-contract      - Deploy a smart contract
  call-contract        - Call a contract function
  peers                - Show connected peers
  network-info         - Show network information
  blockchain-info      - Show blockchain information
  transaction <hash>   - Show transaction details
  block <height/hash>  - Show block details
  mempool              - Show mempool transactions
  contracts            - List deployed contracts
  validator-info       - Show validator information
  sync-status          - Show synchronization status
"""
        print(help_text)
    
    def _show_status(self):
        """Show node status"""
        status = {
            'Running': self.running,
            'Network': self.config['network'],
            'Block Height': len(self.blockchain.chain),
            'Connected Peers': self.sync_state['peers_connected'],
            'Syncing': self.sync_state['syncing'],
            'Mining Enabled': self.config['mining_enabled'],
            'Staking Enabled': self.config['staking_enabled'],
            'Wallet Loaded': self.wallet is not None
        }
        
        print("Node Status:")
        for key, value in status.items():
            print(f"  {key}: {value}")
    
    def _create_wallet(self):
        """Create a new wallet"""
        if self.wallet:
            print("Wallet already loaded. Use 'load-wallet' to switch.")
            return
        
        wallet = create_new_wallet()
        self.wallet = wallet
        print(f"New wallet created:")
        print(f"  Address: {wallet.address}")
        print(f"  Public Key: {wallet.public_key[:30]}...")
        print("  Private Key: [HIDDEN] - Save this securely!")
    
    def _load_wallet(self, args: List[str]):
        """Load wallet from file"""
        if len(args) < 1:
            print("Usage: load-wallet <filename>")
            return
        
        filename = args[0]
        wallet = load_existing_wallet(filename)
        if wallet:
            self.wallet = wallet
            print(f"Wallet loaded: {wallet.address}")
        else:
            print("Failed to load wallet")
    
    def _get_balance(self, args: List[str]):
        """Get balance for address or loaded wallet"""
        address = None
        if args:
            address = args[0]
        elif self.wallet:
            address = self.wallet.address
        else:
            print("No address specified and no wallet loaded")
            return
        
        balance = self.blockchain.get_balance(address)
        print(f"Balance for {address}: {balance} RXY")
    
    def _send_transaction(self, args: List[str]):
        """Send transaction"""
        if not self.wallet:
            print("No wallet loaded")
            return
        
        if len(args) < 2:
            print("Usage: send <to_address> <amount> [fee]")
            return
        
        to_address = args[0]
        amount = int(args[1])
        fee = int(args[2]) if len(args) > 2 else 1
        
        # Create transaction
        transaction = Transaction(
            sender=self.wallet.address,
            recipient=to_address,
            amount=amount,
            fee=fee
        )
        
        # Sign transaction
        transaction.signature = self.wallet.sign_transaction(
            json.dumps(transaction.to_dict())
        )
        
        # Add to blockchain
        if self.blockchain.add_transaction(transaction):
            print(f"Transaction sent: {transaction.hash[:16]}...")
            # Broadcast to network
            asyncio.create_task(self._broadcast_transaction(transaction))
        else:
            print("Failed to send transaction")
    
    async def _mine_block(self):
        """Mine a block"""
        if not self.config['mining_enabled']:
            print("Mining is not enabled")
            return
        
        block = await self._create_new_block()
        if block:
            self.blockchain.add_block(block)
            print(f"Block mined: #{block.index}")
            await self._broadcast_block(block)
        else:
            print("Failed to mine block")
    
    async def _stake_tokens(self, args: List[str]):
        """Stake tokens for validation"""
        if not self.wallet:
            print("No wallet loaded")
            return
        
        amount = int(args[0]) if args else self.blockchain.get_balance(self.wallet.address)
        
        if self.consensus.register_validator(
            self.wallet.address,
            self.wallet.public_key,
            amount
        ):
            print(f"Staked {amount} RXY for validation")
        else:
            print("Failed to stake tokens")
    
    async def _deploy_contract(self, args: List[str]):
        """Deploy smart contract"""
        if not self.wallet:
            print("No wallet loaded")
            return
        
        if len(args) < 1:
            print("Usage: deploy-contract <contract_type> [params...]")
            return
        
        contract_type = args[0].upper()
        params = args[1:]
        
        if contract_type == "ERC20":
            if len(params) < 3:
                print("Usage: deploy-contract ERC20 <name> <symbol> <supply>")
                return
            
            name, symbol, supply = params
            bytecode = StandardContracts.create_erc20_template(name, symbol, int(supply))
            
        elif contract_type == "ERC721":
            if len(params) < 2:
                print("Usage: deploy-contract ERC721 <name> <symbol>")
                return
            
            name, symbol = params
            bytecode = StandardContracts.create_erc721_template(name, symbol)
            
        else:
            print("Unknown contract type. Use ERC20 or ERC721.")
            return
        
        contract_address = self.blockchain.deploy_contract(
            self.wallet.address,
            bytecode
        )
        
        print(f"Contract deployed at: {contract_address}")
    
    async def _call_contract(self, args: List[str]):
        """Call contract function"""
        if not self.wallet:
            print("No wallet loaded")
            return
        
        if len(args) < 3:
            print("Usage: call-contract <address> <function> <args...>")
            return
        
        contract_address, function_name = args[0], args[1]
        function_args = args[2:]
        
        result = self.blockchain.execute_contract(
            contract_address,
            function_name,
            function_args,
            self.wallet.address
        )
        
        print(f"Contract call result: {result}")
    
    def _show_peers(self):
        """Show connected peers"""
        if not self.network:
            print("Network not enabled")
            return
        
        print("Connected Peers:")
        for peer_id, peer in self.network.peers.items():
            print(f"  {peer.address}:{peer.port} - {peer.state.name}")
    
    def _show_network_info(self):
        """Show network information"""
        if not self.network:
            print("Network not enabled")
            return
        
        metrics = self.network.get_metrics()
        print("Network Information:")
        for key, value in metrics.items():
            print(f"  {key}: {value}")
    
    def _show_blockchain_info(self):
        """Show blockchain information"""
        info = {
            'Block Height': len(self.blockchain.chain),
            'Difficulty': self.blockchain.difficulty,
            'Total Transactions': sum(len(block.transactions) for block in self.blockchain.chain),
            'Mempool Size': len(self.blockchain.mempool),
            'Total Supply': self._calculate_total_supply()
        }
        
        print("Blockchain Information:")
        for key, value in info.items():
            print(f"  {key}: {value}")
    
    def _calculate_total_supply(self) -> int:
        """Calculate total coin supply"""
        # Sum of all block rewards
        block_rewards = len(self.blockchain.chain) * self.blockchain.mining_reward
        # Subtract burned fees (simplified)
        return block_rewards
    
    def _show_transaction(self, args: List[str]):
        """Show transaction details"""
        if len(args) < 1:
            print("Usage: transaction <hash>")
            return
        
        tx_hash = args[0]
        # Implementation would lookup transaction
        print(f"Transaction details for {tx_hash}")
    
    def _show_block(self, args: List[str]):
        """Show block details"""
        if len(args) < 1:
            print("Usage: block <height_or_hash>")
            return
        
        identifier = args[0]
        # Implementation would lookup block
        print(f"Block details for {identifier}")
    
    def _show_mempool(self):
        """Show mempool transactions"""
        print(f"Mempool Transactions ({len(self.blockchain.mempool)}):")
        for tx in self.blockchain.mempool[:10]:  # Show first 10
            print(f"  {tx.hash[:16]}...: {tx.sender} -> {tx.recipient} {tx.amount} RXY")
    
    def _show_contracts(self):
        """Show deployed contracts"""
        contracts = self.contract_manager.get_all_contracts()
        print(f"Deployed Contracts ({len(contracts)}):")
        for address, contract in contracts.items():
            print(f"  {address}: {contract.contract_type.name}")
    
    def _show_validator_info(self):
        """Show validator information"""
        if not self.wallet:
            print("No wallet loaded")
            return
        
        validator_info = self.consensus.get_validator_info(self.wallet.address)
        if validator_info:
            print("Validator Information:")
            for key, value in validator_info.items():
                print(f"  {key}: {value}")
        else:
            print("Not registered as validator")
    
    def _show_sync_status(self):
        """Show synchronization status"""
        print("Synchronization Status:")
        print(f"  Syncing: {self.sync_state['syncing']}")
        if self.sync_state['syncing']:
            print(f"  Progress: {self.sync_state['current_block']}/{self.sync_state['target_block']}")
            progress = (self.sync_state['current_block'] / self.sync_state['target_block']) * 100
            print(f"  Complete: {progress:.1f}%")
        print(f"  Connected Peers: {self.sync_state['peers_connected']}")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\nShutting down gracefully...")
    sys.exit(0)

async def main():
    """Main entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="RAYONIX Blockchain Node")
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--data-dir', '-d', help='Data directory path')
    parser.add_argument('--network', '-n', choices=['mainnet', 'testnet', 'devnet'], 
                       help='Network type')
    parser.add_argument('--port', '-p', type=int, help='P2P port number')
    parser.add_argument('--no-network', action='store_true', help='Disable networking')
    parser.add_argument('--mining', action='store_true', help='Enable mining')
    parser.add_argument('--staking', action='store_true', help='Enable staking')
    
    args = parser.parse_args()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and initialize node
    node = RayonixNode(args.config)
    
    # Override config from command line
    if args.data_dir:
        node.config['data_dir'] = args.data_dir
    if args.network:
        node.config['network'] = args.network
    if args.port:
        node.config['port'] = args.port
    if args.no_network:
        node.config['network_enabled'] = False
    if args.mining:
        node.config['mining_enabled'] = True
    if args.staking:
        node.config['staking_enabled'] = True
    
    # Initialize node
    if not await node.initialize():
        print("Failed to initialize node")
        return 1
    
    # Start node
    if not await node.start():
        print("Failed to start node")
        return 1
    
    # Load command history
    if node.history_file.exists():
        readline.read_history_file(node.history_file)
    
    # Main command loop
    print("RAYONIX Blockchain Node started. Type 'help' for commands, 'exit' to quit.")
    
    try:
        while True:
            try:
                command = input("rayonix> ").strip()
                if not command:
                    continue
                
                # Add to history
                node.command_history.append(command)
                readline.add_history(command)
                
                # Parse command
                parts = command.split()
                cmd = parts[0].lower()
                cmd_args = parts[1:]
                
                # Handle command
                should_continue = await node.handle_command(cmd, cmd_args)
                if not should_continue:
                    break
                    
            except EOFError:
                print("\nExiting...")
                break
            except Exception as e:
                logger.error(f"Command error: {e}")
                print(f"Error: {e}")
                
    finally:
        # Save command history
        readline.write_history_file(node.history_file)
        await node.stop()
    
    return 0

if __name__ == "__main__":
    # Run the node
    exit_code = asyncio.run(main())
    sys.exit(exit_code)