# advanced_network.py
import asyncio
import aiohttp
import websockets
import socket
import ssl
import threading
import time
import json
import pickle
import zlib
from typing import Dict, List, Optional, Set, Tuple, Callable, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import logging
import uuid
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import msgpack
import bencode
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing
from collections import deque, defaultdict
import ipaddress
from urllib.parse import urlparse
import dns.resolver
import random
import select
from contextlib import asynccontextmanager
from asyncio import DatagramProtocol

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AdvancedNetwork")

class NetworkType(Enum):
    MAINNET = auto()
    TESTNET = auto()
    DEVNET = auto()
    REGTEST = auto()

class ProtocolType(Enum):
    TCP = auto()
    UDP = auto()
    WEBSOCKET = auto()
    HTTP = auto()
    HTTPS = auto()

class ConnectionState(Enum):
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    AUTHENTICATING = auto()
    READY = auto()
    ERROR = auto()

class MessageType(Enum):
    PING = auto()
    PONG = auto()
    HANDSHAKE = auto()
    PEER_LIST = auto()
    BLOCK = auto()
    TRANSACTION = auto()
    CONSENSUS = auto()
    SYNC_REQUEST = auto()
    SYNC_RESPONSE = auto()
    GOSSIP = auto()
    RPC_REQUEST = auto()
    RPC_RESPONSE = auto()

@dataclass
class NodeConfig:
    """Network node configuration"""
    network_type: NetworkType = NetworkType.MAINNET
    listen_ip: str = "0.0.0.0"
    listen_port: int = 30303
    public_ip: Optional[str] = None
    public_port: Optional[int] = None
    max_connections: int = 50
    max_peers: int = 1000
    connection_timeout: int = 30
    message_timeout: int = 10
    ping_interval: int = 60
    bootstrap_nodes: List[str] = field(default_factory=list)
    enable_nat_traversal: bool = True
    enable_encryption: bool = True
    enable_compression: bool = True
    enable_dht: bool = True
    enable_gossip: bool = True
    enable_syncing: bool = True

@dataclass
class PeerInfo:
    """Peer information"""
    node_id: str
    address: str
    port: int
    protocol: ProtocolType
    version: str
    capabilities: List[str]
    last_seen: float = field(default_factory=time.time)
    connection_count: int = 0
    failed_attempts: int = 0
    reputation: int = 100
    latency: float = 0.0
    state: ConnectionState = ConnectionState.DISCONNECTED
    public_key: Optional[str] = None

@dataclass
class NetworkMessage:
    """Network message structure"""
    message_id: str
    message_type: MessageType
    payload: Any
    timestamp: float = field(default_factory=time.time)
    ttl: int = 10  # Time-to-live for gossip
    signature: Optional[str] = None
    source_node: Optional[str] = None
    destination_node: Optional[str] = None

@dataclass
class ConnectionMetrics:
    """Connection performance metrics"""
    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    connection_time: float = 0.0
    last_activity: float = field(default_factory=time.time)
    latency_history: deque = field(default_factory=lambda: deque(maxlen=100))
    error_count: int = 0
    success_rate: float = 1.0

class AdvancedP2PNetwork:
    """Advanced P2P network implementation with multiple protocols and security"""
    
    def __init__(self, config: NodeConfig, node_id: Optional[str] = None):
        self.config = config
        self.node_id = node_id or self._generate_node_id()
        self.private_key = self._generate_crypto_keys()
        
        # Network state
        self.peers: Dict[str, PeerInfo] = {}
        self.connections: Dict[str, Any] = {}
        self.message_handlers: Dict[MessageType, List[Callable]] = defaultdict(list)
        self.pending_requests: Dict[str, asyncio.Future] = {}
        
        # DHT and routing
        self.dht_table: Dict[str, List[PeerInfo]] = defaultdict(list)
        self.routing_table: Dict[str, List[str]] = defaultdict(list)
        
        # Metrics and statistics
        self.metrics = ConnectionMetrics()
        self.message_queue = asyncio.Queue()
        self.connection_pool: Dict[str, Any] = {}
        
        # Security
        self.session_keys: Dict[str, bytes] = {}
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        
        # Threading and async
        self.loop = asyncio.new_event_loop()
        self.executor = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count() * 2)
        self.process_executor = ProcessPoolExecutor(max_workers=4)
        self.running = False
        
        # Initialize components
        self._initialize_network()
    
    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        return hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    
    def _generate_crypto_keys(self) -> ec.EllipticCurvePrivateKey:
        """Generate cryptographic keys"""
        return ec.generate_private_key(ec.SECP256K1(), default_backend())
    
    def _initialize_network(self):
        """Initialize network components"""
        # Create SSL context for secure connections
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Initialize protocol handlers
        self.protocol_handlers = {
            ProtocolType.TCP: self._handle_tcp_connection,
            ProtocolType.UDP: self._handle_udp_connection,
            ProtocolType.WEBSOCKET: self._handle_websocket_connection,
            ProtocolType.HTTP: self._handle_http_connection,
            ProtocolType.HTTPS: self._handle_https_connection
        }
    
    async def start(self):
        """Start the network node"""
        self.running = True
        
        # Start server listeners
        server_tasks = [
            self._start_tcp_server(),
            self._start_udp_server(),
            self._start_websocket_server(),
            self._start_http_server()
        ]
        
        # Start background tasks
        background_tasks = [
            self._message_processor(),
            self._connection_manager(),
            self._peer_discovery(),
            self._metrics_collector(),
            self._gossip_broadcaster(),
            self._nat_traversal()
        ]
        
        # Bootstrap to network
        await self._bootstrap_network()
        
        # Run all tasks
        try:
            await asyncio.gather(*server_tasks + background_tasks)
        except asyncio.CancelledError:
            logger.info("Network shutdown requested")
        finally:
            await self.stop()
    
    async def stop(self):
        """Stop the network node"""
        self.running = False
        
        # Close all connections
        for connection_id in list(self.connections.keys()):
            await self._close_connection(connection_id)
        
        # Shutdown executors
        self.executor.shutdown(wait=False)
        self.process_executor.shutdown(wait=False)
        
        logger.info("Network stopped gracefully")
    
    async def _start_tcp_server(self):
        """Start TCP server"""
        try:
            server = await asyncio.start_server(
                self._handle_tcp_connection,
                self.config.listen_ip,
                self.config.listen_port,
                reuse_address=True,
                reuse_port=True
            )
            
            logger.info(f"TCP server listening on {self.config.listen_ip}:{self.config.listen_port}")
            async with server:
                await server.serve_forever()
                
        except Exception as e:
            logger.error(f"TCP server error: {e}")
    
    async def _start_udp_server(self):
        """Start UDP server"""
        try:
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPProtocol(self),
                local_addr=(self.config.listen_ip, self.config.listen_port)
            )
            
            logger.info(f"UDP server listening on {self.config.listen_ip}:{self.config.listen_port}")
            
            # Keep the server running
            while self.running:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"UDP server error: {e}")
    
    async def _start_websocket_server(self):
        """Start WebSocket server"""
        try:
            server = await websockets.serve(
                self._handle_websocket_connection,
                self.config.listen_ip,
                self.config.listen_port + 1,  # Different port for WS
                ssl=self.ssl_context if self.config.enable_encryption else None
            )
            
            logger.info(f"WebSocket server listening on {self.config.listen_ip}:{self.config.listen_port + 1}")
            await server.wait_closed()
            
        except Exception as e:
            logger.error(f"WebSocket server error: {e}")
    
    async def _start_http_server(self):
        """Start HTTP server"""
        # Implementation would use aiohttp or similar
        pass
    
    async def _handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming TCP connection"""
        peer_addr = writer.get_extra_info('peername')
        connection_id = f"tcp_{peer_addr[0]}_{peer_addr[1]}"
        
        try:
            # Perform handshake
            await self._perform_handshake(reader, writer, connection_id)
            
            # Add to connections
            self.connections[connection_id] = {
                'reader': reader,
                'writer': writer,
                'protocol': ProtocolType.TCP,
                'metrics': ConnectionMetrics()
            }
            
            # Start message processing
            await self._process_messages(connection_id)
            
        except Exception as e:
            logger.error(f"TCP connection error: {e}")
            writer.close()
            await writer.wait_closed()

    async def _handle_udp_connection(self, reader, writer):
    	peer_addr = writer.get_extra_info('peername')
    	connection_id = f"udp_{peer_addr[0]}_{peer_addr[1]}"
    	try:
    		self.logger.info(f"UDP connection from {peer_addr}")
    		
    		data = await reader.read(4096)  
    		if data:
    			if connection_id not in self.connections:
    				self.connections[connection_id] = {
    				    'protocol': ProtocolType.UDP,
    				    'address': peer_addr,
    				    'metrics': ConnectionMetrics(),
    				    'writer': writer  # Store writer for response
    				}
    				await self._process_incoming_data(data, peer_addr, ProtocolType.UDP, connection_id)
    	except Exception as e:
    		self.logger.error(f"UDP connection error: {e}")
    	finally:
    		if connection_id in self.connections:
    			del self.connections[connection_id]
    		writer.close()
    		await writer.wait_closed()
    		
    async def _process_incoming_data(self, data: bytes, addr: tuple, protocol: ProtocolType, connection_id: str):
        try:
         	 if self.config.enable_encryption:
         	     data = self._decrypt_data(data, connection_id)
         	 if self.config.enable_compression:
         	     data = self._decompress_data(data)
         	 message = self._deserialize_message(data)
         	 await self.message_queue.put((connection_id, message))
        except Exception as e:
         	self.logger.error(f"Error processing incoming data: {e}")
           			  	     
    async def _handle_websocket_connection(self, websocket: websockets.WebSocketServerProtocol):
        """Handle incoming WebSocket connection"""
        peer_addr = websocket.remote_address
        connection_id = f"ws_{peer_addr[0]}_{peer_addr[1]}"
        
        try:
            # Perform handshake
            await self._perform_websocket_handshake(websocket, connection_id)
            
            # Add to connections
            self.connections[connection_id] = {
                'websocket': websocket,
                'protocol': ProtocolType.WEBSOCKET,
                'metrics': ConnectionMetrics()
            }
            
            # Start message processing
            await self._process_websocket_messages(connection_id)
            
        except Exception as e:
            logger.error(f"WebSocket connection error: {e}")
            await websocket.close()
    
    async def _perform_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, connection_id: str):
        """Perform cryptographic handshake"""
        # Send our node ID and public key
        handshake_data = {
            'node_id': self.node_id,
            'public_key': self._get_public_key().hex(),
            'version': '1.0',
            'capabilities': ['block', 'transaction', 'consensus'],
            'timestamp': time.time()
        }
        
        # Sign handshake
        signature = self._sign_data(json.dumps(handshake_data).encode())
        handshake_data['signature'] = signature.hex()
        
        # Send handshake
        await self._send_data(writer, handshake_data)
        
        # Receive response
        response_data = await self._receive_data(reader)
        
        # Verify response
        if not self._verify_handshake(response_data):
            raise ConnectionError("Handshake verification failed")
        
        # Derive session key
        peer_public_key = bytes.fromhex(response_data['public_key'])
        self.session_keys[connection_id] = self._derive_session_key(peer_public_key)
    
    async def _perform_websocket_handshake(self, websocket: websockets.WebSocketServerProtocol, connection_id: str):
        """Perform WebSocket handshake"""
        # Similar to TCP handshake but over WebSocket
        handshake_data = {
            'node_id': self.node_id,
            'public_key': self._get_public_key().hex(),
            'version': '1.0',
            'capabilities': ['block', 'transaction', 'consensus'],
            'timestamp': time.time()
        }
        
        signature = self._sign_data(json.dumps(handshake_data).encode())
        handshake_data['signature'] = signature.hex()
        
        await websocket.send(json.dumps(handshake_data))
        
        response = await websocket.recv()
        response_data = json.loads(response)
        
        if not self._verify_handshake(response_data):
            raise ConnectionError("WebSocket handshake verification failed")
        
        peer_public_key = bytes.fromhex(response_data['public_key'])
        self.session_keys[connection_id] = self._derive_session_key(peer_public_key)
    
    def _verify_handshake(self, handshake_data: Dict) -> bool:
        """Verify handshake signature"""
        try:
            public_key_bytes = bytes.fromhex(handshake_data['public_key'])
            signature = bytes.fromhex(handshake_data['signature'])
            
            # Create copy without signature for verification
            verify_data = handshake_data.copy()
            del verify_data['signature']
            
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), public_key_bytes
            )
            
            public_key.verify(
                signature,
                json.dumps(verify_data).encode(),
                ec.ECDSA(hashes.SHA256())
            )
            
            return True
            
        except (InvalidSignature, ValueError):
            return False
    
    def _derive_session_key(self, peer_public_key: bytes) -> bytes:
        """Derive shared session key using ECDH"""
        shared_secret = self.private_key.exchange(ec.ECDH(), 
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), peer_public_key)
        )
        
        # Use HKDF to derive session key
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'session_key',
        ).derive(shared_secret)
    
    async def _process_messages(self, connection_id: str):
        """Process incoming messages for a connection"""
        connection = self.connections[connection_id]
        reader = connection['reader']
        
        try:
            while self.running:
                message_data = await self._receive_data(reader)
                if not message_data:
                    break
                
                # Decrypt if encryption enabled
                if self.config.enable_encryption:
                    message_data = self._decrypt_data(message_data, connection_id)
                
                # Decompress if compression enabled
                if self.config.enable_compression:
                    message_data = self._decompress_data(message_data)
                
                message = self._deserialize_message(message_data)
                await self.message_queue.put((connection_id, message))
                
        except asyncio.IncompleteReadError:
            logger.debug("Connection closed by peer")
        except Exception as e:
            logger.error(f"Message processing error: {e}")
        finally:
            await self._close_connection(connection_id)
    
    async def _process_websocket_messages(self, connection_id: str):
        """Process WebSocket messages"""
        connection = self.connections[connection_id]
        websocket = connection['websocket']
        
        try:
            async for message in websocket:
                message_data = message
                
                if self.config.enable_encryption:
                    message_data = self._decrypt_data(message_data, connection_id)
                
                if self.config.enable_compression:
                    message_data = self._decompress_data(message_data)
                
                message_obj = self._deserialize_message(message_data)
                await self.message_queue.put((connection_id, message_obj))
                
        except websockets.exceptions.ConnectionClosed:
            logger.debug("WebSocket connection closed")
        except Exception as e:
            logger.error(f"WebSocket message processing error: {e}")
        finally:
            await self._close_connection(connection_id)
    
    async def _message_processor(self):
        """Process messages from queue"""
        while self.running:
            try:
                connection_id, message = await self.message_queue.get()
                await self._handle_message(connection_id, message)
                self.message_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Message processor error: {e}")
    
    async def _handle_message(self, connection_id: str, message: NetworkMessage):
        """Handle incoming message"""
        try:
            # Update metrics
            self.connections[connection_id]['metrics'].messages_received += 1
            self.connections[connection_id]['metrics'].last_activity = time.time()
            
            # Call registered handlers
            if message.message_type in self.message_handlers:
                for handler in self.message_handlers[message.message_type]:
                    try:
                        await handler(connection_id, message)
                    except Exception as e:
                        logger.error(f"Message handler error: {e}")
            
            # Handle specific message types
            if message.message_type == MessageType.PING:
                await self._handle_ping(connection_id, message)
            elif message.message_type == MessageType.PEER_LIST:
                await self._handle_peer_list(connection_id, message)
            elif message.message_type == MessageType.BLOCK:
                await self._handle_block(connection_id, message)
            elif message.message_type == MessageType.TRANSACTION:
                await self._handle_transaction(connection_id, message)
            elif message.message_type == MessageType.RPC_REQUEST:
                await self._handle_rpc_request(connection_id, message)
                
        except Exception as e:
            logger.error(f"Message handling error: {e}")
    
    async def _handle_ping(self, connection_id: str, message: NetworkMessage):
        """Handle ping message"""
        # Respond with pong
        pong_message = NetworkMessage(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.PONG,
            payload={'timestamp': message.payload['timestamp']}
        )
        
        await self.send_message(connection_id, pong_message)
    
    async def _handle_peer_list(self, connection_id: str, message: NetworkMessage):
        """Handle peer list message"""
        peers = message.payload.get('peers', [])
        for peer_info in peers:
            await self._add_peer(peer_info)
    
    async def _handle_block(self, connection_id: str, message: NetworkMessage):
        """Handle block message"""
        # Validate and process block
        block_data = message.payload
        # Implementation would validate and add to blockchain
    
    async def _handle_transaction(self, connection_id: str, message: NetworkMessage):
        """Handle transaction message"""
        # Validate and process transaction
        tx_data = message.payload
        # Implementation would validate and add to mempool
    
    async def _handle_rpc_request(self, connection_id: str, message: NetworkMessage):
        """Handle RPC request"""
        # Process RPC call and send response
        response_payload = await self._process_rpc_call(message.payload)
        
        response_message = NetworkMessage(
            message_id=message.message_id,  # Use same ID for response
            message_type=MessageType.RPC_RESPONSE,
            payload=response_payload
        )
        
        await self.send_message(connection_id, response_message)
    
    async def send_message(self, connection_id: str, message: NetworkMessage) -> bool:
        """Send message to connection"""
        if connection_id not in self.connections:
            return False
        
        try:
            connection = self.connections[connection_id]
            
            # Serialize message
            message_data = self._serialize_message(message)
            
            # Compress if enabled
            if self.config.enable_compression:
                message_data = self._compress_data(message_data)
            
            # Encrypt if enabled
            if self.config.enable_encryption:
                message_data = self._encrypt_data(message_data, connection_id)
            
            # Send based on protocol
            if connection['protocol'] == ProtocolType.TCP:
                writer = connection['writer']
                await self._send_data(writer, message_data)
            elif connection['protocol'] == ProtocolType.WEBSOCKET:
                websocket = connection['websocket']
                await websocket.send(message_data)
            # Add other protocols...
            
            # Update metrics
            connection['metrics'].messages_sent += 1
            connection['metrics'].bytes_sent += len(message_data)
            connection['metrics'].last_activity = time.time()
            
            return True
            
        except Exception as e:
            logger.error(f"Send message error: {e}")
            await self._close_connection(connection_id)
            return False
    
    async def broadcast_message(self, message: NetworkMessage, exclude_connections: Set[str] = None):
        """Broadcast message to all connections"""
        exclude_connections = exclude_connections or set()
        
        for connection_id in list(self.connections.keys()):
            if connection_id not in exclude_connections:
                await self.send_message(connection_id, message)
    
    async def connect_to_peer(self, address: str, port: int, protocol: ProtocolType = ProtocolType.TCP) -> Optional[str]:
        """Connect to a peer"""
        connection_id = f"{protocol.name.lower()}_{address}_{port}"
        
        if connection_id in self.connections:
            return connection_id
        
        try:
            if protocol == ProtocolType.TCP:
                reader, writer = await asyncio.open_connection(address, port)
                await self._perform_handshake(reader, writer, connection_id)
                
                self.connections[connection_id] = {
                    'reader': reader,
                    'writer': writer,
                    'protocol': protocol,
                    'metrics': ConnectionMetrics()
                }
                
                # Start message processing
                asyncio.create_task(self._process_messages(connection_id))
                
            elif protocol == ProtocolType.WEBSOCKET:
                websocket = await websockets.connect(
                    f"ws://{address}:{port}",
                    ssl=self.ssl_context if self.config.enable_encryption else None
                )
                
                await self._perform_websocket_handshake(websocket, connection_id)
                
                self.connections[connection_id] = {
                    'websocket': websocket,
                    'protocol': protocol,
                    'metrics': ConnectionMetrics()
                }
                
                asyncio.create_task(self._process_websocket_messages(connection_id))
            
            logger.info(f"Connected to peer {address}:{port} via {protocol}")
            return connection_id
            
        except Exception as e:
            logger.error(f"Failed to connect to {address}:{port}: {e}")
            return None
    
    async def _close_connection(self, connection_id: str):
        """Close a connection"""
        if connection_id in self.connections:
            connection = self.connections[connection_id]
            
            try:
                if connection['protocol'] == ProtocolType.TCP:
                    writer = connection['writer']
                    writer.close()
                    await writer.wait_closed()
                elif connection['protocol'] == ProtocolType.WEBSOCKET:
                    websocket = connection['websocket']
                    await websocket.close()
            except Exception:
                pass
            
            # Remove from connections
            del self.connections[connection_id]
            if connection_id in self.session_keys:
                del self.session_keys[connection_id]
    
    async def _connection_manager(self):
        """Manage connections and handle failures"""
        while self.running:
            try:
                # Check for dead connections
                current_time = time.time()
                for connection_id, connection in list(self.connections.items()):
                    metrics = connection['metrics']
                    
                    # Close inactive connections
                    if current_time - metrics.last_activity > self.config.connection_timeout:
                        logger.warning(f"Closing inactive connection: {connection_id}")
                        await self._close_connection(connection_id)
                
                # Maintain connection count
                if len(self.connections) < self.config.max_connections:
                    await self._discover_and_connect_peers()
                
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Connection manager error: {e}")
                await asyncio.sleep(5)
    
    async def _discover_and_connect_peers(self):
        """Discover and connect to new peers"""
        # Get peers from DHT and existing connections
        potential_peers = self._get_potential_peers()
        
        for peer_info in potential_peers:
            if len(self.connections) >= self.config.max_connections:
                break
            
            if peer_info.address not in self.blacklist:
                connection_id = await self.connect_to_peer(
                    peer_info.address, peer_info.port, peer_info.protocol
                )
                
                if connection_id:
                    # Add to peers list
                    self.peers[connection_id] = peer_info
                    await asyncio.sleep(0.1)  # Rate limiting
    
    async def _peer_discovery(self):
        """Discover peers through various methods"""
        while self.running:
            try:
                # DNS-based discovery
                await self._dns_discovery()
                
                # Peer exchange with connected nodes
                await self._peer_exchange()
                
                # DHT lookup
                if self.config.enable_dht:
                    await self._dht_lookup()
                
                await asyncio.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                logger.error(f"Peer discovery error: {e}")
                await asyncio.sleep(60)
    
    async def _dns_discovery(self):
        """Discover peers through DNS records"""
        try:
            # Query DNS seeds
            dns_seeds = [
                "seed.rayonix.mainnet",
                "seed.rayonix.testnet",
                "seed.rayonix.devnet"
            ]
            
            for seed in dns_seeds:
                try:
                    answers = dns.resolver.resolve(seed, 'A')
                    for answer in answers:
                        peer_addr = str(answer)
                        await self._add_peer_from_dns(peer_addr)
                except dns.resolver.NXDOMAIN:
                    continue
                    
        except Exception as e:
            logger.error(f"DNS discovery error: {e}")
    
    async def _peer_exchange(self):
        """Exchange peer lists with connected nodes"""
        peer_list_message = NetworkMessage(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.PEER_LIST,
            payload={'peers': list(self.peers.values())}
        )
        
        await self.broadcast_message(peer_list_message)
    
    async def _dht_lookup(self):
        """Lookup peers in DHT"""
        # Implementation would use Kademlia DHT protocol
        pass
    
    async def _gossip_broadcaster(self):
        """Broadcast messages via gossip protocol"""
        while self.running:
            try:
                # Get messages for gossip (new blocks, transactions, etc.)
                gossip_messages = self._get_gossip_messages()
                
                for message in gossip_messages:
                    # Broadcast with gossip protocol
                    await self._gossip_message(message)
                
                await asyncio.sleep(1)  # Gossip interval
                
            except Exception as e:
                logger.error(f"Gossip broadcaster error: {e}")
                await asyncio.sleep(5)
    
    async def _gossip_message(self, message: NetworkMessage):
        """Spread message via gossip protocol"""
        # Select random peers for gossip
        peer_ids = list(self.connections.keys())
        random.shuffle(peer_ids)
        
        # Send to subset of peers
        for connection_id in peer_ids[:3]:  # Send to 3 random peers
            await self.send_message(connection_id, message)
    
    async def _nat_traversal(self):
        """Perform NAT traversal using STUN/ICE"""
        if not self.config.enable_nat_traversal:
            return
        
        while self.running:
            try:
                # Discover public IP using STUN
                public_ip = await self._stun_discovery()
                if public_ip:
                    self.config.public_ip = public_ip
                
                # Setup port forwarding if needed
                await self._setup_port_forwarding()
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"NAT traversal error: {e}")
                await asyncio.sleep(300)
    
    async def _stun_discovery(self) -> Optional[str]:
        """Discover public IP using STUN servers"""
        stun_servers = [
            ("stun.l.google.com", 19302),
            ("stun1.l.google.com", 19302),
            ("stun2.l.google.com", 19302)
        ]
        
        for server, port in stun_servers:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{server}:{port}") as response:
                        if response.status == 200:
                            # Parse STUN response to get public IP
                            return await self._parse_stun_response(await response.read())
            except Exception:
                continue
        
        return None
    
    async def _setup_port_forwarding(self):
        """Setup port forwarding using UPnP or NAT-PMP"""
        try:
            # Try UPnP first
            if await self._upnp_forwarding():
                return True
            
            # Try NAT-PMP
            if await self._nat_pmp_forwarding():
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Port forwarding error: {e}")
            return False
    
    async def _upnp_forwarding(self) -> bool:
        """Setup port forwarding using UPnP"""
        try:
            import miniupnpc
            
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 200
            upnp.discover()
            upnp.selectigd()
            
            # Add port mapping
            upnp.addportmapping(
                self.config.listen_port, 'TCP',
                upnp.lanaddr, self.config.listen_port,
                'Rayonix Node', ''
            )
            
            return True
            
        except Exception:
            return False
    
    async def _nat_pmp_forwarding(self) -> bool:
        """Setup port forwarding using NAT-PMP"""
        try:
            # NAT-PMP implementation would go here
            return False
        except Exception:
            return False
    
    async def _bootstrap_network(self):
        """Bootstrap to the network using bootstrap nodes"""
        for bootstrap_node in self.config.bootstrap_nodes:
            try:
                parsed_url = urlparse(bootstrap_node)
                address = parsed_url.hostname
                port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
                
                connection_id = await self.connect_to_peer(address, port, ProtocolType.TCP)
                if connection_id:
                    logger.info(f"Successfully bootstrapped to {bootstrap_node}")
                    return True
                    
            except Exception as e:
                logger.error(f"Bootstrap failed for {bootstrap_node}: {e}")
        
        logger.warning("All bootstrap nodes failed, using fallback discovery")
        await self._fallback_discovery()
        return False
    
    async def _fallback_discovery(self):
        """Fallback peer discovery methods"""
        # Hardcoded fallback peers
        fallback_peers = [
            ("mainnet.rayonix.org", 30303),
            ("backup.rayonix.org", 30303),
            ("seed.rayonix.org", 30303)
        ]
        
        for address, port in fallback_peers:
            try:
                await self.connect_to_peer(address, port, ProtocolType.TCP)
            except Exception:
                continue
    
    async def _metrics_collector(self):
        """Collect and report network metrics"""
        while self.running:
            try:
                metrics = self._collect_metrics()
                self._report_metrics(metrics)
                
                # Adjust network parameters based on metrics
                self._adaptive_tuning(metrics)
                
                await asyncio.sleep(60)  # Collect every minute
                
            except Exception as e:
                logger.error(f"Metrics collector error: {e}")
                await asyncio.sleep(30)
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """Collect network metrics"""
        metrics = {
            'active_connections': len(self.connections),
            'known_peers': len(self.peers),
            'bytes_sent': self.metrics.bytes_sent,
            'bytes_received': self.metrics.bytes_received,
            'messages_sent': self.metrics.messages_sent,
            'messages_received': self.metrics.messages_received,
            'connection_quality': {},
            'latency_stats': {}
        }
        
        # Connection-specific metrics
        for conn_id, conn in self.connections.items():
            metrics['connection_quality'][conn_id] = conn['metrics'].success_rate
            if conn['metrics'].latency_history:
                metrics['latency_stats'][conn_id] = {
                    'avg': sum(conn['metrics'].latency_history) / len(conn['metrics'].latency_history),
                    'max': max(conn['metrics'].latency_history),
                    'min': min(conn['metrics'].latency_history)
                }
        
        return metrics
    
    def _report_metrics(self, metrics: Dict[str, Any]):
        """Report metrics to logging or monitoring system"""
        logger.info(f"Network Metrics: {metrics}")
    
    def _adaptive_tuning(self, metrics: Dict[str, Any]):
        """Adaptively tune network parameters based on metrics"""
        # Adjust connection timeout based on network conditions
        avg_latency = self._calculate_average_latency(metrics)
        if avg_latency > 1000:  # High latency network
            self.config.connection_timeout = max(60, self.config.connection_timeout)
            self.config.message_timeout = max(30, self.config.message_timeout)
        else:  # Low latency network
            self.config.connection_timeout = min(30, self.config.connection_timeout)
            self.config.message_timeout = min(10, self.config.message_timeout)
    
    def _calculate_average_latency(self, metrics: Dict[str, Any]) -> float:
        """Calculate average network latency"""
        latencies = []
        for stats in metrics['latency_stats'].values():
            latencies.append(stats['avg'])
        
        return sum(latencies) / len(latencies) if latencies else 0
    
    def register_message_handler(self, message_type: MessageType, handler: Callable):
        """Register message handler for specific message type"""
        self.message_handlers[message_type].append(handler)
    
    def unregister_message_handler(self, message_type: MessageType, handler: Callable):
        """Unregister message handler"""
        if message_type in self.message_handlers:
            self.message_handlers[message_type] = [
                h for h in self.message_handlers[message_type] if h != handler
            ]
    
    async def rpc_call(self, connection_id: str, method: str, params: Dict, timeout: int = 30) -> Any:
        """Make RPC call to peer"""
        message_id = str(uuid.uuid4())
        
        rpc_message = NetworkMessage(
            message_id=message_id,
            message_type=MessageType.RPC_REQUEST,
            payload={
                'method': method,
                'params': params,
                'timestamp': time.time()
            }
        )
        
        # Create future for response
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self.pending_requests[message_id] = future
        
        try:
            # Send request
            await self.send_message(connection_id, rpc_message)
            
            # Wait for response with timeout
            return await asyncio.wait_for(future, timeout)
            
        except asyncio.TimeoutError:
            logger.error(f"RPC call {method} timed out")
            raise
        finally:
            if message_id in self.pending_requests:
                del self.pending_requests[message_id]
    
    def _encrypt_data(self, data: bytes, connection_id: str) -> bytes:
        """Encrypt data using session key"""
        if not self.config.enable_encryption or connection_id not in self.session_keys:
            return data
        
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        
        session_key = self.session_keys[connection_id]
        cipher = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))
        
        return cipher.nonce + tag + ciphertext
    
    def _decrypt_data(self, data: bytes, connection_id: str) -> bytes:
        """Decrypt data using session key"""
        if not self.config.enable_encryption or connection_id not in self.session_keys:
            return data
        
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        
        session_key = self.session_keys[connection_id]
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
        
        return plaintext
    
    def _compress_data(self, data: bytes) -> bytes:
        """Compress data"""
        if not self.config.enable_compression:
            return data
        
        return zlib.compress(data)
    
    def _decompress_data(self, data: bytes) -> bytes:
        """Decompress data"""
        if not self.config.enable_compression:
            return data
        
        return zlib.decompress(data)
    
    def _serialize_message(self, message: NetworkMessage) -> bytes:
        """Serialize message to bytes"""
        return msgpack.packb({
            'message_id': message.message_id,
            'message_type': message.message_type.value,
            'payload': message.payload,
            'timestamp': message.timestamp,
            'ttl': message.ttl,
            'signature': message.signature,
            'source_node': message.source_node,
            'destination_node': message.destination_node
        })
    
    def _deserialize_message(self, data: bytes) -> NetworkMessage:
        """Deserialize message from bytes"""
        decoded = msgpack.unpackb(data)
        
        return NetworkMessage(
            message_id=decoded['message_id'],
            message_type=MessageType(decoded['message_type']),
            payload=decoded['payload'],
            timestamp=decoded['timestamp'],
            ttl=decoded['ttl'],
            signature=decoded.get('signature'),
            source_node=decoded.get('source_node'),
            destination_node=decoded.get('destination_node')
        )
    
    def _sign_data(self, data: bytes) -> bytes:
        """Sign data with private key"""
        return self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
    
    def _get_public_key(self) -> bytes:
        """Get public key in compressed format"""
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
    
    async def _send_data(self, writer: asyncio.StreamWriter, data: bytes):
        """Send data with length prefix"""
        # Add length prefix
        length_prefix = len(data).to_bytes(4, 'big')
        writer.write(length_prefix + data)
        await writer.drain()
    
    async def _receive_data(self, reader: asyncio.StreamReader) -> bytes:
        """Receive data with length prefix"""
        # Read length prefix
        length_bytes = await reader.readexactly(4)
        length = int.from_bytes(length_bytes, 'big')
        
        # Read actual data
        return await reader.readexactly(length)
    
    async def _add_peer(self, peer_info: Dict):
        """Add peer to peer list"""
        peer = PeerInfo(
            node_id=peer_info['node_id'],
            address=peer_info['address'],
            port=peer_info['port'],
            protocol=ProtocolType[peer_info['protocol']],
            version=peer_info['version'],
            capabilities=peer_info['capabilities'],
            public_key=peer_info.get('public_key')
        )
        
        # Add to DHT
        self.dht_table[peer.node_id].append(peer)
        
        # Add to routing table
        self._update_routing_table(peer)
    
    def _update_routing_table(self, peer: PeerInfo):
        """Update routing table with peer"""
        # Kademlia-like routing table update
        pass
    
    def _get_potential_peers(self) -> List[PeerInfo]:
        """Get list of potential peers to connect to"""
        potential_peers = []
        
        # Get from DHT
        for peers in self.dht_table.values():
            potential_peers.extend(peers)
        
        # Get from known peers
        potential_peers.extend(self.peers.values())
        
        # Filter and sort by reputation
        potential_peers = [
            p for p in potential_peers 
            if p.reputation > 50 and p.failed_attempts < 3
        ]
        
        potential_peers.sort(key=lambda x: x.reputation, reverse=True)
        
        return potential_peers
    
    def _get_gossip_messages(self) -> List[NetworkMessage]:
        """Get messages that should be gossiped"""
        # Implementation would get new blocks, transactions, etc.
        return []
    
    async def _add_peer_from_dns(self, address: str):
        """Add peer discovered from DNS"""
        peer_info = PeerInfo(
            node_id=hashlib.sha256(address.encode()).hexdigest(),
            address=address,
            port=self.config.listen_port,
            protocol=ProtocolType.TCP,
            version='1.0',
            capabilities=['block', 'transaction']
        )
        
        await self._add_peer(peer_info.__dict__)

class UDPProtocol:
    """UDP protocol handler"""
    def __init__(self, network: 'AdvancedP2PNetwork'):
        self.network = network
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data, addr):
        asyncio.create_task(self._handle_datagram(data, addr))
    
    async def _handle_datagram(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP datagram"""
        try:
            message = self.network._deserialize_message(data)
            connection_id = f"udp_{addr[0]}_{addr[1]}"
            
            # Create temporary connection entry for UDP
            if connection_id not in self.network.connections:
                self.network.connections[connection_id] = {
                    'protocol': ProtocolType.UDP,
                    'address': addr,
                    'metrics': ConnectionMetrics()
                }
            
            await self.network.message_queue.put((connection_id, message))
            
        except Exception as e:
            logger.error(f"UDP handling error: {e}")

# Utility functions
async def create_network_node(config: NodeConfig) -> AdvancedP2PNetwork:
    """Create and start network node"""
    network = AdvancedP2PNetwork(config)
    await network.start()
    return network

async def connect_to_network(network: AdvancedP2PNetwork, bootstrap_nodes: List[str]):
    """Connect to network with bootstrap nodes"""
    network.config.bootstrap_nodes = bootstrap_nodes
    await network._bootstrap_network()

def generate_node_identity() -> Tuple[str, str]:
    """Generate node identity (node_id and private key)"""
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    node_id = hashlib.sha256(public_key).hexdigest()
    
    return node_id, private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

# Example usage
async def main():
    """Example usage of the advanced network"""
    # Generate node identity
    node_id, private_key = generate_node_identity()
    print(f"Node ID: {node_id}")
    
    # Configure network
    config = NodeConfig(
        network_type=NetworkType.MAINNET,
        listen_ip="0.0.0.0",
        listen_port=30303,
        max_connections=50,
        bootstrap_nodes=[
            "node1.rayonix.org:30303",
            "node2.rayonix.org:30303",
            "node3.rayonix.org:30303"
        ]
    )
    
    # Create network node
    network = AdvancedP2PNetwork(config, node_id)
    
    # Register message handlers
    network.register_message_handler(MessageType.BLOCK, handle_block_message)
    network.register_message_handler(MessageType.TRANSACTION, handle_transaction_message)
    
    # Start network
    try:
        await network.start()
    except KeyboardInterrupt:
        await network.stop()

async def handle_block_message(connection_id: str, message: NetworkMessage):
    """Example block message handler"""
    print(f"Received block: {message.payload}")
    # Process block...

async def handle_transaction_message(connection_id: str, message: NetworkMessage):
    """Example transaction message handler"""
    print(f"Received transaction: {message.payload}")
    # Process transaction...

if __name__ == "__main__":
    asyncio.run(main())