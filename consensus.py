# consensus.py
import hashlib
import json
import time
import random
import threading
from typing import Dict, List, Optional, Tuple, Set, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import plyvel
import pickle
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime, timedelta
import asyncio

class ConsensusState(Enum):
    """Consensus process states"""
    IDLE = auto()
    PROPOSING = auto()
    VOTING = auto()
    COMMITTING = auto()
    VIEW_CHANGE = auto()
    RECOVERY = auto()

class ValidatorStatus(Enum):
    """Validator status levels"""
    ACTIVE = auto()
    JAILED = auto()
    INACTIVE = auto()
    SLASHED = auto()
    PENDING = auto()

@dataclass
class Validator:
    """Complete validator information"""
    address: str
    public_key: str
    staked_amount: int
    commission_rate: float  # 0.0 to 1.0
    total_delegated: int = 0
    status: ValidatorStatus = ValidatorStatus.PENDING
    uptime: float = 100.0  # Percentage
    last_active: float = field(default_factory=time.time)
    created_block_height: int = 0
    total_rewards: int = 0
    slashing_count: int = 0
    voting_power: int = 0
    jail_until: Optional[float] = None
    delegators: Dict[str, int] = field(default_factory=dict)  # address -> amount
    
    @property
    def total_stake(self) -> int:
        return self.staked_amount + self.total_delegated
    
    @property
    def effective_stake(self) -> int:
        """Calculate effective stake considering status and uptime"""
        if self.status in [ValidatorStatus.JAILED, ValidatorStatus.SLASHED]:
            return 0
        return int(self.total_stake * (self.uptime / 100.0))
    
    def to_dict(self) -> Dict:
        return {
            'address': self.address,
            'public_key': self.public_key,
            'staked_amount': self.staked_amount,
            'commission_rate': self.commission_rate,
            'total_delegated': self.total_delegated,
            'status': self.status.name,
            'uptime': self.uptime,
            'last_active': self.last_active,
            'created_block_height': self.created_block_height,
            'total_rewards': self.total_rewards,
            'slashing_count': self.slashing_count,
            'voting_power': self.voting_power,
            'jail_until': self.jail_until,
            'delegators': self.delegators              
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Validator':
        return cls(
            address=data['address'],
            public_key=data['public_key'],
            staked_amount=data['staked_amount'],
            commission_rate=data['commission_rate'],
            total_delegated=data['total_delegated'],
            status=ValidatorStatus[data['status']],
            uptime=data['uptime'],
            last_active=data['last_active'],
            created_block_height=data['created_block_height'],
            total_rewards=data['total_rewards'],
            slashing_count=data['slashing_count'],
            voting_power=data['voting_power'],
            jail_until=data.get('jail_until'),
            delegators=data.get('delegators', {})
        )

@dataclass
class BlockProposal:
    """Block proposal structure"""
    block_hash: str
    validator_address: str
    timestamp: float
    signature: str
    view_number: int
    round_number: int
    parent_hash: str
    justification: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return {
            'block_hash': self.block_hash,
            'validator_address': self.validator_address,
            'timestamp': self.timestamp,
            'signature': self.signature,
            'view_number': self.view_number,
            'round_number': self.round_number,
            'parent_hash': self.parent_hash,
            'justification': self.justification
        }

@dataclass
class Vote:
    """Vote for block proposal"""
    block_hash: str
    validator_address: str
    timestamp: float
    signature: str
    view_number: int
    round_number: int
    vote_type: str  # 'pre-vote', 'pre-commit', 'commit'
    
    def to_dict(self) -> Dict:
        return {
            'block_hash': self.block_hash,
            'validator_address': self.validator_address,
            'timestamp': self.timestamp,
            'signature': self.signature,
            'view_number': self.view_number,
            'round_number': self.round_number,
            'vote_type': self.vote_type
        }

class ProofOfStake:
    """Complete Proof-of-Stake consensus implementation with BFT features"""
    
    def __init__(self, min_stake: int = 1000, jail_duration: int = 3600,
                 slash_percentage: float = 0.01, epoch_blocks: int = 100,
                 max_validators: int = 100, db_path: str = './consensus_db'):
        """
        Initialize Proof-of-Stake consensus
        
        Args:
            min_stake: Minimum stake required to become validator
            jail_duration: Jail duration in seconds for misbehavior
            slash_percentage: Percentage of stake to slash for violations
            epoch_blocks: Number of blocks per epoch
            max_validators: Maximum number of active validators
        """
        print(f"DEBUG: ProofOfStake using DB path: {db_path}")
        self.min_stake = min_stake
        self.jail_duration = jail_duration
        self.slash_percentage = slash_percentage
        self.epoch_blocks = epoch_blocks
        self.max_validators = max_validators
        
        self.validators: Dict[str, Validator] = {}
        self.active_validators: List[Validator] = []
        self.pending_validators: List[Validator] = []
        
        self.current_epoch = 0
        self.current_view = 0
        self.current_round = 0
        self.last_block_time = time.time()
        
        self.block_proposals: Dict[str, BlockProposal] = {}
        self.votes: Dict[str, List[Vote]] = {}  # block_hash -> votes
        self.locked_blocks: Set[str] = set()
        self.executed_blocks: Set[str] = set()
        
        self.state = ConsensusState.IDLE
        self.epoch_rewards: Dict[str, int] = {}
        
        # Database for persistence
        self.db = plyvel.DB(db_path, create_if_missing=True)
        
        # COMPATIBILITY ATTRIBUTES
        self.total_stake = 0  # Total stake across all validators
        self._compatibility_mode = True  # Flag for blockchain compatibility
        
        #self._load_state()
        
        # Lock for thread safety
        self.lock = threading.RLock()
        self.validator_lock = threading.RLock()
        
        self._load_state()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _load_state(self):
        """Load consensus state from database"""
        try:
            # Load validators
            validators_data_bytes = self.db.get(b'validators')
            if validators_data_bytes:
                validators_data = pickle.loads(validators_data_bytes)
                self.validators = {k: Validator.from_dict(v) for k, v in validators_data.items()}
            
            # Load active validators
            active_data_bytes = self.db.get(b'active_validators')
            if active_data_bytes:
                active_data = pickle.loads(active_data_bytes)
                self.active_validators = [Validator.from_dict(v) for v in active_data]
            
            # Load other state
            epoch_bytes = self.db.get(b'current_epoch')
            if epoch_bytes:
                self.current_epoch = int.from_bytes(epoch_bytes, 'big')
            
            view_bytes = self.db.get(b'current_view')
            if view_bytes:
                self.current_view = int.from_bytes(view_bytes, 'big')
            
            round_bytes = self.db.get(b'current_round')
            if round_bytes:
                self.current_round = int.from_bytes(round_bytes, 'big')
            
            # Load total_stake for compatibility
            total_stake_bytes = self.db.get(b'total_stake')
            if total_stake_bytes:
                self.total_stake = int.from_bytes(total_stake_bytes, 'big')
            else:
                self.update_total_stake()  # Calculate if not stored
            
        except Exception as e:
            print(f"Error loading state: {e}")
            # Initialize fresh state
            self.update_total_stake()
            self._save_state()
        
    def _save_state(self):
        """Save consensus state to database"""
        with self.lock:
            # Update total stake before saving
            self.update_total_stake()
            
            # Save validators
            validators_data = {k: v.to_dict() for k, v in self.validators.items()}
            self.db.put(b'validators', pickle.dumps(validators_data))
            
            # Save active validators
            active_data = [v.to_dict() for v in self.active_validators]
            self.db.put(b'active_validators', pickle.dumps(active_data))
            
            # Save other state
            self.db.put(b'current_epoch', self.current_epoch.to_bytes(8, 'big'))
            self.db.put(b'current_view', self.current_view.to_bytes(8, 'big'))
            self.db.put(b'current_round', self.current_round.to_bytes(8, 'big'))
            self.db.put(b'total_stake', self.total_stake.to_bytes(8, 'big'))  # Save total_stake
    
    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        def epoch_processor():
            while True:
                time.sleep(30)  # Check every 30 seconds
                self._process_epoch_transition()
        
        def validator_updater():
            while True:
                time.sleep(60)  # Update every minute
                self._update_validator_set()
        
        def jail_checker():
            while True:
                time.sleep(300)  # Check every 5 minutes
                self._check_jailed_validators()
        
        # Start background threads
        threading.Thread(target=epoch_processor, daemon=True).start()
        threading.Thread(target=validator_updater, daemon=True).start()
        threading.Thread(target=jail_checker, daemon=True).start()
    
    # BLOCKCHAIN COMPATIBILITY METHODS
    def validate_validator(self, address: str) -> bool:
        """Check if validator is active and valid - for blockchain compatibility"""
        with self.validator_lock:
            return (address in self.validators and 
                   self.validators[address].status == ValidatorStatus.ACTIVE)
    
    def validate_block(self, block: Any) -> bool:
        """Validate block for blockchain compatibility"""
        # Basic validation - check if validator exists and is active
        if not self.validate_validator(block.validator):
            return False
        # Additional validation can be added here
        return True
    
    def add_validator_simple(self, address: str, stake: int) -> bool:
        """Simple validator addition for blockchain compatibility"""
        # Generate a dummy public key for compatibility
        dummy_public_key = "dummy_public_key_" + address
        return self.register_validator(address, dummy_public_key, stake, 0.1)
    
    def update_total_stake(self):
        """Update total stake calculation"""
        with self.validator_lock:
            self.total_stake = sum(
                (v.staked_amount + v.total_delegated) 
                for v in self.validators.values()
            )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization - blockchain compatibility"""
        with self.validator_lock:
            self.update_total_stake()
            return {
                'validators': {addr: validator.to_dict() for addr, validator in self.validators.items()},
                'min_stake': self.min_stake,
                'total_stake': self.total_stake,
                'active_validators': [v.to_dict() for v in self.active_validators],
                'current_epoch': self.current_epoch,
                'compatibility_mode': self._compatibility_mode
            }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ProofOfStake':
        """Create from dictionary for deserialization - blockchain compatibility"""
        min_stake = data.get('min_stake', 1000)
        pos = cls(min_stake=min_stake)
        
        # Load validators
        validators_data = data.get('validators', {})
        for addr, validator_data in validators_data.items():
            pos.validators[addr] = Validator.from_dict(validator_data)
        
        # Load active validators
        active_data = data.get('active_validators', [])
        pos.active_validators = [Validator.from_dict(v) for v in active_data]
        
        pos.total_stake = data.get('total_stake', 0)
        pos.current_epoch = data.get('current_epoch', 0)
        pos._compatibility_mode = data.get('compatibility_mode', True)
        
        return pos
    
    def register_validator(self, address: str, public_key: str, stake_amount: int, 
                          commission_rate: float = 0.1) -> bool:
        """
        Register a new validator
        
        Args:
            address: Validator address
            public_key: Validator public key
            stake_amount: Amount of tokens to stake
            commission_rate: Commission rate (0.0 to 1.0)
        
        Returns:
            True if registration successful, False otherwise
        """
        with self.validator_lock:
            if address in self.validators:
                return False
            
            if stake_amount < self.min_stake:
                return False
            
            if commission_rate < 0 or commission_rate > 0.2:  # Max 20% commission
                return False
            
            validator = Validator(
                address=address,
                public_key=public_key,
                staked_amount=stake_amount,
                commission_rate=commission_rate,
                status=ValidatorStatus.PENDING,
                created_block_height=self.current_epoch * self.epoch_blocks
            )
            
            self.validators[address] = validator
            self.pending_validators.append(validator)
            self.total_stake += stake_amount  # UPDATE total_stake
            self._save_state()
            
            return True
    
    def delegate_tokens(self, delegator_address: str, validator_address: str, amount: int) -> bool:
        """
        Delegate tokens to a validator
        
        Args:
            delegator_address: Address of the delegator
            validator_address: Address of the validator
            amount: Amount of tokens to delegate
        
        Returns:
            True if delegation successful, False otherwise
        """
        with self.validator_lock:
            if validator_address not in self.validators:
                return False
            
            validator = self.validators[validator_address]
            
            if validator.status not in [ValidatorStatus.ACTIVE, ValidatorStatus.PENDING]:
                return False
            
            # Update delegation
            current_delegation = validator.delegators.get(delegator_address, 0)
            validator.delegators[delegator_address] = current_delegation + amount
            validator.total_delegated += amount
            self.total_stake += amount  # UPDATE total_stake
            
            self._save_state()
            return True
    
    def undelegate_tokens(self, delegator_address: str, validator_address: str, amount: int) -> bool:
        """
        Undelegate tokens from a validator
        
        Args:
            delegator_address: Address of the delegator
            validator_address: Address of the validator
            amount: Amount of tokens to undelegate
        
        Returns:
            True if undelegation successful, False otherwise
        """
        with self.validator_lock:
            if validator_address not in self.validators:
                return False
            
            validator = self.validators[validator_address]
            
            if delegator_address not in validator.delegators:
                return False
            
            current_delegation = validator.delegators[delegator_address]
            if amount > current_delegation:
                return False
            
            validator.delegators[delegator_address] = current_delegation - amount
            validator.total_delegated -= amount
            self.total_stake -= amount  # UPDATE total_stake
            
            if validator.delegators[delegator_address] == 0:
                del validator.delegators[delegator_address]
            
            self._save_state()
            return True
    
    def _update_validator_set(self):
        """Update the active validator set based on stake"""
        with self.validator_lock:
            # Sort validators by effective stake
            sorted_validators = sorted(
                [v for v in self.validators.values() 
                 if v.status in [ValidatorStatus.ACTIVE, ValidatorStatus.PENDING]],
                key=lambda x: x.effective_stake,
                reverse=True
            )
            
            # Select top validators up to max_validators
            new_active = sorted_validators[:self.max_validators]
            
            # Update statuses
            for validator in new_active:
                if validator.status == ValidatorStatus.PENDING:
                    validator.status = ValidatorStatus.ACTIVE
            
            for validator in sorted_validators[self.max_validators:]:
                if validator.status == ValidatorStatus.ACTIVE:
                    validator.status = ValidatorStatus.INACTIVE
            
            self.active_validators = new_active
            self._save_state()
    
    def _process_epoch_transition(self):
        """Process epoch transition and distribute rewards"""
        with self.lock:
            self.current_epoch += 1
            
            # Calculate total stake for reward distribution
            total_stake = sum(v.effective_stake for v in self.active_validators)
            if total_stake == 0:
                return
            
            # Distribute rewards (simplified - would come from block rewards)
            epoch_reward = 1000  # Fixed reward per epoch for demo
            
            for validator in self.active_validators:
                if validator.effective_stake > 0:
                    # Validator's share of rewards
                    validator_share = (validator.effective_stake / total_stake) * epoch_reward
                    
                    # Commission goes to validator
                    commission = validator_share * validator.commission_rate
                    validator.total_rewards += commission
                    
                    # Remainder goes to delegators proportionally
                    delegator_rewards = validator_share - commission
                    self._distribute_delegator_rewards(validator, delegator_rewards)
            
            self._save_state()
    
    def _distribute_delegator_rewards(self, validator: Validator, total_rewards: int):
        """Distribute rewards to delegators"""
        if validator.total_delegated == 0:
            return
        
        for delegator_address, delegated_amount in validator.delegators.items():
            delegator_share = (delegated_amount / validator.total_delegated) * total_rewards
            # In real implementation, this would transfer tokens to delegators
            # For now, just track in validator object
            if 'delegator_rewards' not in validator.__dict__:
                validator.delegator_rewards = {}
            validator.delegator_rewards[delegator_address] = \
                validator.delegator_rewards.get(delegator_address, 0) + delegator_share
    
    def _check_jailed_validators(self):
        """Check and release jailed validators"""
        current_time = time.time()
        
        with self.validator_lock:
            for validator in self.validators.values():
                if (validator.status == ValidatorStatus.JAILED and 
                    validator.jail_until and 
                    validator.jail_until <= current_time):
                    
                    validator.status = ValidatorStatus.ACTIVE
                    validator.jail_until = None
            
            self._save_state()
    
    def select_proposer(self, view_number: int, round_number: int) -> Optional[Validator]:
        """
        Select block proposer for current view and round
        
        Uses weighted random selection based on stake
        """
        with self.validator_lock:
            if not self.active_validators:
                return None
            
            total_stake = sum(v.effective_stake for v in self.active_validators)
            if total_stake == 0:
                return None
            
            # Deterministic selection based on view and round
            random_seed = hashlib.sha256(
                f"{view_number}_{round_number}_{self.current_epoch}".encode()
            ).digest()
            
            random_number = int.from_bytes(random_seed, 'big') % total_stake
            
            current_sum = 0
            for validator in self.active_validators:
                current_sum += validator.effective_stake
                if random_number < current_sum:
                    return validator
            
            return self.active_validators[-1]
    
    def propose_block(self, block_hash: str, validator_address: str, 
                     parent_hash: str, private_key: ec.EllipticCurvePrivateKey) -> Optional[BlockProposal]:
        """
        Create a block proposal
        
        Args:
            block_hash: Hash of the proposed block
            validator_address: Address of proposing validator
            parent_hash: Hash of parent block
            private_key: Validator's private key for signing
        
        Returns:
            Block proposal if successful, None otherwise
        """
        with self.lock:
            if self.state != ConsensusState.IDLE:
                return None
            
            if validator_address not in self.validators:
                return None
            
            validator = self.validators[validator_address]
            if validator.status != ValidatorStatus.ACTIVE:
                return None
            
            # Check if this validator is the proposer for current view/round
            expected_proposer = self.select_proposer(self.current_view, self.current_round)
            if not expected_proposer or expected_proposer.address != validator_address:
                return None
            
            # Create proposal
            proposal = BlockProposal(
                block_hash=block_hash,
                validator_address=validator_address,
                timestamp=time.time(),
                signature="",
                view_number=self.current_view,
                round_number=self.current_round,
                parent_hash=parent_hash
            )
            
            # Sign proposal
            signing_data = self._get_proposal_signing_data(proposal)
            signature = self._sign_data(signing_data, private_key)
            proposal.signature = signature
            
            self.block_proposals[block_hash] = proposal
            self.state = ConsensusState.PROPOSING
            self._save_state()
            
            return proposal
    
    def vote_for_proposal(self, block_hash: str, validator_address: str, 
                         vote_type: str, private_key: ec.EllipticCurvePrivateKey) -> Optional[Vote]:
        """
        Vote for a block proposal
        
        Args:
            block_hash: Hash of the block being voted on
            validator_address: Address of voting validator
            vote_type: Type of vote ('pre-vote', 'pre-commit', 'commit')
            private_key: Validator's private key for signing
        
        Returns:
            Vote object if successful, None otherwise
        """
        with self.lock:
            if block_hash not in self.block_proposals:
                return None
            
            if validator_address not in self.validators:
                return None
            
            validator = self.validators[validator_address]
            if validator.status != ValidatorStatus.ACTIVE:
                return None
            
            proposal = self.block_proposals[block_hash]
            
            # Create vote
            vote = Vote(
                block_hash=block_hash,
                validator_address=validator_address,
                timestamp=time.time(),
                signature="",
                view_number=proposal.view_number,
                round_number=proposal.round_number,
                vote_type=vote_type
            )
            
            # Sign vote
            signing_data = self._get_vote_signing_data(vote)
            signature = self._sign_data(signing_data, private_key)
            vote.signature = signature
            
            # Store vote
            if block_hash not in self.votes:
                self.votes[block_hash] = []
            self.votes[block_hash].append(vote)
            
            # Check if we have enough votes to commit
            if self._check_vote_threshold(block_hash, vote_type):
                self.state = ConsensusState.COMMITTING
                self.executed_blocks.add(block_hash)
                
                # Update validator stats
                validator.last_active = time.time()
                validator.uptime = min(100.0, validator.uptime + 0.1)
            
            self._save_state()
            return vote
    
    def _check_vote_threshold(self, block_hash: str, vote_type: str) -> bool:
        """Check if vote threshold is reached for commitment"""
        if block_hash not in self.votes:
            return False
        
        votes = self.votes[block_hash]
        type_votes = [v for v in votes if v.vote_type == vote_type]
        
        # Need 2/3 of voting power for Byzantine Fault Tolerance
        total_voting_power = sum(v.voting_power for v in self.active_validators)
        voted_power = sum(self.validators[v.validator_address].voting_power 
                         for v in type_votes if v.validator_address in self.validators)
        
        return voted_power > (2 * total_voting_power) / 3
    
    def slash_validator(self, validator_address: str, evidence: Dict, reporter: str) -> bool:
        """
        Slash a validator for misbehavior
        
        Args:
            validator_address: Address of validator to slash
            evidence: Evidence of misbehavior
            reporter: Address of the reporter
        
        Returns:
            True if slashing successful, False otherwise
        """
        with self.validator_lock:
            if validator_address not in self.validators:
                return False
            
            validator = self.validators[validator_address]
            
            # Verify evidence (simplified)
            if not self._validate_evidence(evidence, validator):
                return False
            
            # Calculate slash amount
            slash_amount = int(validator.total_stake * self.slash_percentage)
            
            # Apply slashing
            if validator.staked_amount >= slash_amount:
                validator.staked_amount -= slash_amount
            else:
                # Also slash delegations proportionally if needed
                remaining_slash = slash_amount - validator.staked_amount
                validator.staked_amount = 0
                
                total_delegated = validator.total_delegated
                for delegator_address in list(validator.delegators.keys()):
                    delegation = validator.delegators[delegator_address]
                    delegator_slash = int((delegation / total_delegated) * remaining_slash)
                    validator.delegators[delegator_address] = delegation - delegator_slash
                    validator.total_delegated -= delegator_slash
            
            # Jail validator
            validator.status = ValidatorStatus.JAILED
            validator.jail_until = time.time() + self.jail_duration
            validator.slashing_count += 1
            
            # Reward reporter (small percentage of slashed amount)
            reporter_reward = int(slash_amount * 0.1)
            # In real implementation, this would transfer tokens to reporter
            
            self._update_validator_set()
            self._save_state()
            
            return True
    
    def _validate_evidence(self, evidence: Dict, validator: Validator) -> bool:
        """Validate slashing evidence"""
        # This would verify cryptographic evidence of double-signing or other violations
        # For now, return True for demonstration
        return True
    
    def _get_proposal_signing_data(self, proposal: BlockProposal) -> str:
        """Get data to sign for block proposal"""
        return json.dumps({
            'block_hash': proposal.block_hash,
            'validator_address': proposal.validator_address,
            'timestamp': proposal.timestamp,
            'view_number': proposal.view_number,
            'round_number': proposal.round_number,
            'parent_hash': proposal.parent_hash
        }, sort_keys=True)
    
    def _get_vote_signing_data(self, vote: Vote) -> str:
        """Get data to sign for vote"""
        return json.dumps({
            'block_hash': vote.block_hash,
            'validator_address': vote.validator_address,
            'timestamp': vote.timestamp,
            'view_number': vote.view_number,
            'round_number': vote.round_number,
            'vote_type': vote.vote_type
        }, sort_keys=True)
    
    def _sign_data(self, data: str, private_key: ec.EllipticCurvePrivateKey) -> str:
        """Sign data with private key"""
        signature = private_key.sign(
            data.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return signature.hex()
    
    def verify_signature(self, data: str, signature: str, public_key: str) -> bool:
        """Verify signature with public key"""
        try:
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), bytes.fromhex(public_key)
            )
            pub_key.verify(
                bytes.fromhex(signature),
                data.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except (InvalidSignature, ValueError):
            return False
    
    def get_validator_info(self, address: str) -> Optional[Dict]:
        """Get detailed validator information"""
        with self.validator_lock:
            if address not in self.validators:
                return None
            
            validator = self.validators[address]
            return validator.to_dict()
    
    def get_consensus_state(self) -> Dict:
        """Get current consensus state"""
        with self.lock:
            return {
                'state': self.state.name,
                'current_epoch': self.current_epoch,
                'current_view': self.current_view,
                'current_round': self.current_round,
                'active_validators': len(self.active_validators),
                'total_validators': len(self.validators),
                'total_stake': sum(v.total_stake for v in self.validators.values()),
                'pending_proposals': len(self.block_proposals),
                'locked_blocks': len(self.locked_blocks),
                'executed_blocks': len(self.executed_blocks)
            }
    
    def process_view_change(self):
        """Process view change when consensus stalls"""
        with self.lock:
            if self.state in [ConsensusState.VIEW_CHANGE, ConsensusState.RECOVERY]:
                return
            
            self.state = ConsensusState.VIEW_CHANGE
            self.current_view += 1
            self.current_round = 0
            
            # Clear old proposals and votes
            self.block_proposals.clear()
            self.votes.clear()
            
            self._save_state()
    
    def recover_from_fork(self, new_chain: List[str]):
        """Recover from chain fork"""
        with self.lock:
            self.state = ConsensusState.RECOVERY
            
            # Reset consensus state based on new chain
            self.block_proposals.clear()
            self.votes.clear()
            self.locked_blocks.clear()
            self.executed_blocks.clear()
            
            # Reinitialize from new chain state
            # This would involve complex recovery logic in real implementation
            
            self.state = ConsensusState.IDLE
            self._save_state()

# Advanced BFT Consensus with pipelining
class BFTConsensus(ProofOfStake):
    """Byzantine Fault Tolerant consensus with pipelining"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pipeline_depth = 3
        self.pending_blocks: Dict[int, List[str]] = {}  # height -> block_hashes
        self.finalized_blocks: Set[str] = set()
    
    def pipeline_propose(self, block_hashes: List[str], validator_address: str,
                        private_key: ec.EllipticCurvePrivateKey) -> List[BlockProposal]:
        """Propose multiple blocks in pipeline"""
        proposals = []
        current_height = self.current_epoch * self.epoch_blocks
        
        for i, block_hash in enumerate(block_hashes):
            if i >= self.pipeline_depth:
                break
            
            height = current_height + i
            proposal = self.propose_block(
                block_hash, validator_address, f"parent_{height}", private_key
            )
            if proposal:
                proposals.append(proposal)
                if height not in self.pending_blocks:
                    self.pending_blocks[height] = []
                self.pending_blocks[height].append(block_hash)
        
        return proposals
    
    def pipeline_vote(self, block_hashes: List[str], validator_address: str,
                     private_key: ec.EllipticCurvePrivateKey) -> List[Vote]:
        """Vote for multiple blocks in pipeline"""
        votes = []
        
        for block_hash in block_hashes:
            vote = self.vote_for_proposal(
                block_hash, validator_address, 'pre-commit', private_key
            )
            if vote:
                votes.append(vote)
        
        return votes

# Utility functions
def create_validator_keypair() -> Tuple[str, str]:
    """Create validator key pair"""
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ).hex()
    private_key_hex = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    return private_key_hex, public_key

def calculate_voting_power(stake: int, age: int, uptime: float) -> int:
    """Calculate voting power considering stake, age, and uptime"""
    # Weight factors
    stake_weight = 0.7
    age_weight = 0.2
    uptime_weight = 0.1
    
    # Normalize factors
    normalized_stake = min(stake / 1000000, 1.0)  # Cap at 1M tokens
    normalized_age = min(age / 10000, 1.0)  # Cap at 10K blocks
    normalized_uptime = uptime / 100.0
    
    voting_power = int((
        normalized_stake * stake_weight +
        normalized_age * age_weight +
        normalized_uptime * uptime_weight
    ) * 1000)  # Scale to integer
    
    return max(100, voting_power)  # Minimum voting power

# Example usage
if __name__ == "__main__":
    # Test consensus system
    consensus = ProofOfStake(min_stake=1000, max_validators=5)
    
    # Create validator key pairs
    priv1, pub1 = create_validator_keypair()
    priv2, pub2 = create_validator_keypair()
    
    # Register validators
    consensus.register_validator("val1", pub1, 5000, 0.1)
    consensus.register_validator("val2", pub2, 8000, 0.15)
    
    # Update validator set
    consensus._update_validator_set()
    
    # Get consensus state
    state = consensus.get_consensus_state()
    print(f"Consensus State: {state}")
    
    # Test block proposal
    block_hash = "test_block_hash_123"
    proposal = consensus.propose_block(block_hash, "val1", "parent_hash", 
                                     ec.derive_private_key(int(priv1, 16), ec.SECP256K1()))
    
    if proposal:
        print(f"Block proposed: {proposal.block_hash}")
    
    # Test voting
    vote = consensus.vote_for_proposal(block_hash, "val2", "pre-commit",
                                     ec.derive_private_key(int(priv2, 16), ec.SECP256K1()))
    
    if vote:
        print(f"Vote cast: {vote.block_hash}")