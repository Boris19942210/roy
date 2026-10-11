"""
ROY DHT: Kademlia-подобная распределённая хеш-таблица.
"""

import time
from dataclasses import dataclass
from typing import Optional

from .crypto import sha256
from .packet import Packet, PacketType


K = 20
ALPHA = 3
BUCKETS = 256


def xor_distance(a: bytes, b: bytes) -> int:
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


def bucket_index(node_id: bytes, other_id: bytes) -> int:
    distance = xor_distance(node_id, other_id)
    if distance == 0:
        return 0
    return distance.bit_length() - 1


@dataclass
class DHTEntry:
    key: bytes
    value: bytes
    owner_node_id: bytes
    signature: bytes
    timestamp: float
    ttl: float
    expires_at: float


@dataclass
class PeerInfo:
    node_id: bytes
    address: str
    transport: str
    last_seen: float
    rtt_ms: float = 0
    success_rate: float = 1.0
    
    def is_alive(self, timeout: float = 300) -> bool:
        return time.time() - self.last_seen < timeout


class RoutingTable:
    """Таблица маршрутизации Kademlia."""
    
    def __init__(self, node_id: bytes):
        self.node_id = node_id
        self.buckets: list[list[PeerInfo]] = [[] for _ in range(BUCKETS)]
        self.all_peers: dict[bytes, PeerInfo] = {}
    
    def add_peer(self, peer: PeerInfo) -> bool:
        if peer.node_id == self.node_id:
            return False
        
        if peer.node_id in self.all_peers:
            old = self.all_peers[peer.node_id]
            old.last_seen = peer.last_seen
            old.rtt_ms = peer.rtt_ms
            old.address = peer.address
            idx = bucket_index(self.node_id, peer.node_id)
            bucket = self.buckets[idx]
            for i, p in enumerate(bucket):
                if p.node_id == peer.node_id:
                    bucket.pop(i)
                    bucket.append(p)
                    break
            return True
        
        idx = bucket_index(self.node_id, peer.node_id)
        bucket = self.buckets[idx]
        
        if len(bucket) < K:
            bucket.append(peer)
            self.all_peers[peer.node_id] = peer
            return True
        else:
            oldest = bucket[0]
            if not oldest.is_alive():
                bucket.pop(0)
                bucket.append(peer)
                self.all_peers.pop(oldest.node_id, None)
                self.all_peers[peer.node_id] = peer
                return True
            return False
    
    def get_peer(self, node_id: bytes) -> Optional[PeerInfo]:
        return self.all_peers.get(node_id)
    
    def get_closest(self, target_id: bytes, count: int = K) -> list[PeerInfo]:
        peers = list(self.all_peers.values())
        peers.sort(key=lambda p: xor_distance(p.node_id, target_id))
        return peers[:count]
    
    def size(self) -> int:
        return len(self.all_peers)


class DHT:
    """Распределённая хеш-таблица."""
    
    def __init__(self, node_id: bytes, routing_table: RoutingTable):
        self.node_id = node_id
        self.routing_table = routing_table
        self.storage: dict[bytes, DHTEntry] = {}
    
    def put(self, key: bytes, value: bytes, owner_keypair, ttl: float = 86400) -> bytes:
        if len(key) != 32:
            key = sha256(key)
        
        signature = owner_keypair.sign(key + value)
        
        entry = DHTEntry(
            key=key,
            value=value,
            owner_node_id=owner_keypair.node_id,
            signature=signature,
            timestamp=time.time(),
            ttl=ttl,
            expires_at=time.time() + ttl
        )
        
        self.storage[key] = entry
        return key
    
    def get(self, key: bytes) -> Optional[DHTEntry]:
        if len(key) != 32:
            key = sha256(key)
        
        if key in self.storage:
            entry = self.storage[key]
            if entry.expires_at > time.time():
                return entry
            else:
                del self.storage[key]
        
        return None
    
    def cleanup_expired(self):
        now = time.time()
        for key, entry in list(self.storage.items()):
            if entry.expires_at < now:
                del self.storage[key]