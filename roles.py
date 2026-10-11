"""
ROY Roles: Роли узлов и их возможности.
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional


class NodeRole(Enum):
    """Роль узла в сети."""
    LEAF = "leaf"              # Только клиент
    PARTIAL = "partial"        # Участвует в DHT
    RELAY = "relay"            # Пересылает трафик
    RENDEZVOUS = "rendezvous"  # Помогает NAT traversal
    STORAGE = "storage"        # Хранит данные


@dataclass
class Capabilities:
    """Возможности узла."""
    can_relay: bool = False
    can_store: bool = False
    can_rendezvous: bool = False
    max_connections: int = 5
    bandwidth_upload_kbps: int = 50
    bandwidth_download_kbps: int = 100
    storage_bytes: int = 0
    cpu_cores: int = 1
    ram_mb: int = 512
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @staticmethod
    def from_dict(data: dict) -> "Capabilities":
        return Capabilities(**data)


@dataclass
class NodeInfo:
    """Полная информация об узле."""
    node_id: bytes
    role: NodeRole
    capabilities: Capabilities
    address: str = ""          # "ip:port"
    transport: str = "udp"
    public_key: bytes = b""
    last_seen: float = 0
    version: str = "0.2.0"
    
    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id.hex(),
            "role": self.role.value,
            "capabilities": self.capabilities.to_dict(),
            "address": self.address,
            "transport": self.transport,
            "public_key": self.public_key.hex(),
            "last_seen": self.last_seen,
            "version": self.version,
        }
    
    @staticmethod
    def from_dict(data: dict) -> "NodeInfo":
        return NodeInfo(
            node_id=bytes.fromhex(data["node_id"]),
            role=NodeRole(data["role"]),
            capabilities=Capabilities.from_dict(data["capabilities"]),
            address=data.get("address", ""),
            transport=data.get("transport", "udp"),
            public_key=bytes.fromhex(data.get("public_key", "")),
            last_seen=data.get("last_seen", 0),
            version=data.get("version", "0.2.0"),
        )


class RoleManager:
    """Определяет и обновляет роль узла."""
    
    def __init__(self, node):
        self.node = node
        self.current_role = NodeRole.LEAF
        self.capabilities = Capabilities()
    
    def detect_capabilities(self) -> Capabilities:
        """Автоматически определяет возможности."""
        caps = Capabilities()
        
        # Определяем ресурсы
        try:
            import psutil
            caps.cpu_cores = psutil.cpu_count() or 1
            caps.ram_mb = psutil.virtual_memory().total // (1024 * 1024)
            caps.storage_bytes = psutil.disk_usage("/").free
        except ImportError:
            pass
        
        # Логика определения
        if caps.cpu_cores >= 4 and caps.ram_mb >= 4096:
            caps.can_relay = True
            caps.max_connections = 50
            caps.bandwidth_upload_kbps = 10000
        
        if caps.storage_bytes >= 100 * 1024 * 1024 * 1024:  # 100 GB
            caps.can_store = True
        
        return caps
    
    def update_role(self, cpu_usage: float, battery: Optional[float] = None) -> NodeRole:
        """Обновляет роль на основе ресурсов."""
        caps = self.capabilities
        
        # Телефон с низкой батареей
        if battery is not None and battery < 0.20:
            self.current_role = NodeRole.LEAF
            caps.max_connections = 2
            caps.bandwidth_upload_kbps = 0
            return self.current_role
        
        # Высокая загрузка CPU
        if cpu_usage > 0.70:
            self.current_role = NodeRole.PARTIAL
            caps.max_connections = 5
            return self.current_role
        
        # Низкая загрузка + мощное железо
        if cpu_usage < 0.10 and caps.can_relay:
            self.current_role = NodeRole.RELAY
            caps.max_connections = 50
            return self.current_role
        
        # Средние ресурсы
        if caps.can_store and cpu_usage < 0.30:
            self.current_role = NodeRole.STORAGE
            return self.current_role
        
        self.current_role = NodeRole.PARTIAL
        return self.current_role
    
    def get_announcement(self) -> dict:
        """Создаёт объявление о себе."""
        return {
            "node_id": self.node.node_id.hex(),
            "role": self.current_role.value,
            "capabilities": self.capabilities.to_dict(),
            "version": "0.2.0",
        }