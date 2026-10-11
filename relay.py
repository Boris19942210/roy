"""
ROY Relay: Ретрансляция трафика между узлами.

Используется, когда прямое соединение невозможно (симметричный NAT).

Безопасность:
- Relay видит только зашифрованные пакеты
- Relay не может подделать пакеты (все подписаны)
- Relay может взимать плату за трафик
"""

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

from .crypto import sha256
from .packet import Packet, PacketType


@dataclass
class RelaySession:
    """Сессия ретрансляции между двумя узлами."""
    session_id: bytes
    initiator_id: bytes
    target_id: bytes
    initiator_addr: tuple[str, int]
    target_addr: Optional[tuple[str, int]] = None
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    bytes_relayed: int = 0
    packets_relayed: int = 0
    
    def is_expired(self, timeout: float = 300) -> bool:
        return time.time() - self.last_activity > timeout


class RelayNode:
    """
    Узел-ретранслятор.
    
    Принимает RELAY-запросы, устанавливает сессии,
    пересылает RELAY_DATA пакеты между узлами.
    """
    
    def __init__(self, node_id: bytes, socket: socket.socket):
        self.node_id = node_id
        self.socket = socket
        self.sessions: dict[bytes, RelaySession] = {}
        self.stats = {
            "total_sessions": 0,
            "total_bytes": 0,
            "total_packets": 0,
            "active_sessions": 0,
        }
    
    def create_session(
        self,
        initiator_id: bytes,
        target_id: bytes,
        initiator_addr: tuple[str, int]
    ) -> bytes:
        """Создаёт новую relay-сессию."""
        session_id = sha256(
            initiator_id + target_id + str(time.time()).encode()
        )
        
        session = RelaySession(
            session_id=session_id,
            initiator_id=initiator_id,
            target_id=target_id,
            initiator_addr=initiator_addr
        )
        
        self.sessions[session_id] = session
        self.stats["total_sessions"] += 1
        self.stats["active_sessions"] += 1
        
        return session_id
    
    def handle_relay_request(
        self,
        packet: Packet,
        from_addr: tuple[str, int]
    ) -> Optional[bytes]:
        """
        Обрабатывает RELAY-запрос от узла.
        
        payload: target_node_id (32B)
        Returns: session_id
        """
        if len(packet.payload) < 32:
            return None
        
        target_id = packet.payload[:32]
        initiator_id = packet.src_node_id
        
        session_id = self.create_session(initiator_id, target_id, from_addr)
        
        # Отправляем ответ с session_id
        response = Packet(
            packet_type=PacketType.RELAY,
            src_node_id=self.node_id,
            dst_node_id=initiator_id,
            payload=session_id
        )
        
        try:
            self.socket.sendto(response.serialize(), from_addr)
        except Exception as e:
            print(f"[Relay] Ошибка отправки ответа: {e}")
            return None
        
        return session_id
    
    def handle_relay_data(self, packet: Packet, from_addr: tuple[str, int]):
        """
        Обрабатывает RELAY_DATA.
        
        payload: session_id (32B) + encrypted_data
        """
        if len(packet.payload) < 32:
            return
        
        session_id = packet.payload[:32]
        data = packet.payload[32:]
        
        session = self.sessions.get(session_id)
        if session is None:
            return
        
        # Обновляем активность
        session.last_activity = time.time()
        session.bytes_relayed += len(data)
        session.packets_relayed += 1
        self.stats["total_bytes"] += len(data)
        self.stats["total_packets"] += 1
        
        # Определяем, куда пересылать
        if packet.src_node_id == session.initiator_id:
            # От инициатора → к цели
            if session.target_addr:
                self._forward(packet, session.target_addr)
            else:
                # Цель ещё не подключилась
                # Пытаемся отправить на последний известный адрес
                pass
        elif packet.src_node_id == session.target_id:
            # От цели → к инициатору
            # Обновляем адрес цели
            session.target_addr = from_addr
            self._forward(packet, session.initiator_addr)
    
    def _forward(self, packet: Packet, addr: tuple[str, int]):
        """Пересылает пакет."""
        try:
            forwarded = Packet(
                packet_type=packet.packet_type,
                src_node_id=packet.src_node_id,
                dst_node_id=packet.dst_node_id,
                payload=packet.payload,
                ttl=packet.ttl - 1,
                hop_count=packet.hop_count + 1,
                signature=packet.signature,
                payload_hash=packet.payload_hash
            )
            
            self.socket.sendto(forwarded.serialize(), addr)
        except Exception as e:
            print(f"[Relay] Ошибка пересылки: {e}")
    
    def cleanup_sessions(self, timeout: float = 300):
        """Удаляет просроченные сессии."""
        now = time.time()
        expired = []
        
        for sid, session in self.sessions.items():
            if session.is_expired(timeout):
                expired.append(sid)
        
        for sid in expired:
            del self.sessions[sid]
            self.stats["active_sessions"] -= 1
        
        return len(expired)
    
    def get_stats(self) -> dict:
        return self.stats.copy()


class RelayClient:
    """
    Клиент для использования relay.
    Позволяет узлу отправлять данные через ретранслятор.
    """
    
    def __init__(self, node_id: bytes, socket: socket.socket):
        self.node_id = node_id
        self.socket = socket
        self.relay_nodes: list[tuple[bytes, tuple[str, int]]] = []
        self.active_sessions: dict[bytes, tuple[bytes, tuple[str, int]]] = {}
        self.pending_sessions: dict[bytes, asyncio.Event] = {}
    
    def add_relay(self, node_id: bytes, addr: tuple[str, int]):
        """Добавляет известный relay-узел."""
        self.relay_nodes.append((node_id, addr))
    
    def get_available_relay(self) -> Optional[tuple[bytes, tuple[str, int]]]:
        """Возвращает случайный relay."""
        if not self.relay_nodes:
            return None
        import random
        return random.choice(self.relay_nodes)
    
    async def request_session(
        self,
        target_node_id: bytes,
        timeout: float = 10
    ) -> Optional[bytes]:
        """
        Запрашивает relay-сессию.
        Returns: session_id
        """
        relay = self.get_available_relay()
        if relay is None:
            return None
        
        relay_id, relay_addr = relay
        
        request = Packet(
            packet_type=PacketType.RELAY,
            src_node_id=self.node_id,
            dst_node_id=relay_id,
            payload=target_node_id
        )
        
        try:
            self.socket.sendto(request.serialize(), relay_addr)
        except Exception as e:
            print(f"[RelayClient] Ошибка запроса: {e}")
            return None
        
        # Ждём ответ
        event = asyncio.Event()
        self.pending_sessions[target_node_id] = event
        
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            
            # Проверяем, получили ли session_id
            if target_node_id in self.active_sessions:
                return target_node_id
        except asyncio.TimeoutError:
            pass
        
        return None
    
    def handle_relay_response(self, packet: Packet, from_addr: tuple[str, int]):
        """
        Обрабатывает RELAY-ответ с session_id.
        
        payload: session_id (32B)
        """
        if len(packet.payload) < 32:
            return
        
        session_id = packet.payload[:32]
        relay_id = packet.src_node_id
        
        # Сохраняем сессию
        # Ключ — session_id, значение — (relay_id, relay_addr)
        self.active_sessions[session_id] = (relay_id, from_addr)
        
        # Оповещаем ожидающих
        for target_id, event in self.pending_sessions.items():
            event.set()
    
    def send_via_relay(
        self,
        session_id: bytes,
        target_id: bytes,
        data: bytes
    ) -> bool:
        """Отправляет данные через relay."""
        if session_id not in self.active_sessions:
            return False
        
        relay_id, relay_addr = self.active_sessions[session_id]
        
        packet = Packet(
            packet_type=PacketType.RELAY_DATA,
            src_node_id=self.node_id,
            dst_node_id=target_id,
            payload=session_id + data
        )
        
        try:
            self.socket.sendto(packet.serialize(), relay_addr)
            return True
        except Exception as e:
            print(f"[RelayClient] Ошибка отправки: {e}")
            return False
    
    def cleanup_sessions(self, timeout: float = 600):
        """Удаляет неактивные сессии."""
        # В реальной реализации — проверка времени последней активности
        pass


# ============ Тест ============

async def test_relay():
    """Симуляция relay на localhost."""
    print("=== Симуляция Relay ===")
    
    sock_relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_relay.bind(("127.0.0.1", 42001))
    sock_relay.setblocking(False)
    
    sock_alice = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_alice.bind(("127.0.0.1", 42002))
    sock_alice.setblocking(False)
    
    sock_bob = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_bob.bind(("127.0.0.1", 42003))
    sock_bob.setblocking(False)
    
    alice_id = sha256(b"alice")
    bob_id = sha256(b"bob")
    relay_id = sha256(b"relay")
    
    relay_node = RelayNode(relay_id, sock_relay)
    
    # Alice запрашивает сессию
    request = Packet(
        packet_type=PacketType.RELAY,
        src_node_id=alice_id,
        dst_node_id=relay_id,
        payload=bob_id
    )
    
    sock_alice.sendto(request.serialize(), ("127.0.0.1", 42001))
    
    # Даём время на обработку
    await asyncio.sleep(0.1)
    
    # Relay обрабатывает
    try:
        data, addr = sock_relay.recvfrom(65536)
        packet = Packet.deserialize(data)
        session_id = relay_node.handle_relay_request(packet, addr)
        
        if session_id:
            print(f"[OK] Сессия создана: {session_id[:8].hex()}...")
            print(f"[OK] Активных сессий: {relay_node.stats['active_sessions']}")
    except BlockingIOError:
        print("[!] Нет данных для обработки")
    
    sock_alice.close()
    sock_bob.close()
    sock_relay.close()


if __name__ == "__main__":
    asyncio.run(test_relay())