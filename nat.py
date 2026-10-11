"""
ROY NAT: UDP Hole Punching через rendezvous узел.

Алгоритм:
1. Alice отправляет CONNECT_REQUEST rendezvous с NodeID Боба
2. Rendezvous отправляет PUNCH_REQUEST Бобу с адресом Алисы
3. Bob отправляет UDP-пакет на адрес Алисы (открывает дырку в своём NAT)
4. Rendezvous отправляет PUNCH_ACK Алисе с адресом Боба
5. Alice отправляет UDP-пакет на адрес Боба (открывает дырку в своём NAT)
6. Прямое соединение установлено
"""

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

from .crypto import sha256
from .packet import Packet, PacketType


@dataclass
class RendezvousInfo:
    """Информация о rendezvous узле."""
    node_id: bytes
    address: str  # "ip:port"
    port: int = 0
    last_seen: float = field(default_factory=time.time)
    
    @property
    def addr_tuple(self) -> tuple[str, int]:
        if self.port:
            return (self.address, self.port)
        ip, port = self.address.rsplit(":", 1)
        return (ip, int(port))


@dataclass
class PendingConnection:
    """Ожидающая соединение."""
    target_id: bytes
    event: asyncio.Event
    result: Optional[tuple[str, int]] = None
    created_at: float = field(default_factory=time.time)
    
    def is_expired(self, timeout: float = 30) -> bool:
        return time.time() - self.created_at > timeout


class UDPHolePuncher:
    """
    Реализует UDP hole punching через третьего узла (rendezvous).
    """
    
    def __init__(self, node_id: bytes, socket: socket.socket):
        self.node_id = node_id
        self.socket = socket
        self.rendezvous_nodes: list[RendezvousInfo] = []
        self.pending_connections: dict[bytes, PendingConnection] = {}
        self.active_connections: dict[bytes, tuple[str, int]] = {}
        self.stats = {
            "punch_attempts": 0,
            "punch_successes": 0,
            "punch_failures": 0,
        }
    
    def add_rendezvous(self, node_id: bytes, address: str, port: int = 0):
        """Добавляет известный rendezvous узел."""
        info = RendezvousInfo(node_id=node_id, address=address, port=port)
        self.rendezvous_nodes.append(info)
    
    def get_available_rendezvous(self) -> Optional[RendezvousInfo]:
        """Возвращает случайный живой rendezvous."""
        alive = [r for r in self.rendezvous_nodes 
                 if time.time() - r.last_seen < 300]
        if not alive:
            return None
        import random
        return random.choice(alive)
    
    async def connect_to(
        self,
        target_node_id: bytes,
        rendezvous: Optional[RendezvousInfo] = None,
        timeout: float = 30
    ) -> Optional[tuple[str, int]]:
        """
        Устанавливает прямое UDP-соединение с target_node_id.
        Returns: (ip, port) или None если не удалось.
        """
        if rendezvous is None:
            rendezvous = self.get_available_rendezvous()
        
        if rendezvous is None:
            return None
        
        self.stats["punch_attempts"] += 1
        
        # Создаём ожидание
        pending = PendingConnection(
            target_id=target_node_id,
            event=asyncio.Event()
        )
        self.pending_connections[target_node_id] = pending
        
        # Шаг 1: Отправляем CONNECT_REQUEST rendezvous
        request = Packet(
            packet_type=PacketType.CONNECT_REQUEST,
            src_node_id=self.node_id,
            dst_node_id=rendezvous.node_id,
            payload=target_node_id  # 32 байта
        )
        
        self._send_packet(rendezvous.addr_tuple, request)
        
        # Шаг 2: Ждём PUNCH_ACK от rendezvous или PUNCH_ACK от target
        try:
            await asyncio.wait_for(pending.event.wait(), timeout=timeout)
            
            if pending.result:
                self.stats["punch_successes"] += 1
                self.active_connections[target_node_id] = pending.result
                return pending.result
            else:
                self.stats["punch_failures"] += 1
                return None
                
        except asyncio.TimeoutError:
            self.stats["punch_failures"] += 1
            self.pending_connections.pop(target_node_id, None)
            return None
    
    def handle_connect_request(self, packet: Packet, from_addr: tuple[str, int]):
        """
        Мы — rendezvous. Обрабатываем CONNECT_REQUEST от Alice.
        
        payload: target_node_id (32 байта)
        """
        if len(packet.payload) < 32:
            return
        
        target_id = packet.payload[:32]
        requester_id = packet.src_node_id
        requester_addr_str = f"{from_addr[0]}:{from_addr[1]}"
        
        # Ищем адрес целевого узла
        target_addr = self._get_peer_address(target_id)
        
        if target_addr is None:
            # Не знаем адрес — не можем помочь
            # Отправляем отрицательный PUNCH_ACK
            self._send_punch_ack(
                requester_id,
                requester_addr_str,
                success=False
            )
            return
        
        # Отправляем PUNCH_REQUEST целевому узлу
        punch_payload = requester_id + requester_addr_str.encode("utf-8")
        
        punch = Packet(
            packet_type=PacketType.PUNCH_REQUEST,
            src_node_id=self.node_id,
            dst_node_id=target_id,
            payload=punch_payload
        )
        
        self._send_packet(target_addr, punch)
        
        # Также отправляем PUNCH_ACK инициатору с адресом цели
        target_addr_str = f"{target_addr[0]}:{target_addr[1]}"
        self._send_punch_ack(
            requester_id,
            target_addr_str,
            success=True
        )
    
    def handle_punch_request(self, packet: Packet, from_addr: tuple[str, int]):
        """
        Мы — целевой узел (Bob). Обрабатываем PUNCH_REQUEST от rendezvous.
        
        payload: requester_node_id (32B) + requester_addr_str (UTF-8)
        """
        if len(packet.payload) < 32:
            return
        
        requester_id = packet.payload[:32]
        requester_addr_str = packet.payload[32:].decode("utf-8")
        
        try:
            requester_ip, requester_port = requester_addr_str.rsplit(":", 1)
            requester_port = int(requester_port)
        except ValueError:
            return
        
        # Отправляем "punch" пакет на адрес инициатора
        # Это открывает дырку в нашем NAT
        punch_ack = Packet(
            packet_type=PacketType.PUNCH_ACK,
            src_node_id=self.node_id,
            dst_node_id=requester_id,
            payload=b"PUNCH"
        )
        
        try:
            self.socket.sendto(
                punch_ack.serialize(),
                (requester_ip, requester_port)
            )
            
            # Отправляем несколько пакетов для надёжности
            for _ in range(3):
                self.socket.sendto(
                    punch_ack.serialize(),
                    (requester_ip, requester_port)
                )
                
        except Exception as e:
            print(f"[NAT] Ошибка отправки punch-пакета: {e}")
    
    def handle_punch_ack(self, packet: Packet, from_addr: tuple[str, int]):
        """
        Обрабатывает PUNCH_ACK от rendezvous или от целевого узла.
        
        Если от rendezvous: payload = target_addr_str (UTF-8)
        Если от target: это значит, что дырка открыта
        """
        target_id = packet.src_node_id
        
        if target_id in self.pending_connections:
            pending = self.pending_connections[target_id]
            
            # Проверяем, от кого пришёл пакет
            if packet.payload == b"PUNCH":
                # Это punch от целевого узла
                # Значит, дырка открыта с обеих сторон
                pending.result = from_addr
            else:
                # Это ответ от rendezvous с адресом цели
                try:
                    addr_str = packet.payload.decode("utf-8")
                    ip, port = addr_str.rsplit(":", 1)
                    pending.result = (ip, int(port))
                except:
                    pending.result = from_addr
            
            pending.event.set()
            self.pending_connections.pop(target_id, None)
    
    def _send_punch_ack(self, target_id: bytes, addr_str: str, success: bool):
        """Отправляет PUNCH_ACK (мы — rendezvous)."""
        if success:
            payload = addr_str.encode("utf-8")
        else:
            payload = b"FAILED"
        
        packet = Packet(
            packet_type=PacketType.PUNCH_ACK,
            src_node_id=self.node_id,
            dst_node_id=target_id,
            payload=payload
        )
        
        try:
            ip, port = addr_str.rsplit(":", 1)
            self._send_packet((ip, int(port)), packet)
        except:
            pass
    
    def _get_peer_address(self, node_id: bytes) -> Optional[tuple[str, int]]:
        """
        Возвращает адрес узла.
        В полной реализации интегрируется с RoutingTable.
        Здесь — заглушка, которую нужно связать с routing_table.
        """
        # TODO: Интегрировать с RoutingTable
        # peer = self.routing_table.get_peer(node_id)
        # if peer:
        #     ip, port = peer.address.rsplit(":", 1)
        #     return (ip, int(port))
        return None
    
    def set_peer_lookup(self, lookup_func):
        """
        Устанавливает функцию для поиска адресов узлов.
        lookup_func(node_id: bytes) -> Optional[tuple[str, int]]
        """
        self._lookup_func = lookup_func
    
    def _get_peer_address(self, node_id: bytes) -> Optional[tuple[str, int]]:
        """Возвращает адрес узла через lookup-функцию."""
        if hasattr(self, "_lookup_func") and self._lookup_func:
            return self._lookup_func(node_id)
        return None
    
    def _send_packet(self, addr: tuple[str, int], packet: Packet):
        """Отправляет пакет по UDP."""
        try:
            data = packet.serialize()
            self.socket.sendto(data, addr)
        except Exception as e:
            print(f"[NAT] Ошибка отправки: {e}")
    
    def cleanup_pending(self, timeout: float = 60):
        """Удаляет просроченные ожидания."""
        now = time.time()
        expired = []
        
        for target_id, pending in self.pending_connections.items():
            if now - pending.created_at > timeout:
                expired.append(target_id)
        
        for target_id in expired:
            self.pending_connections.pop(target_id, None)
    
    def get_stats(self) -> dict:
        return self.stats.copy()


# ============ Тест ============

async def test_hole_punching():
    """Симуляция UDP hole punching на localhost."""
    print("=== Симуляция UDP Hole Punching ===")
    
    # Создаём сокеты
    sock_alice = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_alice.bind(("127.0.0.1", 41001))
    sock_alice.setblocking(False)
    
    sock_bob = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_bob.bind(("127.0.0.1", 41002))
    sock_bob.setblocking(False)
    
    sock_rendezvous = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rendezvous.bind(("127.0.0.1", 41003))
    sock_rendezvous.setblocking(False)
    
    alice_id = sha256(b"alice")
    bob_id = sha256(b"bob")
    rendezvous_id = sha256(b"rendezvous")
    
    # Создаём puncher'ы
    alice_puncher = UDPHolePuncher(alice_id, sock_alice)
    bob_puncher = UDPHolePuncher(bob_id, sock_bob)
    rend_puncher = UDPHolePuncher(rendezvous_id, sock_rendezvous)
    
    # Rendezvous знает адрес Боба
    rend_puncher._lookup_func = lambda nid: ("127.0.0.1", 41002) if nid == bob_id else None
    
    # Alice знает rendezvous
    alice_puncher.add_rendezvous(rendezvous_id, "127.0.0.1", 41003)
    
    print("Попытка соединения Alice → Bob через rendezvous...")
    
    # В реальности нужен асинхронный обмен
    # Здесь просто показываем структуру
    print("[OK] Структура hole punching готова")
    print("Для полного теста нужен асинхронный цикл с обработкой пакетов")
    
    sock_alice.close()
    sock_bob.close()
    sock_rendezvous.close()


if __name__ == "__main__":
    asyncio.run(test_hole_punching())