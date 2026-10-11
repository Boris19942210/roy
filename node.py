"""
ROY Node: Основной класс узла.
"""

import asyncio
import json
import socket
import sys
import time
from typing import Optional

from .crypto import KeyPair, generate_keypair_with_pow, sha256
from .packet import Packet, PacketType
from .dht import RoutingTable, DHT, PeerInfo
from .adaptive import AdaptiveNode


class RoyNode:
    """Узел протокола ROY."""

    def __init__(
        self,
        keypair: Optional[KeyPair] = None,
        pow_difficulty: int = 16,
        bind_addr: str = "0.0.0.0",
        port: int = 4001
    ):
        # Ключи
        if keypair:
            self.keypair = keypair
        else:
            priv, node_id, _ = generate_keypair_with_pow(pow_difficulty)
            self.keypair = KeyPair(private_key=priv, node_id=node_id)

        self.node_id = self.keypair.node_id

        # Сеть
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((bind_addr, port))
        self.socket.setblocking(False)
        self.port = port
        self.bind_addr = bind_addr

        # Компоненты
        self.routing_table = RoutingTable(self.node_id)
        self.dht = DHT(self.node_id, self.routing_table)
        self.adaptive = AdaptiveNode()

        # Состояние
        self.running = False
        self.bootstrap_nodes = []
        self.stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "errors": 0,
        }

    # ============ ЖИЗНЕННЫЙ ЦИКЛ ============

    def start(self):
        self.running = True

        print(f"[ROY] NodeID: {self.node_id.hex()}")
        print(f"[ROY] Порт: {self.port}")
        print(f"[ROY] Узел запущен")

        asyncio.create_task(self._receive_loop())
        asyncio.create_task(self._maintenance_loop())

    def stop(self):
        self.running = False
        try:
            self.socket.close()
        except:
            pass
        print("[ROY] Узел остановлен")

    def add_bootstrap(self, node_id: bytes, ip: str, port: int):
        self.bootstrap_nodes.append((node_id, ip, port))
        peer = PeerInfo(
            node_id=node_id,
            address=f"{ip}:{port}",
            transport="udp",
            last_seen=time.time()
        )
        self.routing_table.add_peer(peer)
        print(f"[ROY] Bootstrap добавлен: {node_id[:8].hex()}... ({ip}:{port})")

    # ============ ОТПРАВКА ============

    def send_packet(self, packet: Packet, addr=None) -> bool:
        try:
            if addr is None:
                peer = self.routing_table.get_peer(packet.dst_node_id)
                if peer is None:
                    print(f"[ROY] Ошибка: узел {packet.dst_node_id[:8].hex()}... не найден в таблице")
                    return False
                ip, port = peer.address.rsplit(":", 1)
                addr = (ip, int(port))

            if not packet.signature:
                packet.signature = self.keypair.sign(packet._bytes_to_sign())

            data = packet.serialize()
            self.socket.sendto(data, addr)
            print(f"[ROY] Пакет отправлен на {addr[0]}:{addr[1]}")

            self.stats["packets_sent"] += 1
            return True
        except Exception as e:
            print(f"[ROY] Ошибка отправки: {e}")
            self.stats["errors"] += 1
            return False

    def ping(self, target_id: bytes) -> bool:
        print(f"[ROY] Отправляю PING на {target_id[:8].hex()}...")
        packet = Packet(
            packet_type=PacketType.PING,
            src_node_id=self.node_id,
            dst_node_id=target_id,
            payload=b""
        )
        return self.send_packet(packet)

    # ============ ПОЛУЧЕНИЕ ============

    async def _receive_loop(self):
        loop = asyncio.get_event_loop()

        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self.socket, 65536)
                print(f"[ROY] Получено {len(data)} байт от {addr[0]}:{addr[1]}")

                if len(data) < 174:
                    print(f"[ROY] Пакет слишком короткий: {len(data)}")
                    continue

                packet = Packet.deserialize(data)
                self.stats["packets_received"] += 1

                await self._handle_packet(packet, addr)

            except BlockingIOError:
                await asyncio.sleep(0.001)
            except Exception as e:
                print(f"[ROY] Ошибка приёма: {e}")
                self.stats["errors"] += 1

    async def _handle_packet(self, packet: Packet, addr):
        # Обновляем routing table
        peer = PeerInfo(
            node_id=packet.src_node_id,
            address=f"{addr[0]}:{addr[1]}",
            transport="udp",
            last_seen=time.time()
        )
        self.routing_table.add_peer(peer)

        if packet.packet_type == PacketType.PING:
            print(f"[ROY] Получен PING от {packet.src_node_id[:8].hex()}...")
            response = Packet(
                packet_type=PacketType.PONG,
                src_node_id=self.node_id,
                dst_node_id=packet.src_node_id,
                payload=b""
            )
            self.send_packet(response, addr)
            print(f"[ROY] Отправлен PONG")

        elif packet.packet_type == PacketType.PONG:
            print(f"[ROY] Получен PONG от {packet.src_node_id[:8].hex()}...")

        else:
            type_name = PacketType.NAMES.get(packet.packet_type, "UNKNOWN")
            print(f"[ROY] Получен {type_name}")

    # ============ ОБСЛУЖИВАНИЕ ============

    async def _maintenance_loop(self):
        while self.running:
            try:
                if self.bootstrap_nodes:
                    for node_id, ip, port in self.bootstrap_nodes:
                        self.ping(node_id)
                else:
                    print("[ROY] Нет bootstrap-узлов для пинга")

                await asyncio.sleep(10)
            except Exception as e:
                print(f"[ROY] Ошибка обслуживания: {e}")
                await asyncio.sleep(5)

    def get_stats(self) -> dict:
        stats = self.stats.copy()
        stats.update({
            "routing_table_size": self.routing_table.size(),
        })
        return stats


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4001

    node = RoyNode(pow_difficulty=12, port=port)

    # Узел 2 знает про узел 1
    if port == 4002:
        bootstrap_id = bytes.fromhex(
            "000293dbe6c0001f46b9dfd70d3b2d16f66a4998b9f3c00f92ea2ef6a276ff53"
        )
        node.add_bootstrap(bootstrap_id, "127.0.0.1", 4001)

    node.start()

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        node.stop()


if __name__ == "__main__":
    asyncio.run(main())