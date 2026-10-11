"""
ROY Server Node - сервер с подсчётом скорости.
"""

import asyncio
import socket
import sys
import time

from .crypto import KeyPair, generate_keypair_with_pow
from .packet import Packet, PacketType


class RoyServer:
    def __init__(self, port: int):
        priv, node_id, _ = generate_keypair_with_pow(difficulty=16)
        self.keypair = KeyPair(private_key=priv, node_id=node_id)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("0.0.0.0", port))
        self.socket.setblocking(False)
        self.port = port
        self.running = False

        # Статистика скорости
        self.stats = {
            "bytes": 0,
            "packets": 0,
            "first_time": None,
            "last_time": None,
        }

    def _reset_stats(self):
        self.stats = {
            "bytes": 0,
            "packets": 0,
            "first_time": None,
            "last_time": None,
        }

    def _print_speed(self):
        if self.stats["packets"] == 0:
            return

        elapsed = self.stats["last_time"] - self.stats["first_time"]

        if elapsed <= 0:
            return

        speed_kbps = (self.stats["bytes"] * 8) / elapsed / 1000
        speed_mbps = speed_kbps / 1000

        print(f"[ROY-SERVER] ━━━ СКОРОСТЬ ━━━")
        print(f"[ROY-SERVER] Пакетов: {self.stats['packets']}")
        print(f"[ROY-SERVER] Байт: {self.stats['bytes']}")
        print(f"[ROY-SERVER] Время: {elapsed:.3f} сек")
        print(f"[ROY-SERVER] Скорость: {speed_mbps:.2f} Мбит/с")
        print(f"[ROY-SERVER] ━━━━━━━━━━━━━━━")

    async def start(self):
        self.running = True
        print(f"[ROY-SERVER] NodeID: {self.keypair.node_id.hex()[:16]}...")
        print(f"[ROY-SERVER] Порт: {self.port}")

        loop = asyncio.get_event_loop()
        last_print = time.time()

        while self.running:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(self.socket, 65536),
                    timeout=0.5
                )

                packet = Packet.deserialize(data)
                now = time.time()

                if packet.packet_type == PacketType.PING:
                    response = Packet(
                        packet_type=PacketType.PONG,
                        src_node_id=self.keypair.node_id,
                        dst_node_id=packet.src_node_id,
                        payload=b""
                    )
                    self.socket.sendto(
                        response.serialize(self.keypair.sign),
                        addr
                    )

                elif packet.packet_type == PacketType.DATA:
                    # Проверяем, не команда ли это
                    payload_text = packet.payload.decode("utf-8", errors="ignore")

                    if payload_text.startswith("SPEED_START"):
                        self._reset_stats()
                        print(f"[ROY-SERVER] ⚡ Начало теста скорости")

                    elif payload_text.startswith("SPEED_END"):
                        self._print_speed()
                        self._reset_stats()

                    else:
                        # Считаем статистику
                        if self.stats["first_time"] is None:
                            self.stats["first_time"] = now

                        self.stats["last_time"] = now
                        self.stats["bytes"] += len(packet.payload)
                        self.stats["packets"] += 1

                        # Не спамим лог
                        if self.stats["packets"] % 10 == 0:
                            print(f"[ROY-SERVER] Получено {self.stats['packets']} пакетов")

                        # Отвечаем только на первый
                        if self.stats["packets"] == 1:
                            ack = Packet(
                                packet_type=PacketType.DATA,
                                src_node_id=self.keypair.node_id,
                                dst_node_id=packet.src_node_id,
                                payload=b"START"
                            )
                            self.socket.sendto(
                                ack.serialize(self.keypair.sign),
                                addr
                            )

            except asyncio.TimeoutError:
                continue
            except BlockingIOError:
                await asyncio.sleep(0.01)
            except Exception as e:
                pass


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4001
    server = RoyServer(port)
    try:
        await server.start()
    except KeyboardInterrupt:
        print("\n[ROY-SERVER] Остановлен")


if __name__ == "__main__":
    asyncio.run(main())