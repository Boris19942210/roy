"""
ROY Packet: Формат пакетов протокола.
"""

import struct
import hashlib
from dataclasses import dataclass


MAGIC = b"ROY1"
VERSION = 0x01


class PacketType:
    PING            = 0x01
    PONG            = 0x02
    FIND_NODE       = 0x03
    NODES           = 0x04
    PUT             = 0x05
    GET             = 0x06
    DATA            = 0x07
    ANNOUNCE        = 0x08
    TUNNEL          = 0x09
    PROOF           = 0x0A
    CONNECT_REQUEST = 0x0B
    PUNCH_REQUEST   = 0x0C
    PUNCH_ACK       = 0x0D
    RELAY           = 0x0E
    RELAY_DATA      = 0x0F
    MANIFEST_GET    = 0x10
    MANIFEST_DATA   = 0x11
    BLOCK_GET       = 0x12
    BLOCK_DATA      = 0x13
    BLOCK_ACK       = 0x14

    NAMES = {
        PING: "PING",
        PONG: "PONG",
        FIND_NODE: "FIND_NODE",
        NODES: "NODES",
        PUT: "PUT",
        GET: "GET",
        DATA: "DATA",
        ANNOUNCE: "ANNOUNCE",
        TUNNEL: "TUNNEL",
        PROOF: "PROOF",
        CONNECT_REQUEST: "CONNECT_REQUEST",
        PUNCH_REQUEST: "PUNCH_REQUEST",
        PUNCH_ACK: "PUNCH_ACK",
        RELAY: "RELAY",
        RELAY_DATA: "RELAY_DATA",
        MANIFEST_GET: "MANIFEST_GET",
        MANIFEST_DATA: "MANIFEST_DATA",
        BLOCK_GET: "BLOCK_GET",
        BLOCK_DATA: "BLOCK_DATA",
        BLOCK_ACK: "BLOCK_ACK",
    }


# Формат заголовка:
# MAGIC(4s) VERSION(B) TYPE(B) FLAGS(H) TTL(B) HOP_COUNT(B)
# SRC_NODE_ID(32s) DST_NODE_ID(32s) PAYLOAD_HASH(32s) PAYLOAD_LEN(I) SIGNATURE(64s)
HEADER_FORMAT = ">4sBBHBB32s32s32sI64s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

MAX_PAYLOAD = 1024 * 1024  # 1 MB


@dataclass
class Packet:
    """Пакет протокола ROY."""
    packet_type: int
    src_node_id: bytes
    dst_node_id: bytes
    payload: bytes = b""
    ttl: int = 32
    hop_count: int = 0
    signature: bytes = b""
    payload_hash: bytes = b""

    def __post_init__(self):
        if len(self.src_node_id) != 32:
            raise ValueError("src_node_id должен быть 32 байта")
        if len(self.dst_node_id) != 32:
            raise ValueError("dst_node_id должен быть 32 байта")
        if len(self.payload) > MAX_PAYLOAD:
            raise ValueError(f"Payload слишком большой: {len(self.payload)}")

        if not self.payload_hash:
            self.payload_hash = hashlib.sha256(self.payload).digest()

    def serialize(self, sign_func=None) -> bytes:
        sig = self.signature
        if sign_func and not sig:
            sig = sign_func(self._bytes_to_sign())

        header = struct.pack(
            HEADER_FORMAT,
            MAGIC,
            VERSION,
            self.packet_type,
            0,          # flags
            self.ttl,
            self.hop_count,
            self.src_node_id,
            self.dst_node_id,
            self.payload_hash,
            len(self.payload),
            sig
        )
        return header + self.payload

    def _bytes_to_sign(self) -> bytes:
        header = struct.pack(
            HEADER_FORMAT,
            MAGIC,
            VERSION,
            self.packet_type,
            0,
            self.ttl,
            self.hop_count,
            self.src_node_id,
            self.dst_node_id,
            self.payload_hash,
            len(self.payload),
            b""         # пустая подпись
        )
        return header + self.payload

    @staticmethod
    def deserialize(data: bytes) -> "Packet":
        if len(data) < HEADER_SIZE:
            raise ValueError("Пакет слишком короткий")

        (
            magic, version, ptype, flags,
            ttl, hop_count,
            src, dst, phash, plen, sig
        ) = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])

        if magic != MAGIC:
            raise ValueError("Неверное магическое число")
        if version != VERSION:
            raise ValueError(f"Неверная версия: {version}")

        payload = data[HEADER_SIZE:HEADER_SIZE + plen]

        return Packet(
            packet_type=ptype,
            src_node_id=src,
            dst_node_id=dst,
            payload=payload,
            ttl=ttl,
            hop_count=hop_count,
            signature=sig,
            payload_hash=phash
        )

    def __repr__(self) -> str:
        type_name = PacketType.NAMES.get(self.packet_type, f"UNKNOWN({self.packet_type})")
        return (
            f"Packet(type={type_name}, "
            f"src={self.src_node_id[:6].hex()}..., "
            f"dst={self.dst_node_id[:6].hex()}..., "
            f"payload={len(self.payload)}B)"
        )