"""
ROY Crypto: Ed25519 ключи, PoW для NodeID, подписи, шифрование.
"""

import hashlib
import os
import time
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import serialization
except ImportError:
    raise ImportError("Требуется: python -m pip install cryptography")


POW_DIFFICULTY = 20  # 2^20 ≈ 1M попыток


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def check_pow(node_id: bytes, difficulty: int = POW_DIFFICULTY) -> bool:
    """Проверяет, что node_id имеет difficulty нулевых бит в начале."""
    full_bytes = difficulty // 8
    rem_bits = difficulty % 8

    for i in range(full_bytes):
        if node_id[i] != 0:
            return False

    if rem_bits > 0:
        mask = 0xFF << (8 - rem_bits)
        if node_id[full_bytes] & mask != 0:
            return False

    return True


def generate_keypair_with_pow(difficulty: int = POW_DIFFICULTY):
    """Генерирует Ed25519 ключ и NodeID с Proof of Work."""
    start = time.time()
    attempts = 0

    while True:
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        node_id = sha256(public_bytes)
        attempts += 1

        if check_pow(node_id, difficulty):
            elapsed = time.time() - start
            return private_key, node_id, elapsed


@dataclass
class KeyPair:
    """Пара ключей узла."""
    private_key: Ed25519PrivateKey
    node_id: bytes

    @property
    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self.private_key.public_key().verify(signature, data)
            return True
        except Exception:
            return False


def verify_signature(public_bytes: bytes, data: bytes, signature: bytes) -> bool:
    """Статическая проверка подписи."""
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, data)
        return True
    except Exception:
        return False


def node_id_from_public(public_bytes: bytes) -> bytes:
    """NodeID = SHA256(public_key)."""
    return sha256(public_bytes)


def derive_session_key(
    our_x25519: X25519PrivateKey,
    their_x25519_public: bytes,
    our_node_id: bytes,
    their_node_id: bytes
) -> bytes:
    """Вычисляет общий сессионный ключ."""
    their_public = X25519PublicKey.from_public_bytes(their_x25519_public)
    shared = our_x25519.exchange(their_public)
    ids = sorted([our_node_id, their_node_id])
    return sha256(shared + ids[0] + ids[1])


def encrypt_payload(key: bytes, plaintext: bytes):
    """Шифрование ChaCha20Poly1305. Returns: (ciphertext, nonce)"""
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_payload(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    """Дешифрование ChaCha20Poly1305."""
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, None)