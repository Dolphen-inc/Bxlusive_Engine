"""
Crypto Engine - Stage 3: Poly1305 MAC & ChaCha20-Poly1305 AEAD Engine
Zero-dependency implementation of polynomial authentication over prime 2^130 - 5.
Ref: RFC 7539
"""

import struct
from .core import BinaryEngine
from .chacha import ChaCha20Engine


class Poly1305Engine:
    P = (1 << 130) - 5

    @classmethod
    def _clamp(cls, r_bytes: bytes) -> int:
        r = bytearray(r_bytes)
        r[3] &= 15
        r[7] &= 15
        r[11] &= 15
        r[15] &= 15

        r[4] &= 252
        r[8] &= 252
        r[12] &= 252

        return int.from_bytes(r, byteorder='little')

    @classmethod
    def create_tag(cls, msg: bytes, key: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("Poly1305 key must be exactly 32 bytes.")

        r = cls._clamp(key[:16])
        s = int.from_bytes(key[16:], byteorder='little')

        accumulator = 0

        for i in range(0, len(msg), 16):
            chunk = msg[i:i + 16]
            chunk_int = int.from_bytes(chunk, byteorder='little') + (1 << (8 * len(chunk)))
            accumulator = ((accumulator + chunk_int) * r) % cls.P

        tag_int = (accumulator + s) & ((1 << 128) - 1)
        return tag_int.to_bytes(16, byteorder='little')


class ChaCha20Poly1305AEAD:
    @staticmethod
    def _pad16(data: bytes) -> bytes:
        if len(data) % 16 == 0:
            return b""
        return b"\x00" * (16 - (len(data) % 16))

    @classmethod
    def encrypt_and_seal(cls, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
        poly_key = ChaCha20Engine._block(key, counter=0, nonce=nonce)[:32]
        ciphertext = ChaCha20Engine.encrypt(plaintext, key, nonce, initial_counter=1)

        mac_data = (
            aad + cls._pad16(aad) +
            ciphertext + cls._pad16(ciphertext) +
            struct.pack("<Q", len(aad)) +
            struct.pack("<Q", len(ciphertext))
        )

        auth_tag = Poly1305Engine.create_tag(mac_data, poly_key)

        return {
            "ciphertext_b64": BinaryEngine.bytes_to_base64(ciphertext),
            "auth_tag_hex": BinaryEngine.bytes_to_hex(auth_tag),
            "nonce_hex": BinaryEngine.bytes_to_hex(nonce)
        }

    @classmethod
    def decrypt_and_verify(cls, key: bytes, nonce_hex: str, ciphertext_b64: str, auth_tag_hex: str, aad: bytes = b"") -> bytes:
        ciphertext = BinaryEngine.base64_to_bytes(ciphertext_b64)
        auth_tag = BinaryEngine.hex_to_bytes(auth_tag_hex)
        nonce = BinaryEngine.hex_to_bytes(nonce_hex)

        poly_key = ChaCha20Engine._block(key, counter=0, nonce=nonce)[:32]

        mac_data = (
            aad + cls._pad16(aad) +
            ciphertext + cls._pad16(ciphertext) +
            struct.pack("<Q", len(aad)) +
            struct.pack("<Q", len(ciphertext))
        )

        expected_tag = Poly1305Engine.create_tag(mac_data, poly_key)

        if not cls._constant_time_compare(auth_tag, expected_tag):
            raise ValueError("SECURITY ALERT: Authentication Tag Verification Failed! Payload Tampered.")

        return ChaCha20Engine.decrypt(ciphertext, key, nonce, initial_counter=1)

    @staticmethod
    def _constant_time_compare(val1: bytes, val2: bytes) -> bool:
        if len(val1) != len(val2):
            return False
        result = 0
        for x, y in zip(val1, val2):
            result |= x ^ y
        return result == 0
