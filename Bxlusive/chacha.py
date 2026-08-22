"""
Crypto Engine - Stage 2: Pure ChaCha20 Stream Cipher Engine
Zero-dependency implementation using ARX (Addition, Rotation, XOR) primitives.
Ref: RFC 7539
"""

import struct
from .core import BinaryEngine


class ChaCha20Engine:
    CONSTANTS = (0x61707865, 0x3320646e, 0x79203262, 0x6b206574)

    @staticmethod
    def _rotl32(v: int, n: int) -> int:
        return ((v << n) & 0xFFFFFFFF) | ((v >> (32 - n)) & 0xFFFFFFFF)

    @classmethod
    def _quarter_round(cls, state: list, a: int, b: int, c: int, d: int):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = cls._rotl32(state[d] ^ state[a], 16)

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = cls._rotl32(state[b] ^ state[c], 12)

        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = cls._rotl32(state[d] ^ state[a], 8)

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = cls._rotl32(state[b] ^ state[c], 7)

    @classmethod
    def _block(cls, key: bytes, counter: int, nonce: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes (256 bits).")
        if len(nonce) != 12:
            raise ValueError("Nonce must be exactly 12 bytes (96 bits).")

        key_words = list(struct.unpack("<8I", key))
        nonce_words = list(struct.unpack("<3I", nonce))

        initial_state = list(cls.CONSTANTS) + key_words + [counter & 0xFFFFFFFF] + nonce_words
        state = list(initial_state)

        for _ in range(10):
            cls._quarter_round(state, 0, 4, 8, 12)
            cls._quarter_round(state, 1, 5, 9, 13)
            cls._quarter_round(state, 2, 6, 10, 14)
            cls._quarter_round(state, 3, 7, 11, 15)

            cls._quarter_round(state, 0, 5, 10, 15)
            cls._quarter_round(state, 1, 6, 11, 12)
            cls._quarter_round(state, 2, 7, 8, 13)
            cls._quarter_round(state, 3, 4, 9, 14)

        final_state = [(state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16)]

        return struct.pack("<16I", *final_state)

    @classmethod
    def encrypt(cls, plaintext: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
        encrypted_blocks = bytearray()
        counter = initial_counter

        for i in range(0, len(plaintext), 64):
            chunk = plaintext[i:i + 64]
            keystream = cls._block(key, counter, nonce)
            
            encrypted_chunk = BinaryEngine.xor_bytes(chunk, keystream[:len(chunk)])
            encrypted_blocks.extend(encrypted_chunk)
            
            counter += 1

        return bytes(encrypted_blocks)

    @classmethod
    def decrypt(cls, ciphertext: bytes, key: bytes, nonce: bytes, initial_counter: int = 1) -> bytes:
        return cls.encrypt(ciphertext, key, nonce, initial_counter)
