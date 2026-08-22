"""
Bxlusive Cryptography Library
Zero-dependency, custom-built high-performance AEAD engine.
"""

from .core import BinaryEngine
from .chacha import ChaCha20Engine
from .poly1305 import Poly1305Engine, ChaCha20Poly1305AEAD


class Cryptography:
    """Unified API for Bxlusive Cryptography Operations."""

    @staticmethod
    def encrypt_json(data_dict: dict, key: bytes, nonce: bytes, aad: bytes = b"") -> dict:
        """Encrypts a Python dictionary/JSON payload into authenticated Base64."""
        import json
        plaintext_bytes = json.dumps(data_dict).encode('utf-8')
        return ChaCha20Poly1305AEAD.encrypt_and_seal(key, nonce, plaintext_bytes, aad)

    @staticmethod
    def decrypt_json(sealed_package: dict, key: bytes, aad: bytes = b"") -> dict:
        """Verifies Poly1305 tag and decrypts Base64 payload back to Python dictionary."""
        import json
        decrypted_bytes = ChaCha20Poly1305AEAD.decrypt_and_verify(
            key=key,
            nonce_hex=sealed_package['nonce_hex'],
            ciphertext_b64=sealed_package['ciphertext_b64'],
            auth_tag_hex=sealed_package['auth_tag_hex'],
            aad=aad
        )
        return json.loads(decrypted_bytes.decode('utf-8'))

    # Expose low-level engines directly for raw byte manipulation
    Binary = BinaryEngine
    ChaCha20 = ChaCha20Engine
    Poly1305 = Poly1305Engine
    AEAD = ChaCha20Poly1305AEAD
  
