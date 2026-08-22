"""
Bxlusive Cryptography Library
Zero-dependency, custom-built high-performance AEAD engine.
"""

from .core import BinaryEngine
from .chacha import ChaCha20Engine
from .poly1305 import Poly1305Engine, ChaCha20Poly1305AEAD
import json
import os


class CryptographyEngine:
    """Unified API for Bxlusive Cryptography Operations."""

    def __init__(self):
        # Default 32-byte master key from environment or secure fallback
        self.master_key = os.getenv("BXLUSIVE_KEY", "BxlusiveDefaultSecretKey32Bytes!").encode('utf-8')[:32]

    def _format_key(self, custom_key: str | bytes = None) -> bytes:
        """Converts string keys to bytes and ensures exactly 32 bytes."""
        if custom_key:
            if isinstance(custom_key, str):
                custom_key = custom_key.encode('utf-8')
            return custom_key[:32].ljust(32, b'0')
        return self.master_key

    def encrypt(self, data: dict | str | bytes, key: str | bytes = None) -> dict:
        """
        Encrypts JSON dicts, text strings, or bytes into an authenticated, sealed package.
        Generates a fresh 12-byte nonce for every call.
        """
        active_key = self._format_key(key)
        fresh_nonce = os.urandom(12)  # Generates fresh random nonce every single time

        # Convert input payload to bytes
        if isinstance(data, dict):
            plaintext_bytes = json.dumps(data).encode('utf-8')
        elif isinstance(data, str):
            plaintext_bytes = data.encode('utf-8')
        elif isinstance(data, bytes):
            plaintext_bytes = data
        else:
            raise TypeError(f"Unsupported data type: {type(data)}. Must be dict, str, or bytes.")

        # Encrypt and return sealed package (ciphertext_b64, nonce_hex, auth_tag_hex)
        return ChaCha20Poly1305AEAD.encrypt_and_seal(active_key, fresh_nonce, plaintext_bytes)

    def decrypt(self, sealed_package: dict, key: str | bytes = None) -> dict | str:
        """
        Verifies the Poly1305 anti-tamper tag and decrypts the sealed package back 
        to its original Python dictionary or text string.
        """
        if not isinstance(sealed_package, dict):
            raise ValueError("Invalid payload format. Expected a sealed package dictionary.")

        active_key = self._format_key(key)

        # Decrypt ciphertext using the nonce and tag attached inside the sealed package
        decrypted_bytes = ChaCha20Poly1305AEAD.decrypt_and_verify(
            key=active_key,
            nonce_hex=sealed_package['nonce_hex'],
            ciphertext_b64=sealed_package['ciphertext_b64'],
            auth_tag_hex=sealed_package['auth_tag_hex']
        )

        decoded_str = decrypted_bytes.decode('utf-8')

        # Automatically convert back to a dictionary if it was JSON, otherwise return string
        try:
            return json.loads(decoded_str)
        except json.JSONDecodeError:
            return decoded_str

    # Low-level engine access
    Binary = BinaryEngine
    ChaCha20 = ChaCha20Engine
    Poly1305 = Poly1305Engine
    AEAD = ChaCha20Poly1305AEAD


# Instantiate primary import targets
Cryptography = CryptographyEngine()
cryptography = Cryptography
