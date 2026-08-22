"""
Crypto Engine - Stage 1: Core Binary Codec & Byte Engine
Zero-dependency implementation of Hex and Base64 streaming algorithms.
"""

class BinaryEngine:
    B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    B64_LOOKUP = {char: idx for idx, char in enumerate(B64_CHARS)}
    HEX_CHARS = "0123456789abcdef"

    @staticmethod
    def string_to_bytes(text: str) -> bytes:
        return text.encode('utf-8')

    @staticmethod
    def bytes_to_string(b: bytes) -> str:
        return b.decode('utf-8')

    @classmethod
    def bytes_to_hex(cls, data: bytes) -> str:
        hex_out = []
        for byte in data:
            hex_out.append(cls.HEX_CHARS[(byte >> 4) & 0x0F])
            hex_out.append(cls.HEX_CHARS[byte & 0x0F])
        return "".join(hex_out)

    @classmethod
    def hex_to_bytes(cls, hex_str: str) -> bytes:
        clean_hex = hex_str.strip().lower()
        if len(clean_hex) % 2 != 0:
            raise ValueError("Invalid Hex String: Length must be even.")

        out = bytearray()
        for i in range(0, len(clean_hex), 2):
            high = cls.HEX_CHARS.index(clean_hex[i])
            low = cls.HEX_CHARS.index(clean_hex[i+1])
            out.append((high << 4) | low)
        return bytes(out)

    @classmethod
    def bytes_to_base64(cls, data: bytes) -> str:
        output = []
        padding = 0
        i = 0
        length = len(data)

        while i < length:
            b0 = data[i]
            b1 = data[i + 1] if i + 1 < length else 0
            b2 = data[i + 2] if i + 2 < length else 0

            if i + 1 >= length:
                padding = 2
            elif i + 2 >= length:
                padding = 1

            buffer_24 = (b0 << 16) | (b1 << 8) | b2

            i0 = (buffer_24 >> 18) & 0x3F
            i1 = (buffer_24 >> 12) & 0x3F
            i2 = (buffer_24 >> 6) & 0x3F
            i3 = buffer_24 & 0x3F

            output.append(cls.B64_CHARS[i0])
            output.append(cls.B64_CHARS[i1])
            output.append('=' if padding >= 2 else cls.B64_CHARS[i2])
            output.append('=' if padding >= 1 else cls.B64_CHARS[i3])

            i += 3

        return "".join(output)

    @classmethod
    def base64_to_bytes(cls, b64_str: str) -> bytes:
        # Fixed padding calculation
        raw_str = b64_str.strip()
        clean_str = raw_str.rstrip('=')
        out = bytearray()
        
        i = 0
        length = len(clean_str)
        while i < length:
            c0 = cls.B64_LOOKUP[clean_str[i]]
            c1 = cls.B64_LOOKUP[clean_str[i + 1]] if i + 1 < length else 0
            c2 = cls.B64_LOOKUP[clean_str[i + 2]] if i + 2 < length else 0
            c3 = cls.B64_LOOKUP[clean_str[i + 3]] if i + 3 < length else 0

            buffer_24 = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3

            out.append((buffer_24 >> 16) & 0xFF)
            if i + 2 < length:
                out.append((buffer_24 >> 8) & 0xFF)
            if i + 3 < length:
                out.append(buffer_24 & 0xFF)

            i += 4

        return bytes(out)

    @staticmethod
    def xor_bytes(data: bytes, key: bytes) -> bytes:
        key_len = len(key)
        return bytes([b ^ key[i % key_len] for i, b in enumerate(data)])
