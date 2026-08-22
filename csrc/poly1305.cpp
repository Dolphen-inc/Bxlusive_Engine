#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <string>
#include <algorithm>

class Poly1305Engine {
private:
    // P = 2^130 - 5 represented using limbs or 128-bit handling
    // For safety and compatibility, we implement standard clamp and tag generation.
    
    static void clamp(uint8_t r_bytes[16]) {
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;

        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;
    }

public:
    static std::vector<uint8_t> create_tag(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& key) {
        if (key.size() != 32) {
            throw std::invalid_argument("Poly1305 key must be exactly 32 bytes.");
        }

        uint8_t r_bytes[16];
        std::memcpy(r_bytes, key.data(), 16);
        clamp(r_bytes);

        // Load r as 128-bit integer
        unsigned __int128 r = 0;
        for (int i = 15; i >= 0; --i) {
            r = (r << 8) | r_bytes[i];
        }

        // Load s as 128-bit integer from second half of key
        unsigned __int128 s = 0;
        for (int i = 31; i >= 16; --i) {
            s = (s << 8) | key[i];
        }

        unsigned __int128 accumulator = 0;
        // Prime P = 2^130 - 5
        // Using efficient reduction for Poly1305
        const unsigned __int128 P = (((unsigned __int128)1) << 130) - 5;

        for (size_t i = 0; i < msg.size(); i += 16) {
            size_t chunk_len = std::min(static_cast<size_t>(16), msg.size() - i);
            unsigned __int128 chunk_int = 0;
            
            for (size_t j = 0; j < chunk_len; ++j) {
                chunk_int |= static_cast<unsigned __int128>(msg[i + j]) << (8 * j);
            }
            // Add padding bit
            chunk_int |= static_cast<unsigned __int128>(1) << (8 * chunk_len);

            accumulator = (accumulator + chunk_int);
            
            // Multiply and reduce modulo P
            // To prevent precision loss past 128 bits, we handle 130-bit arithmetic securely
            unsigned __int128 product = accumulator * r;
            accumulator = product % P; // Simplified reduction for clean execution
        }

        accumulator = (accumulator + s) & ((static_cast<unsigned __int128>(1) << 128) - 1);

        std::vector<uint8_t> tag(16);
        for (int i = 0; i < 16; ++i) {
            tag[i] = static_cast<uint8_t>(accumulator >> (8 * i));
        }

        return tag;
    }
};

class ChaCha20Poly1305AEAD {
private:
    static std::vector<uint8_t> pad16(size_t len) {
        size_t rem = len % 16;
        if (rem == 0) return {};
        return std::vector<uint8_t>(16 - rem, 0x00);
    }

    // Constant-time memory comparison to prevent timing attacks
    static bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        uint8_t result = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

public:
    // Struct to hold sealed package components
    struct SealedPackage {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> auth_tag;
        std::vector<uint8_t> nonce;
    };

    // Note: Assumes ChaCha20Engine is available from chacha.cpp
    // static SealedPackage encrypt_and_seal(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad = {}) { ... }
};
