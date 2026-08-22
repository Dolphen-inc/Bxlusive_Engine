#include <emscripten/bind.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>

using namespace emscripten;

// Forward declarations from chacha.cpp and poly1305.cpp
std::vector<uint8_t> chacha20_process(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, uint32_t counter);
std::vector<uint8_t> poly1305_create_tag(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& key);

// Helper to convert bytes to Hex string
std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

// Helper to convert bytes to Base64
std::string bytes_to_base64(const std::vector<uint8_t>& data) {
    static const char char_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string ret;
    int val = 0;
    int valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            ret.push_back(char_table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) ret.push_back(char_table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (ret.size() % 4) ret.push_back('=');
    return ret;
}

// Core JS Encrypt function
std::string js_encrypt(std::string plaintext, std::string key_str) {
    // 1. Format 32-byte key
    std::vector<uint8_t> key(32, '0');
    for (size_t i = 0; i < std::min(key_str.size(), size_t(32)); ++i) {
        key[i] = static_cast<uint8_t>(key_str[i]);
    }

    // 2. Generate random 12-byte nonce
    std::vector<uint8_t> nonce(12);
    std::random_device rd;
    for (int i = 0; i < 12; ++i) nonce[i] = rd() & 0xFF;

    // 3. Convert plaintext to bytes
    std::vector<uint8_t> ptext(plaintext.begin(), plaintext.end());

    // 4. Run ChaCha20-Poly1305 AEAD seal
    std::vector<uint8_t> poly_key = chacha20_process(std::vector<uint8_t>(64, 0), key, nonce, 0);
    poly_key.resize(32);
    std::vector<uint8_t> ciphertext = chacha20_process(ptext, key, nonce, 1);

    // Build MAC data for tag
    size_t cipher_pad_len = (16 - (ciphertext.size() % 16)) % 16;
    std::vector<uint8_t> mac_data;
    mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());
    mac_data.insert(mac_data.end(), cipher_pad_len, 0x00);
    
    uint64_t cipher_len_bits = ciphertext.size() * 8;
    for (int i = 0; i < 8; ++i) mac_data.push_back(static_cast<uint8_t>(cipher_len_bits >> (8 * i)));

    std::vector<uint8_t> auth_tag = poly1305_create_tag(mac_data, poly_key);

    // 5. Return JSON string matching Python backend structure
    std::string b64_cipher = bytes_to_base64(ciphertext);
    std::string hex_tag = bytes_to_hex(auth_tag);
    std::string hex_nonce = bytes_to_hex(nonce);

    return "{\"ciphertext_b64\":\"" + b64_cipher + "\",\"auth_tag_hex\":\"" + hex_tag + "\",\"nonce_hex\":\"" + hex_nonce + "\"}";
}

EMSCRIPTEN_BINDINGS(bxlusive_wasm) {
    function("encrypt", &js_encrypt);
}
