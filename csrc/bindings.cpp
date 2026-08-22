#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
// #include <pybind11/pybind11.h>
#include <vector>
#include <stdexcept>

namespace py = pybind11;

// Forward declarations of our C++ engines (from chacha.cpp and poly.cpp)
std::vector<uint8_t> chacha20_process(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, uint32_t counter);
std::vector<uint8_t> poly1305_create_tag(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& key);

// Unified C++ AEAD Seal function exposed to Python
py::dict cxx_encrypt_and_seal(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& aad) {
    // 1. Generate Poly1305 key using ChaCha20 block counter 0
    std::vector<uint8_t> poly_key = chacha20_process(std::vector<uint8_t>(64, 0), key, nonce, 0);
    poly_key.resize(32);

    // 2. Encrypt plaintext using ChaCha20 (counter starts at 1)
    std::vector<uint8_t> ciphertext = chacha20_process(plaintext, key, nonce, 1);

    // 3. Construct MAC data buffer for Poly1305 authentication tag
    // (AAD + padding + Ciphertext + padding + lengths)
    size_t aad_pad_len = (16 - (aad.size() % 16)) % 16;
    size_t cipher_pad_len = (16 - (ciphertext.size() % 16)) % 16;

    std::vector<uint8_t> mac_data;
    mac_data.insert(mac_data.end(), aad.begin(), aad.end());
    mac_data.insert(mac_data.end(), aad_pad_len, 0x00);
    mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());
    mac_data.insert(mac_data.end(), cipher_pad_len, 0x00);

    // Append 64-bit little endian lengths
    uint64_t aad_len_bits = aad.size() * 8;
    uint64_t cipher_len_bits = ciphertext.size() * 8;
    
    for (int i = 0; i < 8; ++i) mac_data.push_back(static_cast<uint8_t>(aad_len_bits >> (8 * i)));
    for (int i = 0; i < 8; ++i) mac_data.push_back(static_cast<uint8_t>(cipher_len_bits >> (8 * i)));

    // 4. Create Poly1305 authentication tag
    std::vector<uint8_t> auth_tag = poly1305_create_tag(mac_data, poly_key);

    // 5. Return raw bytes back to Python wrapper for Base64/Hex encoding
    py::dict result;
    result["ciphertext"] = py::bytes(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    result["auth_tag"] = py::bytes(reinterpret_cast<const char*>(auth_tag.data()), auth_tag.size());
    result["nonce"] = py::bytes(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    return result;
}

PYBIND11_MODULE(bxlusive_core, m) {
    m.doc() = "Bxlusive High-Performance C++ Core Encryption Engine";

    // Expose raw engine functions to Python
    m.def("chacha20_process", &chacha20_process, "ChaCha20 stream process");
    m.def("poly1305_create_tag", &poly1305_create_tag, "Poly1305 MAC tag generator");
    m.def("encrypt_and_seal", &cxx_encrypt_and_seal, "High-performance C++ AEAD Encryption");
}
