#include <emscripten/bind.h>
#include <vector>
#include <string>

using namespace emscripten;

// Forward declarations of core C++ functions
std::vector<uint8_t> chacha20_process(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, uint32_t counter);
std::vector<uint8_t> poly1305_create_tag(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& key);

// JS-friendly wrapper returning hex/string objects
std::string js_encrypt(std::string plaintext, std::string key_str) {
    // Converts JS strings to byte vectors, runs C++ engine, returns sealed data
    // ...
    return "sealed_package_json_string";
}

EMSCRIPTEN_BINDINGS(bxlusive_wasm) {
    function("encrypt", &js_encrypt);
}
